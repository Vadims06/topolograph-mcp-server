# server.py
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from fastmcp.server.dependencies import get_http_request
import requests
from starlette.requests import Request
from typing import Optional, List
import os
import logging

# Import schemas from separate file
from schemas import (
    NetworkEventsResponse,
    AdjacencyEventsResponse,
    EventsTimelineResponse,
    ShortestPathResponse,
    CspfPathResponse,
    EdgeFailureReactionResponse,
)


logging.basicConfig(level=logging.DEBUG)


mcp = FastMCP(
    name="OSPF_Analyser",
    instructions="""
              Use this MCP in order to get details about OSPF/IS-IS domain.
              Tool provides informations about number of nodes and links are in OSPF/IS-IS domain""",
    version="1.1.0",
)

# Base URL for your Flask+Connexion API
API_BASE = os.getenv("TOPOLOGRAPH_API_BASE", "")
if not API_BASE:
    raise ValueError("TOPOLOGRAPH_API_BASE environment variable is not set")


def get_auth_headers():
    """Get authentication headers for API requests"""

    # Try to get token from request context first
    try:
        request: Request = get_http_request()
        auth_header = request.headers.get('Authorization', '')
        logging.debug(f"Authorization header from context: {auth_header}")
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            logging.debug(f"Using token from request context for authentication: {token[:10]}...")
            return {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json"
            }
    except Exception as e:
        logging.debug(f"Could not get token from request context: {e}")
    
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json"
    }


def raise_for_status_with_context(resp, graph_time: str):
    """Like resp.raise_for_status(), but on error transfers the backend's own
    message (the JSON 'detail' field) and appends the graph_time, so the agent
    can report exactly what the API said and which snapshot it concerned.
    """
    if resp.ok:
        return
    try:
        body = resp.json()
        detail = (body.get("detail") or body.get("error")) if isinstance(body, dict) else None
    except ValueError:
        detail = None
    message = (detail or resp.text or "request failed").strip().rstrip(".")
    raise ValueError(f"{message} in graph_time {graph_time}")


def require_watcher_graph(graph_time: str):
    """Reject event queries on non-watcher graphs. Manually uploaded / YAML graphs
    are not monitored and have no events; reporting 'no events' for them is misleading.
    """
    resp = requests.get(f"{API_BASE}/graph/{graph_time}", headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    if not resp.json().get("is_from_watcher"):
        raise ValueError(
            f"graph_time {graph_time} is not monitored by a watcher (manually "
            f"uploaded), so it has no events; use a graph with is_monitored=true"
        )


@mcp.tool
def get_graph_by_time(graph_time: str):
    """
    Fetch a graph by graph name from Topolograph API.
    graph name is a string with included date and hours and number of hosts, i.e 01Sep2025_12h44m36s_8_hosts

    graph_time (str, optional): The graph time to filter by. Use latest if it's not specified.
    """
    url = f"{API_BASE}/graph/{graph_time}"
    resp = requests.get(url, headers=get_auth_headers())
    resp.raise_for_status()
    return resp.json()

@mcp.tool
def get_all_graphs(
    protocol: Optional[str] = None,
    area: Optional[str] = None,
    is_monitored: Optional[bool] = None,
    name: Optional[str] = None,
    latest_only: bool = False,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """
    Description:
        This tool retrieves available graphs from the Topolograph API with optional
        filtering. This tool is a first step for all analysis.
        Each graph reports two monitoring flags:
          - is_monitored: the graph was received from a watcher (vs manually uploaded).
            Only monitored graphs have events; use is_monitored=true when answering
            change/event questions.
          - is_live: the source watcher is currently sending heartbeats.

    Input fields:
        protocol (str, optional): Filter graphs by protocol (ospf, ospfv3, isis, yaml)
        area (str, optional): Filter graphs by area number
        is_monitored (bool, optional): true = only watcher-received graphs, false = only manually uploaded
        name (str, optional): Case-insensitive substring over graph_time or watcher_name (e.g. "before_maintenance")
        latest_only (bool, optional): Return only the single newest graph among those matching the filters
        page (int): Page number, 1-indexed (default: 1)
        per_page (int): Items per page (default: 50)

    Output fields:
        dict with keys:
            items: list of graphs, each with is_monitored and is_live flags
            pagination: page, per_page, total, total_pages

    Equivalent to GET /graph with query parameters.
    """
    url = f"{API_BASE}/graph"
    params: dict = {"page": page, "per_page": per_page}
    if protocol:
        params["protocol"] = protocol
    if area:
        params["area"] = area
    if is_monitored is not None:
        params["is_monitored"] = str(is_monitored).lower()
    if name:
        params["name"] = name
    if latest_only:
        params["latest_only"] = "true"

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def upload_graph(graph: dict):
    """
    Upload a new graph into Topolograph API.
    Equivalent to POST /graph with JSON body.
    """
    url = f"{API_BASE}/graph"
    resp = requests.post(url, json=graph, headers=get_auth_headers())
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_network_by_graph_time(
    graph_time: str,
    network_w_digit_mask: Optional[str] = None,
    ip_address: Optional[str] = None,
    node_id: Optional[str] = None,
):
    """
    Fetch network data by explicit graph_time.

    Description:
        This tool retrieves network information for a specific graph time.
        Universal tool that works with both OSPF and IS-IS protocols.
        Use 'node_id' to find all networks terminated by a specific node.
        Use 'ip_address' to find which network a specific IP belongs to.

    Input fields:
        graph_time (str): REQUIRED - The specific graph time to query, use the most latest from get_all_graphs to get graph_time.
        network_w_digit_mask (str, optional): Network with mask (e.g., 10.0.0.0/24). Helpful when needed to find all devices which terminate the network
        ip_address (str, optional): IP address to find which network it belongs to
        node_id (str, optional): Universal node identifier to find all networks terminated by this node
                                 - For OSPF: Use Router ID (e.g., "10.10.10.1")
                                 - For IS-IS: Use System ID (e.g., "1921.6800.1001")

    Output fields:
        dict: A dictionary containing network information.

    Examples:
        - get_network_by_graph_time("graph123", node_id="10.10.10.1")  # All networks terminated by OSPF Router ID
        - get_network_by_graph_time("graph123", node_id="1921.6800.1001")  # All networks terminated by IS-IS System ID
        - get_network_by_graph_time("graph123", ip_address="192.168.1.5")  # Find network for IP 192.168.1.5

    Equivalent to GET /network/{graph_time}.
    """
    url = f"{API_BASE}/network/{graph_time}"
    params = {}
    if network_w_digit_mask:
        params["network_w_digit_mask"] = network_w_digit_mask
    if ip_address:
        params["ip_address"] = ip_address
    if node_id:
        params["node_id"] = node_id

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_graph_status(graph_time: str) -> dict:
    """
    Get the status of a graph based on its health.

    Description:
        This tool returns the status of a graph including connectivity information
        and various event counts.

    Input fields:
        graph_time (str): Name of graph = The graph time to get status for.

    Output fields:
        dict: A dictionary containing status information with keys:
            - status: The overall status (ok, warning, critical, no_monitoring_data)
            - details: Dictionary with detailed information including:
                - is_connected: Boolean indicating if graph is connected (Полносвязный граф)
                - up_node_events: Count of node up events (Восстановление узла)
                - down_node_events: Count of node down events (Падение узла)
                - all_host_up_down_events: Count of all host up/down events
                - network_up_down_events: Count of network up/down events (Падение сети)
                - adjacency_cost_change_events: Count of adjacency cost change events (изменение стоимости линка)
                - top_unstable_devices: Top-N [{device, event_count}] sorted desc (самые нестабильные устройства)

    Equivalent to GET /graph/{graph_time}/status.
    """
    url = f"{API_BASE}/graph/{graph_time}/status"
    resp = requests.get(url, headers=get_auth_headers())
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_network_events(
    graph_time: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    last_minutes: Optional[int] = None,
) -> NetworkEventsResponse:
    """
    Description:
        This tool returns networks events: network up/down and network cost change events.
        Use this tool only to get details about networks events.
        Events exist ONLY for watcher-monitored graphs (is_monitored=true).
        Manually uploaded or YAML graphs are not monitored and have no events;
        first call get_all_graphs(is_monitored=true, latest_only=true) to pick a
        monitored graph_time.
        Treat any cost change to or from -1 as down (падение) or up (восстановление) event.

    Input fields:
        graph_time (str): Name of graph = The graph time to filter events.
        start_time (str, optional): Start time to filter events in ISO format (e.g., 2025-06-30T20:00:00Z)
        end_time (str, optional): End time to filter events in ISO format. Defaults to current time if not provided.
        last_minutes (int, optional): Number of minutes to look back from current time for events. If provided, overrides start_time and end_time parameters.

    Output fields:
        NetworkEventsResponse: A dictionary containing network event information with keys:
            - network_up_down_events: List of NetworkUpDownEvent objects
            - network_cost_change_events: List of NetworkMetricChangeEvent objects

    Equivalent to GET /events/{graph_time}/networks.
    """
    require_watcher_graph(graph_time)
    url = f"{API_BASE}/events/{graph_time}/networks"
    params = {}
    if last_minutes:
        params["last_minutes"] = last_minutes
    else:
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_adjacency_events(
    graph_time: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    last_minutes: Optional[int] = None,
) -> AdjacencyEventsResponse:
    """
    Description:
        This tool returns links/adjacencies events including nodes/hosts up/down events.
        Use this tool only to get details about nodes/hosts events.
        Events exist ONLY for watcher-monitored graphs (is_monitored=true).
        Manually uploaded or YAML graphs are not monitored and have no events;
        first call get_all_graphs(is_monitored=true, latest_only=true) to pick a
        monitored graph_time.
        Treat any cost change to or from -1 as down (падение) or up (восстановление) event.

    Input fields:
        graph_time (str): Name of graph = The graph time to filter events.
        start_time (str, optional): Start time to filter events in ISO format (e.g., 2025-06-30T20:00:00Z)
        end_time (str, optional): End time to filter events in ISO format. Defaults to current time if not provided.
        last_minutes (int, optional): Number of minutes to look back from current time for events. If provided, overrides start_time and end_time parameters.

    Output fields:
        AdjacencyEventsResponse: A dictionary containing adjacency event information with keys:
            - all_host_up_down_events: List of all Up/Down nodes/hosts events (Восстановление узла, Падение узла). List includes all events even recovered events (when node is up after being down).
            - single_host_up_events: List of Up nodes/hosts events (Восстановление узла) from the time when graph was collected.
            - single_host_down_events: List of Down nodes/hosts events (Падение узла) from the time when graph was collected.
            - adjacency_cost_change_events: List of link/adjacency cost (or other metrics) change events  (изменение стоимости линка)

    Equivalent to GET /events/{graph_time}/adjacency.
    """
    require_watcher_graph(graph_time)
    url = f"{API_BASE}/events/{graph_time}/adjacency"
    params = {}
    if last_minutes:
        params["last_minutes"] = last_minutes
    else:
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_events_timeline(
    graph_time: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    last_minutes: Optional[int] = None,
    page: int = 1,
    per_page: int = 20,
) -> EventsTimelineResponse:
    """
    Description:
        This tool returns node/host up/down events already grouped into
        chronological time waves (server-side), so you can narrate a network
        incident ("instability started at T from device X; a flapping burst
        from device Y; reconverged at T+n") without scanning hundreds of raw
        events. Use this instead of get_adjacency_events when the user asks
        "what happened", "summarise the incident", "how many bursts/waves".
        Events exist ONLY for watcher-monitored graphs (is_monitored=true);
        first call get_all_graphs(is_monitored=true, latest_only=true).
        Returns wave summaries only (no nested event arrays): to get a wave's
        individual events, call get_adjacency_events with that wave's
        start_ts/end_ts.

    Input fields:
        graph_time (str): The graph time to filter events.
        start_time (str, optional): Start time in ISO format (e.g., 2025-06-30T20:00:00Z)
        end_time (str, optional): End time in ISO format. Defaults to current time if not provided.
        last_minutes (int, optional): Look back this many minutes; overrides start_time/end_time.
        page (int, optional): Page number (1-indexed) over the waves list.
        per_page (int, optional): Number of waves per page.

    Output fields:
        EventsTimelineResponse: A dictionary with keys:
            - graph_time, watcher_name
            - gap_multiplier, median_gap_sec: how the grouping was computed
            - waves: list of per-wave summaries, each with wave_number, start_ts,
              end_ts (ISO 8601, reusable as start_time/end_time), duration_sec,
              event_count, distinct_devices, trigger_device,
              pattern ("outage" left down / "flap" down then up / "up" only ups),
              converged (recovery seen within the queried window; a recovery
              after end_time is not counted)
            - pagination: page, per_page, total, total_pages

    Equivalent to GET /events/{graph_time}/adjacency/timeline.
    """
    require_watcher_graph(graph_time)
    url = f"{API_BASE}/events/{graph_time}/adjacency/timeline"
    params = {"page": page, "per_page": per_page}
    if last_minutes:
        params["last_minutes"] = last_minutes
    else:
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_nodes(
    graph_time: str,
    protocol: Optional[str] = None,
    watcher: Optional[bool] = None,
    area: Optional[str] = None,
    abr: Optional[bool] = None,
    asbr: Optional[bool] = None,
    overload: Optional[bool] = None,
    attached: Optional[bool] = None,
    maxmetric: Optional[bool] = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """
    Get a paginated list of nodes/routers from a graph.

    Description:
        Returns structured node data including hostname, system ID, network count,
        areas, IS-IS flag, and node_attributes (role flags). Supports pre-filtering by
        protocol, watcher origin, area, and node role flag before returning results.
        Note: 'network count' is the number of prefixes/networks on a node, NOT its
        neighbor/adjacency count. To count neighbors per router, use get_edges and
        count edges per src_node; do not derive neighbor counts from this tool.

    Input fields:
        graph_time (str): The graph time identifier
        protocol (str, optional): Filter: only return if graph matches protocol (ospf, ospfv3, isis, yaml)
        watcher (bool, optional): Filter: true for watcher-uploaded graphs, false for manually parsed
        area (str, optional): Filter: only return if graph contains this area (e.g. "0", "0.0.0.1", "49.0001")
        abr (bool, optional): OSPF role filter — true returns only Area Border Routers (false: only non-ABRs)
        asbr (bool, optional): OSPF role filter — true returns only AS Boundary Routers (false: only non-ASBRs)
        overload (bool, optional): IS-IS filter — true returns only routers with the overload (OL) bit set
        attached (bool, optional): IS-IS filter — true returns only routers with the attached (ATT) bit set
        maxmetric (bool, optional): OSPF filter — true returns only routers in max-metric (RFC 3137 stub router) state
        page (int): Page number, 1-indexed (default: 1)
        per_page (int): Items per page (default: 50)

    Output fields:
        dict with keys:
            items: list of nodes with node_id, hostname, systemid, networks_count, areas, is_isis,
                   node_attributes (role flags: {"abr":1,"asbr":0,"maxmetric":0} for OSPF, {"overload":1,"attached":0} for IS-IS)
            pagination: page, per_page, total, total_pages

    Equivalent to GET /graph/{graph_time}/nodes.
    """
    url = f"{API_BASE}/graph/{graph_time}/nodes"
    params: dict = {"page": page, "per_page": per_page}
    if protocol:
        params["protocol"] = protocol
    if watcher is not None:
        params["watcher"] = str(watcher).lower()
    if area:
        params["area"] = area
    # Node role flags forwarded as node-attribute filters (e.g. ?abr=1); the API treats any
    # such query arg as an exact match on the node_attributes map.
    for flag_name, flag_value in (("abr", abr), ("asbr", asbr), ("overload", overload), ("attached", attached), ("maxmetric", maxmetric)):
        if flag_value is not None:
            params[flag_name] = int(flag_value)

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    resp.raise_for_status()
    return resp.json()


@mcp.tool
def get_edges(
    graph_time: str,
    src_node: Optional[str] = None,
    dst_node: Optional[str] = None,
    protocol: Optional[str] = None,
    watcher: Optional[bool] = None,
    area: Optional[str] = None,
    edge_query_params: Optional[dict] = None,
    include: Optional[List[str]] = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """
    Get edges from a graph with optional filtering.

    Description:
        Returns a paginated list of edges. Supports graph-level pre-filters (protocol,
        watcher, area) and per-edge attribute filters. Useful for queries like
        "all IS-IS L1 edges" or "edges with max_rsrv_link_bw < 10Gbps".
        Edges are the source of neighbor/adjacency data: to find a router's neighbor
        count, fetch edges and count those with that router as src_node. Results are
        paginated; read all pages (see pagination.total_pages) before counting.

        Attribute filters use exact match or range operators:
          weight=10, temetric__gt=100, unreserved_bw_0__lt=1000000000
        TE attributes (when present): temetric, admin_group, max_link_bw,
          max_rsrv_link_bw, unreserved_bw_0..7
        IS-IS: isis_level=1 or isis_level=2
        User-defined attributes (e.g. isp_provider=verizon) are also supported.

    Input fields:
        graph_time (str): The graph time identifier
        src_node (str, optional): Filter edges by source node name
        dst_node (str, optional): Filter edges by destination node name
        protocol (str, optional): Graph-level filter (ospf, ospfv3, isis, yaml)
        watcher (bool, optional): Graph-level filter: watcher-uploaded vs manually parsed
        area (str, optional): Graph-level filter by area
        edge_query_params (dict, optional): Edge attribute filters (flat key=value pairs)
        include (list[str], optional): Extra MPLS-TE fields, hidden by default:
          "lsp_left_bw" (how much TE bandwidth is left on each edge, after
          accounting for placed LSP tunnels -- lsp_left_bw_0..7 plus a
          human-readable lsp_reserved_bw/lsp_left_bw/lsp_bandwidth_usage pair
          at the default priority-7 pool), "lsps" (which LSP tunnels traverse
          this edge), "is_te_link" (whether the edge is TE-enabled), "edge_key"
          (stable identity, needed for get_lsps(via_edge_key=) on parallel/ECMP edges)
        page (int): Page number, 1-indexed (default: 1)
        per_page (int): Items per page (default: 50)

    Output fields:
        dict with keys:
            items: list of edges with src, dst, weight, and optional TE/IS-IS/user-defined attrs
            pagination: page, per_page, total, total_pages

    Equivalent to GET /graph/{graph_time}/edges.
    """
    url = f"{API_BASE}/graph/{graph_time}/edges"
    params: dict = {"page": page, "per_page": per_page}
    if src_node:
        params["src_node"] = src_node
    if dst_node:
        params["dst_node"] = dst_node
    if protocol:
        params["protocol"] = protocol
    if watcher is not None:
        params["watcher"] = str(watcher).lower()
    if area:
        params["area"] = area
    if include:
        params["include"] = ",".join(include)
    if edge_query_params:
        params.update(edge_query_params)

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def get_lsps(
    graph_time: str,
    lsp_name: Optional[str] = None,
    status: Optional[str] = None,
    via_node: Optional[str] = None,
    via_edge: Optional[str] = None,
    via_edge_key: Optional[str] = None,
    include_path: bool = False,
) -> dict:
    """
    List MPLS TE LSP tunnels, or get one tunnel by name.

    Description:
        Each returned path already carries its last CSPF placement outcome:
        placed (bool), reason (why placement failed -- bandwidth/affinity/
        srlg/disconnected -- null when placed), cost (total path metric,
        null when unplaced). Getting a single tunnel by lsp_name always
        includes each path's expanded node-name path; the list form omits it
        by default (include_path=True to get it there too, since it can be
        large across many tunnels).

    Input fields:
        graph_time (str): The graph time identifier
        lsp_name (str, optional): Get one tunnel by name instead of listing all
        status (str, optional): "placed" or "unplaced" -- keep only paths matching
        via_node (str, optional): Keep only paths whose CSPF-computed path visits this node
          (e.g. "which tunnels cross router X", pre-maintenance impact check)
        via_edge (str, optional): "srcNode,dstNode" -- keep only paths traversing this hop
        via_edge_key (str, optional): Exact stable edge_key (from get_edges(include=["edge_key"]))
          -- disambiguates parallel/ECMP edges that via_edge alone cannot
        include_path (bool, optional): Also return each path's expanded node-name path in the list form

    Equivalent to GET /graph/{graph_time}/lsps[/{lsp_name}].
    """
    url = f"{API_BASE}/graph/{graph_time}/lsps"
    if lsp_name:
        url += f"/{lsp_name}"
        resp = requests.get(url, headers=get_auth_headers())
        raise_for_status_with_context(resp, graph_time)
        return resp.json()

    params: dict = {}
    if status:
        params["status"] = status
    if via_node:
        params["via_node"] = via_node
    if via_edge:
        params["via_edge"] = via_edge
    if via_edge_key:
        params["via_edge_key"] = via_edge_key
    if include_path:
        params["include"] = "path"

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def add_lsp(graph_time: str, lsp: dict) -> dict:
    """Add an MPLS TE LSP tunnel to a graph."""
    url = f"{API_BASE}/graph/{graph_time}/lsps"
    resp = requests.post(url, headers=get_auth_headers(), json=lsp)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def update_lsp(graph_time: str, lsp_name: str, changes: dict) -> dict:
    """Update or rename an MPLS TE LSP tunnel."""
    url = f"{API_BASE}/graph/{graph_time}/lsps/{lsp_name}"
    resp = requests.patch(url, headers=get_auth_headers(), json=changes)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def delete_lsp(graph_time: str, lsp_name: Optional[str] = None) -> dict:
    """Delete one MPLS TE LSP tunnel, or all tunnels when name is omitted."""
    url = f"{API_BASE}/graph/{graph_time}/lsps"
    if lsp_name:
        url += f"/{lsp_name}"
    resp = requests.delete(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def get_shortest_path(
    graph_time: str,
    src_node: str,
    dst_node: str,
    with_lsps: bool = False,
) -> ShortestPathResponse:
    """
    Calculate the shortest path between two nodes/devices in a graph/diagram.

    Description:
        Plain IGP shortest path by default. For "what if this link is down"
        backup-path analysis, use get_edge_failure_reaction instead -- that
        question now has its own endpoint (whole-network impact, not just a
        recomputed path).

    Input fields:
        graph_time (str): The graph time
        src_node (str): Source node Router ID (e.g., "10.10.10.1")
        dst_node (str): Destination node Router ID (e.g., "20.20.20.1")
        with_lsps (bool, optional): If true, account for autoroute-enabled
          MPLS-TE tunnels as forwarding shortcuts -- the path traffic actually
          takes given the tunnels currently in the graph, not the plain IGP
          path. Off by default (a signaled LSP does not redirect traffic on
          its own without autoroute configured on the tunnel).

    Output fields:
        ShortestPathResponse: A dictionary containing shortest path information with keys:
            - spt_path_nodes_name_as_ll_in_ll: List of lists of node names representing shortest paths
            - cost: Integer representing total path cost
            - unbackup_paths_nodes_name_as_ll_in_ll: List of lists of node names representing backup paths

    Equivalent to GET /graph/{graph_time}/path/{src_node}/{dst_node}.
    """
    url = f"{API_BASE}/graph/{graph_time}/path/{src_node}/{dst_node}"
    params: dict = {}
    if with_lsps:
        params["with_lsps"] = "true"

    resp = requests.get(url, params=params, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def get_cspf_path(
    graph_time: str,
    node_a: str,
    node_b: str,
    bandwidth: Optional[str] = None,
    metric_type: str = "igp",
    admin_exclude_any: Optional[List[str]] = None,
    admin_include_any: Optional[List[str]] = None,
    admin_include_all: Optional[List[str]] = None,
    srlg_exclude: Optional[List[int]] = None,
    setup_priority: int = 7,
) -> CspfPathResponse:
    """
    Constrained-shortest-path (CSPF) query between two nodes.

    Description:
        Answers "will an LSP with these constraints fit, and which path would
        it take" -- an on-demand computation, exactly like get_shortest_path,
        just over a graph pre-filtered by the given TE constraints instead of
        the plain one. No tunnel is created or persisted; this never mutates
        the graph. Use this before calling add_lsp when you want to check
        feasibility first.

    Input fields:
        graph_time (str): The graph time identifier
        node_a (str): Source node name
        node_b (str): Destination node name
        bandwidth (str, optional): Required bandwidth, e.g. "2G", "500M", or a raw bps number
        metric_type (str, optional): "igp" (default) or "te"
        admin_exclude_any (list[str], optional): Affinity group names to exclude
        admin_include_any (list[str], optional): Affinity group names, at least one required
        admin_include_all (list[str], optional): Affinity group names, all required
        srlg_exclude (list[int], optional): SRLG ids to exclude
        setup_priority (int, optional): RSVP-TE setup priority (0-7, default 7) -- selects
          which advertised Unreserved Bandwidth pool the bandwidth check runs against

    Output fields:
        CspfPathResponse: dict with keys:
            - path: list of node names (empty if no path satisfies the constraints)
            - cost: total path metric (null if unplaced)
            - reason: why placement failed, e.g. which constraint removed the only path
              (empty string on success)

    Equivalent to GET /graph/{graph_time}/cspf-path/{node_a}/{node_b}.
    """
    url = f"{API_BASE}/graph/{graph_time}/cspf-path/{node_a}/{node_b}"
    params: dict = {"metric_type": metric_type, "setup_priority": setup_priority}
    if bandwidth:
        params["bandwidth"] = bandwidth
    if admin_exclude_any:
        params["admin_exclude_any"] = ",".join(admin_exclude_any)
    if admin_include_any:
        params["admin_include_any"] = ",".join(admin_include_any)
    if admin_include_all:
        params["admin_include_all"] = ",".join(admin_include_all)
    if srlg_exclude:
        params["srlg_exclude"] = ",".join(str(value) for value in srlg_exclude)

    resp = requests.get(url, params=params, headers=get_auth_headers())
    # 200 even when path is empty -- no path satisfying the constraints is a
    # valid, successful answer (like a search with zero results); 404 is
    # reserved for "the graph itself doesn't exist".
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool
def get_edge_failure_reaction(graph_time: str, failed_edges: list[list[str]]) -> EdgeFailureReactionResponse:
    """
    Predict the whole-network impact if one or more links go down.

    Description:
        Same shape as the node-failure prediction, for links instead of
        nodes: whether the graph stays connected, and the traffic
        rerouting pattern (which links see more/less traffic).

    Input fields:
        graph_time (str): The graph time
        failed_edges (list[list[str]]): Pairs of node names identifying each failed link,
          e.g. [["10.10.10.1", "10.10.10.2"]]

    Output fields:
        EdgeFailureReactionResponse: dict with keys:
            - isGraphStillConnected: bool
            - affectedLinks: {sptPathsIncreasedInPercent, sptPathsDecreasedInPercent}
            - disjointedNodes: list of node-name groups, if the graph split

    Equivalent to POST /network_reaction/edge_failure/.
    """
    url = f"{API_BASE}/network_reaction/edge_failure/"
    payload = {"graph_time": graph_time, "failed_edges_list": failed_edges}

    resp = requests.post(url, json=payload, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.prompt
def ask_about_connected_graphs() -> str:
    """Generates a user message asking about connected graphs."""
    return "Can you please say what graphs are connected?"


@mcp.prompt
def ask_about_ospf(area: str) -> str:
    """Generates a user message asking for an explanation of a OSPF state."""
    return f"Can you please explain the status of OSPF in area {area}?"


@mcp.prompt
def ask_about_isis(area: str) -> str:
    """Generates a user message asking for an explanation of a IS-IS state."""
    return f"Can you please explain the status of IS-IS in area {area}?"


@mcp.prompt
def ask_about_events() -> str:
    """Generates a user message asking for an explanation of a events happened for the last 10 minutes."""
    return "Can you please explain the status of events happened for the last 10 minutes in the area?"


if __name__ == "__main__":
    # Debug: Print FastMCP attributes
    logging.info(f"FastMCP attributes: {dir(mcp)}")
    if hasattr(mcp, 'server'):
        logging.info(f"FastMCP server attributes: {dir(mcp.server)}")
    
    # https://github.com/jlowin/fastmcp/issues/855
    mcp.run(
        transport="http", host="0.0.0.0", port=8000, path="/mcp", stateless_http=True
    )
