# server.py
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, AuthProvider, RemoteAuthProvider, TokenVerifier
from fastmcp.server.dependencies import get_http_request
from mcp.types import ToolAnnotations
import requests
from starlette.requests import Request
from pydantic import Field
from typing import Annotated, Literal, Optional, List, Union
import asyncio
import hashlib
import os
import json
import logging
from pathlib import Path
import time

# Import schemas from separate file
from schemas import (
    NetworkEventsResponse,
    AdjacencyEventsResponse,
    EventsTimelineResponse,
    CspfPathResponse,
    NetworkReactionResponse,
    BgpGraph,
    BgpRouteSummary,
    BgpBinding,
    BgpNodesResponse,
    BgpSessionsResponse,
    BgpRoutesResponse,
    BgpRouteCompareResponse,
    BgpBindingsResponse,
    VrfInventoryResponse,
    VpnsResponse,
)


logging.basicConfig(level=logging.DEBUG)


# Site origin that is both the authorization server and the API host, e.g. https://topolograph.com.
# Unset (self-hosted, CI) leaves the server without HTTP-layer auth: a caller's API token is
# forwarded as before and the API alone decides.
PUBLIC_URL = os.getenv("TOPOLOGRAPH_PUBLIC_URL", "").strip().rstrip("/")

# Revocation reaches the MCP server this late; one userinfo call per request would load the API.
TOKEN_CACHE_TTL_SEC = 30
# A flood of random bearers must not become a flood of userinfo calls.
REJECTED_CACHE_TTL_SEC = 5
TOKEN_CACHE_MAX = 10000
# Unknown bearers cost one userinfo call each; at most this many run at once, the rest wait.
USERINFO_CONCURRENCY = 4


def _remember(cache: dict[str, float], key: str, now: float, ttl_sec: float) -> None:
    """Expired entries are swept only when full, so a flood of rejections stays O(1) each."""
    if len(cache) >= TOKEN_CACHE_MAX:
        for stale in [k for k, until in cache.items() if until <= now]:
            del cache[stale]
        if len(cache) >= TOKEN_CACHE_MAX:
            return
    cache[key] = now + ttl_sec


class TopolographTokenVerifier(TokenVerifier):
    """Rejects a dead token with 401 here, so the client re-authorizes instead of seeing a tool error."""

    def __init__(self, public_url: str):
        super().__init__(base_url=public_url)
        self.userinfo_url = f"{public_url}/oauth/agent/userinfo"
        self.verified_until: dict[str, float] = {}
        self.rejected_until: dict[str, float] = {}
        self.userinfo_slots = asyncio.Semaphore(USERINFO_CONCURRENCY)

    async def verify_token(self, token: str) -> AccessToken | None:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = time.monotonic()
        if self.rejected_until.get(key, 0) > now:
            return None
        if self.verified_until.get(key, 0) > now:
            return AccessToken(token=token, client_id="topolograph", scopes=[])
        async with self.userinfo_slots:
            response = await asyncio.to_thread(
                requests.get, self.userinfo_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        # The wait for a slot and the call can outlast a cache lifetime
        now = time.monotonic()
        if response.status_code != 200:
            self.verified_until.pop(key, None)
            _remember(self.rejected_until, key, now, REJECTED_CACHE_TTL_SEC)
            return None
        _remember(self.verified_until, key, now, TOKEN_CACHE_TTL_SEC)
        return AccessToken(token=token, client_id="topolograph", scopes=[])


def create_auth_provider(public_url: str) -> AuthProvider | None:
    """Advertises Topolograph as the authorization server so a CLI can sign in through the browser."""
    if not public_url:
        return None
    return RemoteAuthProvider(
        token_verifier=TopolographTokenVerifier(public_url),
        authorization_servers=[public_url],
        base_url=public_url,
        resource_name="Topolograph MCP",
    )


mcp = FastMCP(
    name="OSPF_Analyser",
    instructions="""
              Read-only access to OSPF/IS-IS graphs, MPLS TE, BGP and VPN/EVPN data stored in Topolograph.
              Answer routing-domain questions from these tools, not from model knowledge or shell commands.
              Pick the data set first: an IGP graph_time from get_all_graphs, or a BGP epoch from list_bgp_graphs.
              Quote the graph_time used and report empty results as unknown, not as absence.""",
    # server.json is the one place the release version is written
    version=json.loads(Path(__file__).with_name("server.json").read_text())["version"],
    auth=create_auth_provider(PUBLIC_URL),
)

# Base URL for your Flask+Connexion API
API_BASE = os.getenv("TOPOLOGRAPH_API_BASE", "")
if not API_BASE:
    raise ValueError("TOPOLOGRAPH_API_BASE environment variable is not set")

# Read-only mode hides mutation tools (upload_graph, add_lsp, update_lsp,
# delete_lsp) from tools/list entirely, instead of merely rejecting calls to
# them at runtime. Defaults to enabled: agent-facing deployments should opt
# into write access explicitly, not the other way around. Fails closed: only
# a recognized "disable" value turns it off, so a blank or misspelled value
# (e.g. an unset Compose substitution) stays read-only instead of silently
# exposing every mutation tool.
READ_ONLY = os.getenv("TOPOLOGRAPH_MCP_READ_ONLY", "true").strip().lower() not in ("0", "false", "no", "off")

# a host behind a reverse proxy sets 127.0.0.1 so the plain-HTTP port is not public
BIND_HOST = os.getenv("TOPOLOGRAPH_MCP_HOST", "0.0.0.0")


def get_auth_headers():
    """Get authentication headers for API requests"""

    # Try to get token from request context first
    try:
        request: Request = get_http_request()
        auth_header = request.headers.get('Authorization', '')
        logging.debug(f"Authorization header present: {bool(auth_header)}")
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            logging.debug("Using bearer token from request context for authentication")
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


def _require_write_enabled():
    """Defense-in-depth guard for mutation tools. Read-only mode is primarily
    enforced by hiding write/destructive tools from tools/list (see
    mcp.exclude_tags below); this guard protects against a
    mutation tool being reachable despite that -- e.g. a future registration
    or configuration regression -- and must never be the only safeguard.
    """
    if READ_ONLY:
        raise PermissionError(
            "This Topolograph MCP server is running in read-only mode "
            "(TOPOLOGRAPH_MCP_READ_ONLY=true); mutation tools are disabled."
        )


# The agent passes this on to a user who is not signed in, instead of the bare API text.
SIGN_IN_REQUIRED = (
    "Not signed in to Topolograph. On topolograph.com, sign in to ask about your graphs. "
    "On a self-hosted Topolograph, set a valid Topolograph API token for the agent."
)


def raise_for_status_with_context(resp, graph_time: str = ""):
    """Like resp.raise_for_status(), but on error transfers the backend's own
    message (the JSON 'detail' or 'error' field) with its machine-readable
    'code' and 'action', and appends the graph_time, so the agent can report
    exactly what the API said, act on the code, and name the snapshot.
    """
    if resp.ok:
        return
    if resp.status_code == 401:
        raise ValueError(SIGN_IN_REQUIRED)
    try:
        body = resp.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        body = {}
    message = (body.get("detail") or body.get("error") or resp.text or "request failed").strip().rstrip(".")
    hints = [f"{key}={body[key]}" for key in ("code", "action") if body.get(key)]
    if resp.status_code == 429:
        hints.append(f"retry_after_sec={resp.headers.get('Retry-After', 'unknown')}")
    if hints:
        message = f"{message} ({', '.join(hints)})"
    raise ValueError(f"{message} in graph_time {graph_time}" if graph_time else message)


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


# Descriptions shared by several tools, shown in each tool's input schema.
GraphTime = Annotated[str, Field(description="Graph name with date, hours and host count, e.g. 01Sep2025_12h44m36s_8_hosts; the newest comes from get_all_graphs")]
GraphTimeOrWatcher = Annotated[str, Field(description="Graph name, or the name of your OSPF/IS-IS watcher (Enterprise) to read its newest snapshot with events up to now; the answer then names that snapshot in graph_time")]
BgpGraphTime = Annotated[str, Field(description="The BGP graph epoch to query (see list_bgp_graphs)")]
Page = Annotated[int, Field(description="Page number, 1-indexed")]
PerPage = Annotated[int, Field(description="Items per page")]
At = Annotated[Optional[str], Field(description="ISO 8601 moment; state with watcher events applied up to it")]
StartTime = Annotated[Optional[str], Field(description="Start time in ISO 8601 format, e.g. 2025-06-30T20:00:00Z")]
EndTime = Annotated[Optional[str], Field(description="End time in ISO 8601 format; defaults to current time")]
LastMinutes = Annotated[Optional[int], Field(description="Minutes to look back from now; overrides start_time and end_time")]
Prefix = Annotated[Optional[str], Field(description="CIDR is an exact match; an address returns every covering route, longest prefix first")]
Vni = Annotated[Optional[int], Field(description="EVPN L2VNI")]
Vrf = Annotated[Optional[str], Field(description="VRF name, resolved to its RDs across the bound epoch's own routers")]
RouteTarget = Annotated[Optional[str], Field(description="Any of the route's route targets")]
RouteDistinguisher = Annotated[Optional[str], Field(description="Route distinguisher")]
Mac = Annotated[Optional[str], Field(description="EVPN MAC address, exact match")]


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_graph_by_time(graph_time: GraphTime):
    """
    Fetch a graph by graph name from Topolograph API.
    graph name is a string with included date and hours and number of hosts, i.e 01Sep2025_12h44m36s_8_hosts
    """
    url = f"{API_BASE}/graph/{graph_time}"
    resp = requests.get(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()

@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_all_graphs(
    protocol: Annotated[Optional[str], Field(description="Filter graphs by protocol (ospf, ospfv3, isis, yaml)")] = None,
    area: Annotated[Optional[str], Field(description="Filter graphs by area number")] = None,
    is_monitored: Annotated[Optional[bool], Field(description="true = only watcher-received graphs, false = only manually uploaded")] = None,
    name: Annotated[Optional[str], Field(description="Case-insensitive substring over graph_time or watcher_name, e.g. \"before_maintenance\"")] = None,
    latest_only: Annotated[bool, Field(description="Return only the single newest graph among those matching the filters")] = False,
    page: Page = 1,
    per_page: PerPage = 50,
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
    raise_for_status_with_context(resp)
    return resp.json()


@mcp.tool(
    tags={"write"},
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
)
def upload_graph(graph: Annotated[dict, Field(description="Graph to upload, sent as the JSON body of POST /graph")]):
    """
    Upload a new graph into Topolograph API.
    Equivalent to POST /graph with JSON body.
    """
    _require_write_enabled()
    url = f"{API_BASE}/graph"
    resp = requests.post(url, json=graph, headers=get_auth_headers())
    raise_for_status_with_context(resp)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_network_by_graph_time(
    graph_time: GraphTime,
    network_w_digit_mask: Annotated[Optional[str], Field(description="Network with mask, e.g. 10.0.0.0/24; finds all devices which terminate it")] = None,
    ip_address: Annotated[Optional[str], Field(description="IP address to find which network it belongs to")] = None,
    node_id: Annotated[Optional[str], Field(description="Exact node identifier (no hostname or case-insensitive lookup); finds all networks terminated by the node. OSPF: Router ID, e.g. \"10.10.10.1\"; IS-IS: System ID, e.g. \"1921.6800.1001\"")] = None,
    filter_type: Annotated[Optional[Literal['all', 'backuped_only', 'non_backuped_only']], Field(description="Lists the networks of the graph by backup status; not with network_w_digit_mask, ip_address or node_id")] = None,
    at: Annotated[Optional[str], Field(description="ISO 8601 moment; state with watcher events applied up to it. Not with network_w_digit_mask, ip_address or node_id")] = None,
    page: Annotated[int, Field(description="Page number, 1-indexed, of the list read with filter_type or at; check pagination.total")] = 1,
    per_page: Annotated[int, Field(description="Items per page of the list read with filter_type or at")] = 50,
):
    """
    Fetch network data by explicit graph_time.

    Description:
        This tool retrieves network information for a specific graph time.
        Universal tool that works with both OSPF and IS-IS protocols.
        Use 'node_id' to find all networks terminated by a specific node.
        Use 'ip_address' to find which network a specific IP belongs to.

    Output fields:
        dict: A dictionary containing network information.

    Examples:
        - get_network_by_graph_time("graph123", node_id="10.10.10.1")  # All networks terminated by OSPF Router ID
        - get_network_by_graph_time("graph123", node_id="1921.6800.1001")  # All networks terminated by IS-IS System ID
        - get_network_by_graph_time("graph123", ip_address="192.168.1.5")  # Find network for IP 192.168.1.5

    Equivalent to GET /network/{graph_time}, or GET /graph/{graph_time}/networks with filter_type or at.
    """
    if filter_type or at:
        if network_w_digit_mask or ip_address or node_id:
            raise ValueError("filter_type and at cannot be combined with network_w_digit_mask, ip_address or node_id")
        params = {"filter_type": filter_type} if filter_type else {}
        if at:
            params["at"] = at
        params.update(page=page, per_page=per_page)
        resp = requests.get(f"{API_BASE}/graph/{graph_time}/networks", headers=get_auth_headers(), params=params)
        raise_for_status_with_context(resp, graph_time)
        return resp.json()
    url = f"{API_BASE}/network/{graph_time}"
    params = {}
    if network_w_digit_mask:
        params["network_w_digit_mask"] = network_w_digit_mask
    if ip_address:
        params["ip_address"] = ip_address
    if node_id:
        params["node_id"] = node_id

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_graph_status(graph_time: GraphTime) -> dict:
    """
    Get the status of a graph based on its health.

    Description:
        This tool returns the status of a graph including connectivity information
        and various event counts.

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
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_network_events(
    graph_time: GraphTime,
    start_time: StartTime = None,
    end_time: EndTime = None,
    last_minutes: LastMinutes = None,
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
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_adjacency_events(
    graph_time: GraphTime,
    start_time: StartTime = None,
    end_time: EndTime = None,
    last_minutes: LastMinutes = None,
) -> AdjacencyEventsResponse:
    """
    Description:
        This tool returns links/adjacencies events including nodes/hosts up/down events.
        Use this tool only to get details about nodes/hosts events.
        SRv6 locator and End.X changes are also returned here in srv6_events.
        Events exist ONLY for watcher-monitored graphs (is_monitored=true).
        Manually uploaded or YAML graphs are not monitored and have no events;
        first call get_all_graphs(is_monitored=true, latest_only=true) to pick a
        monitored graph_time.
        Treat any cost change to or from -1 as down (падение) or up (восстановление) event.

    Output fields:
        AdjacencyEventsResponse: A dictionary containing adjacency event information with keys:
            - all_host_up_down_events: List of all Up/Down nodes/hosts events (Восстановление узла, Падение узла). List includes all events even recovered events (when node is up after being down).
            - single_host_up_events: List of Up nodes/hosts events (Восстановление узла) from the time when graph was collected.
            - single_host_down_events: List of Down nodes/hosts events (Падение узла) from the time when graph was collected.
            - adjacency_cost_change_events: List of link/adjacency cost (or other metrics) change events  (изменение стоимости линка)
            - srv6_events: SRv6 locator changes (event_name srv6_locator, locator prefix and algorithm) and End.X changes (event_name srv6_end_x, neighbor router, SID, optional LAN neighbor System ID and local/remote IP addresses). Common fields identify the advertising router, status, level and topology; changed events include attribute/old_value/new_value, and non-down events include item.

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
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_events_timeline(
    graph_time: GraphTime,
    start_time: StartTime = None,
    end_time: EndTime = None,
    last_minutes: LastMinutes = None,
    page: Annotated[int, Field(description="Page number, 1-indexed, over the waves list")] = 1,
    per_page: Annotated[int, Field(description="Number of waves per page")] = 20,
) -> EventsTimelineResponse:
    """
    Description:
        This tool returns node/host up/down events already grouped into
        chronological time waves (server-side), so you can narrate a network
        incident ("instability started at T from device X; a flapping burst
        from device Y; reconverged at T+n") without scanning hundreds of raw
        events. Waves hold adjacency up/down only: metric (cost) changes are
        not in them, so for "what happened" also call get_adjacency_events for
        the same window and report its cost changes with the waves.
        Events exist ONLY for watcher-monitored graphs (is_monitored=true);
        first call get_all_graphs(is_monitored=true, latest_only=true).
        Returns wave summaries only (no nested event arrays): to get a wave's
        individual events, call get_adjacency_events with that wave's
        start_ts/end_ts.

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
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_nodes(
    graph_time: GraphTimeOrWatcher,
    protocol: Annotated[Optional[str], Field(description="Only return if graph matches protocol (ospf, ospfv3, isis, yaml, bgp)")] = None,
    watcher: Annotated[Optional[bool], Field(description="true for watcher-uploaded graphs, false for manually parsed")] = None,
    area: Annotated[Optional[str], Field(description="Only return if graph contains this area, e.g. \"0\", \"0.0.0.1\", \"49.0001\"")] = None,
    abr: Annotated[Optional[bool], Field(description="OSPF role filter: true returns only Area Border Routers (false: only non-ABRs)")] = None,
    asbr: Annotated[Optional[bool], Field(description="OSPF role filter: true returns only AS Boundary Routers (false: only non-ASBRs)")] = None,
    overload: Annotated[Optional[bool], Field(description="IS-IS filter: true returns only routers with the overload (OL) bit set")] = None,
    attached: Annotated[Optional[bool], Field(description="IS-IS filter: true returns only routers with the attached (ATT) bit set")] = None,
    maxmetric: Annotated[Optional[bool], Field(description="OSPF filter: true returns only routers in max-metric (RFC 3137 stub router) state")] = None,
    vni: Annotated[Optional[int], Field(description="protocol=\"bgp\" only: keep the routers that are a VTEP for this L2VNI")] = None,
    vrf: Annotated[Optional[str], Field(description="protocol=\"bgp\" only: keep the routers that are a VTEP for this VRF's L3VNI")] = None,
    rt: Annotated[Optional[str], Field(description="protocol=\"bgp\" only: keep the routers whose resolved RIB view carries this route target")] = None,
    page: Page = 1,
    per_page: PerPage = 50,
    at: At = None,
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
        protocol="bgp" answers "which leaves carry VNI/VRF X" (vni/vrf/rt) and
        "which routers are BGP speakers" -- rows then carry can_build_path
        instead of the IGP node fields above.

    Output fields:
        dict with keys:
            items: list of nodes with node_id (canonical graph name), display_name (human-readable
                   text), hostname, systemid, networks_count, areas, is_isis,
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
    for name, value in (("vni", vni), ("vrf", vrf), ("rt", rt)):
        if value is not None:
            params[name] = value
    if at:
        params["at"] = at

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_edges(
    graph_time: GraphTimeOrWatcher,
    src_node: Annotated[Optional[str], Field(description="Filter edges by source node name")] = None,
    dst_node: Annotated[Optional[str], Field(description="Filter edges by destination node name")] = None,
    protocol: Annotated[Optional[str], Field(description="Graph-level filter (ospf, ospfv3, isis, yaml)")] = None,
    watcher: Annotated[Optional[bool], Field(description="Graph-level filter: watcher-uploaded vs manually parsed")] = None,
    area: Annotated[Optional[str], Field(description="Graph-level filter by area")] = None,
    edge_query_params: Annotated[Optional[dict], Field(description="Edge attribute filters as flat key=value pairs, exact match or range operators, e.g. {\"weight\": 10, \"temetric__gt\": 100}")] = None,
    include: Annotated[Optional[List[str]], Field(description="Extra MPLS-TE fields, hidden by default: \"lsp_left_bw\" (TE bandwidth left on each edge after placed LSP tunnels), \"lsps\" (LSP tunnels traversing the edge), \"is_te_link\" (true when the link advertises at least one optional TE value; a zero counts, interface and neighbor addresses do not), \"edge_key\" (stable identity, needed for get_lsps(via_edge_key=) on parallel/ECMP edges)")] = None,
    page: Page = 1,
    per_page: PerPage = 50,
    is_te_link: Annotated[Optional[bool], Field(description="true keeps only TE links, false only links that are not; any other type is rejected with HTTP 400")] = None,
    at: At = None,
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
    if is_te_link is not None:
        params["is_te_link"] = str(is_te_link).lower()
    if at:
        params["at"] = at
    if edge_query_params:
        params.update(edge_query_params)

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_lsps(
    graph_time: GraphTime,
    lsp_name: Annotated[Optional[str], Field(description="Get one tunnel by name instead of listing all")] = None,
    status: Annotated[Optional[str], Field(description="\"placed\" or \"unplaced\": keep only paths matching")] = None,
    via_node: Annotated[Optional[str], Field(description="Keep only paths whose CSPF-computed path visits this node (e.g. \"which tunnels cross router X\", pre-maintenance impact check)")] = None,
    via_edge: Annotated[Optional[str], Field(description="\"srcNode,dstNode\": keep only paths traversing this hop")] = None,
    via_edge_key: Annotated[Optional[str], Field(description="Exact stable edge_key (from get_edges(include=[\"edge_key\"])); disambiguates parallel/ECMP edges that via_edge alone cannot")] = None,
    include_path: Annotated[bool, Field(description="Also return each path's expanded node-name path in the list form")] = False,
) -> dict:
    """
    List MPLS TE LSP tunnels, or get one tunnel by name.

    Description:
        Each returned path already carries its last CSPF placement outcome:
        placed (bool), reason (human-readable explanation, null when placed),
        reason_code (machine-readable failure category, null when placed),
        binding_constraints (which constraints actually block it), cost (total
        path metric, null when unplaced).

        Act on reason_code, not on the wording of reason:
          disconnected -- no path exists even with every constraint lifted;
            the topology is severed and must be repaired.
          constraints_unsatisfiable -- a path DOES exist, but the request is
            too strict. Do not tell the user connectivity is broken; tell them
            which of binding_constraints to relax (bandwidth, affinity, srlg).
            More than one entry means they block only in combination, so
            relaxing just one will fail again.
          ero_strict_hop_unreachable -- a strict ERO hop has no direct edge.
          endpoint_not_found -- src or dst is not in the graph.

        Getting a single tunnel by lsp_name always
        includes each path's expanded node-name path; the list form omits it
        by default (include_path=True to get it there too, since it can be
        large across many tunnels).

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


@mcp.tool(
    tags={"write"},
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
)
def add_lsp(
    graph_time: GraphTime,
    lsp: Annotated[dict, Field(description="LSP tunnel definition, sent as the JSON body of POST /graph/{graph_time}/lsps")],
) -> dict:
    """Add an MPLS TE LSP tunnel to a graph."""
    _require_write_enabled()
    url = f"{API_BASE}/graph/{graph_time}/lsps"
    resp = requests.post(url, headers=get_auth_headers(), json=lsp)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"write", "destructive"},
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True),
)
def update_lsp(
    graph_time: GraphTime,
    lsp_name: Annotated[str, Field(description="Name of the tunnel to update")],
    changes: Annotated[dict, Field(description="Fields to change, sent as the JSON body of the PATCH request; set a new name to rename the tunnel")],
) -> dict:
    """Update or rename an MPLS TE LSP tunnel."""
    _require_write_enabled()
    url = f"{API_BASE}/graph/{graph_time}/lsps/{lsp_name}"
    resp = requests.patch(url, headers=get_auth_headers(), json=changes)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"write", "destructive"},
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True),
)
def delete_lsp(
    graph_time: GraphTime,
    lsp_name: Annotated[Optional[str], Field(description="Name of the tunnel to delete; omit to delete all tunnels of the graph")] = None,
) -> dict:
    """Delete one MPLS TE LSP tunnel, or all tunnels when name is omitted."""
    _require_write_enabled()
    url = f"{API_BASE}/graph/{graph_time}/lsps"
    if lsp_name:
        url += f"/{lsp_name}"
    resp = requests.delete(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_shortest_path(
    graph_time: GraphTime,
    src_node: Annotated[Union[str, List[str]], Field(description="Source Router ID, e.g. \"10.10.10.1\"; a list of sources answers the union of all source-target paths (underlay)")],
    dst_node: Annotated[Union[str, List[str]], Field(description="One destination Router ID, or several, e.g. [\"20.20.20.1\", \"30.30.30.1\"]")],
    with_lsps: Annotated[bool, Field(description="If true, account for autoroute-enabled MPLS-TE tunnels as forwarding shortcuts: the path traffic actually takes given the tunnels currently in the graph. Off by default (a signaled LSP does not redirect traffic without autoroute on the tunnel); keep it off unless the question is about MPLS TE autoroute. One dst_node only; the API rejects it with several. Not with at")] = False,
    failed_edges: Annotated[Optional[List[str]], Field(description="edge_key values from get_edges; the path with these links down (both directions)")] = None,
    failed_nodes: Annotated[Optional[List[str]], Field(description="The path with these routers removed")] = None,
    changed_edge_costs: Annotated[Optional[dict], Field(description="edge_key -> new cost of that direction; keyed by edge_key, unlike resolve_route (igraph id)")] = None,
    at: Annotated[Optional[str], Field(description="ISO 8601 moment; state with watcher events applied up to it. Not with a network")] = None,
) -> dict:
    """
    Calculate the shortest path from one node to one or several destinations.

    Description:
        Plain IGP shortest path by default. For "what if this link is down"
        backup-path analysis, use get_what_if instead -- that
        question now has its own endpoint (whole-network impact, not just a
        recomputed path). Several dst_node values run one SPF from src_node and
        return a cost/path per target plus the union of every target's edges
        (MST-style, for colouring several VTEPs' underlay at once); with_lsps
        takes one destination only.

    Routing of the request:
      - src_node or dst_node containing "/" is an IP or network; a host is
        given as x.x.x.x/32, since a bare IP is read as an OSPF Router ID
      - failed_edges, failed_nodes or changed_edge_costs set: backup path,
        one src and one dst, not with with_lsps
      - src_node as a list: underlay; not with with_lsps or failures

    Output fields:
        One dst_node: dict with spt_path_nodes_name_as_ll_in_ll (list of node-name
          paths), cost, unbackup_paths_nodes_name_as_ll_in_ll.
        Several dst_node: dict with targets (keyed by each destination: cost,
          spt_path_nodes_name_as_ll_in_ll, unbackup_paths_nodes_name_as_ll_in_ll,
          or error when unresolved), plus the edges every target's path crosses.

    Equivalent to GET /graph/{graph_time}/path/{src_node}/{dst_node}, or with the rules above
    GET /graph/{graph_time}/path/network, POST /graph/{graph_time}/analyse/spt-edge-failure
    or POST /graph/{graph_time}/analyse/underlay.
    """
    changed_costs = _get_changed_costs(changed_edge_costs)
    failures = {name: value for name, value in
                {"failed_edges": failed_edges, "failed_nodes": failed_nodes, "changed_costs": changed_costs}.items()
                if value}
    several_sources = isinstance(src_node, list)
    several_targets = isinstance(dst_node, list) and len(dst_node) > 1
    is_network = isinstance(src_node, str) and isinstance(dst_node, str) and "/" in src_node + dst_node
    if with_lsps and (failures or several_sources or is_network or at):
        raise ValueError("with_lsps cannot be combined with failures, several sources, a network or at")
    if isinstance(dst_node, list) and not dst_node:
        raise ValueError("dst_node must not be an empty list")
    if any("/" in name for name in (dst_node if isinstance(dst_node, list) else [])):
        raise ValueError("a network goes in dst_node as a string, not in a list")
    if failures and (several_sources or several_targets or is_network):
        raise ValueError("failed_edges, failed_nodes and changed_edge_costs take one src_node and one dst_node, not a network")
    if at and is_network:
        raise ValueError("at does not apply to a network path")
    base = f"{API_BASE}/graph/{graph_time}"
    if several_sources or failures:
        targets = dst_node if isinstance(dst_node, list) else [dst_node]
        if several_sources:
            url, body = f"{base}/analyse/underlay", {"from": src_node, "to": targets}
        else:
            url, body = f"{base}/analyse/spt-edge-failure", {"from": src_node, "to": targets[0], **failures}
        resp = requests.post(url, json=body, params={"at": at} if at else {}, headers=get_auth_headers())
        raise_for_status_with_context(resp, graph_time)
        return resp.json()
    if is_network:
        resp = requests.get(
            f"{base}/path/network", params={"src_ip_or_network": src_node, "dst_ip_or_network": dst_node},
            headers=get_auth_headers())
        raise_for_status_with_context(resp, graph_time)
        return resp.json()
    dst = ",".join(dst_node) if isinstance(dst_node, list) else dst_node
    url = f"{base}/path/{src_node}/{dst}"
    params: dict = {}
    if with_lsps:
        params["with_lsps"] = "true"
    if at:
        params["at"] = at

    resp = requests.get(url, params=params, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


def _get_changed_costs(changed_edge_costs: Optional[dict]) -> list[dict]:
    return [{"edge_key": key, "cost": cost} for key, cost in (changed_edge_costs or {}).items()]


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_what_if(
    graph_time: GraphTime,
    failed_edges: Annotated[Optional[List[str]], Field(description="edge_key values from get_edges for links that go down in both directions; parallel links have different edge_key values")] = None,
    failed_nodes: Annotated[Optional[List[str]], Field(description="Router names, hostnames or IS-IS System IDs of routers that fail")] = None,
    changed_edge_costs: Annotated[Optional[dict], Field(description="edge_key -> new cost of that one direction; changing both directions requires both edge_key values from get_edges(src_node, dst_node)")] = None,
    shared_media: Annotated[bool, Field(description="If true, failing one link on a multi-access segment fails every adjacency on that segment")] = False,
    at: Annotated[Optional[str], Field(description="ISO 8601 moment whose watcher-derived graph state is the simulation baseline")] = None,
) -> dict:
    """
    Predict the whole-network reaction to topology or link-cost changes.

    Description:
        Use this for routers failing, links failing, or directed link costs
        changing, alone or together. "What happens if R5 fails" uses
        failed_nodes; "if link R1-R2 goes down" uses failed_edges; "if I set
        the cost of R1-R2 to 1" uses changed_edge_costs. A link is named by
        edge_key from get_edges(src_node, dst_node). An edge_key names one
        direction, so changing both directions needs both keys, and parallel
        links have different keys. This is a simulation only and does not
        mutate the graph.

    Output fields:
        dict with result, nodes and edges:
            - result: connected, more_traffic and less_traffic (numbers of
              links that gain or lose shortest paths), pairs (total, changed
              and unreachable router pairs), and parts
            - nodes: per-node effects
            - edges: per-link shortest-path counts before and after the changes

    Equivalent to POST /graph/{graph_time}/analyse/what-if.
    """
    changed_costs = _get_changed_costs(changed_edge_costs)
    changes = {
        name: value for name, value in {
            "failed_edges": failed_edges,
            "failed_nodes": failed_nodes,
            "changed_costs": changed_costs,
        }.items() if value
    }
    if not changes:
        raise ValueError("at least one of failed_edges, failed_nodes or changed_edge_costs must be non-empty")

    url = f"{API_BASE}/graph/{graph_time}/analyse/what-if"
    body = {**changes, "shared_media": shared_media}
    resp = requests.post(
        url,
        json=body,
        params={"at": at} if at else {},
        headers=get_auth_headers(),
    )
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_cspf_path(
    graph_time: GraphTime,
    node_a: Annotated[str, Field(description="Source node name")],
    node_b: Annotated[str, Field(description="Destination node name")],
    bandwidth: Annotated[Optional[str], Field(description="Required bandwidth, e.g. \"2G\", \"500M\", or a raw bps number")] = None,
    metric_type: Annotated[str, Field(description="\"igp\" (default) or \"te\"")] = 'igp',
    admin_exclude_any: Annotated[Optional[List[str]], Field(description="Admin groups to exclude. On an IS-IS graph a group is the number of a bit of the link's admin group mask (bit 0 is the least significant; \"2\" avoids mask 0x00000004); on a YAML diagram it is an affinity name")] = None,
    admin_include_any: Annotated[Optional[List[str]], Field(description="Admin groups, at least one required")] = None,
    admin_include_all: Annotated[Optional[List[str]], Field(description="Admin groups, all required")] = None,
    srlg_exclude: Annotated[Optional[List[int]], Field(description="SRLG ids to exclude")] = None,
    setup_priority: Annotated[int, Field(description="RSVP-TE setup priority (0-7, default 7); selects which advertised Unreserved Bandwidth pool the bandwidth check runs against")] = 7,
    level: Annotated[Optional[int], Field(description="IS-IS level, 1 or 2. Restricts the path to links that advertised their TE data at that level; omit for no level restriction. No effect on a non-IS-IS graph. Fails with isis_level_calculation_unavailable on a graph stored before per-level IS-IS data existed (re-upload the LSDB), and with isis_level_unavailable_for_yaml_diagram on a YAML diagram")] = None,
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
    if level is not None:
        params["level"] = level
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


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_node_failure_reaction(
    graph_time: GraphTime,
    failed_nodes: Annotated[list[str], Field(description="Node names of the failed routers, e.g. [\"10.10.10.2\"]")],
) -> NetworkReactionResponse:
    """
    Predict the whole-network impact if one or more routers go down.

    Description:
        Whether the graph stays connected and which links see more or less
        traffic once these routers fail. A simulation only: nothing is
        changed in the graph.
        For link cost changes or several kinds of change at once, use get_what_if.

    Output fields:
        NetworkReactionResponse: the same keys as get_edge_failure_reaction.

    Equivalent to POST /network-reaction/node-failure/.
    """
    url = f"{API_BASE}/network-reaction/node-failure/"
    payload = {"graph_time": graph_time, "failed_nodes_list": failed_nodes}

    resp = requests.post(url, json=payload, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_edge_failure_reaction(
    graph_time: GraphTime,
    failed_edges: Annotated[list[list[str]], Field(description="Pairs of node names identifying each failed link, e.g. [[\"10.10.10.1\", \"10.10.10.2\"]]")],
) -> NetworkReactionResponse:
    """
    Predict the whole-network impact if one or more links go down.

    Description:
        Same shape as get_node_failure_reaction, for links instead of
        nodes: whether the graph stays connected, and the traffic
        rerouting pattern (which links see more/less traffic). This is a
        simulation only: it does not fail any link or otherwise mutate the
        graph.
        For link cost changes or several kinds of change at once, use get_what_if.

    Output fields:
        NetworkReactionResponse: dict with keys:
            - isGraphStillConnected: bool
            - affectedLinks: {sptPathsIncreasedInPercent, sptPathsDecreasedInPercent},
              each a list of {edge_key, from, to, value}, one per link direction, value in percent
            - disjointedNodes: list of node-name groups, if the graph split

    Equivalent to POST /network-reaction/edge-failure/.
    """
    url = f"{API_BASE}/network-reaction/edge-failure/"
    payload = {"graph_time": graph_time, "failed_edges_list": failed_edges}

    resp = requests.post(url, json=payload, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_graph_analysis(
    graph_time: GraphTime,
    kind: Annotated[str, Field(description="central-nodes, most-loaded, single-point-of-failure, fault-tolerant, heatmap, unsym-paths, unidir-edges, backup-paths-in-ecmp, duplicated-terminated-networks or network-score")],
    at: At = None,
) -> dict:
    """
    Whole-graph report: central routers, most loaded links, single points of failure and more.

    Output fields:
        dict with result, nodes and edges. The routers and links the report names are in nodes and
        edges; backup-paths-in-ecmp and duplicated-terminated-networks list rows in result.rows;
        network-score answers result.total, max, percentage and details.

    Equivalent to GET /graph/{graph_time}/analyse/{kind}.
    """
    params = {"at": at} if at else {}
    resp = requests.get(f"{API_BASE}/graph/{graph_time}/analyse/{kind}", params=params, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_path_tree(
    graph_time: GraphTime,
    node: Annotated[str, Field(description="Node name, hostname or IS-IS System ID")],
    direction: Annotated[str, Field(description="\"out\" for paths from the node (default), \"in\" for paths to it")] = 'out',
    at: At = None,
) -> dict:
    """
    The shortest-path tree rooted at one router, equal-cost paths included.

    Output fields:
        dict with result {root, direction}, nodes and edges (the links of the tree).

    Equivalent to GET /graph/{graph_time}/path/{node}.
    """
    params = {"direction": direction}
    if at:
        params["at"] = at
    resp = requests.get(f"{API_BASE}/graph/{graph_time}/path/{node}", params=params, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def list_bgp_graphs(page: Page = 1, per_page: PerPage = 50) -> dict:
    """
    List BGP graph epochs (one per BMP collection cycle), newest first.

    Equivalent to GET /bgp-graphs.
    """
    url = f"{API_BASE}/bgp-graphs"
    resp = requests.get(url, headers=get_auth_headers(), params={"page": page, "per_page": per_page})
    raise_for_status_with_context(resp)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_bgp_graph(bgp_graph_time: BgpGraphTime) -> BgpGraph:
    """
    Fetch one BGP graph epoch by bgp_graph_time.

    Equivalent to GET /bgp-graph/{bgp_graph_time}.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}"
    resp = requests.get(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def list_bgp_nodes(
    bgp_graph_time: BgpGraphTime,
    role: Annotated[Optional[str], Field(description="Filter by node role")] = None,
    asn: Annotated[Optional[str], Field(description="Filter by autonomous system number")] = None,
    page: Page = 1,
    per_page: PerPage = 50,
) -> BgpNodesResponse:
    """
    List the BGP speakers of a BGP graph epoch.

    Output fields:
        dict with keys: items (list of BgpNode, each with rib_view, can_build_path,
        observed_by), pagination

    Equivalent to GET /bgp-graph/{bgp_graph_time}/nodes.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/nodes"
    params: dict = {"page": page, "per_page": per_page}
    if role:
        params["role"] = role
    if asn:
        params["asn"] = asn
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def list_bgp_sessions(
    bgp_graph_time: BgpGraphTime,
    igp_relation: Annotated[Optional[str], Field(description="Filter by relation to the IGP topology (intra-domain, inter-domain, external)")] = None,
    bgp_session_type: Annotated[Optional[str], Field(description="Filter by session type (ibgp, ebgp)")] = None,
    page: Page = 1,
    per_page: PerPage = 50,
) -> BgpSessionsResponse:
    """
    List BGP peering sessions of a BGP graph epoch.

    Output fields:
        dict with keys: items (list of BgpSession), pagination

    Equivalent to GET /bgp-graph/{bgp_graph_time}/sessions.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/sessions"
    params: dict = {"page": page, "per_page": per_page}
    if igp_relation:
        params["igp_relation"] = igp_relation
    if bgp_session_type:
        params["bgp_session_type"] = bgp_session_type
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def search_bgp_routes(
    bgp_graph_time: BgpGraphTime,
    router_id: Annotated[Optional[str], Field(description="Scope the search to one speaker's resolved RIB view")] = None,
    prefix: Prefix = None,
    vrf: Annotated[Optional[str], Field(description="VPN identifier: VRF name")] = None,
    rd: Annotated[Optional[str], Field(description="VPN identifier: route distinguisher")] = None,
    rt: Annotated[Optional[str], Field(description="VPN identifier: route target")] = None,
    afi: Annotated[Optional[int], Field(description="Address family filter")] = None,
    safi: Annotated[Optional[int], Field(description="Subsequent address family filter")] = None,
    bmp_rib: Annotated[Optional[str], Field(description="Filter by RIB tag (e.g. adj-rib-in-pre, loc-rib)")] = None,
    evidence: Annotated[Optional[str], Field(description="pre_policy, post_policy, loc_rib, or fib")] = None,
    as_path_contains: Annotated[Optional[str], Field(description="Substring match over the AS path")] = None,
    origin: Annotated[Optional[str], Field(description="Filter by BGP origin attribute")] = None,
    local_pref: Annotated[Optional[int], Field(description="Filter by LOCAL_PREF")] = None,
    med: Annotated[Optional[int], Field(description="Filter by MED")] = None,
    community: Annotated[Optional[str], Field(description="Filter by standard community")] = None,
    large_community: Annotated[Optional[str], Field(description="Filter by large community")] = None,
    extended_community: Annotated[Optional[str], Field(description="Filter by extended community")] = None,
    label: Annotated[Optional[int], Field(description="Filter by MPLS label")] = None,
    originator_id: Annotated[Optional[str], Field(description="Filter by ORIGINATOR_ID")] = None,
    peer_ip: Annotated[Optional[str], Field(description="Filter by peer IP address")] = None,
    nexthop: Annotated[Optional[str], Field(description="Filter by next hop")] = None,
    bmp_source: Annotated[Optional[str], Field(description="Ignored when router_id is set")] = None,
    table_filters: Annotated[Optional[str], Field(description="URL-encoded JSON object keyed by route column, e.g. '{\"communities\":{\"conditions\":[{\"join\":\"and\",\"operator\":\"contains\",\"value\":\"65000:100\"}]}}'. Ignored when router_id is set")] = None,
    ribs: Annotated[Optional[str], Field(description="Comma-separated exact RIB-tag set to match against the folded policy set, e.g. \"loc-rib,post\"")] = None,
    sort: Annotated[Optional[str], Field(description="Indexed route column to order by")] = None,
    order: Annotated[str, Field(description="asc or desc")] = 'asc',
    page: Page = 1,
    per_page: PerPage = 50,
) -> BgpRoutesResponse:
    """
    Search BGP routes, one row per distinct RFC 4271 9.1 path.

    Description:
        Without router_id, searches the whole BGP graph's route table
        (GET /routes). With router_id, scopes the search to that speaker's
        own resolved RIB view (GET /node/{router_id}/routes) -- the routes
        that speaker actually holds, folded on the same path definition; that
        scoped form does not accept bmp_source or table_filters (rib_view is
        already a single table). bmp_source and bmp_ribs come back as arrays.

    Equivalent to GET /bgp-graph/{bgp_graph_time}/routes or
    GET /bgp-graph/{bgp_graph_time}/node/{router_id}/routes.
    """
    if router_id:
        url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/node/{router_id}/routes"
    else:
        url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/routes"

    params: dict = {"order": order, "page": page, "per_page": per_page}
    for key, value in (
        ("prefix", prefix), ("vrf", vrf), ("rd", rd), ("rt", rt),
        ("afi", afi), ("safi", safi), ("bmp_rib", bmp_rib), ("evidence", evidence),
        ("as_path_contains", as_path_contains), ("origin", origin),
        ("local_pref", local_pref), ("med", med), ("community", community),
        ("large_community", large_community), ("extended_community", extended_community),
        ("label", label), ("originator_id", originator_id), ("peer_ip", peer_ip),
        ("nexthop", nexthop), ("sort", sort),
    ):
        if value is not None:
            params[key] = value
    if ribs:
        params["ribs"] = ribs
    if not router_id:
        if bmp_source:
            params["bmp_source"] = bmp_source
        if table_filters:
            params["table_filters"] = table_filters

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_bgp_node_route_summary(
    bgp_graph_time: BgpGraphTime,
    router_id: Annotated[str, Field(description="Router ID of the BGP speaker")],
) -> BgpRouteSummary:
    """
    Route totals for one BGP speaker: its resolved RIB view size, a
    per-RIB-tag histogram, and how many routes it advertised (Adj-RIB-Out).

    Equivalent to GET /bgp-graph/{bgp_graph_time}/node/{router_id}/routes/summary.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/node/{router_id}/routes/summary"
    resp = requests.get(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_bgp_route_state(
    bgp_graph_time: BgpGraphTime,
    at: Annotated[Optional[str], Field(description="ISO 8601 timestamp; defaults to now")] = None,
) -> dict:
    """
    Point-in-time BGP route state, reconstructed from stored events.

    Equivalent to GET /bgp-graph/{bgp_graph_time}/routes/state.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/routes/state"
    params: dict = {}
    if at:
        params["at"] = at
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def compare_bgp_routes(
    bgp_graph_time: Annotated[str, Field(description="The BGP graph epoch to query (the t1 epoch)")],
    t0: Annotated[str, Field(description="ISO 8601 timestamp, the earlier instant")],
    t1: Annotated[str, Field(description="ISO 8601 timestamp, the later instant")],
    router_id: Annotated[Optional[str], Field(description="Scope the diff to one reporting speaker")] = None,
    t0_graph_time: Annotated[Optional[str], Field(description="Epoch of t0 when it differs from bgp_graph_time (collector restart); must be the same collector")] = None,
) -> BgpRouteCompareResponse:
    """
    Diff BGP routes between two instants: one row per differing route.

    Output fields:
        dict with key: items (list of BgpRouteDiffRow; diff_status is
        added|withdrawn|changed, a changed row also carries diff_prev).
        There is no total: count the rows per diff_status and quote those counts.

    Equivalent to GET /bgp-graph/{bgp_graph_time}/routes/compare.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/routes/compare"
    params: dict = {"t0": t0, "t1": t1}
    if router_id:
        params["router_id"] = router_id
    if t0_graph_time:
        params["t0_graph_time"] = t0_graph_time
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_bgp_events_timeline(
    bgp_graph_time: BgpGraphTime,
    start_time: StartTime = None,
    end_time: EndTime = None,
    last_minutes: Annotated[Optional[int], Field(description="Look back this many minutes from end_time (default now); overrides start_time")] = None,
    event_name: Annotated[Optional[str], Field(description="Filter by event name")] = None,
    event_status: Annotated[Optional[str], Field(description="Filter by event status")] = None,
    as_rows: Annotated[bool, Field(description="Return one flat row per event instead of the timeline aggregate")] = False,
) -> dict:
    """
    BGP monitoring events (session up/down, route churn), grouped into a
    timeline by default.

    Equivalent to GET /bgp-graph/{bgp_graph_time}/events.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/events"
    params: dict = {}
    if last_minutes:
        params["last_minutes"] = last_minutes
        if end_time:
            params["end_time"] = end_time
    else:
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
    if event_name:
        params["event_name"] = event_name
    if event_status:
        params["event_status"] = event_status
    if as_rows:
        params["response_format"] = "rows"
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def list_bgp_bindings(bgp_graph_time: BgpGraphTime) -> BgpBindingsResponse:
    """
    List the BGP-to-IGP graph bindings known for a BGP graph epoch.

    Output fields:
        dict with key: items (list of BgpBinding)

    Equivalent to GET /bgp-graph/{bgp_graph_time}/bindings.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/bindings"
    resp = requests.get(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_bgp_binding(
    bgp_graph_time: BgpGraphTime,
    graph_time: Annotated[str, Field(description="The IGP graph the BGP epoch is bound to")],
) -> BgpBinding:
    """
    Fetch one BGP-to-IGP graph binding: which IGP graph this BGP epoch is
    correlated with, and how confidently (matched_rids, source_coverage, state).

    Equivalent to GET /bgp-graph/{bgp_graph_time}/{graph_time}/binding.
    """
    url = f"{API_BASE}/bgp-graph/{bgp_graph_time}/{graph_time}/binding"
    resp = requests.get(url, headers=get_auth_headers())
    raise_for_status_with_context(resp, bgp_graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def resolve_route(
    graph_time: Annotated[str, Field(description="The IGP graph to resolve against")],
    start_node: Annotated[str, Field(description="Router ID the resolution starts from")],
    destination: Annotated[str, Field(description="Router ID or free-typed prefix")],
    rt: Annotated[Optional[str], Field(description="Names the VPN; the only one of rt, vrf and rd that identifies it across PEs")] = None,
    vrf: Annotated[Optional[str], Field(description="Names the VPN by VRF name")] = None,
    rd: Annotated[Optional[str], Field(description="Names the VPN by route distinguisher")] = None,
    evidence: Annotated[str, Field(description="pre_policy, post_policy, loc_rib, or fib: what the answer rests on when start_node's table is not observed directly")] = 'loc_rib',
    with_lsps: Annotated[bool, Field(description="Let MPLS TE LSPs override the plain IGP path")] = True,
    changed_edge_costs: Annotated[Optional[dict], Field(description="igraph edge id -> new metric, for what-if cost planning")] = None,
) -> dict:
    """
    Resolve the path a router would take to a destination, one row per
    routing decision -- hands off between static/BGP/IGP/LSP whenever one of
    them overrides the plain SPF path.

    Equivalent to POST /graph/{graph_time}/route-resolution/{start_node}.
    """
    url = f"{API_BASE}/graph/{graph_time}/route-resolution/{start_node}"
    body: dict = {"destination": destination, "evidence": evidence, "with_lsps": with_lsps}
    if rt:
        body["rt"] = rt
    if vrf:
        body["vrf"] = vrf
    if rd:
        body["rd"] = rd
    if changed_edge_costs:
        body["changed_edge_costs"] = changed_edge_costs

    resp = requests.post(url, json=body, headers=get_auth_headers())
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_vrf_inventory(
    graph_time: GraphTime,
    router_id: Annotated[Optional[str], Field(description="Filter by router ID")] = None,
    rd: Annotated[Optional[str], Field(description="Filter by route distinguisher")] = None,
) -> VrfInventoryResponse:
    """
    Router-scoped VRF inventory as of an IGP graph: names, route
    distinguishers, and per-address-family import/export route targets.

    Output fields:
        dict with key: items (list of Vrf)

    Equivalent to GET /graph/{graph_time}/vrfs.
    """
    url = f"{API_BASE}/graph/{graph_time}/vrfs"
    params: dict = {}
    if router_id:
        params["router_id"] = router_id
    if rd:
        params["rd"] = rd
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def list_vpns(
    graph_time: GraphTime,
    router_id: Annotated[Optional[str], Field(description="Scope to one router's resolved RIB view; omit for the fabric-wide list")] = None,
    page: Page = 1,
    per_page: PerPage = 25,
) -> VpnsResponse:
    """
    Answers "which VNI/VRF exists on which leaf": the fabric-wide VPN/VRF/VNI
    inventory of the BGP epochs bound to this graph, or one router's own view.

    Output fields:
        VpnsResponse: dict with items (VpnRow: name, route_targets,
        route_distinguishers, vni, l3vni, prefix_count), pagination, and,
        router-scoped only, evidence/can_build_path/assumptions.

    Equivalent to GET /graph/{graph_time}/vpns or
    GET /graph/{graph_time}/node/{router_id}/vpns.
    """
    if router_id:
        url = f"{API_BASE}/graph/{graph_time}/node/{router_id}/vpns"
    else:
        url = f"{API_BASE}/graph/{graph_time}/vpns"
    params = {"page": page, "per_page": per_page}
    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_routes(
    graph_time: Annotated[str, Field(description="The IGP graph time, or the name of your OSPF/IS-IS watcher (Enterprise): the snapshot alive at `at` (or now) is read and named in the answer's graph_time")],
    router_id: Annotated[Optional[str], Field(description="Scope to one router's resolved RIB view; omit for the whole bound epoch")] = None,
    vni: Vni = None,
    vrf: Vrf = None,
    rt: RouteTarget = None,
    rd: RouteDistinguisher = None,
    vtep: Annotated[Optional[str], Field(description="EVPN originating IP or next-hop")] = None,
    prefix: Prefix = None,
    mac: Mac = None,
    at: Annotated[Optional[str], Field(description="Point in time (ISO 8601) instead of current state")] = None,
    page: Page = 1,
    per_page: PerPage = 50,
) -> dict:
    """
    Answers "where is MAC/IP X", VRF/VNI contents, and hosts behind a leaf:
    routes of the BGP epochs bound to this graph (the latest of every source), current state by default.

    Output fields:
        dict with items (route rows, current state carries the winning
        nexthop) and pagination. An EVPN row's evpn.route_type is the EVPN
        route type: RT-1 Ethernet A-D, RT-2 MAC/IP, RT-3 IMET, RT-4 Ethernet
        Segment, RT-5 IP prefix.

    Equivalent to GET /graph/{graph_time}/routes or
    GET /graph/{graph_time}/node/{router_id}/routes.
    """
    if router_id:
        url = f"{API_BASE}/graph/{graph_time}/node/{router_id}/routes"
    else:
        url = f"{API_BASE}/graph/{graph_time}/routes"
    params: dict = {"page": page, "per_page": per_page}
    for key, value in (
        ("vni", vni), ("vrf", vrf), ("rt", rt), ("rd", rd),
        ("vtep", vtep), ("prefix", prefix), ("mac", mac), ("at", at),
    ):
        if value is not None:
            params[key] = value

    resp = requests.get(url, headers=get_auth_headers(), params=params)
    raise_for_status_with_context(resp, graph_time)
    return resp.json()


@mcp.tool(
    tags={"read"},
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
def get_route_events(
    graph_time: GraphTime,
    start_time: StartTime = None,
    end_time: Annotated[Optional[str], Field(description="End of the ISO 8601 window")] = None,
    last_minutes: LastMinutes = None,
    vni: Vni = None,
    vrf: Vrf = None,
    rt: RouteTarget = None,
    rd: RouteDistinguisher = None,
    prefix: Prefix = None,
    mac: Mac = None,
    page: Page = 1,
    per_page: PerPage = 50,
) -> dict:
    """
    Answers "did MAC/IP X move, from where, when": route event history
    (add/withdraw/MAC-move) of the BGP epochs bound to this graph.

    Output fields:
        dict: route and peer events interleaved by time; a route row carries
        moved_from_vtep when it is a MAC's arrival on a new VTEP.

    Equivalent to GET /events/{graph_time}/routes.
    """
    url = f"{API_BASE}/events/{graph_time}/routes"
    params: dict = {"page": page, "per_page": per_page}
    if last_minutes:
        params["last_minutes"] = last_minutes
    else:
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
    for key, value in (
        ("vni", vni), ("vrf", vrf), ("rt", rt), ("rd", rd),
        ("prefix", prefix), ("mac", mac),
    ):
        if value is not None:
            params[key] = value

    resp = requests.get(url, headers=get_auth_headers(), params=params)
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


# Read-only mode is the primary boundary: it removes write/destructive tools
# from the advertised tool surface (tools/list) so an agent never even sees
# them as an option, rather than relying solely on the runtime guard in
# _require_write_enabled() above.
if READ_ONLY:
    mcp.exclude_tags = {"write"}
    logging.info("TOPOLOGRAPH_MCP_READ_ONLY is enabled: mutation tools are hidden from tools/list")
else:
    logging.info("TOPOLOGRAPH_MCP_READ_ONLY is disabled: mutation tools are exposed")


if __name__ == "__main__":
    # Debug: Print FastMCP attributes
    logging.info(f"FastMCP attributes: {dir(mcp)}")
    if hasattr(mcp, 'server'):
        logging.info(f"FastMCP server attributes: {dir(mcp.server)}")

    # https://github.com/jlowin/fastmcp/issues/855
    mcp.run(
        transport="http", host=BIND_HOST, port=8000, path="/mcp", stateless_http=True
    )
