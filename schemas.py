# schemas.py
from typing import Optional, TypedDict, List, Union
from typing_extensions import NotRequired


class NetworkUpDownEvent(TypedDict):
    event_detected_by: str
    graph_time: str
    timestamp: str
    watcher_time: str
    event_status: str
    watcher_name: str
    level_number: NotRequired[Union[int, str]]
    event_name: str
    event_object: str
    area_num: str
    asn: str
    new_cost: str
    old_cost: str
    protocol: str
    local_ip_address: str
    subnet_type: str
    int_ext_subtype: int
    object_status: str


class NetworkMetricChangeEvent(TypedDict):
    event_detected_by: str
    graph_time: str
    timestamp: str
    watcher_time: str
    event_status: str
    watcher_name: str
    level_number: NotRequired[Union[int, str]]
    event_name: str
    event_object: str
    area_num: str
    asn: str
    new_cost: str
    old_cost: str
    protocol: str
    local_ip_address: str
    subnet_type: str
    int_ext_subtype: int
    object_status: str


class HostUpDownEvent(TypedDict):
    event_detected_by: str
    graph_time: str
    timestamp: str
    watcher_time: str
    event_status: str
    watcher_name: str
    level_number: NotRequired[Union[int, str]]
    event_name: str
    event_object: str
    area_num: str
    asn: str
    new_cost: str
    old_cost: str
    protocol: str
    local_ip_address: str
    object_status: str


class LinkMetricChangeEvent(TypedDict):
    event_detected_by: str
    graph_time: str
    timestamp: str
    watcher_time: str
    event_status: str
    watcher_name: str
    level_number: NotRequired[Union[int, str]]
    event_name: str
    event_object: str
    area_num: str
    asn: str
    new_cost: str
    old_cost: str
    protocol: str
    local_ip_address: str
    object_status: str


class NetworkEventsResponse(TypedDict):
    network_up_down_events: List[NetworkUpDownEvent]
    network_cost_change_events: List[NetworkMetricChangeEvent]


class AdjacencyEventsResponse(TypedDict):
    all_host_up_down_events: List[HostUpDownEvent]
    single_host_up_events: List[HostUpDownEvent]
    single_host_down_events: List[HostUpDownEvent]
    adjacency_cost_change_events: List[LinkMetricChangeEvent]


class TimelineWave(TypedDict):
    wave_number: int
    start_ts: str  # ISO 8601, e.g. 2025-05-10T17:08:17.707000Z
    end_ts: str    # ISO 8601, e.g. 2025-05-10T17:08:17.707000Z
    duration_sec: float
    event_count: int
    distinct_devices: int
    trigger_device: str
    pattern: str  # "outage" | "flap" | "up"
    converged: bool


class Pagination(TypedDict):
    page: int
    per_page: int
    total: int
    total_pages: int


class EventsTimelineResponse(TypedDict):
    graph_time: str
    watcher_name: Optional[str]
    gap_multiplier: float
    median_gap_sec: float
    waves: List[TimelineWave]
    pagination: Pagination


class ShortestPathResponse(TypedDict):
    spt_path_nodes_name_as_ll_in_ll: List[List[str]]
    cost: int
    unbackup_paths_nodes_name_as_ll_in_ll: List[List[str]]


class CspfPathResponse(TypedDict):
    path: List[str]
    cost: Optional[int]
    reason: str


class AffectedLinks(TypedDict):
    sptPathsIncreasedInPercent: dict
    sptPathsDecreasedInPercent: dict


class EdgeFailureReactionResponse(TypedDict):
    isGraphStillConnected: bool
    affectedLinks: AffectedLinks
    disjointedNodes: List[List[str]]


class Graph(TypedDict):
    graph_time: str
    timestamp: str
    hosts: dict
    networks: dict
    areas: List[Union[int, str]]
    watcher_name: NotRequired[Optional[str]]
    protocol: str  # ospf, ospfv3, isis, yaml
    is_from_watcher: bool  # whether from watcher


class BgpGraph(TypedDict):
    graph_time: str
    timestamp: str
    srcid: NotRequired[Optional[str]]
    sesid: NotRequired[Optional[str]]
    nodes: NotRequired[list]
    sessions: NotRequired[list]


class BgpNode(TypedDict):
    name: str
    asn: NotRequired[Union[int, str]]
    role: NotRequired[str]  # speaker, peer
    device_role: NotRequired[str]
    label: NotRequired[str]
    router_ip: NotRequired[str]
    rib_view: NotRequired[Optional[str]]
    can_build_path: NotRequired[bool]
    assumptions: NotRequired[List[str]]  # import_not_observed, reflection_assumed
    observed_by: NotRequired[List[str]]


class BgpSession(TypedDict):
    source: str
    target: str
    source_router_id: NotRequired[str]
    target_router_id: NotRequired[str]
    local_ip: NotRequired[str]
    peer_ip: NotRequired[str]
    asn: NotRequired[Union[int, str]]
    peer_type: NotRequired[int]
    families: NotRequired[List[str]]
    policies: NotRequired[List[str]]
    igp_relation: NotRequired[str]  # intra-domain, inter-domain, external
    bgp_session_type: NotRequired[str]  # ibgp, ebgp


class BgpRoute(TypedDict):
    prefix: str
    afi: NotRequired[int]
    safi: NotRequired[int]
    rd: NotRequired[Optional[str]]
    vrf: NotRequired[Optional[str]]
    nexthop: NotRequired[str]
    labels: NotRequired[List[int]]
    bmp_source: NotRequired[List[str]]
    bmp_ribs: NotRequired[List[str]]
    peer_ip: NotRequired[str]
    path_id: NotRequired[Optional[str]]
    route_targets: NotRequired[List[str]]
    as_path: NotRequired[str]
    local_pref: NotRequired[int]
    med: NotRequired[int]
    origin: NotRequired[str]
    originator_id: NotRequired[Optional[str]]
    cluster_list: NotRequired[List[str]]
    communities: NotRequired[List[str]]
    large_communities: NotRequired[List[str]]
    extended_communities: NotRequired[List[str]]


class BgpRouteSummary(TypedDict):
    rib_view: Optional[str]
    total: int
    by_ribs: List[dict]
    adj_rib_out: int


class BgpRouteDiffRow(TypedDict):
    prefix: str
    diff_status: str  # added, withdrawn, changed
    diff_prev: NotRequired[dict]


class BgpBinding(TypedDict):
    bgp_graph_time: str
    igp_graph_time: str
    matched_rids: List[str]
    source_coverage: float
    state: str  # bound, partial, needs_mapping


class VrfAddressFamily(TypedDict):
    afi: str
    safi: str
    import_rts: List[str]
    export_rts: List[str]


class Vrf(TypedDict):
    router_id: str
    rd: str
    name: str
    observed_at: str
    address_families: List[VrfAddressFamily]


class VpnRouter(TypedDict):
    router_id: str
    vpn_count: int
    evidence: str  # loc_rib, adj_rib_in, loc_rib_reflected, adj_rib_out
    can_build_path: bool
    assumptions: NotRequired[List[str]]


class BgpNodesResponse(TypedDict):
    items: List[BgpNode]
    pagination: Pagination


class BgpSessionsResponse(TypedDict):
    items: List[BgpSession]
    pagination: Pagination


class BgpRoutesResponse(TypedDict):
    items: List[BgpRoute]
    pagination: Pagination
    sortable_columns: List[str]


class BgpRouteCompareResponse(TypedDict):
    items: List[BgpRouteDiffRow]


class BgpBindingsResponse(TypedDict):
    items: List[BgpBinding]


class VrfInventoryResponse(TypedDict):
    items: List[Vrf]


class VpnRoutersResponse(TypedDict):
    items: List[VpnRouter]

