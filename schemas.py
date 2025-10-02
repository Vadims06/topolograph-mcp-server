# schemas.py
from typing import Optional, TypedDict, List, Union


class NetworkUpDownEvent(TypedDict):
    event_detected_by: str
    graph_time: str
    timestamp: str
    watcher_time: str
    event_status: str
    watcher_name: str
    level_number: int
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
    level_number: int
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
    level_number: int
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
    level_number: int
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


class ShortestPathResponse(TypedDict):
    spt_path_nodes_name_as_ll_in_ll: List[List[str]]
    cost: int
    unbackup_paths_nodes_name_as_ll_in_ll: List[List[str]]


class Graph(TypedDict):
    graph_time: str
    timestamp: str
    hosts: dict
    networks: dict
    areas: List[Union[int, str]]
    watcher_name: Optional[str]
    protocol: str  # ospf, ospfv3, isis, yaml
    is_from_watcher: bool  # whether from watcher
