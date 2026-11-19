"""Path-mapping tests for the graph-scoped BGP/EVPN tools: which URL, params
and query-string shape each tool sends. No live API -- requests.get is
monkeypatched to record the call.
"""
import pytest


class StubResponse:
    status_code = 200
    ok = True

    def __init__(self, body=None):
        self._body = body if body is not None else {"items": []}

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


@pytest.fixture
def sent_params(server, monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None):
        captured["url"] = url
        captured["params"] = params
        return StubResponse()

    monkeypatch.setattr(server.requests, "get", fake_get)
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})
    return captured


@pytest.mark.parametrize("router_id, path", [
    (None, "/graph/g1/vpns"),
    ("leaf1", "/graph/g1/node/leaf1/vpns"),
])
def test_list_vpns_scope_follows_router_id(server, sent_params, router_id, path):
    server.list_vpns.fn(graph_time="g1", router_id=router_id, page=2, per_page=10)

    assert sent_params["url"] == f"{server.API_BASE}{path}"
    assert sent_params["params"] == {"page": 2, "per_page": 10}


@pytest.mark.parametrize("router_id, path", [
    (None, "/graph/g1/routes"),
    ("leaf1", "/graph/g1/node/leaf1/routes"),
])
def test_get_routes_passes_its_filters(server, sent_params, router_id, path):
    server.get_routes.fn(graph_time="g1", router_id=router_id, vni=1010, mac="aa:bb:cc:00:00:01")

    assert sent_params["url"] == f"{server.API_BASE}{path}"
    assert sent_params["params"] == {
        "page": 1, "per_page": 50, "vni": 1010, "mac": "aa:bb:cc:00:00:01",
    }


def test_get_route_events_passes_its_filters(server, sent_params):
    server.get_route_events.fn(graph_time="g1", mac="aa:bb:cc:00:00:01", last_minutes=60)

    assert sent_params["url"] == f"{server.API_BASE}/events/g1/routes"
    assert sent_params["params"] == {
        "page": 1, "per_page": 50, "last_minutes": 60, "mac": "aa:bb:cc:00:00:01",
    }


def test_get_nodes_passes_vni_vrf_rt(server, sent_params):
    server.get_nodes.fn(graph_time="g1", protocol="bgp", vni=1010, vrf="tenant1", rt="65000:1")

    assert sent_params["params"] == {
        "page": 1, "per_page": 50, "protocol": "bgp",
        "vni": 1010, "vrf": "tenant1", "rt": "65000:1",
    }


@pytest.mark.parametrize("dst_node, path_tail", [
    ("r2", "r2"),
    (["r2", "r3"], "r2,r3"),
])
def test_get_shortest_path_takes_one_or_several_targets(server, sent_params, dst_node, path_tail):
    server.get_shortest_path.fn(graph_time="g1", src_node="r1", dst_node=dst_node)

    assert sent_params["url"] == f"{server.API_BASE}/graph/g1/path/r1/{path_tail}"


@pytest.mark.parametrize("filter_type", ["all", "backuped_only", "non_backuped_only"])
def test_get_network_by_graph_time_lists_networks_by_backup_status(server, sent_params, filter_type):
    server.get_network_by_graph_time.fn(graph_time="g1", filter_type=filter_type)

    assert sent_params["url"] == f"{server.API_BASE}/graph/g1/networks"
    assert sent_params["params"] == {"filter_type": filter_type, "page": 1, "per_page": 50}


def test_get_network_by_graph_time_without_filter_type_keeps_the_lookup(server, sent_params):
    server.get_network_by_graph_time.fn(graph_time="g1", ip_address="10.0.0.5")

    assert sent_params["url"] == f"{server.API_BASE}/network/g1"
    assert sent_params["params"] == {"ip_address": "10.0.0.5"}


def test_filter_type_is_refused_with_a_lookup(server, sent_params):
    with pytest.raises(ValueError):
        server.get_network_by_graph_time.fn(graph_time="g1", filter_type="all", node_id="r1")


AT = "2026-11-01T10:00:00Z"


@pytest.mark.parametrize("dst_node, path_tail", [("r2", "r2"), (["r2", "r3"], "r2,r3")])
def test_get_shortest_path_sends_at_in_the_plain_mode(server, sent_params, dst_node, path_tail):
    server.get_shortest_path.fn(graph_time="g1", src_node="r1", dst_node=dst_node, at=AT)

    assert sent_params["url"] == f"{server.API_BASE}/graph/g1/path/r1/{path_tail}"
    assert sent_params["params"] == {"at": AT}


@pytest.mark.parametrize("tool, path", [("get_edges", "edges"), ("get_nodes", "nodes")])
def test_get_edges_and_get_nodes_send_at(server, sent_params, tool, path):
    getattr(server, tool).fn(graph_time="g1", at=AT)

    assert sent_params["url"] == f"{server.API_BASE}/graph/g1/{path}"
    assert sent_params["params"] == {"page": 1, "per_page": 50, "at": AT}


@pytest.mark.parametrize("kwargs, params", [
    ({}, {"at": AT, "page": 1, "per_page": 50}),
    ({"filter_type": "all", "page": 3, "per_page": 100}, {"filter_type": "all", "at": AT, "page": 3, "per_page": 100}),
])
def test_get_network_by_graph_time_sends_at_to_the_networks_path(server, sent_params, kwargs, params):
    server.get_network_by_graph_time.fn(graph_time="g1", at=AT, **kwargs)

    assert sent_params["url"] == f"{server.API_BASE}/graph/g1/networks"
    assert sent_params["params"] == params


@pytest.mark.parametrize("lookup", [
    {"network_w_digit_mask": "10.0.0.0/24"}, {"ip_address": "10.0.0.5"}, {"node_id": "r1"}])
def test_at_is_refused_with_a_network_lookup(server, sent_params, lookup):
    with pytest.raises(ValueError):
        server.get_network_by_graph_time.fn(graph_time="g1", at=AT, **lookup)
