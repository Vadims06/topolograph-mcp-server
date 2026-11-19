"""The analysis tools call the public analysis paths."""
import pytest


@pytest.mark.parametrize("tool, args, method, url, expected", [
    ("get_graph_analysis", ("g1", "heatmap", "2026-11-01T10:00:00Z"), "get", "/graph/g1/analyse/heatmap",
     {"params": {"at": "2026-11-01T10:00:00Z"}}),
    ("get_shortest_path", ("g1", "10.0.0.1/32", "192.168.1.0/24"), "get", "/graph/g1/path/network",
     {"params": {"src_ip_or_network": "10.0.0.1/32", "dst_ip_or_network": "192.168.1.0/24"}}),
    ("get_shortest_path", ("g1", "R1", "R4", False, ["k1", "k2"], ["R2", "R3"], {"k3": 50, "k4": 70},
                           "2026-11-01T10:00:00Z"), "post", "/graph/g1/analyse/spt-edge-failure",
     {"json": {"from": "R1", "to": "R4", "failed_edges": ["k1", "k2"], "failed_nodes": ["R2", "R3"],
               "changed_costs": [{"edge_key": "k3", "cost": 50}, {"edge_key": "k4", "cost": 70}]},
      "params": {"at": "2026-11-01T10:00:00Z"}}),
    ("get_shortest_path", ("g1", ["R1", "R2"], ["R3", "R4"]), "post", "/graph/g1/analyse/underlay",
     {"json": {"from": ["R1", "R2"], "to": ["R3", "R4"]}, "params": {}}),
    ("get_shortest_path", ("g1", ["R1", "R2"], "R3"), "post", "/graph/g1/analyse/underlay",
     {"json": {"from": ["R1", "R2"], "to": ["R3"]}, "params": {}}),
    ("get_path_tree", ("g1", "R1", "in"), "get", "/graph/g1/path/R1", {"params": {"direction": "in"}}),
])
def test_an_analysis_tool_calls_its_public_path(server, stub_response, monkeypatch, tool, args, method, url, expected):
    sent = {}

    def fake_call(url, **kwargs):
        sent.update(url=url, **{key: value for key, value in kwargs.items() if key != "headers"})
        return stub_response

    monkeypatch.setattr(server.requests, method, fake_call)
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})
    getattr(server, tool).fn(*args)

    assert sent == {"url": "http://topolograph.test/api" + url, **expected}


@pytest.mark.parametrize("kwargs", [
    {"src_node": "R1", "dst_node": "R4", "with_lsps": True, "failed_nodes": ["R2"]},
    {"src_node": "R1", "dst_node": ["R4", "R5"], "failed_edges": ["k1"]},
    {"src_node": ["R1", "R2"], "dst_node": "R4", "changed_edge_costs": {"k1": 5}},
    {"src_node": "R1", "dst_node": "10.0.0.0/24", "failed_edges": ["k1"]},
    {"src_node": "10.0.0.1/32", "dst_node": "192.168.1.0/24", "at": "2026-11-01T10:00:00Z"},
])
def test_a_shortest_path_mix_of_modes_is_refused(server, monkeypatch, kwargs):
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})

    with pytest.raises(ValueError):
        server.get_shortest_path.fn(graph_time="g1", **kwargs)
