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


@pytest.mark.parametrize("kwargs, expected", [
    (
        {"failed_nodes": ["R5"], "changed_edge_costs": {"k1": 10, "k2": 20}},
        {
            "json": {
                "failed_nodes": ["R5"],
                "changed_costs": [{"edge_key": "k1", "cost": 10}, {"edge_key": "k2", "cost": 20}],
                "shared_media": False,
            },
            "params": {},
        },
    ),
    (
        {"failed_edges": ["k1"], "at": "2026-11-01T10:00:00Z"},
        {"json": {"failed_edges": ["k1"], "shared_media": False},
         "params": {"at": "2026-11-01T10:00:00Z"}},
    ),
])
def test_get_what_if_calls_the_whole_network_analysis(server, stub_response, monkeypatch, kwargs, expected):
    sent = {}

    def fake_post(url, **call_kwargs):
        sent.update(url=url, **{key: value for key, value in call_kwargs.items() if key != "headers"})
        return stub_response

    monkeypatch.setattr(server.requests, "post", fake_post)
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})
    server.get_what_if.fn(graph_time="g1", **kwargs)

    assert sent == {
        "url": "http://topolograph.test/api/graph/g1/analyse/what-if",
        **expected,
    }


def test_get_what_if_refuses_an_empty_change(server, monkeypatch):
    def unexpected_post(*_args, **_kwargs):
        pytest.fail("request must not be sent")

    monkeypatch.setattr(server.requests, "post", unexpected_post)

    with pytest.raises(ValueError, match="at least one"):
        server.get_what_if.fn(graph_time="g1")


@pytest.mark.parametrize("kwargs", [
    {"src_node": "R1", "dst_node": "R4", "with_lsps": True, "failed_nodes": ["R2"]},
    {"src_node": "R1", "dst_node": ["R4", "R5"], "failed_edges": ["k1"]},
    {"src_node": ["R1", "R2"], "dst_node": "R4", "changed_edge_costs": {"k1": 5}},
    {"src_node": "R1", "dst_node": "10.0.0.0/24", "failed_edges": ["k1"]},
    {"src_node": "10.0.0.1/32", "dst_node": "192.168.1.0/24", "at": "2026-11-01T10:00:00Z"},
    {"src_node": "R1", "dst_node": "R4", "with_lsps": True, "at": "2026-11-01T10:00:00Z"},
    {"src_node": "R1", "dst_node": [], "failed_nodes": ["R2"]},
    {"src_node": "R1", "dst_node": ["192.168.1.0/24"]},
])
def test_a_shortest_path_mix_of_modes_is_refused(server, monkeypatch, kwargs):
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})

    with pytest.raises(ValueError):
        server.get_shortest_path.fn(graph_time="g1", **kwargs)
