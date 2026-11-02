"""The analysis tools call the public analysis paths; a rate limit names the wait."""
import pytest


@pytest.mark.parametrize("tool, args, method, url, expected", [
    ("get_graph_analysis", ("g1", "heatmap", "2026-11-01T10:00:00Z"), "get", "/graph/g1/analyse/heatmap",
     {"params": {"at": "2026-11-01T10:00:00Z"}}),
    ("get_path_tree", ("g1", "R1", "in"), "get", "/graph/g1/path/R1", {"params": {"direction": "in"}}),
    ("get_backup_path", ("g1", "R1", "R4", ["k1", "k2"], None, [{"edge_key": "k3", "cost": 50}]), "post",
     "/graph/g1/analyse/spt-edge-failure",
     {"json": {"from": "R1", "to": "R4", "shared_media": False, "failed_edges": ["k1", "k2"],
               "changed_costs": [{"edge_key": "k3", "cost": 50}]}, "params": {}}),
    ("get_underlay_paths", ("g1", ["R1", "R2"], ["R3"]), "post", "/graph/g1/analyse/underlay",
     {"json": {"from": ["R1", "R2"], "to": ["R3"]}, "params": {}}),
    ("get_backup_paths_in_inter_area", ("g1", True), "post", "/graph/g1/analyse/backup-paths-in-inter-area",
     {"json": {"neighbors_with_ecmp_only": True}, "params": {}}),
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


def test_update_nodes_patches_the_graph_nodes(server, stub_response, monkeypatch):
    sent = {}

    def fake_patch(url, json=None, headers=None):
        sent.update(url=url, json=json)
        return stub_response

    changes = [{"name": "10.0.0.1", "hostname": "r1"}, {"name": "10.0.0.2", "router_id": "2.2.2.2"}]
    monkeypatch.setattr(server, "READ_ONLY", False)
    monkeypatch.setattr(server.requests, "patch", fake_patch)
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})
    server.update_nodes.fn("g1", changes)

    assert sent == {"url": "http://topolograph.test/api/graph/g1/nodes", "json": changes}


def test_a_429_names_the_seconds_to_wait(server):
    response = type("Rate", (), {"ok": False, "status_code": 429, "headers": {"Retry-After": "45"},
                                 "text": "", "json": lambda self: {"detail": "Too many analyses"}})()

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    assert str(raised.value) == "Too many analyses (retry_after_sec=45) in graph_time g1"
