"""The analysis tools call the public analysis paths."""
import pytest


@pytest.mark.parametrize("tool, args, method, url, expected", [
    ("get_graph_analysis", ("g1", "heatmap", "2026-11-01T10:00:00Z"), "get", "/graph/g1/analyse/heatmap",
     {"params": {"at": "2026-11-01T10:00:00Z"}}),
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
