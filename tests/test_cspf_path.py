"""get_cspf_path must pass the IS-IS level to the API, or a level-exact CSPF question cannot be asked."""
import pytest


class StubResponse:
    status_code = 200
    ok = True

    def raise_for_status(self):
        return None

    def json(self):
        return {"path": ["r1", "r2"], "cost": 20, "reason": ""}


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


@pytest.mark.parametrize("level", [1, 2])
def test_level_is_sent_as_query_parameter(server, sent_params, level):
    server.get_cspf_path.fn(graph_time="g1", node_a="r1", node_b="r2", level=level)

    assert sent_params["params"]["level"] == level


def test_level_is_omitted_when_not_requested(server, sent_params):
    server.get_cspf_path.fn(graph_time="g1", node_a="r1", node_b="r2")

    assert "level" not in sent_params["params"]
