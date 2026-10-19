"""An API failure must reach the agent with its machine-readable code and next action, not just the prose."""
import pytest


class ErrorResponse:
    ok = False
    text = ""

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


def test_level_failure_keeps_error_code_and_action(server):
    response = ErrorResponse({
        "error": "This graph predates per-level IS-IS data.",
        "code": "isis_level_calculation_unavailable",
        "action": "reupload_graph",
    })

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    message = str(raised.value)
    assert message.startswith("This graph predates per-level IS-IS data")
    assert "code=isis_level_calculation_unavailable" in message
    assert "action=reupload_graph" in message
    assert message.endswith("in graph_time g1")


def test_empty_action_is_not_reported(server):
    response = ErrorResponse({
        "error": "A YAML diagram has no per-level data.",
        "code": "isis_level_unavailable_for_yaml_diagram",
        "action": "",
    })

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    assert "code=isis_level_unavailable_for_yaml_diagram" in str(raised.value)
    assert "action" not in str(raised.value)


def test_plain_detail_message_is_unchanged(server):
    response = ErrorResponse({"detail": "Graph not found"})

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    assert str(raised.value) == "Graph not found in graph_time g1"


REFUSAL = "Events of this graph are not available: its watcher is not registered in Topolograph or is registered as Topology only"


class GraphResponse:
    ok = True
    text = ""

    def json(self):
        return {"is_from_watcher": True}

    def raise_for_status(self):
        pass


class RefusalResponse(ErrorResponse):
    def raise_for_status(self):
        raise RuntimeError("403 Client Error: FORBIDDEN")


@pytest.mark.parametrize("tool", ["get_network_events", "get_adjacency_events", "get_events_timeline"])
def test_an_events_refusal_reaches_the_agent_with_the_server_text(server, monkeypatch, tool):
    def fake_get(url, **_kwargs):
        return RefusalResponse({"error": REFUSAL + "."}) if "/events" in url else GraphResponse()

    monkeypatch.setattr(server.requests, "get", fake_get)

    with pytest.raises(ValueError) as raised:
        getattr(server, tool).fn(graph_time="g1")

    assert str(raised.value) == f"{REFUSAL} in graph_time g1"
