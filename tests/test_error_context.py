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
