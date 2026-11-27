"""An API failure must reach the agent with its machine-readable code and next action, not just the prose."""
import pytest


class ErrorResponse:
    ok = False
    text = ""

    def __init__(self, body, status_code=400, headers=None):
        self._body = body
        self.status_code = status_code
        self.headers = headers or {}

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


@pytest.mark.parametrize("detail", ["No authorization token provided", "Invalid or expired token"])
def test_a_refused_sign_in_asks_the_user_to_sign_in(server, detail):
    response = ErrorResponse({"detail": detail}, status_code=401)

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    assert str(raised.value) == (
        "Not signed in to Topolograph. On topolograph.com, sign in to ask about your graphs. "
        "On a self-hosted Topolograph, set a valid Topolograph API token for the agent."
    )


def test_a_429_names_the_seconds_to_wait(server):
    response = ErrorResponse({"detail": "Too many analyses"}, status_code=429, headers={"Retry-After": "45"})

    with pytest.raises(ValueError) as raised:
        server.raise_for_status_with_context(response, "g1")

    assert str(raised.value) == "Too many analyses (retry_after_sec=45) in graph_time g1"


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


def test_adjacency_events_pass_through_srv6_events(server, monkeypatch):
    srv6_events = [
        {"event_name": "srv6_locator", "event_object": "2001:db8:1::/48", "algorithm": 0},
        {"event_name": "srv6_end_x", "event_object": "R2", "sid": "2001:db8:1::1"},
    ]
    payload = {
        "all_host_up_down_events": [],
        "single_host_up_events": [],
        "single_host_down_events": [],
        "adjacency_cost_change_events": [],
        "srv6_events": srv6_events,
    }

    class AdjacencyResponse:
        ok = True
        text = ""

        def json(self):
            return payload

    monkeypatch.setattr(server, "require_watcher_graph", lambda _graph_time: None)
    monkeypatch.setattr(server.requests, "get", lambda *_args, **_kwargs: AdjacencyResponse())

    assert "srv6_events" in server.AdjacencyEventsResponse.__annotations__
    assert server.get_adjacency_events.fn(graph_time="g1")["srv6_events"] == srv6_events
