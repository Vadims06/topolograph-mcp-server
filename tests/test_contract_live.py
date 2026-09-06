"""Contract test: real Topolograph responses must satisfy the MCP server's own
response models (`schemas.py`).

`schemas.py` is a hand-kept copy of what Topolograph returns and has drifted
before (a field required on every event that only one protocol emits). This
validates a live stack's `/events/*` and `/graph/` responses against those
models for OSPF and IS-IS.

Run against a live stack:

    TOPOLOGRAPH_API_BASE=http://192.168.0.33:8080/api \
    TOPOLOGRAPH_TEST_TOKEN=sk-... \
    pytest tests/test_contract_live.py -v

Env knobs:
- MCP_CONTRACT_REQUIRE_ISIS=0  — allow an OSPF-only stack (default: both).
- MCP_CONTRACT_REQUIRE_EVENTS=0 — allow a stack whose monitored graphs have no
  events yet (default: require at least one, so an eventless stack cannot
  produce a false-green run).
"""
from __future__ import annotations

import os

import pytest
import requests
from pydantic import TypeAdapter

import schemas

API_BASE = os.getenv("TOPOLOGRAPH_API_BASE", "").rstrip("/")
TOKEN = os.getenv("TOPOLOGRAPH_TEST_TOKEN", "")
REQUIRE_ISIS = os.getenv("MCP_CONTRACT_REQUIRE_ISIS", "1") not in ("0", "false", "no")
REQUIRE_EVENTS = os.getenv("MCP_CONTRACT_REQUIRE_EVENTS", "1") not in ("0", "false", "no")

pytestmark = pytest.mark.skipif(
    not (API_BASE and TOKEN),
    reason="set TOPOLOGRAPH_API_BASE and TOPOLOGRAPH_TEST_TOKEN to run the contract test",
)

_HEADERS = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}

# tool name -> (endpoint template, schemas.py response model)
_EVENT_TOOLS = {
    "get_adjacency_events": ("/events/{gt}/adjacency", schemas.AdjacencyEventsResponse),
    "get_network_events": ("/events/{gt}/networks", schemas.NetworkEventsResponse),
}
_EVENT_ARRAY_KEYS = {
    "get_adjacency_events": ("all_host_up_down_events", "adjacency_cost_change_events"),
    "get_network_events": ("network_up_down_events", "network_cost_change_events"),
}
# (tool, array key) — each array is a distinct item model in schemas.py.
_EVENT_ARRAYS = [(tool, key) for tool, keys in _EVENT_ARRAY_KEYS.items() for key in keys]


@pytest.fixture(scope="session")
def monitored_graphs() -> dict[str, str]:
    """The newest monitored graph_time per protocol on the stack."""
    resp = requests.get(f"{API_BASE}/graph/", params={"is_monitored": "true", "per_page": 50},
                        headers=_HEADERS, timeout=15)
    resp.raise_for_status()
    body = resp.json()
    items = body["items"] if isinstance(body, dict) else body
    picked: dict[str, str] = {}
    for g in items:
        picked.setdefault(g.get("protocol", "?"), g["graph_time"])
    return picked


def _graph_for(monitored_graphs: dict[str, str], protocol: str) -> str:
    graph_time = monitored_graphs.get(protocol)
    if graph_time is None:
        if protocol == "isis" and not REQUIRE_ISIS:
            pytest.skip("no monitored IS-IS graph and MCP_CONTRACT_REQUIRE_ISIS=0")
        pytest.fail(f"no monitored {protocol.upper()} graph on the stack — seed one before running")
    return graph_time


def _fetch(endpoint_tpl: str, graph_time: str) -> dict:
    # No time filter: return every event for the graph regardless of age, so
    # replayed fixture events (whose timestamps may be days old) are not missed.
    resp = requests.get(f"{API_BASE}{endpoint_tpl.format(gt=graph_time)}",
                        params={"start_time": "2000-01-01T00:00:00Z"},
                        headers=_HEADERS, timeout=20)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.mark.parametrize("protocol", ["ospf", "isis"])
@pytest.mark.parametrize("tool", sorted(_EVENT_TOOLS))
def test_event_response_matches_mcp_schema(monitored_graphs, protocol, tool):
    """The real response validates against the schemas.py model the MCP tool declares."""
    endpoint_tpl, model = _EVENT_TOOLS[tool]
    payload = _fetch(endpoint_tpl, _graph_for(monitored_graphs, protocol))
    # Raises ValidationError if schemas.py drifts from what Topolograph returns
    # (e.g. level_number made required again -> OSPF payload fails here).
    TypeAdapter(model).validate_python(payload)


@pytest.mark.parametrize("protocol", ["ospf", "isis"])
@pytest.mark.parametrize("tool,array_key", _EVENT_ARRAYS)
def test_event_array_has_a_sample(monitored_graphs, protocol, tool, array_key):
    """`TypeAdapter` never checks the element fields of an empty []. Each array
    is its own item model in schemas.py, so *every* array must carry a sample
    for `test_event_response_matches_mcp_schema` to exercise that model — an
    aggregate count would let one populated array mask an empty sibling."""
    endpoint_tpl, _ = _EVENT_TOOLS[tool]
    payload = _fetch(endpoint_tpl, _graph_for(monitored_graphs, protocol))
    if not payload.get(array_key):
        msg = (f"{array_key} is empty for the monitored {protocol.upper()} graph "
               f"— its item model is never validated")
        if REQUIRE_EVENTS:
            pytest.fail(msg + "; seed a change that produces this event type")
        pytest.skip(msg + " and MCP_CONTRACT_REQUIRE_EVENTS=0")


def test_graph_list_is_a_paginated_envelope():
    """get_all_graphs is `-> dict` (no FastMCP output schema), so the only
    contract is the envelope shape. A bare list here is the v1.0.0
    `List[Graph]` regression."""
    resp = requests.get(f"{API_BASE}/graph/", params={"per_page": 5}, headers=_HEADERS, timeout=15)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, dict) and {"items", "pagination"} <= body.keys(), body
    assert isinstance(body["items"], list)
