"""The failure-reaction tools post the failed nodes or links under the names the API reads."""
import pytest


class StubResponse:
    status_code = 200
    ok = True

    def raise_for_status(self):
        return None

    def json(self):
        return {}


@pytest.mark.parametrize("tool, failed, url, body", [
    ("get_edge_failure_reaction", [["r1", "r2"]], "/network_reaction/edge_failure/", {"failed_edges_list": [["r1", "r2"]]}),
    ("get_node_failure_reaction", ["r2", "r4"], "/network_reaction/node_failure/", {"failed_nodes_list": ["r2", "r4"]}),
])
def test_a_failure_reaction_posts_what_failed(server, monkeypatch, tool, failed, url, body):
    sent = {}

    def fake_post(url, json=None, headers=None):
        sent.update(url=url, json=json)
        return StubResponse()

    monkeypatch.setattr(server.requests, "post", fake_post)
    monkeypatch.setattr(server, "get_auth_headers", lambda: {})
    getattr(server, tool).fn("g1", failed)

    assert sent["url"].endswith(url)
    assert sent["json"] == {"graph_time": "g1", **body}
