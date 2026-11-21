"""The MCP server must send an unauthenticated CLI to the sign-in and still forward a sent API token."""
import asyncio

import pytest
from fastmcp import FastMCP
from starlette.testclient import TestClient

PUBLIC_URL = "https://topolograph.test"


class UserinfoResponse:
    def __init__(self, status_code):
        self.status_code = status_code


@pytest.fixture
def userinfo_calls(monkeypatch, server):
    """Records userinfo requests; a token starting with sk-live is accepted."""
    calls = []

    def fake_get(url, headers, timeout):
        calls.append((url, headers["Authorization"]))
        return UserinfoResponse(200 if headers["Authorization"].startswith("Bearer sk-live") else 401)

    monkeypatch.setattr(server.requests, "get", fake_get)
    return calls


@pytest.fixture
def client(server, userinfo_calls):
    app = FastMCP("t", auth=server.create_auth_provider(PUBLIC_URL)).http_app(path="/mcp", stateless_http=True)
    return TestClient(app)


def test_no_token_gets_401_pointing_at_resource_metadata(client):
    response = client.post("/mcp", json={})

    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith('Bearer error="invalid_token"')
    assert challenge.endswith(
        'resource_metadata="https://topolograph.test/.well-known/oauth-protected-resource/mcp"')


def test_resource_metadata_names_resource_and_authorization_server(client):
    response = client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    body = response.json()
    assert body["resource"] == "https://topolograph.test/mcp"
    assert body["authorization_servers"] == ["https://topolograph.test/"]


def test_revoked_token_gets_401(client, userinfo_calls):
    response = client.post("/mcp", json={}, headers={"Authorization": "Bearer sk-dead"})

    assert response.status_code == 401
    assert userinfo_calls == [("https://topolograph.test/oauth/agent/userinfo", "Bearer sk-dead")]


def test_live_token_passes_auth_and_is_cached(server, userinfo_calls):
    verifier = server.TopolographTokenVerifier(PUBLIC_URL)

    first = asyncio.run(verifier.verify_token("sk-live-1"))
    second = asyncio.run(verifier.verify_token("sk-live-1"))

    assert first.token == second.token == "sk-live-1"
    assert len(userinfo_calls) == 1


def test_no_public_url_leaves_server_without_auth(server):
    assert server.create_auth_provider("") is None


def test_sent_api_token_is_forwarded_unchanged(server, monkeypatch):
    class Request:
        headers = {"Authorization": "Bearer sk-abc"}

    monkeypatch.setattr(server, "get_http_request", lambda: Request())

    assert server.get_auth_headers()["Authorization"] == "Bearer sk-abc"


def test_rejected_token_is_not_rechecked_immediately(server, userinfo_calls):
    verifier = server.TopolographTokenVerifier(PUBLIC_URL)

    results = [asyncio.run(verifier.verify_token("sk-dead")) for _ in range(3)]

    assert results == [None, None, None]
    assert len(userinfo_calls) == 1


def test_unknown_tokens_do_not_flood_userinfo(server, monkeypatch):
    import threading
    import time

    running, peak, lock = [0], [0], threading.Lock()

    def slow_get(url, headers, timeout):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
        return UserinfoResponse(401)

    monkeypatch.setattr(server.requests, "get", slow_get)
    verifier = server.TopolographTokenVerifier(PUBLIC_URL)

    async def flood():
        return await asyncio.gather(*(verifier.verify_token(f"sk-random-{i}") for i in range(20)))

    assert asyncio.run(flood()) == [None] * 20
    assert peak[0] == server.USERINFO_CONCURRENCY == 4


def test_a_slow_rejection_is_still_cached(server, monkeypatch):
    clock = [1000.0]
    calls = []

    def slow_get(url, headers, timeout):
        calls.append(url)
        clock[0] += 10  # longer than the rejection cache lifetime
        return UserinfoResponse(401)

    monkeypatch.setattr(server.requests, "get", slow_get)
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    verifier = server.TopolographTokenVerifier(PUBLIC_URL)

    assert [asyncio.run(verifier.verify_token("sk-dead")) for _ in range(2)] == [None, None]
    assert len(calls) == 1
