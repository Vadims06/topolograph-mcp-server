"""Shared fixtures: the server module is imported once per test session."""
import importlib.util
import os
from pathlib import Path

import pytest

os.environ.setdefault("TOPOLOGRAPH_API_BASE", "http://topolograph.test/api")

SERVER_PATH = Path(__file__).resolve().parents[1] / "mcp-server.py"


@pytest.fixture(scope="session")
def server():
    spec = importlib.util.spec_from_file_location("mcp_server_under_test", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
