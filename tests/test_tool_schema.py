import asyncio


def test_every_tool_argument_has_a_description(server):
    tools = asyncio.run(server.mcp.get_tools())
    missing = [
        f"{name}.{argument}"
        for name, tool in tools.items()
        for argument, schema in tool.to_mcp_tool().inputSchema.get("properties", {}).items()
        if not str(schema.get("description", "")).strip()
    ]
    assert not missing, f"arguments without a description: {missing}"
