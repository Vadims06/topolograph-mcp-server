# Topolograph MCP Server

A Model Context Protocol (MCP) server that provides access to Topolograph API for OSPF/IS-IS network analysis.

## Overview

This MCP server enables AI agents to interact with Topolograph API to analyze network topologies, monitor events, and perform path calculations for OSPF and IS-IS protocols. MCP (Model Context Protocol) is essential for connecting Large Language Models (LLMs) to network infrastructure, allowing AI agents to query and analyze network data in real-time.

This MCP server is included in the [topolograph-docker](https://github.com/Vadims06/topolograph-docker) repository and is available via the provided `docker-compose.yml` file.

## Features

- **Graph Management**: Retrieve and upload network graphs
- **Network Analysis**: Query network information by IP, node ID, or network mask
- **Event Monitoring**: Track network and adjacency events with time filtering
- **Path Calculation**: Calculate shortest paths between nodes with backup path support
- **Status Monitoring**: Check graph connectivity and health status
- **Node/Edge Queries**: Retrieve detailed node and edge information from diagrams

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Set the required environment variable:

```bash
export TOPOLOGRAPH_API_BASE="https://your-topolograph-api-url"
```

Optional authentication:

```bash
export TOPOLOGRAPH_API_TOKEN="your-api-token"
```

Optional read-only mode (defaults to `true`, recommended for agent-facing deployments):

```bash
export TOPOLOGRAPH_MCP_READ_ONLY="true"
```

When enabled, mutation tools (`upload_graph`, `add_lsp`, `update_lsp`, `delete_lsp`) are
removed from the advertised tool surface (`tools/list`) and cannot be called, even by a
client that already knows their name. Set to `false` only for trusted/admin deployments
that need write access.

## Usage

Start the MCP server:

```bash
python mcp-server.py
```

The server runs on `http://0.0.0.0:8000/mcp` by default.

### Docker Compose Integration

This MCP server is included in the [topolograph-docker](https://github.com/Vadims06/topolograph-docker) repository. To use it as part of the complete Topolograph stack:

```bash
git clone https://github.com/Vadims06/topolograph-docker.git
cd topolograph-docker
docker-compose pull
docker-compose up -d
```

The MCP server will be available at `http://localhost:8000/mcp` and automatically connects to the Flask API.

## Available Tools

### Read tools (always available)

- `get_all_graphs`: List available graphs with filtering options
- `get_graph_by_time`: Fetch specific graph by time
- `get_network_by_graph_time`: Query network information
- `get_graph_status`: Check graph health and connectivity
- `get_network_events`: Retrieve network up/down events
- `get_adjacency_events`: Get node/host and link events
- `get_events_timeline`: Node/host events grouped into time waves for incident narration
- `get_nodes`: Query diagram nodes (filter by role flags: ABR/ASBR, IS-IS overload/attached)
- `get_edges`: Query diagram edges (`include=["lsp_left_bw", "lsps", "is_te_link", "edge_key"]` for MPLS TE fields)
- `get_lsps`: List/inspect MPLS TE LSP tunnels (filters: `status`, `via_node`, `via_edge`, `via_edge_key`)
- `get_shortest_path`: Calculate the shortest path between two nodes (`with_lsps=true` to account for autoroute-enabled MPLS-TE tunnels)
- `get_cspf_path`: Constrained-shortest-path (CSPF) feasibility check between two nodes; never mutates the graph
- `get_edge_failure_reaction`: Predict whole-network impact if one or more links go down; simulation only

### BGP topology tools (require Topolograph >= 2.69)

- `list_bgp_graphs` / `get_bgp_graph`: List/fetch BGP graph epochs
- `list_bgp_nodes` / `list_bgp_sessions`: BGP speakers and peering sessions of an epoch
- `search_bgp_routes`: Search the BGP route table, whole-graph or scoped to one speaker's resolved RIB view
- `get_bgp_node_route_summary`: Per-speaker route totals (RIB-tag histogram, Adj-RIB-Out count)
- `get_bgp_route_state`: Point-in-time BGP route state
- `compare_bgp_routes`: Diff BGP routes between two instants
- `get_bgp_events_timeline`: BGP session/route monitoring events
- `list_bgp_bindings` / `get_bgp_binding`: BGP-to-IGP graph correlation
- `resolve_route`: Resolve a path to a destination, including VPN/MPLS handoffs
- `get_vrf_inventory` / `list_vpn_routers`: VRF inventory and VPN start-node candidates for `resolve_route`

### Mutation tools (hidden and disabled when `TOPOLOGRAPH_MCP_READ_ONLY=true`)

- `upload_graph`: Upload new graphs to the API
- `add_lsp` / `update_lsp` / `delete_lsp`: Create, update, and delete MPLS TE LSP tunnels (`delete_lsp` is also tagged destructive)

Tools are tagged `read`, `write`, and/or `destructive` in source, and carry standard MCP
annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`) for clients that use them
for tool selection. Annotations are metadata for clients, not a security boundary: the
actual boundary is `TOPOLOGRAPH_MCP_READ_ONLY` hiding mutation tools from `tools/list`,
backed by a server-side guard that also rejects direct calls to them in read-only mode.

## Wave patterns (`get_events_timeline`)

`get_events_timeline` groups node/host up/down events into chronological
**waves**, each labelled with a `pattern` (`outage` / `flap` / `up`). For the
full field reference and the `pattern` ↔ graph-status mapping, see the docs:

➡️ **[Events Timeline (Waves)](https://docs.topolograph.com/monitoring/events-timeline/)**

## License

See LICENSE file for details.
