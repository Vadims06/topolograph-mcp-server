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

The server runs on `http://0.0.0.0:8000/mcp` by default. Behind a reverse proxy, set `TOPOLOGRAPH_MCP_HOST=127.0.0.1` so the plain-HTTP port is reachable only through the proxy.

### Docker Compose Integration

This MCP server is included in the [topolograph-docker](https://github.com/Vadims06/topolograph-docker) repository. To use it as part of the complete Topolograph stack:

```bash
git clone https://github.com/Vadims06/topolograph-docker.git
cd topolograph-docker
docker-compose pull
docker-compose up -d
```

The MCP server will be available at `http://localhost:8000/mcp` and automatically connects to the Flask API.

## Use with Claude Code and Codex CLI

Sign in with the browser instead of a token (the server must run with `TOPOLOGRAPH_PUBLIC_URL`, e.g. `https://topolograph.com`, which is both the OAuth authorization server and the API host). The CLI opens the Topolograph sign-in and receives a read-only token that Access > API tokens lists and revokes:

```bash
claude mcp add --transport http -s user topolograph https://topolograph.com/mcp
codex mcp add topolograph --url https://topolograph.com/mcp && codex mcp login topolograph
```

With `TOPOLOGRAPH_PUBLIC_URL` set, a request without a valid token gets `401` with a `WWW-Authenticate` challenge pointing to `/.well-known/oauth-protected-resource/mcp`; an API token in `Authorization: Bearer` keeps working. Unset, the server forwards the caller's token as before. The reverse proxy must route `/.well-known/oauth-protected-resource/mcp` to this server next to `/mcp`.

Create an API token in Topolograph, then export it and register the server (replace the URL with your MCP address):

```bash
export TOPOLOGRAPH_MCP_TOKEN=<token>
claude mcp add --transport http -s user topolograph https://topolograph.com/mcp -H 'Authorization: Bearer ${TOPOLOGRAPH_MCP_TOKEN}'
codex mcp add topolograph --url https://topolograph.com/mcp --bearer-token-env-var TOPOLOGRAPH_MCP_TOKEN
```

Optional: an Agent Skill that tells the agent when to use these tools and how to present the evidence. Codex in particular does not call the tools on routing questions without it.

```bash
npx skills add Vadims06/topolograph-mcp-server --skill topolograph
```

## Available Tools

### Read tools (always available)

- `get_all_graphs`: List available graphs with filtering options
- `get_graph_by_time`: Fetch specific graph by time
- `get_network_by_graph_time`: Query network information; `filter_type` (all, backuped_only, non_backuped_only) lists networks by backup status; optional `at` gives the state at a moment
- `get_graph_status`: Check graph health and connectivity
- `get_network_events`: Retrieve network up/down events
- `get_adjacency_events`: Get node/host and link events
- `get_events_timeline`: Node/host and adjacency events grouped into time waves for incident narration (metric changes are not waves)
- `get_nodes`: Query diagram nodes (filter by role flags: ABR/ASBR, IS-IS overload/attached; optional `at`); `protocol="bgp"` with `vni`, `vrf` or `rt` lists the leaves (VTEPs) that carry that VNI, VRF or route target
- `get_edges`: Query diagram edges (`include=["lsp_left_bw", "lsps", "is_te_link", "edge_key"]` for MPLS TE fields; `is_te_link=true|false` keeps only TE links or only the rest; optional `at`)
- `get_lsps`: List/inspect MPLS TE LSP tunnels (filters: `status`, `via_node`, `via_edge`, `via_edge_key`)
- `get_shortest_path`: Calculate the shortest path between two nodes (`with_lsps=true` to account for autoroute-enabled MPLS-TE tunnels); `dst_node` may be a list of targets, such as every VTEP of a VNI, answered from one SPF; `src_node` or `dst_node` with a "/" is an IP or network (a host is `x.x.x.x/32`); `failed_edges` (edge_key), `failed_nodes` or `changed_edge_costs` (edge_key -> cost) give the backup path, simulation only; a list `src_node` gives the union of paths between two sets of routers; optional `at` uses the graph state at that moment
- `get_cspf_path`: Constrained-shortest-path (CSPF) feasibility check between two nodes; never mutates the graph; optional `level` (1 or 2) restricts an IS-IS path to one level
- `get_node_failure_reaction`: Predict whole-network impact if one or more routers go down; simulation only
- `get_edge_failure_reaction`: Predict whole-network impact if one or more links go down; simulation only
- `get_graph_analysis`: Whole-graph reports (`kind`: central-nodes, most-loaded, single-point-of-failure, fault-tolerant, heatmap, unsym-paths, unidir-edges, backup-paths-in-ecmp, duplicated-terminated-networks, network-score); optional `at`
- `get_path_tree`: The shortest-path tree from (`direction="out"`) or to (`"in"`) one node

A rate-limited call (HTTP 429) fails with `retry_after_sec` in the message.

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
- `get_vrf_inventory`: VRF inventory

### BGP VPN and EVPN tools on the IGP graph (require Topolograph >= 2.73)

Asked with the OSPF/IS-IS `graph_time`; the latest BGP epoch of every source bound to that graph answers.

- `list_vpns`: VNIs and VRFs of the fabric, or the VPNs one router (`router_id`) sees
- `get_routes`: Where a MAC or IP is (leaf, VNI, VRF, ESI), what a VRF or VNI holds, and routes behind one VTEP. Filters: `mac`, `prefix`, `vni`, `vrf`, `rt`, `rd`, `vtep`, `at`; `router_id` scopes it to one router's RIB view
- `get_route_events`: Route history; a MAC's arrival on a new VTEP carries `moved_from_vtep`

EVPN route types 1 to 5 are covered (RFC 7432, RFC 9136); the fields are described in the
[BMP Watcher guide](https://docs.topolograph.com/monitoring/bmp-watcher/#evpn).

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

## Releasing

1. Set `version` in `server.json` to the new `X.Y.Z`. The server reports this version too.
2. Push tag `vX.Y.Z`. CI publishes the Docker image and lists the version in the [MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=com.topolograph); a tag that differs from `server.json` fails the job.
3. If the skill changed, publish it to ClawHub: `clawhub publish .agents/skills/topolograph --version <next>`.

## License

See LICENSE file for details.
