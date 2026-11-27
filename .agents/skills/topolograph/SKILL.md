---
name: topolograph
description: Use BEFORE calling any Topolograph MCP tool and for any question about the routing domain stored in Topolograph - OSPF and IS-IS graphs and snapshots, nodes, ABR/ASBR, networks on a router, routes and paths, adjacency and network events, link-failure impact, MPLS TE tunnels and CSPF paths, BGP sessions, routes, route changes and their binding to the IGP graph, VRF/VPN/EVPN (VNI, route targets, where a MAC or IP lives). Defines how to select the snapshot and present evidence. Not for unrelated tasks or live device commands.
---

# Topolograph

Evidence comes only from the Topolograph MCP tools. Never answer from model knowledge, never suggest a shell command or traceroute instead of a tool, and never guess nodes, prefixes, metrics, routes or root causes.

## Data model
- An IGP snapshot is a `graph_time` (from `get_all_graphs`); a BGP collection cycle is a `bgp_graph_time` (from `list_bgp_graphs`). They are different identifiers: BGP is bound to an IGP graph by `list_bgp_bindings`.
- VRF, VPN, VNI and EVPN tools take the IGP `graph_time` and read the BGP epochs bound to it. A route target is the only filter that identifies one VPN across routers; a VRF name or RD is local.
- Several graphs match: use the newest, name the choice and the alternatives. Copy identifiers exactly as returned.

## Workflows
- **Topology** (nodes, ABR/ASBR, links, networks on a router): `get_all_graphs` without `latest_only`, then `get_nodes`, `get_edges`, `get_network_by_graph_time`. A node's network count is not its neighbour count.
- **Path**: resolve names with `get_nodes`, then `get_shortest_path` with defaults (all ECMP paths). Keep `with_lsps` off unless the question is about MPLS TE autoroute. The reverse path may differ.
- **Incident or history**: `get_events_timeline` for a window, then `get_adjacency_events` and `get_network_events` for the same window: timeline waves hold up/down only, metric changes and SRv6 locator / End.X changes (`srv6_events`) come from adjacency events. Events exist only for monitored graphs; an empty result is a quiet network or a silent watcher, check `is_live` and say which. To tell whether events changed a path or a cost, compare `get_shortest_path` (or `get_edges`) with `at` just before the earliest event of all of them and at the end of the window, and report both.
- **What-if**: whole-network impact of routers failing, links failing or a link cost changing (alone or together) is `get_what_if`; a link is its `edge_key` from `get_edges`, one direction each, so change both when the question names no direction and say so. `get_what_if`, `get_edge_failure_reaction`, `get_node_failure_reaction` and `get_cspf_path` are predictions, never present them as observed. "No path" is a result: name the constraints used.
- **MPLS TE**: `get_lsps` is authoritative; the summary in `get_all_graphs` can be empty while tunnels exist.
- **BGP**: newest epoch unless a time is named; `list_bgp_nodes`, `list_bgp_sessions`, `search_bgp_routes`, `compare_bgp_routes`. For BGP versus IGP toward a destination use `resolve_route` and name its `evidence`. Report the binding `state` and `source_coverage`: a weak binding limits any IGP claim about BGP data.

## Answers
- Show `graph_time`, protocol, area and snapshot time (or the BGP epoch time) in every answer that depends on a graph; never mix graphs or epochs.
- Mark statements as observed (tool output), inferred or unknown. Topology alone does not prove a root cause.
- For "what/which/list" give a compact table, not only a count. Count returned items per status before writing a number, and say if a list is truncated.
- An empty search is not proof of absence if another tool shows the object existed: report both results.
- Missing or failing tool, graph or node: say exactly what and stop. Reply in the language of the question.
