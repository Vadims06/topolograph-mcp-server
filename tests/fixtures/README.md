# Contract-test fixtures

The `contract-test` workflow needs, per protocol:

- `ospf_parsed.json` / `isis_parsed.json` — a captured `POST /api/watcher/parsed`
  body (`{watcher_name, protocol, data}`) that builds one monitored graph.
- `ospf_events.json` / `isis_events.json` — the CSV-parser payloads Fluent Bit
  sends, **one JSON object per line**, POSTed to `/websocket`. Include at least
  one deliberate change (a cost change, a link/host down+up) so the
  adjacency/network event arrays are non-empty — an empty array validates
  against any schema and would hide field-level drift.

## Capturing them

Run the public lab (`ospfwatcher/containerlab/ospf01`,
`isiswatcher/containerlab/isis01`) against a local Topolograph:

- `*_parsed.json`: tee the body the containerlab watcher POSTs to
  `/api/watcher/parsed`.
- `*_events.json`: make a few `vtysh` changes, then take the JSON lines the
  Fluent Bit `http` output sends to `/websocket` (or transform
  `watcher/logs/watcher1.*.log` with `fluentbit/parse_events.lua`'s field
  mapping).

Keep them small — a few routers and a handful of events is enough; the test
checks response *shape*, not topology size.
