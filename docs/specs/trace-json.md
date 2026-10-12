### Spec A: `docs/specs/trace-json.md` (Rust, zero dependencies)

- Add `--trace-json <file>` to `query`, and `--trace-dir <dir>` to `serve` (one JSON file per client query). The existing text trace keeps working.
- Turn `Ctx`'s `Vec<String>` into structured events recorded in `ask()`, `check_cache()` and the glueless and CNAME branches of `resolver.rs`. Write a small hand-rolled JSON writer in `src/trace.rs`; no serde.
- Add a command `ferrodns viz <name> [type] [--out dir]`. It runs the query, copies `site/viz/index.html` into the output directory, and embeds the trace as `<script id="trace" type="application/json">`, so the page works over `file://` without fetch. It then prints the path.
- Add a golden-file unit test of the JSON for one sim lookup, with timings stripped.
- Files: `src/resolver.rs`, `src/trace.rs` (new), `src/main.rs`, `src/lib.rs`, `tests/simnet.rs`.

Schema:
```json
{
  "question": {"name": "www.apple.com.", "type": "A"},
  "started_at": "2026-10-12T17:45:00Z",
  "total_ms": 142.7, "rcode": "NOERROR",
  "answers": ["www.apple.com. 300 IN CNAME www.apple.com.edgekey.net."],
  "events": [
    {"t_ms": 0.0, "dur_ms": 21.4, "depth": 0, "kind": "query", "zone": ".",
     "server": "a.root-servers.net.", "ip": "198.41.0.4", "qname": "www.apple.com.",
     "qtype": "A", "transport": "udp", "outcome": "referral",
     "detail": "referral to com. (13 NS, 13 glue)"},
    {"t_ms": 21.5, "dur_ms": 0.0, "depth": 0, "kind": "cache_hit", "qname": "...", "detail": "..."},
    {"t_ms": 60.0, "dur_ms": 0.0, "depth": 0, "kind": "cname", "detail": "a. -> b."}
  ]
}
```
- `kind` is one of: `query | cache_hit | cname | glueless`.
- `outcome` is one of: `answer | cname | referral | nxdomain | nodata | lame | timeout | error`.
