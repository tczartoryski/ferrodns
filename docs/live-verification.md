# Live verification record

Implementation session: 2026-10-12, isolated `live-stream` workspace, approved
plan. No deployment, git push, credentials or binary asset reads.

The checked-in live endpoint is null. No connected Render account or host
outbound proof is available in this task. Hosting remains an owner action.

Gate results are recorded after the final checks below. Socket tests remain
mandatory; a sandbox EPERM is a blocked gate, never a pass or ignored test.

Owner reproduction:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
node --check site/viz/live.js
node scripts/check-viz.cjs site/viz/index.html
node scripts/check-live.cjs
node scripts/check-live-browser.cjs
```

Use `docs/live-deployment.md` for container restrictions and the separate
remote-host proof. Existing public sample browser evidence in
`docs/browser-verification.md` predates this change; it is not live proof.

## Final session gates

| Gate | Result |
| --- | --- |
| `cargo fmt` and `cargo fmt --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test --no-fail-fast` | BLOCKED: 39 passed; 25 failed at socket creation with EPERM (including 20 existing simulator tests) |
| Socketless library diagnostic (three socket tests filtered explicitly) | PASS: 36 tests; this does not replace the full gate |
| Live JS and test script syntax | PASS |
| Existing visualizer mock DOM suite | PASS, including stale sample failure race |
| Live SSE/security/lifecycle mock suite | PASS |
| Real Chromium mobile and five-sample script | BLOCKED: loopback HTTP listen denied with EPERM before Chrome launch |
| `git diff --check` | PASS |
| Container build/run | Not exercised |
| Hosted UDP/TCP 53, HTTPS incremental SSE and dig comparison | Not exercised; no hosting authorization/account connected |

No socket test was ignored or weakened to make the full gate pass. The
socketless diagnostic filtered the three library socket tests only so its
separate result is meaningful. CI keeps the entire suite mandatory.

Remaining risks: full socket/browser execution and container resource limits
need independent verification. Shared proxy and health traffic consume the
per-peer six-request allowance and may cause 429s/unhealthy host probes;
validate the actual hosting proxy/health cadence before enabling Pages.
Conservative public IPv6 policy may reject otherwise usable special-purpose
nameservers. Cold starts exceed the browser request timeout; retry is manual.
DNSSEC is not validated. Endpoint configuration remains null.
