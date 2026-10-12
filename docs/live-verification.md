# Live verification record

Implementation and fix rounds 1–2: 2026-10-12, approved
scope. No deployment, git push, credentials or binary asset reads.
The checked-in live endpoint remains null. Hosting is still account blocked.
The Docker daemon is unavailable; container build/run is not verified.

## Independent owner verification before round1

The owner reports `cargo test` passed all 64 tests outside the sandbox:
39 library + 1 CLI + 2 stream + 22 simulator. Real local recursion for
example.com delivered
its first event at 13.32ms and final at 175.16ms, with addresses matching
dig. www.apple.com delivered its first event at 9.01ms and final around
620ms, with the CNAME chain matching dig.

Real Chromium mobile/five-sample assertions passed, then cleanup failed
with an ENOTEMPTY race. Those assertions used mocked SSE; the new actual
backend browser mode has not yet been owner verified.

## Fix round1 sandbox gates

| Gate | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets -- -D warnings` | PASS |
| `cargo test` / `cargo test --no-fail-fast` | BLOCKED: loopback socket creation returns EPERM |
| Full-suite sandbox totals | 41 passed, 26 socket failures; 67 tests, none ignored |
| New health and deterministic slow writer/permit regressions | PASS |
| IPv6 prefix and standalone export regressions | PASS in existing library tests |
| New live UDP/TCP attempt budget regression | BLOCKED: socket creation EPERM |
| Live JS/browser script syntax | PASS |
| Existing visualizer mock DOM suite | PASS |
| Live SSE/security/lifecycle mock suite | PASS |
| Chromium test execution | BLOCKED: loopback HTTP listen EPERM |
| `git diff --check` | PASS |
| Container build/run | Not verified: Docker daemon unavailable (owner report) |
| Hosted outbound UDP/TCP 53 and HTTPS incremental SSE | Account blocked; not verified |

Owner reproduction after round1:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
node --check site/viz/live.js
node --check scripts/check-live-browser.cjs
node scripts/check-viz.cjs site/viz/index.html
node scripts/check-live.cjs
node scripts/check-live-browser.cjs --run-backend
```

The browser command preserves all mocked lifecycle and five-sample checks,
then runs real loopback ferrodns SSE at desktop and mobile widths. It makes
only two public DNS requests, at least 12 seconds apart, and prints pending
and final DOM timestamps and answers. It requires pending query rendering
before completion. Actual mode serves the browser page at HTTP loopback,
using a test-only
served live.js fetch destination substitution after unchanged HTTPS config
validation. The CDP Origin override is cleared for loopback browser requests.
A same-origin HTTP relay supplies the explicit Pages Origin to the backend and
pipes backend SSE immediately with backpressure, without buffering the complete
response or CDP fulfillment. Disconnect cancels the upstream request. Published
live.js, null config and public CORS remain unchanged. Network.loadingFailed
prints request URLs and browser blocked/CORS diagnostics. This is local
incremental backend/UI proof, not production HTTPS/CORS deployment proof.
An already running loopback backend can be used
with `--actual-backend http://127.0.0.1:8080` instead.

## Fix round2 status

The owner reports all 67 Rust tests, formatting, clippy, release build, mock
suites and real Chromium mocked mobile/sample checks passed after round1
(`/tmp/ferrodns-recovery-verification.log`). Actual-backend mode failed with
browser `Failed to fetch` during the CDP HTTPS-to-loopback URL rewrite.
Round2 replaces that rewrite with the loopback streaming relay above. The
actual-backend browser run independently passed on 2026-10-12
(`/tmp/ferrodns-recovery-browser.log`, exit 0): desktop example.com pending
DOM at 9.2ms and terminal at 136ms; mobile 390px www.apple.com pending at
7.2ms and terminal at 768.8ms. Exactly two A requests, 12 seconds apart,
rendered real answers without overflow. Expected ERR_ABORTED diagnostics
after terminal come from the frontend closing its completed reader. No
hosted actual-browser success is claimed.

Independent direct SSE probes passed: example.com first trace 13.91ms,
done 149.44ms; www.apple.com first trace 10.10ms, done 442.28ms. Arrival
records: `/tmp/ferrodns-recovery-example.log` and
`/tmp/ferrodns-recovery-apple.log`; example.com addresses matched dig,
Apple CNAME chain matched, with expected CDN vantage-dependent final A.
All 67 Rust tests passed (41 library, 1 CLI, 3 stream, 22 simulator), as did
fmt, all-target clippy, release build and JS mock gates. Complete Rust
record: `/tmp/ferrodns-recovery-verification.log`; its initial browser
rewrite failure was fixed within final round2 and superseded by the passing
browser log. No Rust dependencies were added.

Round2 sandbox checks: JS syntax, both existing mock suites and `git diff
--check` passed. A socketless relay check passed incremental chunk delivery
before upstream EOF, Pages Origin, disconnect cancellation, request pacing,
two-query limit and served-script syntax with HTTPS validation retained.
These checks complement the independent passing Chromium run above.

Use `docs/live-deployment.md` for the separate remote-host proof and resource
limits. Local owner verification does not establish future host outbound
DNS or proxy streaming. Existing public sample evidence in
`docs/browser-verification.md` is not live recursion proof.

Remaining limits: users behind a shared proxy share the six-resolve peer
allowance; health probes no longer consume it. Conservative public IPv6
policy may reject otherwise usable special-purpose nameservers. Cold
starts exceed the browser timeout; retry is manual. DNSSEC is not validated.
Endpoint configuration remains null.
