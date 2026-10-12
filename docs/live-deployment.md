# Experimental live recursion

The separate `ferrodns-live` binary exposes HTTP, never a DNS listener. It starts
on `127.0.0.1:8080`; containers explicitly use `--bind 0.0.0.0:8080`. Ordinary
CLI resolution, simulator routes, trace JSON and samples retain their APIs.
Dependencies remain empty. This resolver is experimental and does **not**
validate DNSSEC; do not use it as a production resolver.

`GET /health` returns `ok`. `GET /resolve?name=example.com&type=A` (or `AAAA`)
returns named SSE `started`, `trace`, then exactly one `done` or `error` record.
`done` carries the trace summary and DNS rcode (including NXDOMAIN); `error`
carries an error message. Trace records are delivered during recursion;
`query_start` precedes the socket exchange, `query` follows it. Done events
contain no replay of earlier events. Comments are one-second heartbeats.
The frontend uses one GET fetch stream per manual submission, aborts old
requests, and never reconnects automatically. Retry is an explicit action.

Only `https://tczartoryski.github.io` is an allowed browser Origin. A path is
not part of an Origin. Command-line probes may omit Origin; invalid Origin
is rejected on both routes. OPTIONS, request bodies, transfer encoding,
unknown/duplicate parameters, and methods other than GET are rejected.
Requests require HTTP/1.1 and Host. HTTP is connection-close, without pooling.

Limits: 8 KiB headers; absolute 3-second request read; absolute 1-second deadline per HTTP/SSE write; 16 connections; 4 active resolutions; 15-second resolution deadline;
32 live network attempts (UDP and TCP fallback each spend one); 12 referrals per step; 8 CNAME hops; glueless depth 4;
128 queued events and 512 events per resolution. Queue saturation or receiver
disconnect cancels work. UDP/TCP waits check cancellation at most every 50ms
(TCP connection attempts at most 100ms); TCP frame reads use an absolute
per-exchange and request deadline, even for trickled bytes. Final displayed
answers are capped at 64; event details and answer strings at 2,048 bytes.
The browser caps records at 64 KiB, total stream at 1 MiB and timeout at 18s.

Global DNS allowance is 30 accepted resolve requests per fixed minute window,
per socket peer 6. Health probes bypass this allowance, including when it is
exhausted, but remain subject to the connection cap, header cap and read
deadline. Rejected parses do not spend the DNS allowance. The bounded peer
map uses at most 30 entries in a window (hard cap 1,024). Users sharing a reverse proxy share the conservative DNS peer allowance. Arbitrary X-Forwarded-For is ignored. No proxy trust knob.
Live cache has 256 entries and RTT table at most 1,024 addresses.

Hostnames must be public ASCII names with multiple labels. Every chased
CNAME and NS target is validated. Cached/referral/glueless upstream addresses
are filtered. The transport gate independently rejects private, special,
documentation and transition IPs, mapped IPv6, non-53 ports, and endpoint
overrides **before opening a socket**. Private IP final answers may be
shown, but cannot become upstream endpoints. No configurable roots/upstream,
DNS proxy, URL fetch, credentials, or backend URL query parameter exists.

## Container

Owner-run commands, from the repository root:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
node --check site/viz/live.js
node scripts/check-viz.cjs site/viz/index.html
node scripts/check-live.cjs
docker build --tag ferrodns-live .
docker run --rm --name ferrodns-live --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --memory=128m --pids-limit=64 --cpus=0.5 \
  --publish 127.0.0.1:8080:8080 ferrodns-live
```

No port 53 is exposed or privileged capability granted. Outbound UDP/TCP 53
must be allowed. The runtime is nonroot and needs no writable filesystem.
Docker flags impose these resource restrictions locally; Render's free plan
has platform-managed limits and does not promise the same Docker flags.

## Hosting authorization and proof before enabling Pages

The approved scope reports only GitHub authentication, empty repository
secrets, and no connected hosting account/token. Credentials and secret
stores were not read during implementation. No deployment or push was
performed. Outbound port 53 on a future host is **unverified**.

The minimal owner action is to sign into/create a Render account, authorize
its GitHub integration for this repository only, and explicitly select the
Free compute plan. Do not add a payment method, paid service or secret. If
signup requires billing/card authorization, stop; that is outside this
approval. Import the repository Blueprint (`render.yaml`) using an owner
published branch, inspect `plan: free`, and manually deploy. Keep automatic
deploy disabled. No API token is needed for the dashboard flow.

[Render Free documentation](https://render.com/docs/free) describes roughly
one-minute cold starts after 15 idle minutes, 750 shared workspace instance
hours per month, suspension when hours are exhausted, and suspension or
build disablement at bandwidth/build limits without a payment method.
Unusually heavy outbound traffic can also cause suspension. Its listed
outbound SMTP restrictions do not establish that native DNS works: test it.
The [Blueprint reference](https://render.com/docs/blueprint-spec) documents
the free plan, Docker runtime and manual deployment settings.

1. Record the deployed HTTPS URL and revision. Wake it with one `/health`
   request, then wait for it to be ready. An 18-second browser request may
   time out during a minute-long cold start; retry manually after readiness.
2. On the **host**, prove direct UDP and TCP port 53 independently:

   ```sh
   dig @198.41.0.4 example.com A +norecurse +time=3 +tries=1
   dig @198.41.0.4 example.com A +norecurse +tcp +time=3 +tries=1
   ```

   Render Free has no SSH/dashboard shell. Obtain this proof using a
   temporary owner-operated diagnostic image/start command (with `dig`
   installed in that diagnostic image only), record the two commands and
   responses in deploy logs, then restore this Dockerfile/command. No
   alternate upstream or diagnostic route is added to the public service.
   An answer from local dig or a successful build is not host outbound proof.

   Exact temporary `Dockerfile.probe` for that owner-operated diagnostic
   branch (no public diagnostic endpoint):

   ```dockerfile
   FROM rust:1-bookworm AS build
   WORKDIR /build
   COPY Cargo.toml Cargo.lock ./
   COPY src ./src
   RUN cargo build --locked --release --bin ferrodns-live
   FROM debian:bookworm-slim
   RUN apt-get update && apt-get install -y --no-install-recommends dnsutils && rm -rf /var/lib/apt/lists/*
   COPY --from=build /build/target/release/ferrodns-live /usr/local/bin/ferrodns-live
   USER 65532:65532
   EXPOSE 8080
   ENTRYPOINT ["sh", "-c", "dig @198.41.0.4 example.com A +norecurse +time=3 +tries=1; dig @198.41.0.4 example.com A +norecurse +tcp +time=3 +tries=1; exec /usr/local/bin/ferrodns-live --bind 0.0.0.0:8080"]
   ```

   Owner publishes the temporary branch, changes that service's Dockerfile
   path to `Dockerfile.probe`, and manually deploys that revision. A healthy
   HTTP service alone is insufficient: inspect both dig outputs for valid
   referral/response and absence of timeout. Restore the normal branch and
   `./Dockerfile`, manually redeploy, and record the final revision before
   running step 3. Remove the diagnostic branch/file after recording proof.
3. Pace the following two requests at least 12 seconds apart. Do not run
   internet load tests. Replace `YOUR-SERVICE` only in your local command:

   ```sh
   curl --no-buffer --max-time 25 --trace-time --trace-ascii /tmp/ferrodns-example-sse.txt \
     -H 'Origin: https://tczartoryski.github.io' \
     'https://YOUR-SERVICE.onrender.com/resolve?name=example.com&type=A'
   curl --no-buffer --max-time 25 --trace-time --trace-ascii /tmp/ferrodns-cname-sse.txt \
     -H 'Origin: https://tczartoryski.github.io' \
     'https://YOUR-SERVICE.onrender.com/resolve?name=www.apple.com&type=A'
   dig example.com A +noall +answer
   dig www.apple.com A +noall +answer
   ```

   Record timestamps proving started/query_start arrived **before** the
   terminal record, and compare rcode/CNAME/answers to dig, allowing CDN,
   TTL and resolver vantage differences. Test A/AAAA individually when
   enabling their published support, paced in a later rate window. Confirm
   the proxy does not buffer SSE; abort a stream and confirm no reconnect.
4. Only after that evidence and real mobile browser checks, set
   `site/viz/live-config.json` to `{"endpoint":"https://YOUR-SERVICE.onrender.com/"}`
   in an owner-reviewed change. Until then Pages remains honest sample mode
   with disabled live resolution. Never publish a localhost endpoint.

[Cloudflare Workers protocols](https://developers.cloudflare.com/workers/reference/protocols/)
provide outbound TCP rather than this native Rust UDP recursion runtime.
[Fly pricing](https://docs.fly.io/about/pricing) has no free tier for new
accounts (legacy allowances differ). Oracle's credit-card signup is not
approved. No alternative hosting account should be created by this task.

## Verification

CI runs Rust formatting, all-target clippy, all tests, frontend syntax and
mock DOM/SSE tests, with no real internet DNS. Rust socket tests use ephemeral
loopback ports: delayed upstream event arrival, trickled TCP deadline,
slow HTTP headers, HTTP responses, and cancellation. Socketless tests prove
public-target policy, forbidden cached CNAMEs, private glue/glueless answers,
endpoint overrides, event ceiling, queue full/disconnect, rates and permits.

`node scripts/check-live-browser.cjs` runs actual headless Chromium at a
390px mobile viewport with an isolated temporary profile, five existing
samples, published-null availability, explicit Origin, mocked SSE injection,
and interruption with no retry. Set `FERRODNS_CHROME` to a Chromium executable
if necessary. It overrides only its temporary served config; the checked-in
config remains null. This is browser rendering proof with mocked DNS, not
remote host recursion proof. No binary assets are read or generated.

Actual backend browser mode (owner-run, internet required):

```sh
node scripts/check-live-browser.cjs --run-backend
# Or start ferrodns-live yourself, then:
node scripts/check-live-browser.cjs --actual-backend http://127.0.0.1:8080
```

This preserves the mocked lifecycle checks and adds exactly two public A
queries, at least 12 seconds apart: example.com at desktop 1280px and
www.apple.com at mobile 390px. Actual mode serves the test page at HTTP
loopback. Its served copy of live.js substitutes only the fetch destination
with a same-origin loopback relay after unchanged HTTPS-only config validation.
The temporary config still uses a synthetic HTTPS endpoint; the checked-in
endpoint remains null and live.js is not edited. Actual mode clears the CDP
Origin override for browser requests; the relay supplies the explicit Pages
Origin to the backend. The relay flushes
response headers and pipes SSE with native backpressure, without collecting
or fulfilling a complete response through CDP. Browser disconnect destroys
the upstream request; the relay never retries. The real SSE reaches the
browser's fetch reader; assertions require a pending query row before the successful terminal DOM,
answers and no viewport overflow. JSON output records first pending and final
DOM timestamps in milliseconds from submission, plus the real answers.
Network.loadingFailed diagnostics include request URL, browser error and any
blocked/CORS reason. No browser security flags, public CORS policy or published
config changes are needed. This local relay path tests incremental backend/UI
behavior; it does not prove the production HTTPS browser-to-backend path.
Chrome exit is awaited before profile removal with retries.
Set `CARGO` to the cargo executable if it is not on PATH. The script stops
its own backend process group on exit; an externally started backend is
left running.

The owner reports all 67 Rust tests, formatting, clippy, release build, mock
suites and real Chromium mocked mobile/sample checks passed after round1
(`/tmp/ferrodns-recovery-verification.log`). The previous actual-backend CDP
HTTPS-to-loopback rewrite failed with browser `Failed to fetch`. Round2 replaces
that path with the relay described above. Independent recovery verification
passed actual Chromium desktop/mobile incremental rendering: example.com
pending at 9.2ms, terminal at 136ms; www.apple.com pending at 7.2ms, terminal
at 768.8ms. See `/tmp/ferrodns-recovery-browser.log`. This sandbox blocks socket creation (`EPERM`).
Hosting remains account blocked; local success does not
prove host outbound DNS. The Docker daemon is unavailable: container
build/run is not verified. See `docs/live-verification.md` for details.
