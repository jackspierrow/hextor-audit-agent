# Test Report — Hextor Audit Agent v1.0.0

Tested locally on 14 Nov 2026 ~18:07–18:12 WIB (11:07–11:12 UTC).
Command: `python3 api/index.py` (port 8000, no `AGENT_SHARED_SECRET`
unless noted). No credentials, wallets, or external accounts touched.

## 1. GET /health

```bash
curl http://127.0.0.1:8000/health
```

Result: `{"status": "ok"}` — PASS.

## 2. POST /audit — real domains

| Domain | Reachable | Score | Verdict | Findings |
|---|---|---|---|---|
| google.com | yes | 100 | pass | none — all 5 URLs live, Expires 2030-04-01 |
| github.com | yes | 100 | pass | none |
| qonto.eu | yes | 80 | needs-attention | Low: Contact `security@qonto.eu` is not a URI; Low: missing Expires |
| example.com | no (HTTP 404) | 40 | needs-attention | Low: security.txt not found |
| commerzbank.com | no (HTTP 555) | 40 | needs-attention | Low: security.txt not found — see note below |

Notes:

- **qonto.eu** is a real imperfect file: its Contact is a bare email
  address instead of a `mailto:` URI, and it has no Expires field.
  (Its file changed since our QNT-1 bounty draft — the inline
  Encryption block from that draft is gone. The agent reports only
  what is live now, no copied claims.)
- **commerzbank.com — HTTP 555 is a sandbox artifact, not a real
  result.** 555 is not a standard HTTP status; the dev VM's egress
  proxy returns it for this host. The agent handled it correctly
  (treated as "not found", score 40), but the dead-Encryption-URL
  finding class could NOT be re-verified end-to-end from this VM.
  **Re-test from the deployed Vercel endpoint before claiming the
  dead-URL path works in production.**
- **Latency is proxy-bound in this VM, not code-bound.** A single
  request through the dev VM's egress proxy takes 2–7 s
  (measured: HEAD `g.co/vulnz` 6.66 s). google.com's audit took
  ~21 s here. On a normal network each fetch is ~0.2–1 s, so the
  same audit should take ~2–4 s. URL checks run concurrently
  (ThreadPoolExecutor, 5 workers); Contact/Encryption URLs are
  verified twice, Acknowledgments/Policy/Hiring once.
  **Vercel Hobby functions cap at 10 s** — on a normal network the
  audit fits; on a slow network a file with many URLs could exceed
  it. If that happens in production, the fix is Vercel Pro (60 s)
  or fewer double-checks, not more timeout.

## 3. HMAC auth (AGENT_SHARED_SECRET=testsecret123)

| Case | Expected | Got |
|---|---|---|
| No `X-Signature` header | 401 | 401 `{"error": "invalid or missing X-Signature"}` |
| Correct HMAC-SHA256 hex of raw body | 200 | 200 |
| Wrong signature | 401 | 401 |

PASS — all three cases correct.

## 4. Input validation / SSRF guard

| Input | Expected | Got |
|---|---|---|
| `localhost` | rejected, verdict fail | fail — "Invalid or blocked domain" |
| `not a domain!!` | rejected, verdict fail | fail — "Invalid or blocked domain" |
| missing `domain` key | 400 | 400 `{"error": "missing \"domain\""}` |
| invalid JSON body | 400 | 400 `{"error": "body must be valid JSON"}` |

Note: the guard uses an explicit blocklist of networks (loopback,
RFC1918, link-local, CGNAT, multicast, reserved) instead of
`ip.is_private`, because Python's `is_private` also covers
198.18.0.0/15 — the range this dev VM's proxy resolves every public
host into. A blanket `is_private` check rejected every domain in
this VM. On Vercel, real DNS returns real public IPs.

## 5. Not tested (needs deploy / real network)

- Deploy to Vercel (`vercel deploy`) — parent's job.
- Dead-URL finding end-to-end on a domain whose security.txt
  actually contains a dead link (commerzbank.com blocked by the
  sandbox proxy; re-test after deploy).
- Behaviour under Vercel's 10 s Hobby limit with a URL-heavy file.
