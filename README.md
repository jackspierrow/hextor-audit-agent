# Hextor Audit Agent

A public, read-only **security.txt auditor** — built for the
[zkVerify Agent Games](https://agentgames.zkverify.io), **Wildcard track**.

It checks any domain's `security.txt` (RFC 9116) the way a real bug-bounty
hunter does: fetch it live, verify every contact / encryption / policy URL
**twice**, check whether `Expires` has passed, and report only what the
evidence actually proves. It never sends reports or emails — it only
audits and returns JSON.

## Who it helps

- **Security researchers** — before writing a report, check whether the
  target's documented contact channel actually works. A dead contact link
  means your report may never arrive.
- **Small teams / site owners** — a 10-second check that their
  `security.txt` is present, current, and pointing at live pages.
- **Bug-bounty programs** — a cheap, repeatable hygiene check for every
  program in scope.

## How it works

1. `POST /audit {"domain": "example.com"}`.
2. The agent fetches `https://<domain>/.well-known/security.txt`
   (follows redirects, 10 s timeout, clearly labelled User-Agent).
3. It parses the RFC 9116 fields: `Contact`, `Expires`, `Encryption`,
   `Acknowledgments`, `Policy`, `Hiring`, `Preferred-Languages`,
   `Canonical`.
4. Every URL in a contact/encryption field is verified **live,
   twice** (HEAD, GET fallback). A URL is only called *dead* when both
   checks fail; one failure is reported as *flaky*, not as a finding.
   Acknowledgments / Policy / Hiring links are low-severity and checked
   once. A 403 / 429 / WAF block is reported as *blocked*, never as a finding.
5. It scores the file (100 start, −10 low / −20 medium / −30 high) and
   returns a verdict: `pass` (≥90), `needs-attention` (60–89),
   `fail` (<60).

Methodology comes from our bug-bounty hunt checklist (87 verified
reports sent): live evidence twice, adversarial self-check, severity
never higher than the proven impact. Docs-only findings are
Informational/Low — never inflated.

## Run locally

Python 3.10+, **stdlib only — no dependencies to install**.

```bash
python3 api/index.py          # serves on http://127.0.0.1:8000
```

Optional auth (same scheme the Agent Games arenas use — shared-secret
HMAC):

```bash
AGENT_SHARED_SECRET="isi-rahasia-di-sini" python3 api/index.py
```

Then every `POST /audit` must carry the header

```
X-Signature: <HMAC-SHA256 hex of the raw request body, keyed with the secret>
```

Without the secret set, the endpoint runs open (demo mode).

## Examples

```bash
# liveness
curl http://127.0.0.1:8000/health
# {"status": "ok"}

# audit a domain
curl -X POST http://127.0.0.1:8000/audit \
  -H 'Content-Type: application/json' \
  -d '{"domain": "github.com"}'
```

Response (trimmed):

```json
{
  "domain": "github.com",
  "reachable": true,
  "fields": {"contact": ["https://github.com/contact/report-abuse", "..."]},
  "findings": [],
  "score": 100,
  "verdict": "pass",
  "checked_at": "2026-11-14T11:10:00+00:00"
}
```

With HMAC auth:

```bash
BODY='{"domain":"github.com"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$AGENT_SHARED_SECRET" | cut -d' ' -f2)
curl -X POST http://127.0.0.1:8000/audit \
  -H 'Content-Type: application/json' -H "X-Signature: $SIG" -d "$BODY"
```

## Deploy (Vercel)

```bash
vercel deploy        # or connect the repo in the Vercel dashboard
```

`vercel.json` routes everything to `api/index.py`. Set the
`AGENT_SHARED_SECRET` env var in the Vercel project to enable HMAC auth.

## Honest limitations

- **Only checks `security.txt`.** This is not a full security scan — no
  port scan, no vulnerability probe, no authenticated testing.
- **Public data only.** It fetches one public file and the public URLs
  listed inside it. It never logs in anywhere and never touches
  credentials.
- **SSRF-guarded.** Localhost, private/reserved IPs and malformed
  hostnames are rejected before any fetch.
- **Live checks can be flaky.** A site behind a WAF may block the fetch;
  that is reported as *blocked*, not as a finding.
- **Severity is capped by evidence.** A missing file is a hygiene issue,
  not a vulnerability — the score reflects that.
- **No zkVerify proof (yet).** Findings are checkable claims anyone can
  re-verify with `curl` in 10 seconds; writing a zkVerify proof for them
  is optional under the Wildcard rules and is not implemented in v1.
