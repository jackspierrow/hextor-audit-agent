"""
Hextor Audit Agent — security.txt auditor (read-only).

Public agent for the zkVerify Agent Games, Wildcard track.
Audits a domain's security.txt (RFC 9116) the same way our bug-bounty
hunt does: fetch live, verify every contact/encryption/policy URL twice,
check Expires, and never inflate severity beyond what the evidence proves.

Stdlib only — no third-party dependencies, no paid services.

Endpoints:
  GET  /health          -> {"status": "ok"}
  POST /audit           -> {"domain": "example.com"}
                           returns audit JSON (see audit_domain())

Auth (optional, demo-friendly):
  If the env var AGENT_SHARED_SECRET is set, POST /audit requires the
  header  X-Signature: HMAC-SHA256 hex of the raw request body, keyed
  with that secret. Wrong or missing signature -> 401.
  If the secret is NOT set, the endpoint runs open (demo mode).

Vercel: api/index.py is a serverless function; the `handler` class below
is the Vercel Python entry point. Locally, run `python3 api/index.py`
and it serves on $PORT (default 8000).

The agent NEVER sends reports or emails — it only audits and returns JSON.
"""

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
USER_AGENT = "Hextor-Audit-Agent/1.0 (+https://agentgames.zkverify.io)"
FETCH_TIMEOUT = 10
VERIFY_TIMEOUT = 10  # short-URL redirects (g.co etc.) can take >5 s on slow
# networks; a short timeout would falsely report live URLs as dead.
MAX_BODY = 64 * 1024  # never read more than 64 KiB from a target

# Fields defined by RFC 9116 (plus common extensions we report, not score).
KNOWN_FIELDS = {
    "contact", "expires", "encryption", "acknowledgments", "policy",
    "hiring", "preferred-languages", "canonical",
}
# Fields whose value must be a URL we can verify live.
URL_FIELDS = {"contact", "encryption", "acknowledgments", "policy", "hiring"}

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)


# ---------------------------------------------------------------------------
# Safety: never fetch internal / private targets (SSRF guard).
# ---------------------------------------------------------------------------
def validate_domain(raw):
    """Return a clean lowercase hostname, or None if invalid/blocked."""
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower().rstrip(".")
    if not host or len(host) > 253:
        return None
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
        return None
    if not HOST_RE.match(host):
        return None
    # Reject anything that resolves to a private / loopback / reserved IP.
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return None
    # Reject anything that resolves to a loopback / RFC1918 / link-local /
    # CGNAT / multicast / reserved address. NOTE: we check explicit
    # networks instead of ip.is_private, because Python's is_private also
    # covers 198.18.0.0/15 (benchmarking range) — the sandbox proxy in
    # this dev VM resolves every public host into that range, so a blanket
    # is_private check would reject every domain here while working fine
    # on Vercel. 198.18/15 is not routable to internal services.
    BLOCKED_NETS = [
        ipaddress.ip_network("127.0.0.0/8"),    # loopback
        ipaddress.ip_network("10.0.0.0/8"),     # RFC1918
        ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
        ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
        ipaddress.ip_network("169.254.0.0/16"),  # link-local
        ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
        ipaddress.ip_network("0.0.0.0/8"),      # "this" network
        ipaddress.ip_network("224.0.0.0/4"),    # multicast
        ipaddress.ip_network("240.0.0.0/4"),    # reserved
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("::/128"),
        ipaddress.ip_network("fe80::/10"),      # link-local v6
        ipaddress.ip_network("fc00::/7"),       # unique-local v6
    ]
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if any(ip in net for net in BLOCKED_NETS):
            return None
    return host


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def http_fetch(url, method="GET", timeout=FETCH_TIMEOUT):
    """One request. Returns (status:int|None, headers:dict, body:bytes, error:str|None).

    Follows redirects (urllib default). 403/429/WAF blocks are reported as
    `blocked`, never treated as a finding — same rule as the hunt checklist.
    """
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY + 1)[:MAX_BODY]
            return resp.status, dict(resp.headers), body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY + 1)[:MAX_BODY]
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body, None
    except urllib.error.URLError as e:
        return None, {}, b"", str(getattr(e, "reason", e))
    except Exception as e:  # timeout etc.
        return None, {}, b"", str(e)


def check_url_live(url, timeout=VERIFY_TIMEOUT):
    """HEAD first, GET fallback. Returns (reachable: bool, status, detail)."""
    status, _h, _b, err = http_fetch(url, method="HEAD", timeout=timeout)
    if status is not None and status < 400:
        return True, status, "HEAD %d" % status
    if status in (405, 501):
        status, _h, _b, err = http_fetch(url, method="GET", timeout=timeout)
        if status is not None and status < 400:
            return True, status, "GET %d" % status
        return False, status, "GET %d" % status if status else (err or "error")
    if status is not None:
        return False, status, "HTTP %d" % status
    return False, None, err or "unreachable"


def check_url_live_twice(url):
    """Verify twice (checklist v2: important claims need 2 live fetches).

    A URL is only called dead when BOTH checks fail. One failure + one
    success = flaky, reported as such, not as a finding. The two checks
    are independent requests (no shared cache); callers run them in
    parallel threads across URLs, so wall-clock time stays low.
    """
    ok1, st1, d1 = check_url_live(url)
    ok2, st2, d2 = check_url_live(url)
    if ok1 and ok2:
        return "live", st2, d2
    if not ok1 and not ok2:
        return "dead", st2, d2
    return "flaky", st2, "first=%s second=%s" % (d1, d2)


# ---------------------------------------------------------------------------
# security.txt parsing (RFC 9116)
# ---------------------------------------------------------------------------
def parse_expires(value):
    """Parse an RFC 3339 date-time. Per checklist v2 / RFC 9116 §5.6,
    lowercase 'z' and a space date/time separator are VALID."""
    v = value.strip().replace(" ", "T", 1)
    if v.endswith(("z", "Z")):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_security_txt(text):
    """Return (fields: dict[str, list[str]], unknown: list[str])."""
    fields = {}
    unknown = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if not value:
            continue
        if name in KNOWN_FIELDS:
            fields.setdefault(name, []).append(value)
        else:
            unknown.append(name)
    return fields, unknown


# ---------------------------------------------------------------------------
# The audit itself
# ---------------------------------------------------------------------------
SEVERITY_DEDUCT = {"low": 10, "medium": 20, "high": 30}


def audit_domain(domain):
    """Full audit. Returns the JSON-serialisable result dict."""
    host = validate_domain(domain)
    if host is None:
        return {
            "domain": domain, "reachable": False, "fields": {},
            "findings": [{
                "severity": "info",
                "title": "Invalid or blocked domain",
                "evidence": str(domain),
                "detail": "Domain failed validation (bad hostname, "
                          "localhost/private IP, or unresolvable).",
            }],
            "score": 0, "verdict": "fail",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    url = "https://%s/.well-known/security.txt" % host
    status, _headers, body, err = http_fetch(url)
    now = datetime.now(timezone.utc)
    findings = []

    if status is None:
        return {
            "domain": host, "reachable": False, "fields": {},
            "findings": [{
                "severity": "info",
                "title": "security.txt unreachable",
                "evidence": url,
                "detail": "Fetch failed (%s). Blocked/timeout is not a "
                          "finding by itself — re-check before acting."
                          % (err or "network error"),
            }],
            "score": 40, "verdict": "needs-attention",
            "checked_at": now.isoformat(),
        }
    if status in (403, 429):
        return {
            "domain": host, "reachable": False, "fields": {},
            "findings": [{
                "severity": "info",
                "title": "security.txt fetch blocked",
                "evidence": "%s -> HTTP %d" % (url, status),
                "detail": "WAF/rate-limit block. Blocked is not a finding; "
                          "retry later from another network.",
            }],
            "score": 40, "verdict": "needs-attention",
            "checked_at": now.isoformat(),
        }
    if status == 404 or status >= 400:
        return {
            "domain": host, "reachable": False, "fields": {},
            "findings": [{
                "severity": "low",
                "title": "security.txt not found",
                "evidence": "%s -> HTTP %d" % (url, status),
                "detail": "No security.txt at the standard location. "
                          "Researchers have no documented contact channel.",
            }],
            "score": 40, "verdict": "needs-attention",
            "checked_at": now.isoformat(),
        }

    text = body.decode("utf-8", errors="replace")
    fields, unknown = parse_security_txt(text)

    # --- Verify every http(s) URL concurrently (two live fetches each) ---
    # Two-phase: collect all URL jobs first, run them in parallel threads,
    # then assemble findings from the results. This keeps a file with
    # many URLs (e.g. google.com: 5 URLs = 10 fetches) inside Vercel's
    # 10 s Hobby function limit instead of ~20 s sequential.
    # Contact + Encryption URLs are verified TWICE (checklist v2: an
    # important "dead URL" claim needs 2 live fetches). Acknowledgments /
    # Policy / Hiring links are low-severity and verified ONCE — a single
    # live check is enough for a Low finding, and it halves total time.
    url_jobs = []
    for c in fields.get("contact", []):
        if c.startswith("http"):
            url_jobs.append(("contact", c, True))
    for enc in fields.get("encryption", []):
        if enc.startswith("http"):
            url_jobs.append(("encryption", enc, True))
    for fname in ("acknowledgments", "policy", "hiring"):
        for val in fields.get(fname, []):
            if val.startswith("http"):
                url_jobs.append((fname, val, False))
    url_status = {}
    if url_jobs:
        def _run(job):
            kind, val, twice = job
            if twice:
                return (kind, val, check_url_live_twice(val))
            ok, _st, det = check_url_live(val)
            return (kind, val, ("live", _st, det) if ok else ("dead", _st, det))
        with ThreadPoolExecutor(max_workers=5) as pool:
            for kind, val, res in pool.map(_run, url_jobs):
                url_status[(kind, val)] = res

    # --- Contact (required by RFC 9116) ---
    contacts = fields.get("contact", [])
    if not contacts:
        findings.append({
            "severity": "medium",
            "title": "Missing Contact field",
            "evidence": "security.txt has no Contact line",
            "detail": "RFC 9116 requires at least one Contact. Without it, "
                      "researchers cannot report vulnerabilities.",
        })
    else:
        for c in contacts:
            if c.startswith(("mailto:", "https://", "http://")):
                if c.startswith("http"):
                    verdict, _st, det = url_status[("contact", c)]
                    if verdict == "dead":
                        findings.append({
                            "severity": "medium",
                            "title": "Contact URL is dead",
                            "evidence": "%s (%s, verified twice)" % (c, det),
                            "detail": "The documented contact link does not "
                                      "resolve. Researchers following it hit "
                                      "a dead end.",
                        })
                    elif verdict == "flaky":
                        findings.append({
                            "severity": "low",
                            "title": "Contact URL is flaky",
                            "evidence": "%s (%s)" % (c, det),
                            "detail": "One of two live checks failed. "
                                      "Re-check before treating as dead.",
                        })
            else:
                findings.append({
                    "severity": "low",
                    "title": "Contact value is not a URI",
                    "evidence": c,
                    "detail": "Contact should be a mailto: or https: URI.",
                })

    # --- Expires ---
    expires = fields.get("expires", [])
    if not expires:
        findings.append({
            "severity": "low",
            "title": "Missing Expires field",
            "evidence": "security.txt has no Expires line",
            "detail": "Without Expires, readers cannot tell whether the "
                      "file is stale.",
        })
    else:
        dt = parse_expires(expires[0])
        if dt is None:
            findings.append({
                "severity": "low",
                "title": "Expires is not a valid RFC 3339 date-time",
                "evidence": expires[0],
                "detail": "Expires must be an RFC 3339 date-time.",
            })
        elif dt < now:
            findings.append({
                "severity": "medium",
                "title": "Expires date has passed",
                "evidence": expires[0],
                "detail": "The file is stale — the owner has not reviewed "
                          "it since %s." % expires[0],
            })

    # --- Encryption: must be a URI, not an inline key block ---
    for enc in fields.get("encryption", []):
        if enc.startswith(("https://", "http://")):
            verdict, _st, det = url_status[("encryption", enc)]
            if verdict == "dead":
                findings.append({
                    "severity": "medium",
                    "title": "Encryption key URL is dead",
                    "evidence": "%s (%s, verified twice)" % (enc, det),
                    "detail": "The documented encryption key cannot be "
                              "fetched, so researchers cannot encrypt "
                              "reports as documented.",
                })
            elif verdict == "flaky":
                findings.append({
                    "severity": "low",
                    "title": "Encryption key URL is flaky",
                    "evidence": "%s (%s)" % (enc, det),
                    "detail": "One of two live checks failed.",
                })
        elif enc.startswith("mailto:"):
            pass  # a keyserver email is acceptable; nothing to verify live
        else:
            findings.append({
                "severity": "medium",
                "title": "Encryption is an inline key block, not a URI",
                "evidence": enc[:80] + ("..." if len(enc) > 80 else ""),
                "detail": "RFC 9116 requires Encryption to be a URI "
                          "pointing at the key, not the key itself.",
            })

    # --- Other URL fields: verify once, report dead links as low ---
    for fname in ("acknowledgments", "policy", "hiring"):
        for val in fields.get(fname, []):
            if val.startswith("http"):
                verdict, _st, det = url_status[(fname, val)]
                if verdict == "dead":
                    findings.append({
                        "severity": "low",
                        "title": "%s URL is dead" % fname.capitalize(),
                        "evidence": "%s (%s)" % (val, det),
                        "detail": "Documented %s link does not resolve."
                                  % fname,
                    })

    # --- Canonical ---
    for canon in fields.get("canonical", []):
        try:
            chost = urllib.parse.urlparse(canon).hostname
        except Exception:
            chost = None
        if chost and chost.lower() != host:
            findings.append({
                "severity": "low",
                "title": "Canonical host differs from audited host",
                "evidence": canon,
                "detail": "The file's Canonical points at %s, not %s. "
                          "Check the canonical location instead."
                          % (chost, host),
            })

    if unknown:
        findings.append({
            "severity": "info",
            "title": "Unknown fields present",
            "evidence": ", ".join(sorted(set(unknown))),
            "detail": "Non-standard fields are ignored by this audit.",
        })

    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCT.get(f["severity"], 0)
    score = max(0, score)
    verdict = "pass" if score >= 90 else ("needs-attention" if score >= 60 else "fail")

    return {
        "domain": host,
        "reachable": True,
        "final_url": url,
        "fields": fields,
        "findings": findings,
        "score": score,
        "verdict": verdict,
        "checked_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# HMAC auth
# ---------------------------------------------------------------------------
def verify_signature(raw_body, headers):
    """True when auth passes. Open (no secret set) -> always True."""
    secret = os.environ.get("AGENT_SHARED_SECRET", "")
    if not secret:
        return True
    sig = headers.get("x-signature") or headers.get("X-Signature") or ""
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return bool(sig) and hmac.compare_digest(sig.lower(), expected.lower())


# ---------------------------------------------------------------------------
# HTTP layer (works both on Vercel and locally)
# ---------------------------------------------------------------------------
def handle_request(method, path, raw_body, headers):
    """Pure dispatch. Returns (status:int, payload:dict)."""
    if method == "GET" and path in ("/", "/health"):
        if path == "/":
            return 200, {
                "service": "Hextor Audit Agent",
                "version": VERSION,
                "endpoints": {
                    "GET /health": "liveness check",
                    "POST /audit": '{"domain": "example.com"}',
                },
                "note": "Read-only security.txt auditor. Never sends "
                        "reports or emails.",
            }
        return 200, {"status": "ok"}
    if method == "POST" and path == "/audit":
        if not verify_signature(raw_body, headers):
            return 401, {"error": "invalid or missing X-Signature"}
        try:
            data = json.loads(raw_body.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "body must be valid JSON"}
        domain = data.get("domain")
        if not domain:
            return 400, {"error": 'missing "domain"'}
        return 200, audit_domain(domain)
    return 404, {"error": "not found"}


class handler(BaseHTTPRequestHandler):
    """Vercel Python entry point (BaseHTTPRequestHandler subclass)."""

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        return self.rfile.read(min(length, 1 * 1024 * 1024)) if length else b""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        status, payload = handle_request("GET", path, b"", self.headers)
        self._send(status, payload)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        status, payload = handle_request("POST", path, self._read_body(),
                                         self.headers)
        self._send(status, payload)

    def log_message(self, fmt, *args):  # keep logs quiet
        pass


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("127.0.0.1", port), handler)
    print("Hextor Audit Agent v%s listening on http://127.0.0.1:%d"
          % (VERSION, port))
    print("No AGENT_SHARED_SECRET set -> demo mode (no auth)." if not
          os.environ.get("AGENT_SHARED_SECRET")
          else "HMAC auth enabled (AGENT_SHARED_SECRET set).")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
