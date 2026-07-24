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

    return jsonify({
        "slug": slug,
        "password_tested": password,
        "login_url": login_url,
        "any_success": any_success,
        "results": results,
    })


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
  <p class="subtitle">Source-code analysis · Password discovery · Burp-style proxy · Manual testing</p>

  <!-- Tabs -->
  <div class="tabs">
    <button class="tab active" onclick="switchTab('analyzer')">📊 Analyzer</button>
    <button class="tab" onclick="switchTab('proxy')">🔁 Proxy / Repeater</button>
    <button class="tab" onclick="switchTab('tester')">🔑 Password Tester</button>
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

// Load history on proxy tab open (lazy)
loadHistory();
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
║   📜 JS        — External JS secret scanning            ║
╚══════════════════════════════════════════════════════════╝
""")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
