#!/usr/bin/env python3
"""
Proxy Rotator for Pixieset Cracker
===================================
Fetches, validates, and rotates HTTP/SOCKS proxies so each gallery attempt
comes from a different IP — defeating Cloudflare IP-based rate limiting.

Proxy sources (free, checked at runtime):
- proxylist.geonode.com (API)
- proxy-list.download (API)
- openproxy.space/list (HTTP)
- proxyscrape.com (HTTP)

Usage:
    # As a standalone module
    from proxy_rotator import ProxyRotator
    rotator = ProxyRotator()
    proxy = rotator.next()       # returns dict: {"http": "http://1.2.3.4:8080"}
    rotator.mark_dead(proxy)     # remove and fetch replacement
    print(rotator.stats())       # pool size, good/dead counts

    # CLI: test proxies
    python3 proxy_rotator.py --test
    python3 proxy_rotator.py --export proxies.json
"""

import argparse
import concurrent.futures
import json
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    from curl_cffi import requests as cffi_requests
except ImportError:
    import requests as cffi_requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TEST_URL = "https://pixieset.com"
TEST_TIMEOUT = 10
MIN_POOL_SIZE = 5
MAX_POOL_SIZE = 50
FETCH_TIMEOUT = 8
PROXY_SOURCES = [
    # geonode fast API — returns working proxies with latency
    "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=80&speed=fast&protocols=http,https",
    # proxyscrape
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json&limit=50&timeout=5000",
    # webanetlabs
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    # openproxy
    "https://api.openproxy.space/lists/http?limit=50",
]

IMPERSONATE = "chrome110"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/110.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------------------------
@dataclass
class Proxy:
    url: str
    protocol: str  # "http" or "socks5"
    host: str
    port: int
    source: str = ""
    latency: float = 0.0
    fail_count: int = 0
    last_used: float = 0.0
    last_checked: float = 0.0

    @staticmethod
    def from_string(raw: str, source: str = "") -> Optional["Proxy"]:
        """Parse proxy strings like 'http://1.2.3.4:8080' or '1.2.3.4:8080'."""
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return None

        # Already has protocol
        if "://" in raw:
            parsed = urlparse(raw)
            protocol = parsed.scheme or "http"
            host = parsed.hostname
            port = parsed.port
        else:
            # Plain host:port
            parts = raw.rsplit(":", 1)
            if len(parts) != 2:
                return None
            host, port_str = parts
            port = int(port_str) if port_str.isdigit() else None
            protocol = "http"

        if not host or not port:
            return None
        return Proxy(
            url=f"{protocol}://{host}:{port}",
            protocol=protocol,
            host=host,
            port=port,
            source=source,
        )

    @property
    def dict_for_requests(self) -> dict:
        """Return the format requests/curl_cffi expects."""
        return {"http": self.url, "https": self.url}


class ProxyRotator:
    """Thread-safe rotating proxy pool with auto-fetch and validation."""

    def __init__(
        self,
        pool_size: int = 10,
        test_url: str = TEST_URL,
        timeout: int = TEST_TIMEOUT,
        proxy_file: Optional[str] = None,
    ):
        self.pool_size = pool_size
        self.test_url = test_url
        self.timeout = timeout
        self._lock = threading.Lock()
        self._pool: list[Proxy] = []
        self._index = 0
        self._dead_count = 0
        self._total_fetched = 0
        self._session = cffi_requests.Session()
        self._session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        })

        # Load pre-saved proxies if available
        if proxy_file and Path(proxy_file).exists():
            self._load_from_file(proxy_file)

    # ------------------------------------------------------------------
    # Fetching
    # ------------------------------------------------------------------
    def fetch_proxies(self, count: int = 30) -> list[Proxy]:
        """Fetch fresh proxies from all sources. Returns list of validated proxies."""
        raw_proxies: dict[str, Proxy] = {}  # dedup by host:port

        for source_url in PROXY_SOURCES:
            try:
                resp = self._session.get(
                    source_url, timeout=FETCH_TIMEOUT,
                    impersonate=IMPERSONATE,
                )
            except Exception:
                continue

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                # Plain text format (one proxy per line)
                data = None

            if data:
                self._parse_json_source(data, raw_proxies, source_url)
            else:
                self._parse_text_source(resp.text, raw_proxies, source_url)

        proxies = list(raw_proxies.values())
        self._total_fetched += len(proxies)
        return proxies

    def _parse_json_source(self, data, out: dict, source: str):
        """Parse various JSON proxy API formats."""
        # geonode format: {"data": [{...}]}
        if isinstance(data, dict):
            items = data.get("data", data.get("proxies", data.get("list", [])))
        elif isinstance(data, list):
            items = data
        else:
            return

        for item in items:
            if isinstance(item, dict):
                ip = item.get("ip", item.get("host", ""))
                port = item.get("port", "")
                proto = item.get("protocols", item.get("protocol", "http"))
                if isinstance(proto, list):
                    proto = proto[0] if proto else "http"
                proto = str(proto).lower().replace("socks4", "socks5")
                if ip and port:
                    raw = f"{proto}://{ip}:{port}"
            elif isinstance(item, str):
                raw = item
            else:
                continue
            p = Proxy.from_string(raw, source)
            if p and f"{p.host}:{p.port}" not in out:
                out[f"{p.host}:{p.port}"] = p

    def _parse_text_source(self, text: str, out: dict, source: str):
        """Parse plain-text proxy lists (one per line)."""
        for line in text.splitlines():
            p = Proxy.from_string(line.strip(), source)
            if p and f"{p.host}:{p.port}" not in out:
                out[f"{p.host}:{p.port}"] = p

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate_proxy(self, proxy: Proxy) -> bool:
        """Test a proxy against the target URL. Returns True if working."""
        try:
            start = time.time()
            resp = self._session.get(
                self.test_url,
                proxies=proxy.dict_for_requests,
                timeout=self.timeout,
                impersonate=IMPERSONATE,
            )
            proxy.latency = time.time() - start
            proxy.last_checked = time.time()
            # 200 or any non-proxy-error status is considered working
            return resp.status_code < 500
        except Exception:
            return False

    def validate_all(self, proxies: list[Proxy], workers: int = 10) -> list[Proxy]:
        """Validate a batch of proxies with concurrent checks."""
        good = []

        def _check(p):
            if self.validate_proxy(p):
                return p
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_check, p): p for p in proxies}
            for f in concurrent.futures.as_completed(futures):
                result = f.result()
                if result:
                    good.append(result)

        return good

    # ------------------------------------------------------------------
    # Pool management
    # ------------------------------------------------------------------
    def fill_pool(self, min_count: int = None):
        """Ensure the pool has at least min_count valid proxies."""
        if min_count is None:
            min_count = self.pool_size

        with self._lock:
            current = len(self._pool)
            if current >= min_count:
                return

            needed = min_count - current
            print(f"  [proxy] Pool has {current}, need {needed} more — fetching...")

        fresh = self.fetch_proxies(max(needed * 3, 20))
        good = self.validate_all(fresh)

        with self._lock:
            added = 0
            existing = {(p.host, p.port) for p in self._pool}
            for p in good:
                if (p.host, p.port) not in existing:
                    self._pool.append(p)
                    existing.add((p.host, p.port))
                    added += 1
                    if added >= needed:
                        break

        print(f"  [proxy] Added {added} valid proxies (pool: {len(self._pool)})")

    def next(self) -> Optional[Proxy]:
        """Return the next proxy in rotation. Auto-fills pool if empty."""
        with self._lock:
            if not self._pool:
                pass  # will fill below

        if len(self._pool) < MIN_POOL_SIZE:
            self.fill_pool(MIN_POOL_SIZE)

        with self._lock:
            if not self._pool:
                return None
            # Round-robin with shuffle
            self._index = (self._index + 1) % len(self._pool)
            p = self._pool[self._index]
            p.last_used = time.time()
            return p

    def get_dict(self) -> Optional[dict]:
        """Return proxy dict for requests library (or None if no proxy needed)."""
        p = self.next()
        return p.dict_for_requests if p else None

    def mark_dead(self, proxy: Proxy):
        """Remove a non-working proxy from the pool."""
        with self._lock:
            self._dead_count += 1
            try:
                self._pool.remove(proxy)
            except ValueError:
                pass

    def stats(self) -> dict:
        """Current pool statistics."""
        with self._lock:
            return {
                "pool_size": len(self._pool),
                "total_fetched": self._total_fetched,
                "dead_proxies": self._dead_count,
                "proxies": [
                    {"url": p.url, "latency": round(p.latency, 3),
                     "fail_count": p.fail_count, "last_used": p.last_used}
                    for p in self._pool[:10]
                ],
            }

    def _load_from_file(self, path: str):
        """Load proxies from a JSON file."""
        with open(path) as f:
            data = json.load(f)
        for item in data:
            p = Proxy.from_string(item.get("url", ""), item.get("source", "file"))
            if p:
                self._pool.append(p)
        print(f"  [proxy] Loaded {len(self._pool)} proxies from {path}")

    def save_to_file(self, path: str):
        """Export current pool to a JSON file for later reuse."""
        with self._lock:
            data = [{"url": p.url, "source": p.source, "protocol": p.protocol}
                    for p in self._pool]
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  [proxy] Saved {len(data)} proxies to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Proxy Rotator — test and export")
    p.add_argument("--test", action="store_true", help="Fetch and validate proxies, print results")
    p.add_argument("--export", type=str, help="Export working proxies to JSON file")
    p.add_argument("--pool-size", type=int, default=10, help="Target pool size")
    args = p.parse_args()

    rotator = ProxyRotator(pool_size=args.pool_size)
    rotator.fill_pool(args.pool_size)

    stats = rotator.stats()
    print(json.dumps(stats, indent=2))

    if args.export:
        rotator.save_to_file(args.export)

    if args.test:
        print("\nTesting proxies...")
        for proxy_url in stats["proxies"]:
            p = rotator._pool[0]
            ok = rotator.validate_proxy(p) if rotator._pool else False
            status = "✓" if ok else "✗"
            print(f"  {status} {proxy_url['url']} (latency: {proxy_url['latency']}s)")


if __name__ == "__main__":
    main()
