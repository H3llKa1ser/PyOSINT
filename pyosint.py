#!/usr/bin/env python3
"""
PyOSINT - A Modular OSINT Framework (Extended Edition)
=======================================================
An extensible framework for Open Source Intelligence gathering.

Features:
  - Plugin-based module architecture
  - Async concurrent collection
  - Rate limiting & retry logic
  - Multiple output formats (JSON, CSV, console)
  - Caching to avoid redundant requests
  - Structured logging
  - Proxy / Tor rotation support
  - Modules: username enum, domain recon, IP geo, breach check,
             Shodan, Wayback Machine archive discovery

DISCLAIMER: Use only on targets you are authorized to investigate.
Respect terms of service, robots.txt, and applicable laws (GDPR, CFAA, etc.).
"""

import asyncio
import json
import csv
import logging
import os
import re
import hashlib
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import aiohttp  # pip install aiohttp
# Optional Tor/SOCKS support: pip install aiohttp_socks
try:
    from aiohttp_socks import ProxyConnector
    _SOCKS_AVAILABLE = True
except ImportError:
    _SOCKS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pyosint")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
class TargetType(str, Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    NAME = "name"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single piece of intelligence discovered by a module."""
    source: str                          # module that produced it
    category: str                        # e.g. "social_profile", "dns_record"
    value: str                           # the data itself
    confidence: float = 0.5              # 0.0 - 1.0
    url: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class Target:
    """The subject of an investigation."""
    raw: str
    ttype: TargetType = TargetType.UNKNOWN

    def __post_init__(self):
        if self.ttype == TargetType.UNKNOWN:
            self.ttype = self._classify(self.raw)

    @staticmethod
    def _classify(value: str) -> TargetType:
        value = value.strip()
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            return TargetType.EMAIL
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", value):
            return TargetType.IP
        if re.fullmatch(r"\+?\d[\d\s\-()]{6,}", value):
            return TargetType.PHONE
        if re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", value):
            return TargetType.DOMAIN
        if re.fullmatch(r"[a-zA-Z0-9_.\-]{2,30}", value):
            return TargetType.USERNAME
        return TargetType.NAME


# ---------------------------------------------------------------------------
# HTTP Client (with caching, rate-limiting, retries, proxy/Tor)
# ---------------------------------------------------------------------------
class HttpClient:
    # A small pool of realistic UAs to rotate through
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    def __init__(
        self,
        rate_limit: float = 1.0,           # seconds between requests
        max_retries: int = 3,
        timeout: int = 15,
        cache_dir: str = ".osint_cache",
        use_cache: bool = True,
        proxy: Optional[str] = None,       # e.g. "http://127.0.0.1:8080"
        tor: bool = False,                 # route via socks5://127.0.0.1:9050
        rotate_ua: bool = True,
    ):
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.use_cache = use_cache
        self.rotate_ua = rotate_ua
        self.proxy = proxy
        self.tor = tor
        self._last_request = 0.0
        self._lock = asyncio.Lock()
        self._session: Optional[aiohttp.ClientSession] = None
        self.cache_dir = Path(cache_dir)
        if self.use_cache:
            self.cache_dir.mkdir(exist_ok=True)

    def _build_connector(self):
        if self.tor:
            if not _SOCKS_AVAILABLE:
                raise RuntimeError(
                    "Tor requested but aiohttp_socks not installed. "
                    "Run: pip install aiohttp_socks"
                )
            log.info("routing traffic through Tor (socks5://127.0.0.1:9050)")
            return ProxyConnector.from_url("socks5://127.0.0.1:9050")
        return aiohttp.TCPConnector(ssl=False)

    def _ua(self) -> str:
        if self.rotate_ua:
            return random.choice(self.USER_AGENTS)
        return self.USER_AGENTS[0]

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            connector=self._build_connector(),
            timeout=self.timeout,
        )
        return self

    async def __aexit__(self, *exc):
        if self._session:
            await self._session.close()

    def _cache_path(self, url: str) -> Path:
        key = hashlib.sha256(url.encode()).hexdigest()[:32]
        return self.cache_dir / f"{key}.cache"

    async def _throttle(self):
        async with self._lock:
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
            self._last_request = time.monotonic()

    async def get(
        self, url: str, use_cache: Optional[bool] = None, headers: Optional[dict] = None, **kwargs
    ) -> Optional[tuple[int, str]]:
        """Returns (status_code, body) or None on failure."""
        cache_enabled = self.use_cache if use_cache is None else use_cache
        cache_file = self._cache_path(url) if cache_enabled else None

        if cache_enabled and cache_file.exists():
            log.debug("cache hit: %s", url)
            data = json.loads(cache_file.read_text())
            return data["status"], data["body"]

        req_headers = {"User-Agent": self._ua()}
        if headers:
            req_headers.update(headers)

        proxy = self.proxy if (self.proxy and not self.tor) else None

        for attempt in range(1, self.max_retries + 1):
            await self._throttle()
            try:
                async with self._session.get(
                    url, headers=req_headers, proxy=proxy, **kwargs
                ) as resp:
                    body = await resp.text()
                    if cache_enabled:
                        cache_file.write_text(
                            json.dumps({"status": resp.status, "body": body})
                        )
                    return resp.status, body
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                wait = 2 ** attempt
                log.warning("attempt %d failed for %s (%s), retry in %ds",
                            attempt, url, e, wait)
                await asyncio.sleep(wait)
        log.error("giving up on %s", url)
        return None


# ---------------------------------------------------------------------------
# Module Base Class
# ---------------------------------------------------------------------------
class OSINTModule(ABC):
    name: str = "base"
    description: str = ""
    supported_types: set[TargetType] = set()

    def supports(self, target: Target) -> bool:
        return target.ttype in self.supported_types

    @abstractmethod
    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        ...


# ---------------------------------------------------------------------------
# Module: Username Enumeration
# ---------------------------------------------------------------------------
class UsernameEnumModule(OSINTModule):
    """Checks for a username's presence on popular platforms."""
    name = "username_enum"
    description = "Enumerate username across social platforms"
    supported_types = {TargetType.USERNAME, TargetType.EMAIL}

    # url template + a substring that, if present, indicates "NOT found"
    PLATFORMS = {
        "GitHub":    ("https://github.com/{u}", "Not Found"),
        "Reddit":    ("https://www.reddit.com/user/{u}/about.json", "error"),
        "Instagram": ("https://www.instagram.com/{u}/", "Page Not Found"),
        "Telegram":  ("https://t.me/{u}", "tgme_page_title"),
        "Medium":    ("https://medium.com/@{u}", "PAGE NOT FOUND"),
        "GitLab":    ("https://gitlab.com/{u}", "not found"),
        "Keybase":   ("https://keybase.io/{u}", "not found"),
    }

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        username = target.raw.split("@")[0]
        findings: list[Finding] = []

        async def check(platform: str, tmpl: str, neg_marker: str):
            url = tmpl.format(u=username)
            result = await http.get(url)
            if not result:
                return
            status, body = result
            if status == 200 and neg_marker.lower() not in body.lower():
                findings.append(Finding(
                    source=self.name,
                    category="social_profile",
                    value=f"{platform}: {username}",
                    confidence=0.75,
                    url=url,
                    metadata={"platform": platform, "http_status": status},
                ))

        await asyncio.gather(
            *(check(p, t, m) for p, (t, m) in self.PLATFORMS.items())
        )
        return findings


# ---------------------------------------------------------------------------
# Module: Domain Recon
# ---------------------------------------------------------------------------
class DomainReconModule(OSINTModule):
    """Basic domain intelligence using public APIs."""
    name = "domain_recon"
    description = "DNS, subdomain and certificate transparency lookups"
    supported_types = {TargetType.DOMAIN}

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        domain = target.raw.lower()
        findings: list[Finding] = []

        # Certificate Transparency logs (crt.sh) - reveals subdomains
        ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        result = await http.get(ct_url)
        if result and result[0] == 200:
            try:
                entries = json.loads(result[1])
                subdomains = {
                    name.lstrip("*.").lower()
                    for e in entries
                    for name in e.get("name_value", "").split("\n")
                }
                for sub in sorted(subdomains):
                    findings.append(Finding(
                        source=self.name,
                        category="subdomain",
                        value=sub,
                        confidence=0.8,
                        url=ct_url,
                    ))
            except json.JSONDecodeError:
                log.warning("crt.sh returned non-JSON for %s", domain)

        # DNS-over-HTTPS lookups (Cloudflare) for several record types
        for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
            doh_url = (
                f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
            )
            dns_result = await http.get(
                doh_url, headers={"accept": "application/dns-json"},
            )
            if dns_result and dns_result[0] == 200:
                try:
                    data = json.loads(dns_result[1])
                    for ans in data.get("Answer", []):
                        findings.append(Finding(
                            source=self.name,
                            category="dns_record",
                            value=ans.get("data", ""),
                            confidence=0.95,
                            metadata={"type": rtype, "ttl": ans.get("TTL")},
                        ))
                except json.JSONDecodeError:
                    pass

        return findings


# ---------------------------------------------------------------------------
# Module: IP Geolocation
# ---------------------------------------------------------------------------
class IPGeoModule(OSINTModule):
    """Geolocation and ASN info for an IP address."""
    name = "ip_geo"
    description = "IP geolocation and network ownership"
    supported_types = {TargetType.IP}

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        ip = target.raw
        findings: list[Finding] = []
        url = f"https://ipapi.co/{ip}/json/"
        result = await http.get(url)
        if result and result[0] == 200:
            try:
                data = json.loads(result[1])
                for key in ("city", "region", "country_name", "org", "asn"):
                    if data.get(key):
                        findings.append(Finding(
                            source=self.name,
                            category="geolocation",
                            value=f"{key}: {data[key]}",
                            confidence=0.7,
                            url=url,
                            metadata={"field": key},
                        ))
            except json.JSONDecodeError:
                pass
        return findings


# ---------------------------------------------------------------------------
# Module: Breach Check  (NEW)
# ---------------------------------------------------------------------------
class BreachCheckModule(OSINTModule):
    """Check if an email appears in known data breaches (requires API key)."""
    name = "breach_check"
    description = "Query a breach-data API for an email address"
    supported_types = {TargetType.EMAIL}

    def __init__(self, api_key: Optional[str] = None):
        # Pulls from env var if not passed explicitly
        self.api_key = api_key or os.getenv("HIBP_API_KEY")

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        if not self.api_key:
            log.warning("%s skipped: no API key (set HIBP_API_KEY)", self.name)
            return findings

        # Example uses the Have I Been Pwned v3 API shape
        url = (
            "https://haveibeenpwned.com/api/v3/breachedaccount/"
            f"{target.raw}?truncateResponse=false"
        )
        # Breach data should never be cached to disk for privacy reasons
        result = await http.get(
            url, use_cache=False,
            headers={"hibp-api-key": self.api_key},
        )
        if not result:
            return findings

        status, body = result
        if status == 404:
            findings.append(Finding(
                source=self.name,
                category="data_breach",
                value="No known breaches found",
                confidence=0.9,
            ))
        elif status == 200:
            try:
                for breach in json.loads(body):
                    findings.append(Finding(
                        source=self.name,
                        category="data_breach",
                        value=breach.get("Name", "unknown"),
                        confidence=0.9,
                        url="https://haveibeenpwned.com/",
                        metadata={
                            "domain": breach.get("Domain"),
                            "breach_date": breach.get("BreachDate"),
                            "pwn_count": breach.get("PwnCount"),
                            "data_classes": breach.get("DataClasses", []),
                        },
                    ))
            except json.JSONDecodeError:
                log.warning("breach API returned non-JSON")
        elif status == 401:
            log.error("breach API: invalid API key")
        elif status == 429:
            log.warning("breach API: rate limited")
        return findings


# ---------------------------------------------------------------------------
# Module: Shodan  (NEW)
# ---------------------------------------------------------------------------
class ShodanModule(OSINTModule):
    """Pull host intelligence from Shodan (open ports, services, vulns)."""
    name = "shodan"
    description = "Shodan host lookup for IPs and domains"
    supported_types = {TargetType.IP, TargetType.DOMAIN}

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")

    async def _resolve_domain(self, domain: str, http: HttpClient) -> Optional[str]:
        """Resolve a domain to an IP via Shodan DNS endpoint."""
        url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={self.api_key}"
        result = await http.get(url, use_cache=False)
        if result and result[0] == 200:
            try:
                return json.loads(result[1]).get(domain)
            except json.JSONDecodeError:
                return None
        return None

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        if not self.api_key:
            log.warning("%s skipped: no API key (set SHODAN_API_KEY)", self.name)
            return findings

        # Determine the IP to query
        if target.ttype == TargetType.DOMAIN:
            ip = await self._resolve_domain(target.raw, http)
            if not ip:
                log.warning("shodan: could not resolve %s", target.raw)
                return findings
        else:
            ip = target.raw

        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}"
        result = await http.get(url, use_cache=False)
        if not result or result[0] != 200:
            if result and result[0] == 404:
                log.info("shodan: no information available for %s", ip)
            return findings

        try:
            data = json.loads(result[1])
        except json.JSONDecodeError:
            return findings

        # Open ports
        for port in data.get("ports", []):
            findings.append(Finding(
                source=self.name,
                category="open_port",
                value=f"{ip}:{port}",
                confidence=0.95,
                url=f"https://www.shodan.io/host/{ip}",
                metadata={"port": port},
            ))

        # Detected vulnerabilities (CVEs)
        for cve in data.get("vulns", []):
            findings.append(Finding(
                source=self.name,
                category="vulnerability",
                value=cve,
                confidence=0.85,
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                metadata={"host": ip},
            ))

        # Organisation / hostnames / OS
        for key, cat in (("org", "network_owner"),
                         ("os", "operating_system"),
                         ("isp", "isp")):
            if data.get(key):
                findings.append(Finding(
                    source=self.name,
                    category=cat,
                    value=f"{key}: {data[key]}",
                    confidence=0.8,
                    url=f"https://www.shodan.io/host/{ip}",
                ))

        for hostname in data.get("hostnames", []):
            findings.append(Finding(
                source=self.name,
                category="hostname",
                value=hostname,
                confidence=0.9,
                metadata={"ip": ip},
            ))

        return findings


# ---------------------------------------------------------------------------
# Module: Wayback Machine  (NEW)
# ---------------------------------------------------------------------------
class WaybackModule(OSINTModule):
    """Discover historical/archived URLs for a domain via the Wayback Machine."""
    name = "wayback"
    description = "Find archived snapshots and historical URLs"
    supported_types = {TargetType.DOMAIN}

    def __init__(self, limit: int = 50):
        self.limit = limit

    async def run(self, target: Target, http: HttpClient) -> list[Finding]:
        domain = target.raw.lower()
        findings: list[Finding] = []

        # CDX API: list unique archived URLs for the domain
        cdx_url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original,timestamp,statuscode"
            f"&collapse=urlkey&limit={self.limit}"
        )
        result = await http.get(cdx_url)
        if result and result[0] == 200:
            try:
                rows = json.loads(result[1])
                # First row is the header
                for row in rows[1:]:
                    original, timestamp = row[0], row[1]
                    status = row[2] if len(row) > 2 else "?"
                    snapshot = f"https://web.archive.org/web/{timestamp}/{original}"
                    findings.append(Finding(
                        source=self.name,
                        category="archived_url",
                        value=original,
                        confidence=0.7,
                        url=snapshot,
                        metadata={"timestamp": timestamp, "status": status},
                    ))
            except (json.JSONDecodeError, IndexError):
                log.warning("wayback: unexpected response for %s", domain)
        return findings


# ---------------------------------------------------------------------------
# Engine / Orchestrator
# ---------------------------------------------------------------------------
class OSINTEngine:
    """Coordinates modules against a target and aggregates findings."""

    def __init__(self, http: Optional[HttpClient] = None):
        self.modules: list[OSINTModule] = []
        self.http = http or HttpClient()

    def register(self, module: OSINTModule) -> "OSINTEngine":
        self.modules.append(module)
        log.info("registered module: %s", module.name)
        return self

    def register_all(self, *modules: OSINTModule) -> "OSINTEngine":
        for m in modules:
            self.register(m)
        return self

    async def investigate(self, target: Target) -> list[Finding]:
        applicable = [m for m in self.modules if m.supports(target)]
        log.info(
            "investigating %s (%s) with %d module(s)",
            target.raw, target.ttype.value, len(applicable),
        )
        if not applicable:
            log.warning("no modules support target type %s", target.ttype.value)
            return []

        async with self.http as http:
            results = await asyncio.gather(
                *(self._safe_run(m, target, http) for m in applicable),
                return_exceptions=True,
            )

        findings: list[Finding] = []
        for module, res in zip(applicable, results):
            if isinstance(res, Exception):
                log.error("module %s crashed: %s", module.name, res)
            else:
                findings.extend(res)
        log.info("collected %d finding(s)", len(findings))
        return findings

    @staticmethod
    async def _safe_run(module, target, http) -> list[Finding]:
        try:
            return await module.run(target, http)
        except Exception as e:                       # noqa: BLE001
            log.exception("error in %s", module.name)
            raise e


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
class Reporter:
    """Render findings in various output formats."""

    @staticmethod
    def to_console(target: Target, findings: list[Finding]) -> None:
        print("\n" + "=" * 64)
        print(f"  OSINT REPORT  ::  {target.raw}  ({target.ttype.value})")
        print(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
        print("=" * 64)

        if not findings:
            print("  No findings.")
            return

        by_cat: dict[str, list[Finding]] = {}
        for f in findings:
            by_cat.setdefault(f.category, []).append(f)

        for category, items in sorted(by_cat.items()):
            print(f"\n  [{category.upper()}]  ({len(items)})")
            print("  " + "-" * 60)
            for f in sorted(items, key=lambda x: -x.confidence):
                bar = "#" * int(f.confidence * 10)
                print(f"   • {f.value}")
                print(f"     source={f.source}  confidence={f.confidence:.2f} [{bar:<10}]")
                if f.url:
                    print(f"     {f.url}")
        print("\n" + "=" * 64 + "\n")

    @staticmethod
    def to_json(target: Target, findings: list[Finding], path: str) -> None:
        payload = {
            "target": asdict(target),
            "generated": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "findings": [asdict(f) for f in findings],
        }
        Path(path).write_text(json.dumps(payload, indent=2))
        log.info("wrote JSON report -> %s", path)

    @staticmethod
    def to_csv(findings: list[Finding], path: str) -> None:
        if not findings:
            log.warning("no findings to write to CSV")
            return
        fieldnames = ["source", "category", "value", "confidence", "url", "timestamp"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for f in findings:
                writer.writerow(asdict(f))
        log.info("wrote CSV report -> %s", path)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
async def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="PyOSINT - modular OSINT collection framework (Extended)",
        epilog="Authorized use only. Respect laws and terms of service.",
    )
    parser.add_argument("target", help="email / username / domain / IP / phone")
    parser.add_argument("-t", "--type",
                        choices=[t.value for t in TargetType],
                        help="force target type (auto-detected by default)")
    parser.add_argument("-o", "--output",
                        help="output file prefix (writes .json + .csv)")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="seconds between HTTP requests (default 1.0)")
    parser.add_argument("--no-cache", action="store_true",
                        help="disable response caching")

    # Proxy / anonymity
    parser.add_argument("--proxy",
                        help="HTTP proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--tor", action="store_true",
                        help="route traffic through Tor (socks5://127.0.0.1:9050)")
    parser.add_argument("--no-rotate-ua", action="store_true",
                        help="disable User-Agent rotation")

    # API keys (fall back to env vars if omitted)
    parser.add_argument("--hibp-key", help="Have I Been Pwned API key")
    parser.add_argument("--shodan-key", help="Shodan API key")

    parser.add_argument("-v", "--verbose", action="store_true",
                        help="debug logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Build target
    ttype = TargetType(args.type) if args.type else TargetType.UNKNOWN
    target = Target(raw=args.target, ttype=ttype)

    # Build HTTP client
    http = HttpClient(
        rate_limit=args.rate,
        use_cache=not args.no_cache,
        proxy=args.proxy,
        tor=args.tor,
        rotate_ua=not args.no_rotate_ua,
    )

    # Build engine & register all modules
    engine = OSINTEngine(http=http)
    engine.register_all(
        UsernameEnumModule(),
        DomainReconModule(),
        IPGeoModule(),
        BreachCheckModule(api_key=args.hibp_key),
        ShodanModule(api_key=args.shodan_key),
        WaybackModule(limit=50),
        # add your own modules here...
    )

    # Run investigation
    findings = await engine.investigate(target)

    # Report
    Reporter.to_console(target, findings)
    if args.output:
        Reporter.to_json(target, findings, f"{args.output}.json")
        Reporter.to_csv(findings, f"{args.output}.csv")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
