#!/usr/bin/env python3
"""
DNSUnlock
---------
Python-only DNS forwarder with category-based IP override and an Apple-style
web UI. Domain规则直接读取本地 blackmatrix7/ios_rule_script，不在面板显示。
针对分类选择一个 IP，所有匹配域名直接解析到该 IP（不再转发到上游 DNS）。
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from typing import Optional, Tuple
from string import Template
from pathlib import Path
import ipaddress
import urllib.request
import shutil
import subprocess


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# Default configuration. Users can override ports and IP pools in config.json.
DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "web_host": "0.0.0.0",
    "dns_port": 5353,
    "web_port": 8080,
    "timeout_ms": 2000,
    "token": "changeme",
    "upstream_dns": "8.8.8.8",
    "upstream_dns_pool": ["1.1.1.1", "8.8.8.8"],
    "ip_pool": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "active_service": {
        "streaming": {"_default": "1.1.1.1"},
        "ai": {"_default": "1.1.1.1"},
        "major": {"_default": "1.1.1.1"},
        "default": {"_default": "8.8.8.8"},
    },
    # Local cache dir for downloaded rule files
    "rules_root": "rules_cache",
    # Remote rule sources; fetched on refresh to the cache dir.
    "rule_sources": [
        {"cat": "streaming", "svc": "youtube", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.list"},
        {"cat": "streaming", "svc": "netflix", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.list"},
        {"cat": "streaming", "svc": "disney", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.list"},
        {"cat": "streaming", "svc": "hbo", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/HBO/HBO.list"},
        {"cat": "streaming", "svc": "primevideo", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/PrimeVideo/PrimeVideo.list"},
        {"cat": "streaming", "svc": "bilibili", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Bilibili/Bilibili.list"},
        {"cat": "streaming", "svc": "appletv", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/AppleTV/AppleTV.list"},
        {"cat": "streaming", "svc": "hulu", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hulu/Hulu.list"},
        {"cat": "streaming", "svc": "paramount", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ParamountPlus/ParamountPlus.list"},
        {"cat": "streaming", "svc": "peacock", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Peacock/Peacock.list"},
        {"cat": "streaming", "svc": "spotify", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.list"},
        {"cat": "streaming", "svc": "tiktok", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.list"},
        {"cat": "streaming", "svc": "iqiyi", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/iQIYI/iQIYI.list"},
        {"cat": "ai", "svc": "openai", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.list"},
        {"cat": "ai", "svc": "gemini", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Bard/Bard.list"},
        {"cat": "ai", "svc": "claude", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.list"},
        {"cat": "ai", "svc": "copilot", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Copilot/Copilot.list"},
        {"cat": "ai", "svc": "perplexity", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Perplexity/Perplexity.list"},
        {"cat": "ai", "svc": "grok", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/XAI/XAI.list"},
        {"cat": "ai", "svc": "midjourney", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/MidJourney/MidJourney.list"},
        {"cat": "ai", "svc": "runway", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Runway/Runway.list"},
        {"cat": "ai", "svc": "stability", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/StableDiffusion/StableDiffusion.list"},
        {"cat": "major", "svc": "google", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.list"},
        {"cat": "major", "svc": "microsoft", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Microsoft/Microsoft.list"},
        {"cat": "major", "svc": "apple", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Apple/Apple.list"},
        {"cat": "major", "svc": "cloudflare", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Cloudflare/Cloudflare.list"},
        {"cat": "major", "svc": "amazon", "url": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Amazon/Amazon.list"}
    ],
}

SERVICE_CATALOG = {
    "ai": [
        {"slug": "openai", "name": "ChatGPT / OpenAI", "keywords": ["openai", "chatgpt", "gpt", "ai.com", "api.openai", "oai"]},
        {"slug": "gemini", "name": "Gemini / Bard", "keywords": ["gemini", "bard", "googleai", "palm"]},
        {"slug": "claude", "name": "Claude / Anthropic", "keywords": ["claude", "anthropic"]},
        {"slug": "copilot", "name": "Copilot", "keywords": ["copilot", "githubcopilot", "bingai"]},
        {"slug": "perplexity", "name": "Perplexity", "keywords": ["perplexity", "pplx"]},
        {"slug": "grok", "name": "Grok / xAI", "keywords": ["grok", "xai", "x-ai"]},
        {"slug": "midjourney", "name": "Midjourney", "keywords": ["midjourney"]},
        {"slug": "runway", "name": "Runway", "keywords": ["runwayml", "runway"]},
        {"slug": "stability", "name": "Stability / SD", "keywords": ["stability", "stablediffusion", "sd"]},
    ],
    "streaming": [
        {"slug": "youtube", "name": "YouTube", "keywords": ["youtube", "yt"]},
        {"slug": "netflix", "name": "Netflix", "keywords": ["netflix", "nflx"]},
        {"slug": "disney", "name": "Disney+", "keywords": ["disneyplus", "disney"]},
        {"slug": "hbo", "name": "HBO / Max", "keywords": ["hbo", "hbomax", "max"]},
        {"slug": "primevideo", "name": "Prime Video", "keywords": ["primevideo", "prime-video"]},
        {"slug": "appletv", "name": "Apple TV+", "keywords": ["appletv", "appletvplus", "apple-tv"]},
        {"slug": "hulu", "name": "Hulu", "keywords": ["hulu"]},
        {"slug": "paramount", "name": "Paramount+", "keywords": ["paramount"]},
        {"slug": "peacock", "name": "Peacock", "keywords": ["peacock"]},
        {"slug": "spotify", "name": "Spotify", "keywords": ["spotify"]},
        {"slug": "tiktok", "name": "TikTok", "keywords": ["tiktok", "douyin"]},
        {"slug": "bilibili", "name": "Bilibili", "keywords": ["bilibili"]},
        {"slug": "iqiyi", "name": "iQIYI", "keywords": ["iqiyi"]},
    ],
    "major": [
        {"slug": "google", "name": "Google", "keywords": ["google"]},
        {"slug": "microsoft", "name": "Microsoft / Bing / Office", "keywords": ["microsoft", "bing", "office", "live", "outlook"]},
        {"slug": "apple", "name": "Apple / iCloud", "keywords": ["apple", "icloud", "appleid"]},
        {"slug": "cloudflare", "name": "Cloudflare", "keywords": ["cloudflare"]},
        {"slug": "amazon", "name": "Amazon / AWS", "keywords": ["amazon", "aws"]},
    ],
}

# ---------- Rule loading (from ios_rule_script) ----------
def extract_domain(line: str) -> Optional[str]:
    """Parse a Clash/Surge rule line to a bare domain."""
    line = line.strip()
    if not line or line.startswith(("#", "//", ";")):
        return None
    if "," in line:
        _, rhs = line.split(",", 1)
        return rhs.strip().lower()
    return line.lower()


def guess_category(path_lower: str) -> str:
    """Heuristic to map ios_rule_script file name to a category."""
    s = path_lower
    for cat, services in SERVICE_CATALOG.items():
        for svc in services:
            if any(kw in s for kw in svc["keywords"]):
                return cat
    # fallback到默认分类
    return "default"


def guess_service(path_lower: str, category: str) -> str:
    """Return service slug within category based on filename/path."""
    for svc in SERVICE_CATALOG.get(category, []):
        if any(kw in path_lower for kw in svc["keywords"]):
            return svc["slug"]
    return "misc"


def fetch_and_cache_rules(root: str, sources: list):
    """Download rule files from remote sources into cache directory."""
    os.makedirs(root, exist_ok=True)
    downloaded = set()
    for src in sources:
        url = src.get("url")
        cat = src.get("cat")
        svc = src.get("svc", "misc")
        if not url or not cat:
            continue
        filename = f"{cat}__{svc}.list"
        dest = os.path.join(root, filename)
        try:
            with urllib.request.urlopen(url, timeout=10) as r, open(dest, "wb") as f:
                shutil.copyfileobj(r, f)
            downloaded.add(filename)
        except Exception:
            # keep old cache if download fails
            continue
    # Ensure every service has a local file; generate fallback with keywords
    for cat, services in SERVICE_CATALOG.items():
        for svc in services:
            slug = svc["slug"]
            filename = f"{cat}__{slug}.list"
            dest = os.path.join(root, filename)
            if filename in downloaded or os.path.exists(dest):
                continue
            try:
                with open(dest, "w", encoding="utf-8") as f:
                    for kw in svc.get("keywords", []):
                        f.write(f"DOMAIN-SUFFIX,{kw}\n")
                downloaded.add(filename)
            except Exception:
                continue


def load_rules_from_repo(root: str):
    """Walk rules_root and build:
    - rules: category -> service -> sorted domain list
    - domain_map: domain -> (category, service)
    """
    rules = {cat: {} for cat in SERVICE_CATALOG.keys()}
    domain_map = {}
    if not os.path.isdir(root):
        return rules, domain_map
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if not fname.endswith(".list"):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root).lower()
            cat = guess_category(rel)
            svc = guess_service(rel, cat)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        dom = extract_domain(line)
                        if dom:
                            rules.setdefault(cat, {}).setdefault(svc, set()).add(dom)
                            domain_map[dom] = (cat, svc)
            except Exception:
                continue
    # ensure deterministic ordering
    rules_sorted = {}
    for cat, svc_dict in rules.items():
        rules_sorted[cat] = {svc: sorted(list(domains)) for svc, domains in svc_dict.items()}
    return rules_sorted, domain_map

def fetch_ip_meta(ip: str, timeout: float = 6.0) -> dict:
    """Use curl with --resolve to query ifconfig.co/json via the target IP.
    Returns dict: {ok: bool, ip: str, country_iso: str|None, asn_org: str|None, real_ip: str|None}
    """
    if not is_valid_ip(ip):
        return {"ok": False, "ip": ip}
    cmd = [
        "curl",
        "--resolve", f"ifconfig.co:80:{ip}",
        "-m", str(int(timeout)),
        "--connect-timeout", "3",
        "-s",
        "http://ifconfig.co/json",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout+1)
        data = json.loads(out.decode("utf-8", errors="ignore"))
        return {
            "ok": True,
            "ip": ip,
            "real_ip": data.get("ip"),
            "country_iso": data.get("country_iso"),
            "asn_org": data.get("asn_org"),
        }
    except Exception:
        return {"ok": False, "ip": ip}


# ---------- Config management ----------
def ensure_config():
    """Load config or create default, and migrate old schema if needed."""
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # Migrate legacy upstreams/rules to new schema (category-level active -> per-service).
    if "active_service" not in cfg:
        ups = cfg.get("active") or cfg.get("upstreams") or {}
        pool = cfg.get("ip_pool") or list(dict.fromkeys(ups.values())) or DEFAULT_CONFIG["ip_pool"]
        def pick(key, idx=0):
            if isinstance(ups, dict) and key in ups:
                return ups[key]
            return pool[min(idx, len(pool)-1)]
        cfg["ip_pool"] = pool
        cfg["active_service"] = {
            "streaming": {"_default": pick("streaming")},
            "ai": {"_default": pick("ai")},
            "major": {"_default": pick("major")},
            "default": {"_default": pick("default", 1 if len(pool) > 1 else 0)},
        }
        cfg["rules_root"] = cfg.get("rules_root", DEFAULT_CONFIG["rules_root"])

    # Ensure required keys exist.
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
    # token ensure non-empty
    if not cfg.get("token"):
        cfg["token"] = DEFAULT_CONFIG["token"]
    # Normalize upstream_dns_pool
    udp = cfg.get("upstream_dns_pool")
    if isinstance(udp, str):
        udp_list = [ln.strip() for ln in udp.splitlines() if ln.strip()]
        cfg["upstream_dns_pool"] = udp_list or [cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])]
    elif not udp:
        cfg["upstream_dns_pool"] = [cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])]
    else:
        cfg["upstream_dns_pool"] = udp
    # Normalize upstream_dns if it contains accidental newlines
    if isinstance(cfg.get("upstream_dns"), str) and "\n" in cfg["upstream_dns"]:
        first = cfg["upstream_dns"].splitlines()[0].strip()
        cfg["upstream_dns"] = first or DEFAULT_CONFIG["upstream_dns"]
    # Normalize ip_pool (split comma/newline if stored as single string)
    ip_raw = cfg.get("ip_pool")
    if isinstance(ip_raw, list) and len(ip_raw) == 1 and isinstance(ip_raw[0], str) and ("\\n" in ip_raw[0] or "\n" in ip_raw[0] or "," in ip_raw[0]):
        raw = ip_raw[0].replace(",", "\n").replace("\\n", "\n")
        cfg["ip_pool"] = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    elif isinstance(ip_raw, str):
        raw = ip_raw.replace(",", "\n").replace("\\n", "\n")
        cfg["ip_pool"] = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    # Normalize active_service values and ensure entries exist
    pool = cfg.get("ip_pool") or DEFAULT_CONFIG["ip_pool"]
    active_service = cfg.get("active_service", {})
    for cat in SERVICE_CATALOG.keys() | {"default"}:
        active_service.setdefault(cat, {})
        active_service[cat].setdefault("_default", pool[0])
        for svc in [s["slug"] for s in SERVICE_CATALOG.get(cat, [])] + ["misc"]:
            val = active_service[cat].get(svc, active_service[cat]["_default"])
            if isinstance(val, str) and ("\n" in val or "\\n" in val or "," in val):
                raw = val.replace(",", "\n").replace("\\n", "\n")
                parts = [ln.strip() for ln in raw.splitlines() if ln.strip()]
                val = parts[0] if parts else active_service[cat]["_default"]
            if val != "__upstream__" and val not in pool:
                val = pool[0]
            active_service[cat][svc] = val
    # 移除已废弃的类别（如 others）
    for cat in list(active_service.keys()):
        if cat not in SERVICE_CATALOG and cat != "default":
            active_service.pop(cat, None)
    cfg["active_service"] = active_service
    # Ensure required keys exist.
    return cfg


class ConfigManager:
    """Thread-safe config + rules holder."""
    @staticmethod
    def _normalize_list(value):
        """Accept list or string with comma/\\n separators, return list of strings."""
        if isinstance(value, list):
            items = []
            for v in value:
                if isinstance(v, str):
                    v = v.replace(",", "\n").replace("\\n", "\n")
                    items.extend([ln.strip() for ln in v.splitlines() if ln.strip()])
                else:
                    items.append(str(v))
            return items
        if isinstance(value, str):
            value = value.replace(",", "\n").replace("\\n", "\n")
            return [ln.strip() for ln in value.splitlines() if ln.strip()]
        return []

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.config = ensure_config()
        self.rules, self.domain_map = load_rules_from_repo(self.config.get("rules_root", "rules"))
        self.rules_loaded_at = time.time()
        self.ip_meta_cache = {}
        self.ip_meta_fetched_at = 0
        self.reloading = False

    def save(self):
        with self.lock:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)

    def update_ip_pool(self, ip_pool, active_map, upstream_dns, upstream_pool):
        with self.lock:
            # Normalize lists to avoid accidental"\n"拼接
            ip_pool_norm = [ip for ip in self._normalize_list(ip_pool) if is_valid_ip(ip)] or ["1.1.1.1"]
            upstream_pool_norm = [ip for ip in self._normalize_list(upstream_pool) if is_valid_ip(ip)]
            if not upstream_pool_norm:
                upstream_pool_norm = [self.config.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])]

            # sanitize upstream_dns
            try:
                ipaddress.ip_address(upstream_dns)
            except Exception:
                upstream_dns = upstream_pool_norm[0]
            if upstream_dns not in upstream_pool_norm:
                upstream_pool_norm.insert(0, upstream_dns)

            # sanitize active selections: keep __upstream__ or item in ip_pool
            for cat, svc_map in active_map.items():
                for svc, val in list(svc_map.items()):
                    if isinstance(val, str) and ("\n" in val or "," in val or "\\n" in val):
                        parts = self._normalize_list([val])
                        val = parts[0] if parts else svc_map.get("_default", ip_pool_norm[0])
                    if val != "__upstream__" and val not in ip_pool_norm:
                        val = ip_pool_norm[0]
                    svc_map[svc] = val

            self.config["ip_pool"] = ip_pool_norm
            self.config["active_service"] = active_map
            self.config["upstream_dns"] = upstream_dns
            self.config["upstream_dns_pool"] = upstream_pool_norm
            self.save()

    def reload_rules(self):
        with self.lock:
            root = self.config.get("rules_root", "rules")
            sources = self.config.get("rule_sources", [])
        fetch_and_cache_rules(root, sources)
        self.rules, self.domain_map = load_rules_from_repo(root)
        self.rules_loaded_at = time.time()

    def reload_rules_async(self):
        with self.lock:
            if self.reloading:
                return False
            self.reloading = True

        def worker():
            try:
                self.reload_rules()
            finally:
                with self.lock:
                    self.reloading = False

        threading.Thread(target=worker, daemon=True).start()
        return True

    def get_snapshot(self):
        with self.lock:
            cfg_copy = self.config.copy()
            rule_counts = {
                cat: sum(len(v) for v in svc_dict.values())
                for cat, svc_dict in self.rules.items()
            }
            service_counts = {
                cat: {svc: len(domains) for svc, domains in svc_dict.items()}
                for cat, svc_dict in self.rules.items()
            }
            rules_meta = {
                "rule_counts": rule_counts,
                "service_counts": service_counts,
                "rules_loaded_at": self.rules_loaded_at,
                "reloading": self.reloading,
            }
        meta = rules_meta
        combined = {**cfg_copy, **meta}
        return json.dumps(combined).encode("utf-8"), combined

    def select_upstream(self, qname: str) -> str:
        """Return route ("ip" or "upstream", target)."""
        name = qname.lower().rstrip(".")
        labels = name.split(".")
        with self.lock:
            domain_map = self.domain_map
            active = self.config.get("active_service", {})
            pool = self.config.get("ip_pool") or DEFAULT_CONFIG["ip_pool"]
            default_route = active.get("default", {}).get("_default", pool[0])
            upstream_dns = self.config.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
        # Check all suffixes
        for i in range(len(labels)):
            suf = ".".join(labels[i:])
            if suf in domain_map:
                cat, svc = domain_map[suf]
                cat_map = active.get(cat, {})
                chosen = cat_map.get(svc, cat_map.get("_default", default_route))
                if chosen == "__upstream__":
                    return ("upstream", upstream_dns)
                return ("ip", chosen)
        if default_route == "__upstream__":
            return ("upstream", upstream_dns)
        return ("ip", default_route)

    def get_ip_meta(self, force=False):
        """Return IP meta info dict ip->meta; refresh if cache stale or force."""
        with self.lock:
            pool = list(self.config.get("ip_pool", []))
            age = time.time() - self.ip_meta_fetched_at
            cached = self.ip_meta_cache if not force and age < 600 else {}
        if cached and set(cached.keys()) == set(pool):
            return cached
        meta = {}
        for ip in pool:
            meta[ip] = fetch_ip_meta(ip)
        with self.lock:
            self.ip_meta_cache = meta
            self.ip_meta_fetched_at = time.time()
        return meta

    def peek_ip_meta(self):
        """Return cached ip meta without triggering fetch."""
        with self.lock:
            return dict(self.ip_meta_cache)

    def get_ip_meta_one(self, ip: str, force=False):
        """Return meta for single ip, caching with 10min TTL unless force."""
        now = time.time()
        with self.lock:
            age = now - self.ip_meta_fetched_at
            if not force and age < 600 and ip in self.ip_meta_cache:
                return self.ip_meta_cache[ip]
        meta = fetch_ip_meta(ip)
        with self.lock:
            self.ip_meta_cache[ip] = meta
            self.ip_meta_fetched_at = now
        return meta


# ---------- DNS plumbing ----------
def parse_question(packet: bytes) -> Tuple[str, int, int, int]:
    """
    Parse QNAME, QTYPE, QCLASS.
    Returns (qname, qtype, qclass, end_offset_of_question).
    """
    pos = 12
    labels = []
    if len(packet) < 14:
        raise ValueError("packet too short")
    length = packet[pos]
    while length != 0:
        pos += 1
        labels.append(packet[pos : pos + length].decode("utf-8", errors="ignore"))
        pos += length
        if pos >= len(packet):
            raise ValueError("truncated qname")
        length = packet[pos]
    qname = ".".join(labels)
    qtype = int.from_bytes(packet[pos + 1 : pos + 3], "big")
    qclass = int.from_bytes(packet[pos + 3 : pos + 5], "big")
    end = pos + 5
    return qname, qtype, qclass, end


def build_servfail(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    header = bytearray(query[:12])
    header[2] |= 0x80  # QR=1
    header[3] = (header[3] & 0xF0) | 0x02
    return bytes(header) + query[12:]


def build_empty_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    qdcount = query[4:6]
    flags = int.from_bytes(query[2:4], "big")
    flags |= 0x8000  # QR
    flags |= 0x0400  # RA
    flags &= 0xFFEF  # clear TC
    flags &= 0xFFF0  # clear RCODE
    resp = bytearray()
    resp += query[0:2]  # ID
    resp += flags.to_bytes(2, "big")
    resp += qdcount  # QDCOUNT
    resp += (0).to_bytes(2, "big")  # ANCOUNT
    resp += (0).to_bytes(2, "big")  # NS
    resp += (0).to_bytes(2, "big")  # AR
    resp += query[12:]  # question
    return bytes(resp)


def build_a_response(query: bytes, ip_str: str, qend: int) -> bytes:
    """Build an IPv4 A record response pointing to ip_str."""
    try:
        ip_bytes = ipaddress.IPv4Address(ip_str).packed
    except Exception:
        return build_servfail(query)
    qdcount = query[4:6]
    flags = int.from_bytes(query[2:4], "big")
    flags |= 0x8000  # QR
    flags |= 0x0400  # RA
    flags &= 0xFFEF  # clear TC
    flags &= 0xFFF0  # clear RCODE
    resp = bytearray()
    resp += query[0:2]  # ID
    resp += flags.to_bytes(2, "big")
    resp += qdcount              # QDCOUNT
    resp += (1).to_bytes(2, "big")  # ANCOUNT
    resp += (0).to_bytes(2, "big")  # NS
    resp += (0).to_bytes(2, "big")  # AR
    # Question
    resp += query[12:qend]
    # Answer
    resp += b"\xc0\x0c"  # name pointer to offset 12
    resp += (1).to_bytes(2, "big")  # TYPE A
    resp += (1).to_bytes(2, "big")  # CLASS IN
    resp += (60).to_bytes(4, "big")  # TTL
    resp += (4).to_bytes(2, "big")   # RDLENGTH
    resp += ip_bytes
    return bytes(resp)


def forward_query(upstream: str, query: bytes, timeout_ms: int) -> bytes:
    """Forward DNS query to an upstream resolver and return its response."""
    addr = (upstream, 53)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout_ms / 1000.0)
        s.sendto(query, addr)
        return s.recvfrom(4096)[0]


def dns_worker(server_sock: socket.socket, cfg: ConfigManager, executor: ThreadPoolExecutor):
    while True:
        data, addr = server_sock.recvfrom(4096)
        executor.submit(process_query, data, addr, server_sock, cfg)


def process_query(data: bytes, client_addr, server_sock: socket.socket, cfg: ConfigManager):
    try:
        qname, qtype, _, qend = parse_question(data)
    except Exception:
        response = build_servfail(data)
    else:
        mode, target = cfg.select_upstream(qname)
        if mode == "upstream":
            _, snapshot = cfg.get_snapshot()
            timeout_ms = snapshot.get("timeout_ms", 2000)
            try:
                response = forward_query(target, data, timeout_ms)
            except Exception:
                response = build_servfail(data)
        else:
            if qtype == 1:  # A
                response = build_a_response(data, target, qend)
            elif qtype == 28:  # AAAA
                response = build_empty_response(data)  # no IPv6 override
            else:
                response = build_empty_response(data)
    try:
        server_sock.sendto(response, client_addr)
    except Exception:
        pass


# ---------- Web UI ----------
class WebHandler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return  # silence default logging

    @property
    def cfg(self) -> ConfigManager:
        return self.server.config  # type: ignore

    def _check_token(self, qs) -> bool:
        token_cfg = self.cfg.config.get("token", "")
        token_req = None
        if isinstance(qs, dict):
            token_req = qs.get("token", [None])[0]
        if not token_req:
            token_req = self.headers.get("X-Token")
        if token_cfg and token_req == token_cfg:
            return True
        self._send(403, b"Forbidden: token missing or invalid", "text/plain; charset=utf-8")
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        if not self._check_token(qs):
            return
        if path.endswith("api/config"):
            body, _ = self.cfg.get_snapshot()
            return self._send(200, body, "application/json")
        if path.endswith("api/ipinfo"):
            ip = qs.get("ip", [None])[0]
            force = "refresh" in qs
            if ip:
                meta = self.cfg.get_ip_meta_one(ip, force=force)
            else:
                meta = self.cfg.get_ip_meta(force=force)
            return self._send(200, json.dumps(meta).encode("utf-8"), "application/json")
        if path.endswith("api/rules_info"):
            _, snap = self.cfg.get_snapshot()
            info = {
                "rule_counts": snap.get("rule_counts"),
                "rules_loaded_at": snap.get("rules_loaded_at"),
                "rules_root": snap.get("rules_root"),
                "reloading": snap.get("reloading", False),
            }
            return self._send(200, json.dumps(info).encode("utf-8"), "application/json")
        return self._send(200, self.render_dashboard().encode("utf-8"))

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        qs = parse_qs(urlparse(self.path).query)
        if not self._check_token(qs):
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        data = parse_qs(raw)

        if path.endswith("save_upstreams"):
            # 只更新提交的部分，其他保持当前配置
            _, snap = self.cfg.get_snapshot()
            current_cfg = snap

            # --- IP池与上游池 ---
            new_ip_pool = current_cfg.get("ip_pool", [])
            if "ip_pool" in data:
                pool_raw = data.get("ip_pool", [""])[0].replace("\\n", "\n").replace(",", "\n")
                pool_lines = pool_raw.splitlines()
                ip_pool = [ln.strip() for ln in pool_lines if ln.strip()]
                # 校验 IP
                ip_pool = [ip for ip in ip_pool if is_valid_ip(ip)]
                if ip_pool:
                    new_ip_pool = ip_pool

            new_upstream_pool = current_cfg.get("upstream_dns_pool", [])
            if "upstream_dns_pool" in data:
                dns_raw = data.get("upstream_dns_pool", [""])[0].replace("\\n", "\n").replace(",", "\n")
                dns_lines = dns_raw.splitlines()
                upstream_pool = [ln.strip() for ln in dns_lines if ln.strip() and is_valid_ip(ln.strip())]
                if upstream_pool:
                    new_upstream_pool = upstream_pool

            # 上游DNS当前值
            new_upstream_dns = current_cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
            if "upstream_dns" in data:
                cand = data.get("upstream_dns", [""])[0].strip()
                if cand and is_valid_ip(cand):
                    new_upstream_dns = cand

            # 确保上游dns在上游池内
            if new_upstream_dns not in new_upstream_pool:
                new_upstream_pool = [new_upstream_dns] + [ip for ip in new_upstream_pool if ip != new_upstream_dns]

            # --- active_service 只覆盖提交的 select 项 ---
            active_map = {cat: dict(vals) for cat, vals in current_cfg.get("active_service", {}).items()}
            for key, vals in data.items():
                if not key.startswith("sel_"):
                    continue
                body = key[4:]
                if "__" not in body:
                    continue
                cat, svc = body.split("__", 1)
                val = vals[0]
                # 校验：允许 __upstream__ 或合法 IP 且在池内
                if val == "__upstream__":
                    pass
                elif is_valid_ip(val) and val in new_ip_pool:
                    pass
                else:
                    # 如果值非法，保持原值
                    val = active_map.get(cat, {}).get(svc, active_map.get(cat, {}).get("_default", new_ip_pool[0] if new_ip_pool else new_upstream_dns))
                active_map.setdefault(cat, {})[svc] = val

            # 填充缺省
            for cat in SERVICE_CATALOG.keys() | {"default"}:
                active_map.setdefault(cat, {})
                active_map[cat].setdefault("_default", active_map[cat].get("_default", new_ip_pool[0] if new_ip_pool else new_upstream_dns))
                for svc in [s["slug"] for s in SERVICE_CATALOG.get(cat, [])]:
                    active_map[cat].setdefault(svc, active_map[cat]["_default"])

            self.cfg.update_ip_pool(new_ip_pool, active_map, new_upstream_dns, new_upstream_pool)
        elif path.endswith("refresh_rules"):
            started = self.cfg.reload_rules_async()
            resp = {"started": started}
            self._send(202 if started else 200, json.dumps(resp).encode("utf-8"), "application/json")
            return
        # 默认返回 204，避免浏览器自动重定向到根路径（可能丢失 token）
        self.send_response(204)
        self.end_headers()

    def render_dashboard(self) -> str:
        _, cfg = self.cfg.get_snapshot()
        ip_pool = cfg.get("ip_pool", []) or ["1.1.1.1"]
        active = cfg.get("active_service", {})
        upstream_dns = cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
        upstream_pool = cfg.get("upstream_dns_pool", [upstream_dns])
        # 仅读取缓存，不触发远程获取，避免首屏阻塞
        ip_meta = self.cfg.peek_ip_meta()
        token = cfg.get("token", "")
        rule_counts = cfg.get("rule_counts", {})
        service_counts = cfg.get("service_counts", {})
        rules_root = cfg.get("rules_root", "rules")
        loaded_at_raw = cfg.get("rules_loaded_at", 0)
        loaded_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(loaded_at_raw))

        def select_html(cat, slug, current):
            name = f"sel_{cat}__{slug}"
            opts = []
            opts.append(f'<option value="__upstream__" {"selected" if current=="__upstream__" else ""}>上游DNS ({upstream_dns})</option>')
            for ip in ip_pool:
                sel = "selected" if ip == current else ""
                opts.append(f'<option value="{ip}" {sel}>{ip}</option>')
            return '<select name="%s" class="select">%s</select>' % (name, "".join(opts))

        def category_block(cat, title):
            services = SERVICE_CATALOG.get(cat, [])
            svc_list = services if cat != "default" else [{"slug": "_default", "name": "默认"}]
            rows = []
            counts_cat = service_counts.get(cat, {})
            cat_map = active.get(cat, {})
            for svc in svc_list:
                slug = svc["slug"]
                label = svc["name"]
                current = cat_map.get(slug, cat_map.get("_default", ip_pool[0]))
                count = counts_cat.get(slug, 0)
                badge = f"<span class='pill'>{count} 条规则</span>"
                rows.append(f'<div class="row"><div class="row-head"><span>{label}</span>{badge}</div>{select_html(cat, slug, current)}</div>')
            return f'<section class="card"><h2>{title}</h2>{"".join(rows)}</section>'

        # pre-fill chip text; color will be set by JS after拉取 /api/ipinfo
        ip_chips = "".join([f'<span class="chip" data-ip="{ip}">{ip}</span>' for ip in ip_pool])
        dns_chips = "".join([
            (f'<span class="chip active" data-ip="{ip}">{ip}</span>' if ip == upstream_dns else f'<span class="chip" data-ip="{ip}">{ip}</span>')
            for ip in upstream_pool
        ])
        category_html = "".join([
            category_block("ai", "AI 分类"),
            category_block("streaming", "流媒体"),
            category_block("major", "主站点"),
            category_block("default", "默认"),
        ])
        rule_summary = f"流媒体 {rule_counts.get('streaming',0)} · AI {rule_counts.get('ai',0)} · 主站 {rule_counts.get('major',0)} · 默认 {rule_counts.get('default',0)}"

        tpl_path = Path(__file__).parent / 'templates' / 'dashboard.html'
        tpl = Template(tpl_path.read_text(encoding='utf-8'))
        return tpl.safe_substitute(
            ip_chips=ip_chips,
            dns_chips=dns_chips,
            listen_host=cfg.get("listen_host"),
            dns_port=cfg.get("dns_port"),
            web_host=cfg.get("web_host", "0.0.0.0"),
            web_port=cfg.get("web_port"),
            category_blocks=category_html,
            rules_root=rules_root,
            rule_summary=rule_summary,
            loaded_at=loaded_at,
            upstream_dns=upstream_dns,
            loaded_at_ts=str(int(loaded_at_raw)),
            ip_meta_json=json.dumps(ip_meta),
            token=token,
            token_query=f"token={token}",
        )


# ---------- Server bootstrap ----------
def run_servers():
    cfg_mgr = ConfigManager(CONFIG_PATH)
    _, cfg = cfg_mgr.get_snapshot()
    dns_port = cfg["dns_port"]
    listen_host = cfg["listen_host"]
    web_host = cfg.get("web_host", "0.0.0.0")
    web_port = cfg["web_port"]

    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dns_sock.bind((listen_host, dns_port))

    executor = ThreadPoolExecutor(max_workers=16)
    dns_thread = threading.Thread(
        target=dns_worker, args=(dns_sock, cfg_mgr, executor), daemon=True
    )
    dns_thread.start()

    class WebServer(ThreadingHTTPServer):
        daemon_threads = True
        def __init__(self, server_address, handler_class):
            super().__init__(server_address, handler_class)
            self.config = cfg_mgr

    web_srv = WebServer((web_host, web_port), WebHandler)

    print(f"[DNS] listening on {listen_host}:{dns_port}")
    print(f"[WEB] open http://{web_host}:{web_port} to manage rules")
    try:
        web_srv.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        web_srv.server_close()
        executor.shutdown(wait=False)
        dns_sock.close()


if __name__ == "__main__":
    run_servers()
