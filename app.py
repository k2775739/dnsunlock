#!/usr/bin/env python3
"""
DNSUnlock
---------
Python-only DNS forwarder with Clash-style policy groups and an Apple-style web UI.

- 读取 Clash 策略（INI / config.yaml），按规则命中分流组
- 分流组选择等同 Clash：选择某 IP = DNS 直接解析到该 IP；选择 DIRECT = 使用上游 DNS 正常解析
- url-test 以 curl --resolve 探测方式代替真实代理测速（默认 `http://www.gstatic.com/generate_204`，也会读取策略里的 url）
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import hashlib
import html
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote, urlencode
from typing import Optional, Tuple, List, Dict
from string import Template
from pathlib import Path
import ipaddress
import urllib.request
import subprocess
import yaml


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False

def ip_version(ip: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip).version
    except Exception:
        return None

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
LOCAL_POLICY_FILENAME = "local_group.ini"
LOCAL_POLICY_PATH = Path(__file__).parent / LOCAL_POLICY_FILENAME
MAX_PROFILE_TEXT_BYTES = 1024 * 1024  # 1 MiB
MAX_FETCH_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_POST_BYTES = 2 * 1024 * 1024  # 2 MiB

# Default configuration. Users can override ports and IP pools in config.json.
DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "web_host": "0.0.0.0",
    "dns_port": 5353,
    "web_port": 8080,
    "timeout_ms": 2000,
    # IP 池探测站点：netvigator / ifconfig
    "ip_info_site": "netvigator",
    # Clash 分流策略（支持订阅转换 ini 与标准 config.yaml）
    "clash_profile_source": "local",  # local / remote
    "clash_profile_url": "https://raw.githubusercontent.com/cutethotw/ClashRule/refs/heads/main/Customization/Andy120527.ini",
    "clash_cache_dir": "clash_cache",
    # 仅对 type=select 的分组生效：group_name -> selected_member
    "clash_group_selection": {},
    # GEOIP,CN 的近似实现：使用公开 CN IP 段列表（非 MaxMind mmdb）
    "geoip_cn_url": "https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt",
    "token": "changeme",
    "upstream_dns": "8.8.8.8",
    "upstream_dns_pool": ["1.1.1.1", "8.8.8.8"],
    "ip_pool": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
}

IP_INFO_SITES = ("netvigator", "ifconfig")
DEFAULT_URLTEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_LOCAL_POLICY_TEXT = """[custom]
; 本地 Clash 策略（ACL4SSR 风格）
; 你可以在 Web 面板里点击“编辑本地配置”修改本文件。
;
; 最少需要一个 FINAL 规则作为兜底：
ruleset=🐟 漏网之鱼,[]FINAL

enable_rule_generator=true
overwrite_original_rules=true
"""


def _ensure_local_policy_file() -> None:
    try:
        if LOCAL_POLICY_PATH.exists():
            return
        LOCAL_POLICY_PATH.write_text(DEFAULT_LOCAL_POLICY_TEXT, encoding="utf-8")
    except Exception:
        pass


def _read_local_policy_text() -> str:
    _ensure_local_policy_file()
    try:
        if LOCAL_POLICY_PATH.is_symlink():
            raise ValueError("local policy file must not be a symlink")
        if LOCAL_POLICY_PATH.exists() and LOCAL_POLICY_PATH.stat().st_size > MAX_PROFILE_TEXT_BYTES:
            raise ValueError("local policy file too large")
        return LOCAL_POLICY_PATH.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _write_local_policy_text(text: str) -> None:
    if not isinstance(text, str):
        text = str(text)
    data = text.encode("utf-8", errors="ignore")
    if len(data) > MAX_PROFILE_TEXT_BYTES:
        raise ValueError("policy text too large")
    if LOCAL_POLICY_PATH.exists() and LOCAL_POLICY_PATH.is_symlink():
        raise ValueError("local policy file must not be a symlink")
    tmp = LOCAL_POLICY_PATH.with_suffix(LOCAL_POLICY_PATH.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW  # best-effort: avoid symlink writes on supported platforms
    fd = os.open(str(tmp), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(str(tmp), str(LOCAL_POLICY_PATH))
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def _curl_resolve_target(host: str, port: int, ip: str) -> str:
    """Format curl --resolve target, handling IPv6 brackets."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return f"{host}:{port}:{ip}"
    if isinstance(ip_obj, ipaddress.IPv6Address):
        return f"{host}:{port}:[{ip}]"
    return f"{host}:{port}:{ip}"


def _fetch_ip_meta_ifconfig(ip: str, timeout: float = 6.0) -> dict:
    """Query ifconfig.co/json via the target IP (curl --resolve).

    Returns dict:
      {ok, ip, real_ip, country_iso, asn_org, source}
    """
    if not is_valid_ip(ip):
        return {"ok": False, "ip": ip, "source": "ifconfig"}
    cmd = [
        "curl",
        "--resolve",
        _curl_resolve_target("ifconfig.co", 80, ip),
        "-m",
        str(int(timeout)),
        "--connect-timeout",
        "3",
        "-s",
        "http://ifconfig.co/json",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        data = json.loads(out.decode("utf-8", errors="ignore").strip() or "{}")
        return {
            "ok": True,
            "ip": ip,
            "real_ip": data.get("ip"),
            "country_iso": data.get("country_iso"),
            "asn_org": data.get("asn_org"),
            "source": "ifconfig",
        }
    except Exception:
        return {"ok": False, "ip": ip, "source": "ifconfig"}


def _fetch_ip_meta_netvigator(ip: str, timeout: float = 6.0) -> dict:
    """Query v46check.netvigator.com via the target IP (curl --resolve).

    Netvigator response example:
      {"resultCode":"6","ip":"2400:...","countryCode":"HK","isp":"null"}

    Returns dict:
      {ok, ip, real_ip, country_iso, asn_org, source, result_code}
    """
    if not is_valid_ip(ip):
        return {"ok": False, "ip": ip, "source": "netvigator"}
    cmd = [
        "curl",
        "--resolve",
        _curl_resolve_target("v46check.netvigator.com", 443, ip),
        "-m",
        str(int(timeout)),
        "--connect-timeout",
        "3",
        "-s",
        "https://v46check.netvigator.com/ipcheck/test-ip.jsp",
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        raw = out.decode("utf-8", errors="ignore").strip()
        data = json.loads(raw or "{}")
        real_ip = data.get("ip")
        country_code = data.get("countryCode")
        isp = data.get("isp")
        if isinstance(isp, str) and isp.lower() == "null":
            isp = None
        result_code = data.get("resultCode")
        ok = bool(real_ip) and bool(country_code) and str(result_code) in ("4", "6")
        return {
            "ok": ok,
            "ip": ip,
            "real_ip": real_ip,
            "country_iso": country_code,
            "asn_org": isp,
            "source": "netvigator",
            "result_code": result_code,
        }
    except Exception:
        return {"ok": False, "ip": ip, "source": "netvigator"}


def probe_url_latency(ip: str, url: str, timeout: float = 4.0) -> Tuple[bool, int]:
    """Probe the given URL by forcing DNS resolve to the provided IP.

    This approximates Clash url-test delay: connect+request total time (ms).
    """
    # Rate limit: at most once per minute for the same (ip, url).
    key_url = (url or "").strip() or DEFAULT_URLTEST_URL
    key = (str(ip or "").strip(), key_url)
    now = time.monotonic()
    try:
        cache = probe_url_latency._cache  # type: ignore[attr-defined]
        lock = probe_url_latency._lock    # type: ignore[attr-defined]
    except Exception:
        cache = {}
        lock = threading.RLock()
        probe_url_latency._cache = cache  # type: ignore[attr-defined]
        probe_url_latency._lock = lock    # type: ignore[attr-defined]
    with lock:
        rec = cache.get(key)
        if isinstance(rec, dict) and now - float(rec.get("ts", 0)) < 60.0:
            return bool(rec.get("ok")), int(rec.get("ms") or 0)

    if not is_valid_ip(ip):
        with lock:
            cache[key] = {"ok": False, "ms": 0, "ts": now}
        return False, 0
    effective_url = (url or "").strip()
    u = urlparse(effective_url)
    host = u.hostname
    if not host:
        effective_url = DEFAULT_URLTEST_URL
        u = urlparse(effective_url)
        host = u.hostname
    if not host:
        with lock:
            cache[key] = {"ok": False, "ms": 0, "ts": now}
        return False, 0
    scheme = (u.scheme or "http").lower()
    port = u.port or (443 if scheme == "https" else 80)
    resolve = _curl_resolve_target(host, int(port), ip)
    cmd = [
        "curl",
        "--resolve",
        resolve,
        "-m",
        str(int(timeout)),
        "--connect-timeout",
        "3",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{http_code}",
        effective_url,
    ]
    start = time.monotonic()
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        ms = int((time.monotonic() - start) * 1000)
        code_s = (out.decode("utf-8", errors="ignore").strip() or "0").strip()
        try:
            code = int(code_s)
        except Exception:
            code = 0
        ok = 200 <= code < 400
        with lock:
            cache[key] = {"ok": bool(ok), "ms": int(ms), "ts": now}
        return ok, ms
    except Exception:
        ms = int((time.monotonic() - start) * 1000)
        with lock:
            cache[key] = {"ok": False, "ms": int(ms), "ts": now}
        return False, ms


def fetch_ip_meta(ip: str, timeout: float = 6.0, site: str = "netvigator") -> dict:
    """Fetch IP meta using the configured site.

    site:
      - netvigator: https://v46check.netvigator.com/ipcheck/test-ip.jsp
      - ifconfig:   http://ifconfig.co/json
    """
    site_norm = (site or "").strip().lower()
    if site_norm not in IP_INFO_SITES:
        site_norm = DEFAULT_CONFIG.get("ip_info_site", "netvigator")
    if site_norm == "ifconfig":
        return _fetch_ip_meta_ifconfig(ip, timeout=timeout)
    return _fetch_ip_meta_netvigator(ip, timeout=timeout)


# ---------- Config management ----------
def ensure_config():
    """Load config or create default, and normalize schema."""
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    dirty = False

    # Drop legacy rule-based schema keys (已废弃：完全以 Clash 策略为准)
    for k in ("active", "upstreams", "active_service", "rules_root", "rule_sources"):
        if k in cfg:
            cfg.pop(k, None)
            dirty = True

    # Ensure required keys exist.
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = v
            dirty = True
    # token ensure non-empty
    if not cfg.get("token"):
        cfg["token"] = DEFAULT_CONFIG["token"]
        dirty = True

    # Normalize ip_info_site
    site_raw = cfg.get("ip_info_site", DEFAULT_CONFIG.get("ip_info_site", "netvigator"))
    site_norm = str(site_raw).strip().lower() if isinstance(site_raw, str) else DEFAULT_CONFIG.get("ip_info_site", "netvigator")
    if site_norm not in IP_INFO_SITES:
        site_norm = DEFAULT_CONFIG.get("ip_info_site", "netvigator")
    if cfg.get("ip_info_site") != site_norm:
        cfg["ip_info_site"] = site_norm
        dirty = True

    # Normalize clash_profile_url if it contains accidental newlines
    # Normalize clash_profile_source
    src_raw = cfg.get("clash_profile_source", DEFAULT_CONFIG.get("clash_profile_source", "local"))
    src_norm = str(src_raw or "").strip().lower()
    if src_norm not in ("local", "remote"):
        src_norm = DEFAULT_CONFIG.get("clash_profile_source", "local")
    if cfg.get("clash_profile_source") != src_norm:
        cfg["clash_profile_source"] = src_norm
        dirty = True

    if isinstance(cfg.get("clash_profile_url"), str) and "\n" in cfg["clash_profile_url"]:
        first = cfg["clash_profile_url"].splitlines()[0].strip()
        cfg["clash_profile_url"] = first or DEFAULT_CONFIG["clash_profile_url"]
        dirty = True
    if not isinstance(cfg.get("clash_profile_url"), str) or not cfg.get("clash_profile_url"):
        cfg["clash_profile_url"] = DEFAULT_CONFIG["clash_profile_url"]
        dirty = True
    # Normalize clash_cache_dir
    if not isinstance(cfg.get("clash_cache_dir"), str) or not cfg.get("clash_cache_dir"):
        cfg["clash_cache_dir"] = DEFAULT_CONFIG["clash_cache_dir"]
        dirty = True
    # Normalize clash_group_selection
    if not isinstance(cfg.get("clash_group_selection"), dict):
        cfg["clash_group_selection"] = {}
        dirty = True
    # Normalize geoip_cn_url
    if isinstance(cfg.get("geoip_cn_url"), str) and "\n" in cfg["geoip_cn_url"]:
        first = cfg["geoip_cn_url"].splitlines()[0].strip()
        cfg["geoip_cn_url"] = first or DEFAULT_CONFIG["geoip_cn_url"]
        dirty = True
    if not isinstance(cfg.get("geoip_cn_url"), str) or not cfg.get("geoip_cn_url"):
        cfg["geoip_cn_url"] = DEFAULT_CONFIG["geoip_cn_url"]
        dirty = True
    # Normalize upstream_dns_pool
    udp = cfg.get("upstream_dns_pool")
    udp_list = []
    if isinstance(udp, str):
        raw = udp.replace(",", "\n").replace("\\n", "\n")
        udp_list = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    elif isinstance(udp, list):
        udp_list = [str(x).strip() for x in udp if str(x).strip()]
    udp_list = [ip for ip in udp_list if is_valid_ip(ip)]
    # Normalize upstream_dns if it contains accidental newlines
    if isinstance(cfg.get("upstream_dns"), str) and "\n" in cfg["upstream_dns"]:
        first = cfg["upstream_dns"].splitlines()[0].strip()
        cfg["upstream_dns"] = first or DEFAULT_CONFIG["upstream_dns"]
        dirty = True
    if not isinstance(cfg.get("upstream_dns"), str) or not is_valid_ip(cfg.get("upstream_dns", "")):
        cfg["upstream_dns"] = DEFAULT_CONFIG["upstream_dns"]
        dirty = True
    if not udp_list:
        udp_list = [cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])]
    if cfg["upstream_dns"] not in udp_list:
        udp_list = [cfg["upstream_dns"]] + [x for x in udp_list if x != cfg["upstream_dns"]]
    if cfg.get("upstream_dns_pool") != udp_list:
        cfg["upstream_dns_pool"] = udp_list
        dirty = True

    # Normalize ip_pool (split comma/newline if stored as single string)
    ip_raw = cfg.get("ip_pool")
    pool_list = []
    if isinstance(ip_raw, str):
        raw = ip_raw.replace(",", "\n").replace("\\n", "\n")
        pool_list = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    elif isinstance(ip_raw, list):
        if len(ip_raw) == 1 and isinstance(ip_raw[0], str) and ("\\n" in ip_raw[0] or "\n" in ip_raw[0] or "," in ip_raw[0]):
            raw = ip_raw[0].replace(",", "\n").replace("\\n", "\n")
            pool_list = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        else:
            pool_list = [str(x).strip() for x in ip_raw if str(x).strip()]
    pool_list = [ip for ip in pool_list if is_valid_ip(ip)]
    pool_list = list(dict.fromkeys(pool_list))
    if not pool_list:
        pool_list = list(DEFAULT_CONFIG["ip_pool"])
    if cfg.get("ip_pool") != pool_list:
        cfg["ip_pool"] = pool_list
        dirty = True

    if dirty:
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass
    return cfg


# ---------- Clash policy (routing) ----------
COUNTRY_LABELS = {
    "HK": ("Hong Kong", "香港"),
    "JP": ("Japan", "日本"),
    "US": ("United States", "美国"),
    "TW": ("Taiwan", "台湾"),
    "SG": ("Singapore", "新加坡"),
    "CN": ("China", "中国"),
    "KR": ("South Korea", "韩国"),
}


class CidrTrie:
    """Prefix trie for CIDR membership checks (order-insensitive)."""

    def __init__(self, bits: int):
        self.bits = bits
        self.root = {}

    def insert(self, net):
        try:
            prefix = int(net.prefixlen)
            ip_int = int(net.network_address)
        except Exception:
            return
        node = self.root
        for i in range(prefix):
            bit = (ip_int >> (self.bits - 1 - i)) & 1
            node = node.setdefault(bit, {})
        node["$"] = True

    def contains(self, ip_obj) -> bool:
        try:
            ip_int = int(ip_obj)
        except Exception:
            return False
        node = self.root
        for i in range(self.bits):
            if "$" in node:
                return True
            bit = (ip_int >> (self.bits - 1 - i)) & 1
            nxt = node.get(bit)
            if nxt is None:
                return False
            node = nxt
        return "$" in node


def _cache_dir_from_cfg(cfg: dict) -> str:
    root = cfg.get("clash_cache_dir") or DEFAULT_CONFIG["clash_cache_dir"]
    base = Path(__file__).parent / str(root)
    base.mkdir(parents=True, exist_ok=True)
    return str(base)


def _url_cache_path(cache_dir: str, url: str, suffix: str = ".txt") -> str:
    def safe_component(s: str) -> str:
        s = unquote(str(s or "")).replace("\x00", "").strip()
        s = s.replace("/", "_").replace("\\", "_").replace(":", "_")
        if not s or s in (".", ".."):
            return "_"
        return s

    p = urlparse(url or "")
    host = safe_component(p.netloc) or "unknown"
    raw_path = unquote(p.path or "")
    parts = [safe_component(x) for x in raw_path.split("/") if x and x not in (".", "..")]
    if not parts:
        name = "index"
        if suffix:
            suf = suffix if suffix.startswith(".") else f".{suffix}"
            name += suf
        parts = [name]
    else:
        last = parts[-1]
        if "." not in last and suffix:
            suf = suffix if suffix.startswith(".") else f".{suffix}"
            parts[-1] = f"{last}{suf}"
    if p.query:
        qh = hashlib.sha1(p.query.encode("utf-8")).hexdigest()[:8]
        base, ext = os.path.splitext(parts[-1])
        parts[-1] = f"{base}__q{qh}{ext}"
    return os.path.join(cache_dir, host, *parts)


_URL_SAFETY_CACHE = {}
_URL_SAFETY_LOCK = threading.RLock()
_URL_SAFETY_TTL_SEC = 600


def _is_public_ip(ip_s: str) -> bool:
    try:
        return ipaddress.ip_address(ip_s).is_global
    except Exception:
        return False


def _validate_remote_url(url: str) -> str:
    u = str(url or "").strip()
    if not u:
        raise ValueError("empty url")
    if len(u) > 2048:
        raise ValueError("url too long")
    p = urlparse(u)
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("only http/https urls are allowed")
    if p.username or p.password:
        raise ValueError("userinfo in url is not allowed")
    host = (p.hostname or "").strip().rstrip(".")
    if not host:
        raise ValueError("missing hostname")
    if host.lower() in ("localhost",):
        raise ValueError("localhost is not allowed")
    port = p.port or (443 if scheme == "https" else 80)

    # Fast path: IP literal.
    try:
        ip_obj = ipaddress.ip_address(host)
        if not ip_obj.is_global:
            raise ValueError("non-public ip is not allowed")
        return u
    except ValueError:
        # not an IP literal
        pass

    # Cached DNS safety verdict.
    key = (host.lower(), int(port))
    now = time.time()
    with _URL_SAFETY_LOCK:
        cached = _URL_SAFETY_CACHE.get(key)
        if isinstance(cached, dict) and now - float(cached.get("ts", 0)) < _URL_SAFETY_TTL_SEC:
            if cached.get("ok"):
                return u
            raise ValueError(cached.get("reason") or "unsafe url")

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        with _URL_SAFETY_LOCK:
            _URL_SAFETY_CACHE[key] = {"ok": False, "ts": now, "reason": "dns resolve failed"}
        raise ValueError("dns resolve failed")

    ips = []
    for _family, _socktype, _proto, _canon, sockaddr in infos:
        try:
            ip_s = sockaddr[0]
        except Exception:
            continue
        if ip_s and ip_s not in ips:
            ips.append(ip_s)

    if not ips:
        with _URL_SAFETY_LOCK:
            _URL_SAFETY_CACHE[key] = {"ok": False, "ts": now, "reason": "dns resolve empty"}
        raise ValueError("dns resolve empty")

    for ip_s in ips:
        if not _is_public_ip(ip_s):
            with _URL_SAFETY_LOCK:
                _URL_SAFETY_CACHE[key] = {"ok": False, "ts": now, "reason": f"non-public ip not allowed: {ip_s}"}
            raise ValueError("non-public ip is not allowed")

    with _URL_SAFETY_LOCK:
        _URL_SAFETY_CACHE[key] = {"ok": True, "ts": now, "ips": ips}
    return u


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_remote_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_text_cached(url: str, cache_dir: str, suffix: str = ".txt", timeout: int = 15, force: bool = False) -> str:
    """Fetch URL text with on-disk cache; on failure, fall back to cached copy."""
    safe_url = _validate_remote_url(url)
    dest = _url_cache_path(cache_dir, safe_url, suffix=suffix)
    legacy_dest = os.path.join(cache_dir, f"{hashlib.sha1(safe_url.encode('utf-8')).hexdigest()[:16]}{suffix}")
    if not force and os.path.exists(dest):
        try:
            if os.path.getsize(dest) > MAX_FETCH_BYTES:
                raise ValueError("cached file too large")
            return Path(dest).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    if not force and os.path.exists(legacy_dest):
        try:
            if os.path.getsize(legacy_dest) > MAX_FETCH_BYTES:
                raise ValueError("cached file too large")
            text = Path(legacy_dest).read_text(encoding="utf-8", errors="ignore")
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                Path(dest).write_text(text, encoding="utf-8")
                try:
                    os.remove(legacy_dest)
                except Exception:
                    pass
            except Exception:
                pass
            return text
        except Exception:
            pass
    tmp = dest + ".tmp"
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        opener = urllib.request.build_opener(_SafeRedirectHandler())
        req = urllib.request.Request(safe_url, headers={"User-Agent": "DNSUnlock/1.0"})
        with opener.open(req, timeout=timeout) as r:
            final_url = r.geturl()
            if final_url:
                _validate_remote_url(final_url)
            data = r.read(MAX_FETCH_BYTES + 1)
        if len(data) > MAX_FETCH_BYTES:
            raise ValueError("response too large")
        Path(tmp).write_bytes(data)
        os.replace(tmp, dest)
        if os.path.exists(legacy_dest):
            try:
                os.remove(legacy_dest)
            except Exception:
                pass
        return data.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return Path(dest).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            try:
                return Path(legacy_dest).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
            raise


def _detect_profile_kind(text: str, url: str = "") -> str:
    t = text or ""
    if re.search(r"^\s*\[rule\]\s*$", t, flags=re.IGNORECASE | re.MULTILINE):
        return "shadowrocket"
    if re.search(r"^\s*\[proxy\s+group\]\s*$", t, flags=re.IGNORECASE | re.MULTILINE):
        return "shadowrocket"
    if "proxy-groups:" in t or "rules:" in t:
        return "yaml"
    head = ""
    for ln in t.splitlines():
        s = ln.strip()
        if not s or s.startswith(("#", ";")):
            continue
        head = s
        break
    if head.startswith("[") and "]" in head:
        return "ini"
    u = (url or "").lower()
    if u.endswith(".conf"):
        return "shadowrocket"
    # Default to INI (ACL4SSR-style) for empty/unknown inputs.
    return "ini"


def _json_for_html_script(obj) -> str:
    """JSON safe to embed directly inside a <script> block."""
    s = json.dumps(obj, ensure_ascii=False)
    # Prevent `</script>` break-out and reduce XSS risk.
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    u = (url or "").lower()
    if u.endswith((".yml", ".yaml")):
        return "yaml"
    if u.endswith(".ini"):
        return "ini"
    return "ini"


def parse_clash_rule_token(token: str):
    """Parse a single rule token (from payload/list/rules). Returns (kind, value) or None."""
    s = (token or "").strip()
    if not s:
        return None
    if s.startswith("-"):
        s = s[1:].strip()
    if not s or s.startswith(("#", "//", ";")):
        return None
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return None
    if len(parts) == 1:
        # Plain domain line (common in .list) -> treat as DOMAIN-SUFFIX
        return ("DOMAIN-SUFFIX", parts[0].lower())
    kind = parts[0].upper()
    if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        if len(parts) >= 2:
            return (kind, parts[1].lower())
        return None
    if kind in ("IP-CIDR", "IP-CIDR6"):
        if len(parts) >= 2:
            return (kind, parts[1])
        return None
    return None


class RuleProvider:
    def __init__(self, name: str, url: str, text: str):
        self.name = name
        self.url = url
        self.domain_exact = set()
        self.domain_suffix = set()
        self.keywords = set()
        self.cidr_v4 = CidrTrie(32)
        self.cidr_v6 = CidrTrie(128)
        self.has_ip_rules = False
        self.count = 0
        self._parse(text)

    def _parse_text_lines(self, lines):
        for raw in lines:
            parsed = parse_clash_rule_token(raw)
            if not parsed:
                continue
            kind, val = parsed
            self.count += 1
            if kind == "DOMAIN":
                self.domain_exact.add(val)
            elif kind == "DOMAIN-SUFFIX":
                self.domain_suffix.add(val)
            elif kind == "DOMAIN-KEYWORD":
                self.keywords.add(val)
            elif kind == "IP-CIDR":
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if isinstance(net, ipaddress.IPv4Network):
                        self.cidr_v4.insert(net)
                        self.has_ip_rules = True
                except Exception:
                    continue
            elif kind == "IP-CIDR6":
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if isinstance(net, ipaddress.IPv6Network):
                        self.cidr_v6.insert(net)
                        self.has_ip_rules = True
                except Exception:
                    continue

    def _parse(self, text: str):
        t = text or ""
        # Try YAML payload first (clash classic)
        try:
            obj = yaml.safe_load(t)
            payload = None
            if isinstance(obj, dict):
                if isinstance(obj.get("payload"), list):
                    payload = obj.get("payload")
                elif isinstance(obj.get("rules"), list):
                    payload = obj.get("rules")
            elif isinstance(obj, list):
                payload = obj
            if payload is not None:
                self._parse_text_lines([str(x) for x in payload])
                return
        except Exception:
            pass
        # Fallback plain text
        self._parse_text_lines(t.splitlines())

    def match_domain(self, qname: str) -> bool:
        name = (qname or "").lower().rstrip(".")
        if not name:
            return False
        if name in self.domain_exact:
            return True
        labels = name.split(".")
        for i in range(len(labels)):
            suf = ".".join(labels[i:])
            if suf in self.domain_suffix:
                return True
        for kw in self.keywords:
            if kw and kw in name:
                return True
        return False

    def match_ips(self, ip_objs) -> bool:
        if not self.has_ip_rules or not ip_objs:
            return False
        for ip_obj in ip_objs:
            try:
                if isinstance(ip_obj, ipaddress.IPv4Address) and self.cidr_v4.contains(ip_obj):
                    return True
                if isinstance(ip_obj, ipaddress.IPv6Address) and self.cidr_v6.contains(ip_obj):
                    return True
            except Exception:
                continue
        return False


def parse_acl4ssr_ini(text: str):
    rules = []
    groups = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("ruleset="):
            rest = line[len("ruleset=") :].strip()
            if "," not in rest:
                continue
            group, spec = rest.split(",", 1)
            rules.append({"kind": "INI-RULESET", "target": group.strip(), "spec": spec.strip()})
            continue
        if line.startswith("custom_proxy_group="):
            rest = line[len("custom_proxy_group=") :].strip()
            parts = rest.split("`")
            if len(parts) < 2:
                continue
            name = parts[0].strip()
            gtype = parts[1].strip().lower()
            params = parts[2:]
            items = []
            url = None
            interval = None
            if gtype in ("url-test", "fallback", "load-balance"):
                if params:
                    items.append({"kind": "regex", "value": params[0]})
                if len(params) >= 2:
                    url = params[1]
                if len(params) >= 3:
                    m = re.match(r"^(\\d+)", str(params[2]).strip())
                    if m:
                        interval = int(m.group(1))
            else:
                for p in params:
                    token = str(p).strip()
                    if not token:
                        continue
                    if token.startswith("[]"):
                        items.append({"kind": "option", "value": token[2:]})
                    else:
                        items.append({"kind": "regex", "value": token})
            groups[name] = {"name": name, "type": gtype, "items": items, "url": url, "interval": interval}
            continue
    return rules, groups


def parse_shadowrocket_conf(text: str):
    rules = []
    groups = {}
    section = ""
    default_sep = re.compile(r"\s*=\s*")
    t = (text or "").replace("\r\n", "\n").replace("\r", "\n")

    for raw in t.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue

        if section in ("proxy group", "proxy-group", "proxygroup"):
            if "=" not in line:
                continue
            name, rest = default_sep.split(line, maxsplit=1)
            name = name.strip()
            rest = rest.strip()
            if not name or not rest:
                continue
            parts = [p.strip() for p in rest.split(",") if p.strip()]
            if not parts:
                continue
            gtype = parts[0].strip().lower()
            items = []
            url = None
            interval = None
            default_name = None
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    k = k.strip().lower()
                    v = v.strip()
                    if k in ("url", "test-url"):
                        if v:
                            url = v
                        continue
                    if k == "interval":
                        m = re.match(r"^(\d+)", v)
                        if m:
                            interval = int(m.group(1))
                        continue
                    if k in ("policy-regex-filter", "regex"):
                        if v:
                            items.append({"kind": "regex", "value": v})
                        continue
                    if k in ("policy-select-name", "default"):
                        if v:
                            default_name = v
                        continue
                    continue
                token = p.strip()
                if not token:
                    continue
                items.append({"kind": "option", "value": token})
            items = _normalize_group_items(items)
            if not default_name or str(default_name).strip().upper() == "PROXY":
                default_name = "DIRECT"
            if default_name:
                idx = None
                for i, item in enumerate(items):
                    if item.get("kind") == "option" and str(item.get("value")) == default_name:
                        idx = i
                        break
                if idx is not None:
                    item = items.pop(idx)
                    items.insert(0, item)
                else:
                    items.insert(0, {"kind": "option", "value": default_name})
            groups[name] = {"name": name, "type": gtype, "items": items, "url": url, "interval": interval}
            continue

        if section == "rule":
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if not parts:
                continue
            kind = parts[0].upper()
            if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                if len(parts) >= 3:
                    rules.append({"kind": kind, "value": parts[1].lower(), "target": parts[2]})
                continue
            if kind in ("IP-CIDR", "IP-CIDR6"):
                if len(parts) >= 3:
                    try:
                        net = ipaddress.ip_network(parts[1], strict=False)
                    except Exception:
                        continue
                    no_resolve = any(p.lower() == "no-resolve" for p in parts[3:])
                    rules.append({"kind": kind, "value": parts[1], "net": net, "target": parts[2], "no_resolve": no_resolve})
                continue
            if kind in ("GEOIP",):
                if len(parts) >= 3:
                    rules.append({"kind": "GEOIP", "value": parts[1].upper(), "target": parts[2]})
                continue
            if kind in ("RULE-SET", "DOMAIN-SET"):
                if len(parts) >= 3:
                    rules.append({"kind": "RULE-SET", "value": parts[1], "target": parts[2]})
                continue
            if kind in ("FINAL", "MATCH"):
                if len(parts) >= 2:
                    rules.append({"kind": "MATCH", "target": parts[1]})
                continue
    return rules, groups


def parse_clash_yaml_config(text: str):
    """Parse standard Clash/Mihomo config.yaml (subset we need)."""
    obj = yaml.safe_load(text or "") or {}
    groups = {}
    rules = []
    providers_def = obj.get("rule-providers") if isinstance(obj, dict) else None
    if isinstance(obj, dict) and isinstance(obj.get("proxy-groups"), list):
        for g in obj.get("proxy-groups"):
            if not isinstance(g, dict):
                continue
            name = str(g.get("name") or "").strip()
            if not name:
                continue
            gtype = str(g.get("type") or "select").strip().lower()
            items = []
            proxies = g.get("proxies")
            if isinstance(proxies, list):
                for m in proxies:
                    items.append({"kind": "option", "value": str(m)})
            url = g.get("url")
            interval = g.get("interval")
            try:
                interval = int(interval) if interval is not None else None
            except Exception:
                interval = None
            groups[name] = {"name": name, "type": gtype, "items": items, "url": url, "interval": interval}
    if isinstance(obj, dict) and isinstance(obj.get("rules"), list):
        for r in obj.get("rules"):
            s = str(r).strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split(",")]
            kind = parts[0].upper() if parts else ""
            if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                if len(parts) >= 3:
                    rules.append({"kind": kind, "value": parts[1].lower(), "target": parts[2]})
                continue
            if kind in ("IP-CIDR", "IP-CIDR6"):
                if len(parts) >= 3:
                    try:
                        net = ipaddress.ip_network(parts[1], strict=False)
                    except Exception:
                        continue
                    rules.append({"kind": kind, "value": parts[1], "net": net, "target": parts[2]})
                continue
            if kind in ("GEOIP",):
                if len(parts) >= 3:
                    rules.append({"kind": "GEOIP", "value": parts[1].upper(), "target": parts[2]})
                continue
            if kind in ("RULE-SET",):
                if len(parts) >= 3:
                    rules.append({"kind": "RULE-SET", "value": parts[1], "target": parts[2]})
                continue
            if kind in ("MATCH", "FINAL"):
                if len(parts) >= 2:
                    rules.append({"kind": "MATCH", "target": parts[1]})
                continue
            # ignore unsupported types (PROCESS-NAME / SRC-IP-CIDR etc.)
    return rules, groups, providers_def


def load_rule_provider(url: str, cache_dir: str, force: bool = False) -> RuleProvider:
    suffix = ".yaml" if url.lower().endswith((".yml", ".yaml")) else ".txt"
    try:
        text = fetch_text_cached(url, cache_dir, suffix=suffix, force=force)
    except Exception:
        text = ""
    return RuleProvider(name=url, url=url, text=text)


def _normalize_group_type(t: str) -> str:
    t = (t or "").strip().lower()
    if t in ("select", "url-test", "fallback", "load-balance"):
        return t
    return "select"

def _normalize_group_items(items: list) -> list:
    """Remove PROXY, ensure DIRECT exists and stays at first position."""
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("kind") != "option":
            out.append(item)
            continue
        val = str(item.get("value") or "").strip()
        if not val:
            continue
        if val.upper() == "PROXY":
            continue
        out.append({"kind": "option", "value": val})
    # ensure DIRECT exists and move to front
    idx = None
    for i, item in enumerate(out):
        if item.get("kind") == "option" and str(item.get("value") or "").strip().upper() == "DIRECT":
            idx = i
            break
    if idx is None:
        out.insert(0, {"kind": "option", "value": "DIRECT"})
    elif idx != 0:
        out.insert(0, out.pop(idx))
    return out


def build_proxy_catalog(ip_pool: list, ip_meta: dict) -> dict:
    """Return proxy_name -> {ip, match_text, meta}."""
    proxies = {}
    for ip in ip_pool or []:
        meta = ip_meta.get(ip) if isinstance(ip_meta, dict) else None
        meta = meta if isinstance(meta, dict) else {}
        cc = (meta.get("country_iso") or "").upper()
        en, zh = COUNTRY_LABELS.get(cc, ("", ""))
        isp = meta.get("asn_org") or ""
        match_text = " ".join([ip, cc, en, zh, str(isp)]).strip()
        proxies[ip] = {"ip": ip, "match_text": match_text, "meta": meta}
    return proxies


def materialize_group_members(group: dict, proxies: dict) -> list:
    """Expand group items into member names (options + regex-expanded proxies), deduping while preserving order."""
    members = []
    for item in group.get("items") or []:
        kind = item.get("kind")
        val = str(item.get("value") or "")
        if not val:
            continue
        if kind == "option":
            members.append(val)
            continue
        if kind == "regex":
            try:
                rx = re.compile(val, flags=re.IGNORECASE)
            except Exception:
                continue
            for name, p in proxies.items():
                if rx.search(p.get("match_text") or name):
                    members.append(name)
    # de-dup
    return list(dict.fromkeys(members))


def parse_ip_list_to_trie(text: str) -> CidrTrie:
    trie = CidrTrie(32)
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or s.startswith(("#", ";")):
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                trie.insert(net)
        except Exception:
            continue
    return trie


class ClashPolicy:
    def __init__(self, kind: str):
        self.kind = kind
        self.rules = []
        self.groups = {}
        self.providers = {}
        self.loaded_at = time.time()
        self.rule_count = 0


def load_clash_policy(cfg: dict, force: bool = False) -> ClashPolicy:
    """Load policy from cfg['clash_profile_url'] (INI or YAML), including rule providers."""
    cache_dir = _cache_dir_from_cfg(cfg)
    source = (cfg.get("clash_profile_source") or DEFAULT_CONFIG.get("clash_profile_source") or "local").strip().lower()
    if source not in ("local", "remote"):
        source = DEFAULT_CONFIG.get("clash_profile_source") or "local"

    if source == "local":
        _ensure_local_policy_file()
        url = str(LOCAL_POLICY_PATH)
        text = _read_local_policy_text()
    else:
        url = (cfg.get("clash_profile_url") or DEFAULT_CONFIG["clash_profile_url"]).strip()
        if url.lower().endswith(".ini"):
            profile_suffix = ".ini"
        elif url.lower().endswith((".yml", ".yaml")):
            profile_suffix = ".yaml"
        elif url.lower().endswith(".conf"):
            profile_suffix = ".conf"
        else:
            profile_suffix = ".txt"
        text = fetch_text_cached(url, cache_dir, suffix=profile_suffix, force=force)
    kind = _detect_profile_kind(text, url=url)
    policy = ClashPolicy(kind=kind)

    if kind == "ini":
        ini_rules, ini_groups = parse_acl4ssr_ini(text)
        for gname, g in ini_groups.items():
            g["type"] = _normalize_group_type(g.get("type"))
            if g["type"] == "select":
                g["items"] = _normalize_group_items(g.get("items") or [])
            policy.groups[gname] = g

        for r in ini_rules:
            target = r.get("target")
            spec = (r.get("spec") or "").strip()
            if not target or not spec:
                continue
            if spec.startswith("[]GEOIP,"):
                cc = spec.split(",", 1)[1].strip().upper() if "," in spec else ""
                policy.rules.append({"kind": "GEOIP", "value": cc, "target": target})
                policy.rule_count += 1
                continue
            if spec.startswith("[]FINAL"):
                policy.rules.append({"kind": "MATCH", "target": target})
                policy.rule_count += 1
                continue
            provider_url = spec
            if spec.startswith("clash-classic:"):
                provider_url = spec.split(":", 1)[1].strip()
            if provider_url:
                if provider_url not in policy.providers:
                    policy.providers[provider_url] = load_rule_provider(provider_url, cache_dir, force=force)
                policy.rules.append({"kind": "RULE-SET", "value": provider_url, "target": target})
                policy.rule_count += 1
        return policy

    if kind == "shadowrocket":
        s_rules, s_groups = parse_shadowrocket_conf(text)
        for gname, g in s_groups.items():
            g["type"] = _normalize_group_type(g.get("type"))
            if g["type"] == "select":
                g["items"] = _normalize_group_items(g.get("items") or [])
            policy.groups[gname] = g
        policy.rules = s_rules or []
        policy.rule_count = len(policy.rules)

        # Case-insensitive mapping for Shadowrocket group names in rule targets/options.
        group_lower_map = {str(k).lower(): k for k in policy.groups.keys()}
        for r in policy.rules:
            target = r.get("target")
            if isinstance(target, str):
                mapped = group_lower_map.get(target.lower())
                if mapped:
                    r["target"] = mapped

        for g in policy.groups.values():
            items = g.get("items") or []
            for item in items:
                if item.get("kind") != "option":
                    continue
                val = str(item.get("value") or "")
                if not val or val.upper() in ("DIRECT", "REJECT"):
                    continue
                mapped = group_lower_map.get(val.lower())
                if mapped:
                    item["value"] = mapped

        for r in policy.rules:
            if r.get("kind") != "RULE-SET":
                continue
            provider_key = (r.get("value") or "").strip()
            if not provider_key or provider_key in policy.providers:
                continue
            if provider_key.lower().startswith(("http://", "https://")):
                policy.providers[provider_key] = load_rule_provider(provider_key, cache_dir, force=force)
                continue
            # Local file path (relative to app.py if not absolute)
            try:
                p = Path(provider_key)
                if not p.is_absolute():
                    p = Path(__file__).parent / p
                if p.exists():
                    content = p.read_text(encoding="utf-8", errors="ignore")
                    policy.providers[provider_key] = RuleProvider(name=provider_key, url=str(p), text=content)
            except Exception:
                continue
        return policy

    # YAML config
    y_rules, y_groups, providers_def = parse_clash_yaml_config(text)
    for gname, g in (y_groups or {}).items():
        g["type"] = _normalize_group_type(g.get("type"))
        if g["type"] == "select":
            g["items"] = _normalize_group_items(g.get("items") or [])
        policy.groups[gname] = g
    policy.rules = y_rules or []
    policy.rule_count = len(policy.rules)

    # Load rule-providers referenced by RULE-SET
    referenced = {r.get("value") for r in policy.rules if r.get("kind") == "RULE-SET"}
    if isinstance(providers_def, dict):
        for name in referenced:
            if not name or name in policy.providers:
                continue
            pd = providers_def.get(name)
            if not isinstance(pd, dict):
                continue
            purl = pd.get("url")
            ppath = pd.get("path")
            if isinstance(ppath, str) and not purl:
                try:
                    p = Path(ppath)
                    if not p.is_absolute():
                        p = Path(__file__).parent / p
                    if p.exists():
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        policy.providers[name] = RuleProvider(name=name, url=str(p), text=content)
                        continue
                except Exception:
                    pass
            if isinstance(purl, str) and purl.strip():
                policy.providers[name] = load_rule_provider(purl.strip(), cache_dir, force=force)

    return policy

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
        # Legacy规则/分类分流已废弃，保留字段仅用于兼容旧配置文件
        self.rules = {}
        self.domain_map = {}
        self.keyword_rules = []
        self.cidr_rules_v4 = []
        self.cidr_rules_v6 = []
        # Clash 策略
        self.clash_policy: Optional[ClashPolicy] = None
        self.rules_loaded_at = 0
        self.ip_meta_cache = {}
        self.ip_meta_fetched_at = 0
        self.ip_meta_site_cached = None
        self.urltest_cache = {}
        self.geoip_cn_trie = None
        self.geoip_cn_loaded_at = 0
        self.reloading = False
        # Load policy in background to avoid blocking startup (remote fetch + IP meta warmup can be slow).
        try:
            self.reload_rules_async(force=False)
        except Exception:
            pass

    def save(self):
        with self.lock:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)

    def update_ip_pool(self, ip_pool, upstream_dns, upstream_pool):
        with self.lock:
            old_pool = list(self.config.get("ip_pool", []))
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

            self.config["ip_pool"] = ip_pool_norm
            self.config["upstream_dns"] = upstream_dns
            self.config["upstream_dns_pool"] = upstream_pool_norm
            # Invalidate caches when pool changes
            if old_pool != ip_pool_norm:
                self.urltest_cache = {}
                self.ip_meta_cache = {k: v for k, v in self.ip_meta_cache.items() if k in set(ip_pool_norm)}
            self.save()

    def set_ip_info_site(self, site: str) -> bool:
        site_norm = (site or "").strip().lower()
        if site_norm not in IP_INFO_SITES:
            return False
        with self.lock:
            current = (self.config.get("ip_info_site") or DEFAULT_CONFIG.get("ip_info_site") or "netvigator").strip().lower()
            if current == site_norm:
                return False
            self.config["ip_info_site"] = site_norm
            # invalidate cache when site changes
            self.ip_meta_cache = {}
            self.ip_meta_fetched_at = 0
            self.ip_meta_site_cached = site_norm
            self.save()
        return True

    def reload_rules(self, force: bool = False):
        """Reload Clash policy from profile URL (kept old name for UI compatibility)."""
        with self.lock:
            cfg_copy = dict(self.config)
        policy = load_clash_policy(cfg_copy, force=force)
        with self.lock:
            self.clash_policy = policy
            self.rules_loaded_at = policy.loaded_at
            # policy changed -> invalidate url-test cache
            self.urltest_cache = {}
        # NOTE: Do not probe/fetch IP meta here to avoid blocking and unintended network access.

    def reload_rules_async(self, force: bool = False):
        with self.lock:
            if self.reloading:
                return False
            self.reloading = True

        def worker():
            try:
                self.reload_rules(force=force)
            finally:
                with self.lock:
                    self.reloading = False

        threading.Thread(target=worker, daemon=True).start()
        return True

    def get_snapshot(self):
        with self.lock:
            cfg_copy = self.config.copy()
            pol = self.clash_policy
            rules_meta = {
                "policy_kind": getattr(pol, "kind", None),
                "policy_rule_count": getattr(pol, "rule_count", 0) if pol else 0,
                "policy_group_count": len(getattr(pol, "groups", {}) or {}) if pol else 0,
                "policy_provider_count": len(getattr(pol, "providers", {}) or {}) if pol else 0,
                "rules_loaded_at": self.rules_loaded_at,
                "reloading": self.reloading,
            }
        meta = rules_meta
        combined = {**cfg_copy, **meta}
        return json.dumps(combined).encode("utf-8"), combined

    def set_clash_profile_url(self, url: str) -> bool:
        url = (url or "").strip()
        if not url:
            return False
        with self.lock:
            if self.config.get("clash_profile_url") == url:
                return False
            self.config["clash_profile_url"] = url
            self.save()
        return True

    def set_clash_profile_source(self, source: str) -> bool:
        source = (source or "").strip().lower()
        if source not in ("local", "remote"):
            return False
        with self.lock:
            if self.config.get("clash_profile_source") == source:
                return False
            self.config["clash_profile_source"] = source
            self.save()
        return True

    def set_clash_group_selected(self, group: str, selected: str) -> bool:
        group = str(group or "").strip()
        selected = str(selected or "").strip()
        if not group:
            return False
        with self.lock:
            sel = self.config.get("clash_group_selection")
            if not isinstance(sel, dict):
                sel = {}
            # "__auto__" means remove manual override (use group default/auto behavior)
            if selected in ("", "__auto__"):
                if group not in sel:
                    return False
                sel.pop(group, None)
                self.config["clash_group_selection"] = sel
                self.save()
                return True
            if sel.get(group) == selected:
                return False
            sel[group] = selected
            self.config["clash_group_selection"] = sel
            self.save()
        return True

    def is_ipv6_node(self, selected_ip: str) -> bool:
        """Return True if the selected node should be treated as IPv6."""
        with self.lock:
            meta = self.ip_meta_cache.get(selected_ip)
        if isinstance(meta, dict):
            real_ip = meta.get("real_ip")
            if ip_version(real_ip) == 6:
                return True
        return False

    def pick_region_fallback_ipv4(self, selected_ip: str) -> Optional[str]:
        """Pick a same-region IPv4 candidate for an IPv6-selected node."""
        if not self.is_ipv6_node(selected_ip):
            return None
        with self.lock:
            pool = list(self.config.get("ip_pool", []))
            meta_cache = dict(self.ip_meta_cache)
        meta = meta_cache.get(selected_ip)
        if not isinstance(meta, dict):
            return None
        region = (meta.get("country_iso") or "").upper()
        if not region:
            return None
        candidates = []
        for ip in pool:
            if ip == selected_ip:
                continue
            try:
                ip2 = ipaddress.ip_address(ip)
            except Exception:
                continue
            if not isinstance(ip2, ipaddress.IPv4Address):
                continue
            m = meta_cache.get(ip)
            if not isinstance(m, dict):
                continue
            if (m.get("country_iso") or "").upper() != region:
                continue
            # Only accept real IPv4 nodes (skip nodes that resolve to IPv6).
            if ip_version(m.get("real_ip")) != 4:
                continue
            ok = bool(m.get("ok")) if "ok" in m else False
            ms = m.get("ms")
            try:
                ms_i = int(ms)
            except Exception:
                ms_i = None
            candidates.append((ok, ms_i, ip))
        if not candidates:
            return None
        ok_candidates = [c for c in candidates if c[0]]
        pick_list = ok_candidates if ok_candidates else candidates
        pick_list.sort(key=lambda x: (x[1] is None, x[1] if x[1] is not None else 10**9))
        return pick_list[0][2]

    def _ensure_geoip_cn(self, force: bool = False):
        now = time.time()
        with self.lock:
            if self.geoip_cn_trie is not None and not force and now - self.geoip_cn_loaded_at < 86400:
                return
            url = (self.config.get("geoip_cn_url") or DEFAULT_CONFIG["geoip_cn_url"]).strip()
            cache_dir = _cache_dir_from_cfg(self.config)
        try:
            text = fetch_text_cached(url, cache_dir, suffix=".txt", force=force, timeout=20)
            trie = parse_ip_list_to_trie(text)
        except Exception:
            return
        with self.lock:
            self.geoip_cn_trie = trie
            self.geoip_cn_loaded_at = now

    @staticmethod
    def _match_domain_suffix(name: str, suffix: str) -> bool:
        if name == suffix:
            return True
        return name.endswith("." + suffix)

    def _probe_latency_ms(self, ip: str, url: Optional[str] = None, timeout: float = 4.0) -> Tuple[bool, int]:
        return probe_url_latency(ip, url or DEFAULT_URLTEST_URL, timeout=timeout)

    def _urltest_pick(self, group_name: str, group: dict, candidates: list) -> str:
        interval = group.get("interval") or 300
        try:
            interval = int(interval)
        except Exception:
            interval = 300
        test_url = (group.get("url") or DEFAULT_URLTEST_URL) if isinstance(group, dict) else DEFAULT_URLTEST_URL
        test_url = str(test_url or DEFAULT_URLTEST_URL).strip() or DEFAULT_URLTEST_URL
        now = time.time()
        key = (group_name, test_url, tuple(candidates))
        with self.lock:
            cached = self.urltest_cache.get(key)
        if cached and now - cached.get("tested_at", 0) < interval:
            return cached.get("selected") or "DIRECT"
        best = None
        best_ms = None
        results = {}
        for ip in candidates:
            ok, ms = self._probe_latency_ms(ip, url=test_url)
            results[ip] = {"ok": ok, "ms": ms}
            if ok and (best is None or ms < best_ms):
                best = ip
                best_ms = ms
        if best is None and candidates:
            best = candidates[0]
        with self.lock:
            self.urltest_cache[key] = {"selected": best or "DIRECT", "tested_at": now, "results": results}
        return best or "DIRECT"

    def _resolve_member(self, name: str, proxies: dict, seen: set, allow_probe: bool = False) -> str:
        if not name:
            return "DIRECT"
        upper = name.upper()
        if upper in ("DIRECT", "REJECT"):
            return upper
        if name in proxies:
            return name
        with self.lock:
            pol = self.clash_policy
            sel = self.config.get("clash_group_selection") if isinstance(self.config.get("clash_group_selection"), dict) else {}
        if not pol or name not in (pol.groups or {}):
            return "DIRECT"
        if name in seen:
            return "DIRECT"
        seen.add(name)
        group = pol.groups.get(name) or {}
        gtype = _normalize_group_type(group.get("type"))
        if gtype == "select":
            chosen = sel.get(name) if isinstance(sel, dict) else None
            chosen = str(chosen or "").strip()
            # If user explicitly selected something, trust it even if it is no longer in the
            # dynamically materialized member list (e.g. regex depends on IP meta).
            if chosen:
                chosen_upper = chosen.upper()
                if chosen_upper in ("DIRECT", "REJECT"):
                    return chosen_upper
                if chosen in proxies:
                    return chosen
                if is_valid_ip(chosen):
                    return chosen
                if chosen in (pol.groups or {}):
                    return self._resolve_member(chosen, proxies, seen, allow_probe=allow_probe)
            members = materialize_group_members(group, proxies)
            chosen_fallback = members[0] if members else "DIRECT"
            return self._resolve_member(chosen_fallback, proxies, seen, allow_probe=allow_probe)
        # url-test/fallback/load-balance -> auto pick (may probe if allowed)
        # Allow manual override for non-select groups as well.
        chosen = sel.get(name) if isinstance(sel, dict) else None
        chosen = str(chosen or "").strip()
        if chosen:
            chosen_upper = chosen.upper()
            if chosen_upper in ("DIRECT", "REJECT"):
                return chosen_upper
            if chosen in proxies:
                return chosen
            if is_valid_ip(chosen):
                return chosen
            if chosen in (pol.groups or {}):
                return self._resolve_member(chosen, proxies, seen, allow_probe=allow_probe)
        members = materialize_group_members(group, proxies)
        candidates = [m for m in members if m in proxies]
        if not candidates:
            picked = "DIRECT"
        elif allow_probe:
            picked = self._urltest_pick(name, group, candidates)
        else:
            test_url = (group.get("url") or DEFAULT_URLTEST_URL) if isinstance(group, dict) else DEFAULT_URLTEST_URL
            test_url = str(test_url or DEFAULT_URLTEST_URL).strip() or DEFAULT_URLTEST_URL
            key = (name, test_url, tuple(candidates))
            with self.lock:
                cached = self.urltest_cache.get(key) if isinstance(self.urltest_cache, dict) else None
            picked = cached.get("selected") if isinstance(cached, dict) else None
            if not picked:
                picked = candidates[0]
        return self._resolve_member(str(picked or "DIRECT"), proxies, seen, allow_probe=allow_probe)

    def resolve_chain(self, name: str, proxies: dict, max_depth: int = 12, allow_probe: bool = False) -> List[str]:
        """Resolve a member into its final leaf and return the resolution chain.

        Example:
          '🎬 NETFLIX' member '🇸🇬 新加坡节点' -> ['🇸🇬 新加坡节点', '22.22.22.10']
        """
        cur = str(name or "").strip()
        if not cur:
            return ["DIRECT"]
        chain: List[str] = []
        seen: set = set()
        for _ in range(max_depth):
            chain.append(cur)
            upper = cur.upper()
            if upper in ("DIRECT", "REJECT"):
                break
            if cur in proxies:
                break
            if is_valid_ip(cur):
                break

            with self.lock:
                pol = self.clash_policy
                sel = self.config.get("clash_group_selection") if isinstance(self.config.get("clash_group_selection"), dict) else {}

            if not pol or cur not in (pol.groups or {}):
                chain.append("DIRECT")
                break
            if cur in seen:
                chain.append("DIRECT")
                break
            seen.add(cur)

            group = pol.groups.get(cur) or {}
            gtype = _normalize_group_type(group.get("type"))

            def valid_override(v: str) -> Optional[str]:
                v = str(v or "").strip()
                if not v or v == "__auto__":
                    return None
                vu = v.upper()
                if vu in ("DIRECT", "REJECT"):
                    return vu
                if v in proxies:
                    return v
                if is_valid_ip(v):
                    return v
                if v in (pol.groups or {}):
                    return v
                return None

            chosen = valid_override(sel.get(cur) if isinstance(sel, dict) else None)
            if chosen:
                cur = chosen
                continue

            members = materialize_group_members(group, proxies)
            if gtype == "select":
                cur = members[0] if members else "DIRECT"
                continue

            candidates = [m for m in members if m in proxies]
            if not candidates:
                cur = "DIRECT"
                continue
            if allow_probe:
                cur = self._urltest_pick(cur, group, candidates)
                continue
            # cached-only: do not block page render; return AUTO if not yet tested
            key = (cur, tuple(candidates))
            with self.lock:
                cached = self.urltest_cache.get(key) if isinstance(self.urltest_cache, dict) else None
            picked = cached.get("selected") if isinstance(cached, dict) else None
            cur = str(picked).strip() if picked else "AUTO"
            if cur == "AUTO":
                break

        return chain

    def _eval_policy_target(self, qname: str, ip_objs=None):
        with self.lock:
            pol = self.clash_policy
        if not pol:
            return "DIRECT"
        name = (qname or "").lower().rstrip(".")
        if not name:
            return "DIRECT"
        for rule in pol.rules or []:
            kind = rule.get("kind")
            if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                val = rule.get("value") or ""
                if kind == "DOMAIN" and name == val:
                    return rule.get("target")
                if kind == "DOMAIN-SUFFIX" and val and self._match_domain_suffix(name, val):
                    return rule.get("target")
                if kind == "DOMAIN-KEYWORD" and val and val in name:
                    return rule.get("target")
                continue
            if kind == "RULE-SET":
                prov_key = rule.get("value")
                prov = (pol.providers or {}).get(prov_key)
                if not prov:
                    continue
                if prov.match_domain(name):
                    return rule.get("target")
                if prov.has_ip_rules:
                    if ip_objs is None:
                        return None
                    if prov.match_ips(ip_objs):
                        return rule.get("target")
                continue
            if kind in ("IP-CIDR", "IP-CIDR6"):
                net = rule.get("net")
                if not net:
                    continue
                if ip_objs is None:
                    if rule.get("no_resolve"):
                        continue
                    return None
                for ip_obj in ip_objs or []:
                    try:
                        if ip_obj.version == net.version and ip_obj in net:
                            return rule.get("target")
                    except Exception:
                        continue
                continue
            if kind == "GEOIP":
                cc = (rule.get("value") or "").upper()
                if ip_objs is None:
                    return None
                if cc == "CN":
                    self._ensure_geoip_cn()
                    with self.lock:
                        trie = self.geoip_cn_trie
                    if trie:
                        for ip_obj in ip_objs or []:
                            try:
                                if isinstance(ip_obj, ipaddress.IPv4Address) and trie.contains(ip_obj):
                                    return rule.get("target")
                            except Exception:
                                continue
                continue
            if kind in ("MATCH", "FINAL"):
                return rule.get("target")
        return "DIRECT"

    def explain_policy_target(self, qname: str, ip_objs=None):
        """Return (target, matched_rule). target may be None if IPs are required."""
        with self.lock:
            pol = self.clash_policy
        if not pol:
            return "DIRECT", None
        name = (qname or "").lower().rstrip(".")
        if not name:
            return "DIRECT", None
        for rule in pol.rules or []:
            kind = rule.get("kind")
            if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                val = rule.get("value") or ""
                if kind == "DOMAIN" and name == val:
                    return rule.get("target"), rule
                if kind == "DOMAIN-SUFFIX" and val and self._match_domain_suffix(name, val):
                    return rule.get("target"), rule
                if kind == "DOMAIN-KEYWORD" and val and val in name:
                    return rule.get("target"), rule
                continue
            if kind == "RULE-SET":
                prov_key = rule.get("value")
                prov = (pol.providers or {}).get(prov_key)
                if not prov:
                    continue
                if prov.match_domain(name):
                    return rule.get("target"), rule
                if prov.has_ip_rules:
                    if ip_objs is None:
                        return None, rule
                    if prov.match_ips(ip_objs):
                        return rule.get("target"), rule
                continue
            if kind in ("IP-CIDR", "IP-CIDR6"):
                net = rule.get("net")
                if not net:
                    continue
                if ip_objs is None:
                    if rule.get("no_resolve"):
                        continue
                    return None, rule
                for ip_obj in ip_objs or []:
                    try:
                        if ip_obj.version == net.version and ip_obj in net:
                            return rule.get("target"), rule
                    except Exception:
                        continue
                continue
            if kind in ("GEOIP",):
                cc = (rule.get("value") or "").upper()
                if ip_objs is None:
                    return None, rule
                if cc == "CN":
                    self._ensure_geoip_cn()
                    with self.lock:
                        trie = self.geoip_cn_trie
                    if trie:
                        for ip_obj in ip_objs or []:
                            try:
                                if isinstance(ip_obj, ipaddress.IPv4Address) and trie.contains(ip_obj):
                                    return rule.get("target"), rule
                            except Exception:
                                continue
                continue
            if kind in ("MATCH", "FINAL"):
                return rule.get("target"), rule
        return "DIRECT", None

    def decide_route(self, qname: str, ips: Optional[List[str]] = None):
        """Return ('ip', ip) / ('upstream', upstream_dns) / ('reject', None) / None(needs upstream ips)."""
        with self.lock:
            upstream_dns = self.config.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
            ip_pool = list(self.config.get("ip_pool", []))
        ip_objs = None
        if ips is not None:
            objs = []
            for ip_s in ips:
                try:
                    objs.append(ipaddress.ip_address(ip_s))
                except Exception:
                    continue
            ip_objs = objs
        target = self._eval_policy_target(qname, ip_objs=ip_objs)
        if target is None:
            return None
        if isinstance(target, str) and target.upper() == "REJECT":
            return ("reject", None)
        if isinstance(target, str) and target.upper() == "DIRECT":
            return ("upstream", upstream_dns)
        if isinstance(target, str) and is_valid_ip(target):
            return ("ip", target)
        # Build proxies using cached IP meta only (DNS path must not trigger probing/fetching).
        ip_meta = self.peek_ip_meta()
        proxies = build_proxy_catalog(ip_pool, ip_meta)
        final = self._resolve_member(str(target), proxies, seen=set(), allow_probe=False)
        if final == "REJECT":
            return ("reject", None)
        if final == "DIRECT":
            return ("upstream", upstream_dns)
        # final is proxy name (ip string)
        if final in proxies:
            return ("ip", proxies[final]["ip"])
        if is_valid_ip(final):
            return ("ip", final)
        return ("upstream", upstream_dns)

    def get_ip_meta(self, force=False):
        """Return IP meta info dict ip->meta.

        fetch_ip_meta is only triggered when:
          - force=True (user clicked "refresh probe"), or
          - the IP is missing in cache (first dashboard open / new IP added).
        """
        with self.lock:
            pool = list(self.config.get("ip_pool", []))
            site = (self.config.get("ip_info_site") or DEFAULT_CONFIG.get("ip_info_site") or "netvigator").strip().lower()
            cached = dict(self.ip_meta_cache) if (not force and self.ip_meta_site_cached == site) else {}
        meta = {}
        for ip in pool:
            if not force and ip in cached and isinstance(cached.get(ip), dict):
                info = dict(cached[ip])
            else:
                info = fetch_ip_meta(ip, site=site)
                if not isinstance(info, dict):
                    info = {}
            lat_ok, lat_ms = probe_url_latency(ip, DEFAULT_URLTEST_URL, timeout=4.0)
            if "meta_ok" not in info:
                info["meta_ok"] = bool(info.get("ok"))
            info["ok"] = bool(lat_ok)
            info["ms"] = int(lat_ms)
            meta[ip] = info
        with self.lock:
            self.ip_meta_cache = meta
            self.ip_meta_fetched_at = time.time()
            self.ip_meta_site_cached = site
        return meta

    def peek_ip_meta(self):
        """Return cached ip meta without triggering fetch."""
        with self.lock:
            return dict(self.ip_meta_cache)

    def get_ip_meta_one(self, ip: str, force=False):
        """Return meta for a single IP.

        fetch_ip_meta is only triggered when:
          - force=True (user clicked "refresh probe"), or
          - this IP is missing in cache (first dashboard open / new IP added).
        """
        now = time.time()
        with self.lock:
            site = (self.config.get("ip_info_site") or DEFAULT_CONFIG.get("ip_info_site") or "netvigator").strip().lower()
            cached = self.ip_meta_cache.get(ip) if (not force and self.ip_meta_site_cached == site) else None
        if not force and isinstance(cached, dict):
            meta = dict(cached)
        else:
            meta = fetch_ip_meta(ip, site=site)
            if not isinstance(meta, dict):
                meta = {}
        lat_ok, lat_ms = probe_url_latency(ip, DEFAULT_URLTEST_URL, timeout=4.0)
        if "meta_ok" not in meta:
            meta["meta_ok"] = bool(meta.get("ok"))
        meta["ok"] = bool(lat_ok)
        meta["ms"] = int(lat_ms)
        with self.lock:
            if self.ip_meta_site_cached != site:
                self.ip_meta_cache = {}
            self.ip_meta_cache[ip] = meta
            self.ip_meta_fetched_at = now
            self.ip_meta_site_cached = site
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


def patch_question_qtype(query: bytes, qend: int, new_qtype: int) -> bytes:
    """Return a copy of a DNS query with its QTYPE replaced.

    Assumes QDCOUNT=1 and that qend is the end offset of the first question.
    """
    if not query or qend < 4 or len(query) < qend:
        return query
    try:
        b = bytearray(query)
        b[qend - 4 : qend - 2] = int(new_qtype).to_bytes(2, "big")
        return bytes(b)
    except Exception:
        return query


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


def build_aaaa_response(query: bytes, ip_str: str, qend: int) -> bytes:
    """Build an IPv6 AAAA record response pointing to ip_str."""
    try:
        ip_bytes = ipaddress.IPv6Address(ip_str).packed
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
    resp += qdcount                 # QDCOUNT
    resp += (1).to_bytes(2, "big")  # ANCOUNT
    resp += (0).to_bytes(2, "big")  # NS
    resp += (0).to_bytes(2, "big")  # AR
    # Question
    resp += query[12:qend]
    # Answer
    resp += b"\xc0\x0c"  # name pointer to offset 12
    resp += (28).to_bytes(2, "big")  # TYPE AAAA
    resp += (1).to_bytes(2, "big")   # CLASS IN
    resp += (60).to_bytes(4, "big")  # TTL
    resp += (16).to_bytes(2, "big")  # RDLENGTH
    resp += ip_bytes
    return bytes(resp)


def forward_query(upstream: str, query: bytes, timeout_ms: int) -> bytes:
    """Forward DNS query to an upstream resolver and return its response."""
    last_err = None
    infos = socket.getaddrinfo(upstream, 53, proto=socket.IPPROTO_UDP)
    for family, socktype, proto, _canon, sockaddr in infos:
        try:
            with socket.socket(family, socktype) as s:
                s.settimeout(timeout_ms / 1000.0)
                s.sendto(query, sockaddr)
                return s.recvfrom(4096)[0]
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise OSError("upstream query failed")


def _read_name(packet: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Read a DNS name at offset, handling compression. Returns (name, next_offset)."""
    labels: List[str] = []
    jumped = False
    next_offset = offset
    while True:
        if offset >= len(packet):
            return None, offset
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        # compression pointer
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                return None, offset + 2
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        offset += 1
        if offset + length > len(packet):
            return None, offset + length
        labels.append(packet[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels).lower() if labels else "", next_offset


def extract_a_records(resp: bytes) -> List[str]:
    """Extract IPv4 A record addresses from a DNS response."""
    ips: List[str] = []
    if len(resp) < 12:
        return ips
    try:
        qdcount = int.from_bytes(resp[4:6], "big")
        ancount = int.from_bytes(resp[6:8], "big")
        pos = 12
        for _ in range(qdcount):
            _, pos = _read_name(resp, pos)
            pos += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            _, pos = _read_name(resp, pos)
            if pos + 10 > len(resp):
                break
            rtype = int.from_bytes(resp[pos : pos + 2], "big")
            rdlen = int.from_bytes(resp[pos + 8 : pos + 10], "big")
            pos += 10
            rdata = resp[pos : pos + rdlen]
            if rtype == 1 and rdlen == 4:
                try:
                    ips.append(str(ipaddress.IPv4Address(rdata)))
                except Exception:
                    pass
            pos += rdlen
    except Exception:
        return ips
    return ips


def extract_aaaa_records(resp: bytes) -> List[str]:
    """Extract IPv6 AAAA record addresses from a DNS response."""
    ips: List[str] = []
    if len(resp) < 12:
        return ips
    try:
        qdcount = int.from_bytes(resp[4:6], "big")
        ancount = int.from_bytes(resp[6:8], "big")
        pos = 12
        for _ in range(qdcount):
            _, pos = _read_name(resp, pos)
            pos += 4  # QTYPE + QCLASS
        for _ in range(ancount):
            _, pos = _read_name(resp, pos)
            if pos + 10 > len(resp):
                break
            rtype = int.from_bytes(resp[pos : pos + 2], "big")
            rdlen = int.from_bytes(resp[pos + 8 : pos + 10], "big")
            pos += 10
            rdata = resp[pos : pos + rdlen]
            if rtype == 28 and rdlen == 16:
                try:
                    ips.append(str(ipaddress.IPv6Address(rdata)))
                except Exception:
                    pass
            pos += rdlen
    except Exception:
        return ips
    return ips


def build_dns_query(qname: str, qtype: int = 1) -> bytes:
    """Build a simple DNS query (RD=1) for qname."""
    name = (qname or "").strip().rstrip(".")
    if not name:
        raise ValueError("empty qname")
    labels = name.split(".")
    parts = []
    for label in labels:
        if not label:
            continue
        if len(label) > 63:
            raise ValueError("label too long")
        parts.append(len(label).to_bytes(1, "big"))
        parts.append(label.encode("utf-8", errors="ignore"))
    qname_bytes = b"".join(parts) + b"\x00"
    qtype = int(qtype)
    qclass = 1
    msg_id = int.from_bytes(os.urandom(2), "big")
    flags = 0x0100  # RD
    header = (
        msg_id.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )
    question = qname_bytes + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")
    return header + question


def query_upstream_records(qname: str, qtype: int, upstream_dns: str, timeout_ms: int) -> List[str]:
    try:
        query = build_dns_query(qname, qtype=qtype)
        resp = forward_query(upstream_dns, query, timeout_ms)
    except Exception:
        return []
    if qtype == 28:
        return extract_aaaa_records(resp)
    return extract_a_records(resp)

def match_ips_to_cidr(ips: List[str], cidr_rules) -> Optional[Tuple[str, str]]:
    """Return (cat, svc) if any IP hits a CIDR rule."""
    if not ips or not cidr_rules:
        return None
    ip_objs = []
    for ip_s in ips:
        try:
            ip_objs.append(ipaddress.ip_address(ip_s))
        except Exception:
            continue
    for net, cat, svc, _pri in cidr_rules:
        for ip_obj in ip_objs:
            try:
                if ip_obj.version == net.version and ip_obj in net:
                    return cat, svc
            except Exception:
                continue
    return None


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
        _, snapshot = cfg.get_snapshot()
        timeout_ms = snapshot.get("timeout_ms", 2000)
        upstream_dns = snapshot.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])

        def check_upstream_aaaa():
            q_aaaa = data if qtype == 28 else patch_question_qtype(data, qend, 28)
            try:
                resp = forward_query(upstream_dns, q_aaaa, timeout_ms)
            except Exception:
                return False, None
            ips6 = extract_aaaa_records(resp)
            return bool(ips6), resp

        # Only override A/AAAA; other types always upstream
        if qtype not in (1, 28):
            try:
                response = forward_query(upstream_dns, data, timeout_ms)
            except Exception:
                response = build_servfail(data)
        elif qtype == 28:
            # For AAAA:
            # - if matched to a specific IPv6 -> answer (only if upstream has AAAA)
            # - if matched to a specific IPv4 -> empty (force v4)
            # - only DIRECT can freely ask upstream for AAAA
            decision = cfg.decide_route(qname, ips=None)
            if decision is None:
                # Need upstream A records to evaluate IP-based rules (e.g. GEOIP/IP-CIDR).
                q_a = patch_question_qtype(data, qend, 1)
                try:
                    upstream_a = forward_query(upstream_dns, q_a, timeout_ms)
                except Exception:
                    upstream_a = build_servfail(q_a)
                ips = extract_a_records(upstream_a)
                decision = cfg.decide_route(qname, ips=ips)
                if decision is None:
                    decision = ("upstream", upstream_dns)

            if decision and decision[0] == "ip" and decision[1]:
                node_ipv6 = cfg.is_ipv6_node(decision[1])
                if node_ipv6:
                    has_aaaa, upstream_aaaa = check_upstream_aaaa()
                    if not has_aaaa:
                        response = build_empty_response(data)
                    else:
                        if ip_version(decision[1]) == 6:
                            response = build_aaaa_response(data, decision[1], qend)
                        else:
                            response = build_empty_response(data)
                else:
                    response = build_empty_response(data)
            elif decision and decision[0] == "reject":
                response = build_empty_response(data)
            else:
                dns = decision[1] if decision and len(decision) > 1 and decision[1] else upstream_dns
                try:
                    response = forward_query(dns, data, timeout_ms)
                except Exception:
                    response = build_servfail(data)
        else:
            # A record
            decision = cfg.decide_route(qname, ips=None)
            upstream_resp = None
            if decision is None:
                # Need upstream A records to evaluate IP-based rules
                try:
                    upstream_resp = forward_query(upstream_dns, data, timeout_ms)
                except Exception:
                    upstream_resp = build_servfail(data)
                ips = extract_a_records(upstream_resp)
                decision = cfg.decide_route(qname, ips=ips)
                if decision is None:
                    decision = ("upstream", upstream_dns)

            if decision and decision[0] == "ip" and decision[1]:
                node_ipv6 = cfg.is_ipv6_node(decision[1])
                if node_ipv6:
                    has_aaaa, _ = check_upstream_aaaa()
                    if has_aaaa:
                        if ip_version(decision[1]) == 4:
                            response = build_a_response(data, decision[1], qend)
                        else:
                            response = build_empty_response(data)
                    else:
                        fallback_ip = cfg.pick_region_fallback_ipv4(decision[1])
                        if fallback_ip:
                            response = build_a_response(data, fallback_ip, qend)
                        else:
                            if upstream_resp is None:
                                try:
                                    upstream_resp = forward_query(upstream_dns, data, timeout_ms)
                                except Exception:
                                    upstream_resp = build_servfail(data)
                            response = upstream_resp
                else:
                    try:
                        ip_obj = ipaddress.ip_address(decision[1])
                    except Exception:
                        ip_obj = None
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        response = build_a_response(data, decision[1], qend)
                    else:
                        response = build_empty_response(data)
            elif decision and decision[0] == "reject":
                response = build_empty_response(data)
            else:
                dns = decision[1] if decision and len(decision) > 1 and decision[1] else upstream_dns
                if upstream_resp is None or dns != upstream_dns:
                    try:
                        upstream_resp = forward_query(dns, data, timeout_ms)
                    except Exception:
                        upstream_resp = build_servfail(data)
                response = upstream_resp
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
        if path.endswith("api/local_policy"):
            text = _read_local_policy_text()
            return self._send(200, text.encode("utf-8"), "text/plain; charset=utf-8")
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
                "policy_kind": snap.get("policy_kind"),
                "policy_rule_count": snap.get("policy_rule_count"),
                "policy_group_count": snap.get("policy_group_count"),
                "policy_provider_count": snap.get("policy_provider_count"),
                "rules_loaded_at": snap.get("rules_loaded_at"),
                "reloading": snap.get("reloading", False),
            }
            return self._send(200, json.dumps(info).encode("utf-8"), "application/json")
        if path.endswith("api/group_section"):
            _, cfg = self.cfg.get_snapshot()
            ip_pool = cfg.get("ip_pool", []) or ["1.1.1.1"]
            upstream_dns = cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
            # Do NOT block page render; use cached meta only (browser will refresh asynchronously).
            ip_meta = self.cfg.peek_ip_meta()
            html_section = self.render_group_section(cfg, ip_pool, upstream_dns, ip_meta)
            return self._send(200, html_section.encode("utf-8"), "text/html; charset=utf-8")
        if path.endswith("api/domain_check"):
            raw = qs.get("domain", [""])[0]
            domain = (raw or "").strip()
            if "://" in domain:
                try:
                    p = urlparse(domain)
                    domain = p.hostname or domain
                except Exception:
                    pass
            domain = (domain or "").strip().rstrip(".")
            if not domain or not re.match(r"^[A-Za-z0-9.-]+$", domain):
                return self._send(400, b"Bad Request: invalid domain", "text/plain; charset=utf-8")
            _, snap = self.cfg.get_snapshot()
            upstream_dns = snap.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
            timeout_ms = snap.get("timeout_ms", 2000)
            ip_pool = snap.get("ip_pool", []) or []
            ip_meta = self.cfg.peek_ip_meta()
            proxies = build_proxy_catalog(ip_pool, ip_meta)
            pol = self.cfg.clash_policy

            lines = []
            lines.append(f"域名: {domain}")
            lines.append(f"策略类型: {getattr(pol, 'kind', '-') if pol else '-'}")

            ips_a = []
            rule_target, rule_info = self.cfg.explain_policy_target(domain, ip_objs=None)
            if rule_target is None:
                ips_a = query_upstream_records(domain, 1, upstream_dns, timeout_ms)
                ip_objs = []
                for ip_s in ips_a:
                    try:
                        ip_objs.append(ipaddress.ip_address(ip_s))
                    except Exception:
                        continue
                rule_target, rule_info = self.cfg.explain_policy_target(domain, ip_objs=ip_objs)

            if rule_info:
                kind = rule_info.get("kind")
                value = rule_info.get("value")
                target = rule_info.get("target")
                if kind == "RULE-SET":
                    lines.append(f"命中规则: RULE-SET -> {target} ({value})")
                elif kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                    lines.append(f"命中规则: {kind} {value} -> {target}")
                elif kind in ("IP-CIDR", "IP-CIDR6", "GEOIP"):
                    lines.append(f"命中规则: {kind} {value} -> {target}")
                elif kind in ("MATCH", "FINAL"):
                    lines.append(f"命中规则: FINAL -> {target}")
            else:
                lines.append("命中规则: (无) -> DIRECT")

            if ips_a:
                lines.append(f"上游A: {', '.join(ips_a)}")

            if rule_target is None:
                rule_target = "DIRECT"

            if pol and isinstance(getattr(pol, "groups", None), dict) and rule_target in pol.groups:
                chain = self.cfg.resolve_chain(rule_target, proxies, allow_probe=False)
                if chain:
                    lines.append("分组链: " + " -> ".join([str(x) for x in chain]))

            decision = self.cfg.decide_route(domain, ips=ips_a or None)
            if decision is None:
                decision = ("upstream", upstream_dns)

            if decision[0] == "reject":
                lines.append("A结果: REJECT")
            elif decision[0] == "upstream":
                if not ips_a:
                    ips_a = query_upstream_records(domain, 1, upstream_dns, timeout_ms)
                if ips_a:
                    lines.append(f"A结果: DIRECT -> {', '.join(ips_a)}")
                else:
                    lines.append("A结果: DIRECT -> (无返回)")
            elif decision[0] == "ip" and decision[1]:
                sel_ip = str(decision[1])
                node_ipv6 = self.cfg.is_ipv6_node(sel_ip)
                if node_ipv6:
                    ips_aaaa = query_upstream_records(domain, 28, upstream_dns, timeout_ms)
                    lines.append(f"上游AAAA: {', '.join(ips_aaaa) if ips_aaaa else '-'}")
                    if ips_aaaa:
                        if ip_version(sel_ip) == 4:
                            lines.append(f"A结果: {sel_ip}（IPv6可用）")
                        else:
                            lines.append("A结果: 空（IPv6可用，节点为IPv6）")
                    else:
                        fallback_ip = self.cfg.pick_region_fallback_ipv4(sel_ip)
                        if fallback_ip:
                            lines.append(f"A结果: {fallback_ip}（同区域IPv4回退）")
                        else:
                            if not ips_a:
                                ips_a = query_upstream_records(domain, 1, upstream_dns, timeout_ms)
                            if ips_a:
                                lines.append(f"A结果: DIRECT -> {', '.join(ips_a)}")
                            else:
                                lines.append("A结果: DIRECT -> (无返回)")
                else:
                    if ip_version(sel_ip) == 4:
                        lines.append(f"A结果: {sel_ip}")
                    else:
                        lines.append("A结果: 空（节点非IPv6且为IPv6地址）")
            else:
                lines.append("A结果: DIRECT")

            payload = {"domain": domain, "lines": lines}
            return self._send(200, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json")
        return self._send(200, self.render_dashboard().encode("utf-8"))

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/")
        qs = parse_qs(urlparse(self.path).query)
        if not self._check_token(qs):
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_POST_BYTES:
            self._send(413, b"Payload Too Large", "text/plain; charset=utf-8")
            return
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        data = parse_qs(raw)

        if path.endswith("save_upstreams"):
            # 只更新提交的部分，其他保持当前配置
            _, snap = self.cfg.get_snapshot()
            current_cfg = snap

            # --- IP 探测站点 ---
            if "ip_info_site" in data:
                site = (data.get("ip_info_site", [""])[0] or "").strip()
                self.cfg.set_ip_info_site(site)

            # --- Clash 策略来源/链接 ---
            if "clash_profile_source" in data:
                src = (data.get("clash_profile_source", [""])[0] or "").strip().lower()
                if src not in ("local", "remote"):
                    self._send(400, b"Bad Request: invalid clash_profile_source", "text/plain; charset=utf-8")
                    return
                self.cfg.set_clash_profile_source(src)

            if "clash_profile_url" in data:
                url = (data.get("clash_profile_url", [""])[0] or "").strip()
                if url:
                    try:
                        _validate_remote_url(url)
                    except Exception as e:
                        self._send(400, f"Bad Request: {e}".encode("utf-8"), "text/plain; charset=utf-8")
                        return
                    self.cfg.set_clash_profile_url(url)

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

            # --- Clash 分流组选择（仅保存提交项） ---
            for key, vals in data.items():
                if not key.startswith("selg__"):
                    continue
                group = key[len("selg__") :]
                val = vals[0]
                self.cfg.set_clash_group_selected(group, val)

            self.cfg.update_ip_pool(new_ip_pool, new_upstream_dns, new_upstream_pool)
        elif path.endswith("save_local_policy"):
            text = data.get("text", [""])[0]
            try:
                _write_local_policy_text(text)
            except Exception as e:
                self._send(400, f"Bad Request: {e}".encode("utf-8"), "text/plain; charset=utf-8")
                return
            # Apply immediately (no-op if current strategy is remote).
            self.cfg.reload_rules_async(force=True)
        elif path.endswith("refresh_rules"):
            started = self.cfg.reload_rules_async(force=True)
            resp = {"started": started}
            self._send(202 if started else 200, json.dumps(resp).encode("utf-8"), "application/json")
            return
        # 默认返回 204，避免浏览器自动重定向到根路径（可能丢失 token）
        self.send_response(204)
        self.end_headers()

    def render_dashboard(self) -> str:
        _, cfg = self.cfg.get_snapshot()
        ip_pool = cfg.get("ip_pool", []) or ["1.1.1.1"]
        upstream_dns = cfg.get("upstream_dns", DEFAULT_CONFIG["upstream_dns"])
        upstream_pool = cfg.get("upstream_dns_pool", [upstream_dns])
        # 首屏避免阻塞：仅使用缓存的 IP 元信息；浏览器会异步刷新
        ip_meta = self.cfg.peek_ip_meta()
        token = cfg.get("token", "")
        clash_profile_source = cfg.get("clash_profile_source", DEFAULT_CONFIG.get("clash_profile_source", "local"))
        clash_profile_url = cfg.get("clash_profile_url", DEFAULT_CONFIG["clash_profile_url"])
        policy_kind = cfg.get("policy_kind") or "-"
        policy_rule_count = cfg.get("policy_rule_count", 0)
        policy_group_count = cfg.get("policy_group_count", 0)
        policy_provider_count = cfg.get("policy_provider_count", 0)
        loaded_at_raw = cfg.get("rules_loaded_at", 0)
        loaded_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(loaded_at_raw))
        group_html = self.render_group_section(cfg, ip_pool, upstream_dns, ip_meta)

        # pre-fill chip text; color will be set by JS after拉取 /api/ipinfo
        ip_chips = "".join([f'<span class="chip" data-ip="{ip}">{ip}</span>' for ip in ip_pool])
        dns_chips = "".join([
            (f'<span class="chip active" data-ip="{ip}">{ip}</span>' if ip == upstream_dns else f'<span class="chip" data-ip="{ip}">{ip}</span>')
            for ip in upstream_pool
        ])

        tpl_path = Path(__file__).parent / 'templates' / 'dashboard.html'
        tpl = Template(tpl_path.read_text(encoding='utf-8'))
        return tpl.safe_substitute(
            ip_chips=ip_chips,
            dns_chips=dns_chips,
            listen_host=cfg.get("listen_host"),
            dns_port=cfg.get("dns_port"),
            web_host=cfg.get("web_host", "0.0.0.0"),
            web_port=cfg.get("web_port"),
            category_blocks=group_html,
            clash_profile_source=html.escape(str(clash_profile_source), quote=True),
            clash_profile_url=html.escape(str(clash_profile_url), quote=True),
            local_policy_filename=html.escape(str(LOCAL_POLICY_FILENAME), quote=True),
            policy_kind=html.escape(str(policy_kind)),
            policy_rule_count=str(int(policy_rule_count)),
            policy_group_count=str(int(policy_group_count)),
            policy_provider_count=str(int(policy_provider_count)),
            loaded_at=loaded_at,
            upstream_dns=upstream_dns,
            loaded_at_ts=str(int(loaded_at_raw)),
            ip_meta_json=_json_for_html_script(ip_meta),
            ip_info_site=cfg.get("ip_info_site", DEFAULT_CONFIG.get("ip_info_site", "netvigator")),
            token=token,
            token_query=urlencode({"token": token}),
        )

    def render_group_section(self, cfg: dict, ip_pool: list, upstream_dns: str, ip_meta: dict) -> str:
        """Render the Clash group selector section (HTML)."""
        with self.cfg.lock:
            pol = self.cfg.clash_policy
            sel_map = self.cfg.config.get("clash_group_selection") if isinstance(self.cfg.config.get("clash_group_selection"), dict) else {}

        proxies = build_proxy_catalog(ip_pool, ip_meta)

        def group_select(name: str, current: str, members: list, group_type: str):
            safe_name = html.escape(name, quote=True)
            opts = []
            for m in members:
                m_str = str(m)
                m_val = html.escape(m_str, quote=True)
                label = m_str
                if m_str == "__auto__":
                    label = "AUTO"
                else:
                    if m_str.upper() == "DIRECT":
                        label = f"DIRECT（上游DNS {upstream_dns}）"
                    else:
                        try:
                            if pol and isinstance(getattr(pol, "groups", None), dict) and m_str in pol.groups:
                                chain = self.cfg.resolve_chain(m_str, proxies, allow_probe=False)
                                if chain:
                                    parts = [str(x) for x in chain]
                                    if parts and str(parts[-1]).upper() == "DIRECT":
                                        parts[-1] = f"DIRECT（上游DNS {upstream_dns}）"
                                    # show latency on the final IP (if available in cached ip_meta)
                                    if parts:
                                        last = str(parts[-1])
                                        if is_valid_ip(last) and isinstance(ip_meta, dict):
                                            meta = ip_meta.get(last)
                                            if isinstance(meta, dict):
                                                ms = meta.get("ms")
                                                try:
                                                    ms_i = int(ms)
                                                except Exception:
                                                    ms_i = None
                                                if ms_i is not None:
                                                    ms_disp = (ms_i + 1) // 2 if ms_i >= 0 else ms_i
                                                    parts[-1] = f"{last} · {ms_disp}ms"
                                    label = " -> ".join(parts)
                        except Exception:
                            pass
                sel_attr = " selected" if m_str == current else ""
                opts.append(f'<option value="{m_val}"{sel_attr}>{html.escape(label)}</option>')
            return f'<select name="{safe_name}" class="select">{"".join(opts)}</select>'

        # Count rules hit by each target (for UI badge only)
        rules_by_target = {}
        if pol:
            for r in pol.rules or []:
                target = r.get("target")
                if not target:
                    continue
                inc = 1
                if r.get("kind") == "RULE-SET":
                    prov_key = r.get("value")
                    prov = (pol.providers or {}).get(prov_key)
                    inc = int(getattr(prov, "count", 0) or 0)
                rules_by_target[target] = rules_by_target.get(target, 0) + inc

        # --- Clash groups ---
        group_cards = []
        if pol and isinstance(getattr(pol, "groups", None), dict):
            for gname, g in pol.groups.items():
                gtype = _normalize_group_type(g.get("type"))
                if gtype not in ("select", "url-test", "fallback", "load-balance"):
                    continue

                current = str(sel_map.get(gname) or "").strip()
                if gtype == "select":
                    members = materialize_group_members(g, proxies)
                    if not members:
                        members = ["DIRECT"]
                    if current and current not in members:
                        members = [current] + members
                    if not current:
                        current = members[0]
                else:
                    members = materialize_group_members(g, proxies)
                    candidates = [m for m in members if m in proxies]
                    if not candidates:
                        candidates = list(proxies.keys())
                    members = ["__auto__", "DIRECT"] + candidates
                    if not current or current == "__auto__":
                        current = "__auto__"
                    elif current not in members:
                        members = [current] + members

                rules_cnt = rules_by_target.get(gname, 0)
                badge = ""
                # url-test/fallback/load-balance groups are usually "node pickers", not rule targets.
                # Only show rule count for select groups to reduce noise.
                if gtype == "select":
                    badge = f"<span class='pill' title='该分组命中的规则条数'>{int(rules_cnt or 0)} 条规则</span>"
                group_cards.append(
                    "<section class=\"card group-card\">"
                    f"<div class=\"row-head\"><span>{html.escape(gname)}</span>{badge}</div>"
                    f"{group_select('selg__' + gname, current, members, gtype)}"
                    "</section>"
                )

        head_html = (
            "<div class=\"groups-head\">"
            "<div class=\"groups-head-left\">"
            "<h2>分流组选择</h2>"
            "<span class=\"pill clash\">Clash</span>"
            "</div>"
            "</div>"
        )

        if not group_cards:
            if cfg.get("reloading"):
                msg = "策略加载中，请稍候…"
            else:
                msg = "未加载策略或策略无可选分组。"
            return (
                '<section id="clash-groups" class="groups-area">'
                f"{head_html}"
                '<div class="group-grid">'
                f'<section class="card group-card"><p style="color:var(--muted);margin:0;">{html.escape(msg)}</p></section>'
                "</div>"
                "</section>"
            )

        return (
            '<section id="clash-groups" class="groups-area">'
            f"{head_html}"
            f'<div class="group-grid">{"".join(group_cards)}</div>'
            "</section>"
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
