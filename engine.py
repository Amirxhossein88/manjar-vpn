# -*- coding: utf-8 -*-
"""
ManjarVPN Engine v1.1
=====================
موتور سریع برنامه: دریافت موازی کانفیگ‌ها از ۱۷ منبع، پیش‌فیلتر TCP،
تست پینگ + تست سرعت واقعی با هسته Xray، حافظه‌ی سرورهای خوب قبلی
(اتصال مجدد در چند ثانیه)، انتخاب بهترین کانفیگ و اتصال + پروکسی سیستم ویندوز.
"""
from __future__ import annotations

import atexit
import base64
import itertools
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote

import requests

APP_NAME = "ManjarVPN"
VERSION = "1.2.0"

# ============================ تنظیمات قابل تغییر ============================
MAX_TEST_NODES = 600          # حداکثر کانفیگ برای پیش‌فیلتر TCP
TCP_PREFILTER_WORKERS = 200   # اتصال‌های همزمان TCP (خیلی سبک است)
TCP_PREFILTER_TIMEOUT = 1.5   # ثانیه
MAX_XRAY_LATENCY_TESTS = 320  # بعد از پیش‌فیلتر، حداکثر تست پینگ واقعی
CONCURRENT_TESTS = 48         # تست‌های پینگ همزمان
TOP_SPEED_TESTS = 8           # بهترین‌های پینگ برای تست سرعت
EXTRA_SPEED_SAMPLES = 3       # + چند نمونه تصادفی سالم برای تنوع
CONCURRENT_SPEED_TESTS = 6
LATENCY_TIMEOUT = 5
SPEED_TIMEOUT = 7
SPEED_MAX_BYTES = 6_000_000
GOOD_SPEED_EARLY = 12.0       # Mbps — اگر برسد دیگر لازم نیست صبر کامل کنیم
MIN_GOOD_SPEED_MBPS = 0.3
# تست واقعی: علاوه بر 204، یک سایت واقعی TLS هم باید باز شود (ضد «وصل شد ولی کار نمی‌کند»)
REAL_SITE_URL = "https://www.wikipedia.org/static/favicon/wikipedia.ico"
UPLOAD_TEST_URL = "https://speed.cloudflare.com/__up"

# حافظه‌ی سرورهای خوب (اتصال سریع در اجراهای بعدی)
CACHE_MAX = 20
CACHE_TTL_DAYS = 7
QUICK_MIN_SPEED_MBPS = 2.0

XRAY_SOCKS_PORT = 10808
XRAY_HTTP_PORT = 10809

UA = {"User-Agent": f"{APP_NAME}/{VERSION}"}
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ============================ منابع کانفیگ (۱۷ منبع زنده) ============================
SUBSCRIPTION_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/trojan.txt",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/mix",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/reality",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vless",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vmess",
]

MIRROR_TEMPLATES = [
    "{url}",
    "https://mirror.ghproxy.com/{url}",
    "https://gh-proxy.com/{url}",
]

SUPPORTED_NETS = {"tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "h2"}

# ============================ جلسه HTTP ============================
SESSION = requests.Session()
SESSION.trust_env = False
SESSION.headers.update(UA)

# رمزهای مدرن Shadowsocks (AEAD)
MODERN_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}


# ============================ مدل داده ============================
@dataclass
class Node:
    proto: str
    name: str
    server: str
    port: int
    extra: dict = field(default_factory=dict)
    uri: str = ""
    latency: float | None = None
    speed: float = 0.0

    def key(self):
        ident = self.extra.get("id") or self.extra.get("password") or \
            (self.extra.get("method", "") + ":" + self.extra.get("password", ""))
        return (self.proto, self.server.lower(), self.port, ident)

    def display(self):
        n = re.sub(r"[\x00-\x1f]+", "", self.name or "").strip() or f"{self.proto}://{self.server}"
        return n[:60]


# ============================ ابزارهای پایه ============================
def _b64d(s: str) -> str:
    s = "".join(s.split())
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def _split_hostport(hp: str):
    hp = hp.strip().strip("/")
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        port = rest.lstrip(":")
        try:
            return host, int(port)
        except ValueError:
            return host, 0
    if ":" in hp:
        host, _, port = hp.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return hp, 0
    return hp, 0


def _wait_port(port: int, timeout: float = 3.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _kill_proc(proc: subprocess.Popen):
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
    except Exception:
        pass


# ============================ پارس کانفیگ‌ها ============================
def _parse_vmess(payload: str):
    data = None
    try:
        data = json.loads(payload)
    except Exception:
        dec = _b64d(payload)
        if dec:
            try:
                data = json.loads(dec)
            except Exception:
                return None
    if not isinstance(data, dict):
        return None
    server = str(data.get("add", "")).strip()
    try:
        port = int(float(str(data.get("port", 0)) or 0))
    except ValueError:
        return None
    uid = str(data.get("id", "")).strip()
    if not server or not (0 < port < 65536) or not uid:
        return None
    net = str(data.get("net") or "tcp").lower()
    net = {"h2": "http"}.get(net, net)
    if net not in SUPPORTED_NETS:
        return None
    extra = {
        "id": uid,
        "aid": str(data.get("aid") or 0),
        "scy": str(data.get("scy") or "auto"),
        "net": net,
        "path": str(data.get("path") or ""),
        "host": str(data.get("host") or ""),
        "sec": "tls" if str(data.get("tls", "")).lower() == "tls" else "",
        "sni": str(data.get("sni") or ""),
        "fp": str(data.get("fp") or ""),
        "alpn": str(data.get("alpn") or ""),
    }
    name = str(data.get("ps") or "VMess").strip()
    return Node("vmess", name, server, port, extra)


def _parse_userinfo_scheme(scheme: str, rest: str, default_sec: str = ""):
    body, _, frag = rest.partition("#")
    if "@" not in body:
        return None
    userinfo, hostport = body.split("@", 1)
    q = {}
    if "?" in hostport:
        hostport, qs = hostport.split("?", 1)
        q = parse_qs(qs, keep_blank_values=True)
    host, port = _split_hostport(hostport)
    if not host or not (0 < port < 65536):
        return None

    def qp(k, d=""):
        v = q.get(k)
        return v[0] if v else d

    net = qp("type", "tcp").lower()
    net = {"h2": "http", "raw": "tcp"}.get(net, net)
    if net not in SUPPORTED_NETS:
        return None
    extra = {
        "net": net,
        "sec": qp("security").lower(),
        "sni": qp("sni") or qp("peer"),
        "fp": qp("fp"),
        "pbk": qp("pbk"),
        "sid": qp("sid"),
        "spx": qp("spx"),
        "flow": qp("flow"),
        "path": unquote(qp("path")),
        "host": unquote(qp("host")),
        "serviceName": unquote(qp("serviceName")),
        "alpn": qp("alpn"),
    }
    if scheme == "trojan":
        extra["password"] = unquote(userinfo)
        if not extra["sec"]:
            extra["sec"] = default_sec
        ident = extra["password"]
    else:
        extra["id"] = userinfo.strip()
        ident = extra["id"]
    if not ident or " " in ident:
        return None
    name = unquote(frag).strip() or scheme.upper()
    return Node(scheme, name, host, port, extra)


def _parse_ss(rest: str):
    body = rest
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    if "?" in body:
        body, qs = body.split("?", 1)
        q = parse_qs(qs, keep_blank_values=True)
        if q.get("plugin"):
            return None
    method = password = ""
    host = ""
    port = 0
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        if ":" not in userinfo:
            dec = _b64d(userinfo)
            if ":" not in dec:
                return None
            userinfo = dec
        if ":" not in userinfo:
            userinfo = unquote(userinfo)
        try:
            method, password = userinfo.split(":", 1)
        except ValueError:
            return None
        host, port = _split_hostport(hostport)
    else:
        dec = _b64d(body)
        m = re.match(r"^(?P<method>[^:]+):(?P<pw>.*)@(?P<host>.+):(?P<port>\d+)$", dec)
        if not m:
            return None
        method, password = m.group("method"), m.group("pw")
        host, port = m.group("host"), int(m.group("port"))
    if not host or not (0 < port < 65536) or not method or not password:
        return None
    if not re.match(r"^[A-Za-z0-9\-_]+$", method):
        return None
    return Node("ss", unquote(frag).strip() or "Shadowsocks", host, port,
                {"method": method, "password": password})


def parse_uri(uri: str):
    if not uri:
        return None
    uri = uri.strip()
    if not uri or uri.startswith("#") or uri.startswith("//"):
        return None
    low = uri.lower()
    try:
        if low.startswith("vmess://"):
            n = _parse_vmess(uri[8:])
        elif low.startswith("vless://"):
            n = _parse_userinfo_scheme("vless", uri[8:])
        elif low.startswith("trojan://"):
            n = _parse_userinfo_scheme("trojan", uri[9:], default_sec="tls")
        elif low.startswith("ss://"):
            n = _parse_ss(uri[5:])
        else:
            return None
    except Exception:
        return None
    if n is not None:
        n.uri = uri
    return n


def decode_subscription(text: str) -> list:
    text = text.strip()
    if not text:
        return []
    lines = [l.strip() for l in text.splitlines()
             if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("//")]
    joined = "\n".join(lines)
    if "://" in joined:
        return [l for l in lines if "://" in l]
    blob = _b64d("".join(lines))
    if "://" in blob:
        return [l for l in blob.splitlines() if "://" in l]
    out = []
    for l in lines:
        dec = _b64d(l)
        if "://" in dec:
            out.extend(x for x in dec.splitlines() if "://" in x)
    return out


# ============================ تشخیص خودکار قابلیت‌های هسته ============================
_FEATURES = {
    "allow_insecure": True,
    "http_transport": True,
    "legacy_ss_cipher": True,
    "plain_vless": True,
}
_FEATURES_LOCK = threading.Lock()
_FEATURES_PROBED = [False]


def probe_features(xray_path: str) -> list:
    with _FEATURES_LOCK:
        if _FEATURES_PROBED[0]:
            return [k for k, v in _FEATURES.items() if not v]

        def accepts(cfg: dict) -> bool:
            f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
            try:
                json.dump(cfg, f)
                f.close()
                p = subprocess.run([xray_path, "run", "-test", "-c", f.name],
                                   capture_output=True, text=True, timeout=20,
                                   creationflags=CREATE_NO_WINDOW)
                return p.returncode == 0
            except Exception:
                return True
            finally:
                try:
                    os.unlink(f.name)
                except OSError:
                    pass

        dummy_sock = {"listen": "127.0.0.1", "port": 39099, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True}}
        base = {"log": {"loglevel": "none"}, "inbounds": [dummy_sock]}
        uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

        _FEATURES["allow_insecure"] = accepts({**base, "outbounds": [
            {"protocol": "trojan", "settings": {"servers": [
                {"address": "1.2.3.4", "port": 443, "password": "x"}]},
             "streamSettings": {"network": "tcp", "security": "tls",
                                "tlsSettings": {"allowInsecure": True,
                                                "serverName": "x.com",
                                                "fingerprint": "chrome"}}}]})
        _FEATURES["http_transport"] = accepts({**base, "outbounds": [
            {"protocol": "vmess", "settings": {"vnext": [
                {"address": "1.2.3.4", "port": 80,
                 "users": [{"id": uuid, "alterId": 0, "security": "auto"}]}]},
             "streamSettings": {"network": "http", "security": "none",
                                "httpSettings": {"host": ["x.com"], "path": "/"}}}]})
        _FEATURES["legacy_ss_cipher"] = accepts({**base, "outbounds": [
            {"protocol": "shadowsocks", "settings": {"servers": [
                {"address": "1.2.3.4", "port": 8388,
                 "method": "aes-128-cfb", "password": "x"}]},
             "streamSettings": {"network": "tcp", "security": "none"}}]})
        _FEATURES["plain_vless"] = accepts({**base, "outbounds": [
            {"protocol": "vless", "settings": {"vnext": [
                {"address": "8.8.8.8", "port": 443,
                 "users": [{"id": uuid, "encryption": "none"}]}]},
             "streamSettings": {"network": "tcp", "security": "none"}}]})
        _FEATURES_PROBED[0] = True
        return [k for k, v in _FEATURES.items() if not v]


def filter_supported(nodes: list) -> list:
    out = []
    for n in nodes:
        if n.proto == "vless" and not _FEATURES["plain_vless"]:
            sec = (n.extra.get("sec") or "").lower()
            if sec not in ("tls", "reality"):
                continue
        if n.proto == "ss" and not _FEATURES["legacy_ss_cipher"]:
            if (n.extra.get("method") or "").lower() not in MODERN_SS_METHODS:
                continue
        if (n.extra.get("net") or "tcp") == "http" and not _FEATURES["http_transport"]:
            continue
        out.append(n)
    return out


# ============================ ساخت کانفیگ Xray ============================
def build_outbound(node: Node):
    e = node.extra
    net = e.get("net") or "tcp"
    if net not in SUPPORTED_NETS:
        return None
    if net == "http" and not _FEATURES["http_transport"]:
        return None
    stream = {"network": net, "security": "none"}
    sec = (e.get("sec") or "").lower()
    sni = e.get("sni") or node.server
    fp = e.get("fp") or "chrome"
    if node.proto == "trojan" and not sec:
        sec = "tls"
    if sec == "tls":
        tls = {"serverName": sni, "fingerprint": fp}
        if _FEATURES["allow_insecure"]:
            tls["allowInsecure"] = True
        alpn = [a.strip() for a in (e.get("alpn") or "").split(",") if a.strip()]
        if alpn:
            tls["alpn"] = alpn
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif sec == "reality":
        if not e.get("pbk"):
            return None
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp,
            "publicKey": e["pbk"], "shortId": e.get("sid", ""),
            "spiderX": e.get("spx") or "/",
        }
    if net == "ws":
        stream["wsSettings"] = {"path": e.get("path") or "/",
                                "headers": {"Host": e.get("host") or sni}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": e.get("serviceName") or e.get("path") or "",
                                  "multiMode": False}
    elif net == "http":
        stream["httpSettings"] = {"host": [e.get("host") or sni], "path": e.get("path") or "/"}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": e.get("path") or "/", "host": e.get("host") or sni}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": e.get("path") or "/", "host": e.get("host") or sni}

    if node.proto == "vmess":
        try:
            aid = int(float(str(e.get("aid") or 0)))
        except ValueError:
            aid = 0
        return {"tag": "proxy", "protocol": "vmess",
                "settings": {"vnext": [{"address": node.server, "port": node.port,
                                        "users": [{"id": e["id"], "alterId": aid,
                                                   "security": e.get("scy") or "auto", "level": 0}]}]},
                "streamSettings": stream, "mux": {"enabled": False}}
    if node.proto == "vless":
        user = {"id": e["id"], "encryption": "none", "level": 0}
        if e.get("flow") and sec in ("tls", "reality") and net == "tcp":
            user["flow"] = e["flow"]
        return {"tag": "proxy", "protocol": "vless",
                "settings": {"vnext": [{"address": node.server, "port": node.port,
                                        "users": [user]}]},
                "streamSettings": stream}
    if node.proto == "trojan":
        return {"tag": "proxy", "protocol": "trojan",
                "settings": {"servers": [{"address": node.server, "port": node.port,
                                          "password": e["password"], "level": 0}]},
                "streamSettings": stream}
    if node.proto == "ss":
        return {"tag": "proxy", "protocol": "shadowsocks",
                "settings": {"servers": [{"address": node.server, "port": node.port,
                                          "method": e["method"], "password": e["password"],
                                          "uot": True}]},
                "streamSettings": {"network": "tcp", "security": "none"}}
    return None


def build_xray_config(node: Node, socks_port: int, http_port: int | None = None):
    outbound = build_outbound(node)
    if outbound is None:
        return None
    sniffing = {"enabled": True, "destOverride": ["http", "tls"]}
    inbounds = [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                 "protocol": "socks", "settings": {"auth": "noauth", "udp": True},
                 "sniffing": sniffing}]
    if http_port:
        inbounds.append({"tag": "http-in", "listen": "127.0.0.1", "port": http_port,
                         "protocol": "http", "settings": {}, "sniffing": sniffing})
    return {"log": {"loglevel": "warning"},
            "inbounds": inbounds,
            "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}]}


# ============================ یافتن هسته Xray ============================
def find_xray() -> str:
    exe = "xray.exe" if os.name == "nt" else "xray"
    candidates = []
    env = os.environ.get("MANJAR_XRAY")
    if env:
        candidates.append(env)
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", None) or os.path.dirname(sys.executable)
        candidates.append(os.path.join(base, exe))
        candidates.append(os.path.join(os.path.dirname(sys.executable), exe))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), exe))
    candidates.append(exe)
    for c in candidates:
        if c == exe:
            w = shutil.which("xray")
            if w:
                return w
        elif os.path.isfile(c):
            return c
    raise FileNotFoundError("هسته Xray پیدا نشد (xray.exe)")


def find_logo() -> str | None:
    name = "logo.png"
    candidates = []
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", None) or os.path.dirname(sys.executable)
        candidates.append(os.path.join(base, name))
        candidates.append(os.path.join(os.path.dirname(sys.executable), name))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), name))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ============================ پروکسی سیستم ویندوز ============================
_PROXY_SET_FLAG = [False]
_ALL_PROCS: list = []
_ALL_PROCS_LOCK = threading.Lock()


def set_system_proxy(enable: bool, port: int = XRAY_HTTP_PORT):
    if sys.platform != "win32":
        return
    try:
        import winreg
        keypath = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, keypath, 0, winreg.KEY_SET_VALUE) as k:
            if enable:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                                  "localhost;127.*;10.*;172.16.*;192.168.*;<local>")
            else:
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        _PROXY_SET_FLAG[0] = enable
        import ctypes
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(None, 39, None, 0)
        internet_set_option(None, 37, None, 0)
    except Exception:
        pass


def cleanup_stale_proxy() -> bool:
    """اگر از اجرای قبلی (کرش/بسته‌شدن اجباری) پروکسی سیستم روشن مانده، پاکش می‌کند."""
    if sys.platform != "win32":
        return False
    try:
        import winreg
        kp = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, kp, 0, winreg.KEY_READ) as k:
            try:
                enabled, _ = winreg.QueryValueEx(k, "ProxyEnable")
            except OSError:
                return False
            try:
                server, _ = winreg.QueryValueEx(k, "ProxyServer")
            except OSError:
                server = ""
        if enabled and any(p in str(server) for p in ("10808", "10809")):
            set_system_proxy(False)
            return True
    except Exception:
        pass
    return False


def _cleanup_atexit():
    try:
        if _PROXY_SET_FLAG[0]:
            set_system_proxy(False)
    except Exception:
        pass
    try:
        with _ALL_PROCS_LOCK:
            for p in _ALL_PROCS:
                _kill_proc(p)
            _ALL_PROCS.clear()
    except Exception:
        pass


atexit.register(_cleanup_atexit)


# ============================ حافظه‌ی سرورهای خوب ============================
def _cache_dir() -> str:
    if sys.platform == "win32":
        base = os.path.join(os.environ.get("APPDATA", tempfile.gettempdir()), APP_NAME)
    else:
        base = os.path.join(os.path.expanduser("~"), ".manjarvpn")
    os.makedirs(base, exist_ok=True)
    return base


def load_cache() -> list:
    try:
        with open(os.path.join(_cache_dir(), "known_good.json"), encoding="utf-8") as f:
            entries = json.load(f)
        cutoff = time.time() - CACHE_TTL_DAYS * 86400
        return [e for e in entries if isinstance(e, dict) and e.get("uri")
                and e.get("ts", 0) >= cutoff]
    except Exception:
        return []


def save_cache(entries: list):
    try:
        with open(os.path.join(_cache_dir(), "known_good.json"), "w", encoding="utf-8") as f:
            json.dump(entries[:CACHE_MAX], f, ensure_ascii=False, indent=1)
    except Exception:
        pass


# ============================ موتور اصلی ============================
class VpnEngine:
    def __init__(self, log_cb=None, progress_cb=None):
        self.log_cb = log_cb
        self.progress_cb = progress_cb
        self.stop_flag = threading.Event()
        self.xray_path: str | None = None
        self.proc: subprocess.Popen | None = None
        self.socks_port = 10808
        self.http_port = 10809
        self._err_file = None
        self.current_node: Node | None = None
        self.test_procs: list = []
        self.test_procs_lock = threading.Lock()
        self._port_counter = itertools.count(1)
        self._port_lock = threading.Lock()
        self._features_logged = False

    # ---------- callbacks ----------
    def log(self, msg: str):
        if self.log_cb:
            try:
                self.log_cb(str(msg))
            except Exception:
                pass

    def progress(self, phase: str, done: int, total: int, msg: str):
        if self.progress_cb:
            try:
                self.progress_cb(phase, done, total, msg)
            except Exception:
                pass

    # ---------- زیرساخت ----------
    def ensure_xray(self) -> str:
        if not self.xray_path:
            self.xray_path = find_xray()
        return self.xray_path

    def ensure_features(self):
        xray = self.ensure_xray()
        unsupported = probe_features(xray)
        if unsupported and not self._features_logged:
            self._features_logged = True
            self.log(f"ℹ هسته Xray از این قابلیت‌ها پشتیبانی نمی‌کند (رد می‌شوند): "
                     f"{', '.join(unsupported)}")

    def _next_port(self) -> int:
        with self._port_lock:
            return 30000 + (next(self._port_counter) % 20000)

    def _start_xray(self, cfg_path: str, stderr_path: str | None = None) -> subprocess.Popen:
        xray = self.ensure_xray()
        if stderr_path:
            err = open(stderr_path, "w", encoding="utf-8")
            self._err_file = err
        else:
            err = subprocess.DEVNULL
        proc = subprocess.Popen(
            [xray, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=err,
            creationflags=CREATE_NO_WINDOW,
        )
        with _ALL_PROCS_LOCK:
            _ALL_PROCS.append(proc)
        return proc

    def _stop_xray(self, proc: subprocess.Popen):
        _kill_proc(proc)
        with _ALL_PROCS_LOCK:
            if proc in _ALL_PROCS:
                _ALL_PROCS.remove(proc)
        with self.test_procs_lock:
            if proc in self.test_procs:
                self.test_procs.remove(proc)

    # ---------- بررسی اینترنت ----------
    def check_internet(self):
        for url in ("http://cp.cloudflare.com/generate_204",
                    "https://www.gstatic.com/generate_204"):
            try:
                t0 = time.time()
                r = SESSION.get(url, timeout=6)
                if r.status_code < 500:
                    return True, int((time.time() - t0) * 1000)
            except Exception:
                continue
        return False, None

    # ---------- پیش‌فیلتر TCP (خیلی سریع) ----------
    def _tcp_alive(self, server: str, port: int) -> bool:
        try:
            infos = socket.getaddrinfo(server, port, type=socket.SOCK_STREAM)
        except Exception:
            return False
        try:
            af, st, proto, cn, sa = infos[0]
            with socket.create_connection(sa, timeout=TCP_PREFILTER_TIMEOUT):
                return True
        except Exception:
            return False

    def tcp_prefilter(self, nodes: list) -> list:
        alive = []
        total = len(nodes)
        done = 0
        with ThreadPoolExecutor(max_workers=TCP_PREFILTER_WORKERS) as ex:
            futs = {ex.submit(self._tcp_alive, n.server, n.port): n for n in nodes}
            for f in as_completed(futs):
                n = futs[f]
                if f.result():
                    alive.append(n)
                done += 1
                if self.stop_flag.is_set():
                    break
                if done % 50 == 0 or done == total:
                    self.progress("tcp", done, total,
                                  f"پیش‌فیلتر سرورها {done}/{total} — {len(alive)} سرور زنده")
        return alive

    # ---------- دریافت موازی منابع ----------
    def _fetch_url(self, url: str) -> str | None:
        for tpl in MIRROR_TEMPLATES:
            if self.stop_flag.is_set():
                return None
            try:
                r = SESSION.get(tpl.format(url=url), timeout=20)
                if r.status_code == 200 and r.text.strip():
                    return r.text
            except Exception:
                continue
        return None

    def fetch_all(self, max_nodes: int = 8000) -> list:
        try:
            self.ensure_features()
        except Exception:
            pass
        total = len(SUBSCRIPTION_SOURCES)
        by_index: dict = {}
        done = 0

        def work(i, src):
            return i, src, self._fetch_url(src)

        with ThreadPoolExecutor(max_workers=min(10, total)) as ex:
            futs = [ex.submit(work, i, src) for i, src in enumerate(SUBSCRIPTION_SOURCES, 1)]
            for f in as_completed(futs):
                i, src, text = f.result()
                done += 1
                if text is None:
                    self.log(f"✗ منبع در دسترس نبود: {src}")
                else:
                    got = decode_subscription(text)
                    self.log(f"✓ منبع {i}/{total}: {len(got)} کانفیگ")
                    by_index[i] = got
                self.progress("fetch", done, total, f"دریافت {done}/{total} منبع …")
                if self.stop_flag.is_set():
                    break

        uris = [u for i in sorted(by_index) for u in by_index[i]]
        nodes = []
        seen = set()
        per_server = {}
        for u in uris:
            n = parse_uri(u)
            if n is None:
                continue
            k = n.key()
            if k in seen:
                continue
            sk = (n.server.lower(), n.port)
            if per_server.get(sk, 0) >= 3:   # حداکثر ۳ کانفیگ از هر سرور → تنوع بیشتر
                continue
            seen.add(k)
            per_server[sk] = per_server.get(sk, 0) + 1
            nodes.append(n)
            if len(nodes) >= max_nodes:
                break
        return filter_supported(nodes)

    # ---------- تست یک نود ----------
    def test_latency(self, node: Node):
        if self.stop_flag.is_set():
            return None
        port = self._next_port()
        cfg = build_xray_config(node, port)
        if cfg is None:
            return None
        tmp = os.path.join(tempfile.gettempdir(), f"manjarvpn_{os.getpid()}_{port}.json")
        proc = None
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
            proc = self._start_xray(tmp)
            with self.test_procs_lock:
                self.test_procs.append(proc)
            if proc.poll() is not None:
                return None
            if not _wait_port(port, 2.0):
                return None
            proxies = {"http": f"socks5h://127.0.0.1:{port}",
                       "https": f"socks5h://127.0.0.1:{port}"}
            t0 = time.time()
            r = SESSION.get("http://cp.cloudflare.com/generate_204",
                            proxies=proxies, timeout=LATENCY_TIMEOUT)
            if r.status_code >= 400:
                return None
            if not self._real_site_ok(proxies):
                return None
            return (time.time() - t0) * 1000.0
        except Exception:
            return None
        finally:
            if proc:
                self._stop_xray(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_speed(self, node: Node):
        if self.stop_flag.is_set():
            return 0.0
        port = self._next_port()
        cfg = build_xray_config(node, port)
        if cfg is None:
            return 0.0
        tmp = os.path.join(tempfile.gettempdir(), f"manjarvpn_sp_{os.getpid()}_{port}.json")
        proc = None
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
            proc = self._start_xray(tmp)
            with self.test_procs_lock:
                self.test_procs.append(proc)
            if proc.poll() is not None:
                return 0.0
            if not _wait_port(port, 2.0):
                return 0.0
            proxies = {"http": f"socks5h://127.0.0.1:{port}",
                       "https": f"socks5h://127.0.0.1:{port}"}
            t0 = time.time()
            total = 0
            with SESSION.get("https://speed.cloudflare.com/__down?bytes=6000000",
                             stream=True, proxies=proxies,
                             timeout=(5, SPEED_TIMEOUT)) as r:
                if r.status_code >= 400:
                    return 0.0
                for chunk in r.iter_content(65536):
                    total += len(chunk)
                    if total >= SPEED_MAX_BYTES:
                        break
                    if time.time() - t0 > SPEED_TIMEOUT:
                        break
            elapsed = time.time() - t0
            if elapsed <= 0.05 or total < 100_000:
                return 0.0
            return total * 8.0 / elapsed / 1e6
        except Exception:
            return 0.0
        finally:
            if proc:
                self._stop_xray(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------- تست‌های تکمیلی ----------
    def _real_site_ok(self, proxies: dict, timeout: float = 6.0) -> bool:
        """باز شدن یک سایت واقعی TLS از داخل تونل (ضد «وصل شد ولی کار نمی‌کند»)."""
        try:
            r = SESSION.get(REAL_SITE_URL, proxies=proxies, stream=True,
                            timeout=(4, timeout))
            ok = r.status_code < 400
            first = next(r.iter_content(4096), b"")
            r.close()
            return ok and len(first) > 0
        except Exception:
            return False

    def measure_upload(self, seconds: float = 6.0) -> float:
        """اندازه‌گیری سرعت آپلود از داخل تونل فعال (Mbps)."""
        if not self.proc:
            return 0.0
        port = self.http_port
        proxies = {"http": f"http://127.0.0.1:{port}",
                   "https": f"http://127.0.0.1:{port}"}
        payload = b"x" * 300_000
        try:
            t0 = time.time()
            sent = 0
            with SESSION.post(UPLOAD_TEST_URL, data=payload, proxies=proxies,
                              timeout=(5, seconds)) as r:
                if r.status_code < 400:
                    sent = len(payload)
            el = time.time() - t0
            if sent <= 0 or el <= 0.05:
                return 0.0
            return sent * 8.0 / el / 1e6
        except Exception:
            return 0.0

    # ---------- اسکن کامل ----------
    def scan(self, nodes: list):
        """پیش‌فیلتر TCP → پینگ موازی → تست سرعت بهترین‌ها. خروجی: (بهترین، سالم‌ها)"""
        try:
            self.ensure_features()
        except Exception:
            pass
        if len(nodes) > MAX_TEST_NODES:
            nodes = random.sample(nodes, MAX_TEST_NODES)
            self.log(f"→ نمونه‌گیری تصادفی: بررسی {len(nodes)} کانفیگ")

        alive = self.tcp_prefilter(nodes)
        if self.stop_flag.is_set():
            return None, []
        self.log(f"⚡ پیش‌فیلتر: {len(alive)} سرور از {len(nodes)} زنده — شروع تست پینگ")
        if len(alive) > MAX_XRAY_LATENCY_TESTS:
            alive = random.sample(alive, MAX_XRAY_LATENCY_TESTS)

        lat_ok = []
        done = 0
        with ThreadPoolExecutor(max_workers=CONCURRENT_TESTS) as ex:
            futs = {ex.submit(self.test_latency, n): n for n in alive}
            for f in as_completed(futs):
                if self.stop_flag.is_set():
                    break
                n = futs[f]
                r = f.result()
                done += 1
                if r is not None:
                    n.latency = r
                    lat_ok.append(n)
                if done % 10 == 0 or done == len(alive):
                    self.progress("latency", done, len(alive),
                                  f"تست پینگ {done}/{len(alive)} — {len(lat_ok)} کانفیگ سالم")
        if self.stop_flag.is_set():
            return None, lat_ok
        lat_ok.sort(key=lambda n: n.latency)
        self.log(f"✓ پینگ تمام شد: {len(lat_ok)} کانفیگ سالم از {len(alive)}")

        top = lat_ok[:TOP_SPEED_TESTS]
        rest = lat_ok[TOP_SPEED_TESTS:]
        if rest and EXTRA_SPEED_SAMPLES:
            top = top + random.sample(rest, min(EXTRA_SPEED_SAMPLES, len(rest)))
        if top:
            sdone = 0
            with ThreadPoolExecutor(max_workers=CONCURRENT_SPEED_TESTS) as ex:
                futs = {ex.submit(self.test_speed, n): n for n in top}
                for f in as_completed(futs):
                    n = futs[f]
                    n.speed = f.result()
                    sdone += 1
                    self.progress("speed", sdone, len(top),
                                  f"تست سرعت {sdone}/{len(top)} — {n.display()} ({n.speed:.1f} Mbps)")
            for n in sorted(top, key=lambda x: -x.speed):
                self.log(f"   {n.display():<40} پینگ {int(n.latency):>4}ms  سرعت {n.speed:>6.1f} Mbps")

        fast = [n for n in top if n.speed >= MIN_GOOD_SPEED_MBPS]
        if fast:
            best = max(fast, key=lambda n: (n.speed, -n.latency))
        elif top:
            best = top[0]
        else:
            best = None
        return best, lat_ok

    # ---------- مسیر سریع: سرورهای خوب قبلی ----------
    def quick_connect_check(self):
        """کانفیگ‌های خوب قبلی را تست می‌کند؛ اگر یکی سریع بود برمی‌گرداند (اتصال چند‌ثانیه‌ای)."""
        entries = load_cache()
        if not entries:
            return None, []
        nodes = []
        for e in entries:
            n = parse_uri(e.get("uri", ""))
            if n is not None:
                n.speed = float(e.get("speed", 0) or 0)
                nodes.append(n)
        if not nodes:
            return None, []
        self.log(f"⚡ {len(nodes)} سرور خوب قبلی در حافظه — تست سریع…")
        alive = self.tcp_prefilter(nodes)
        if self.stop_flag.is_set() or not alive:
            return None, []
        lat_ok = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(self.test_latency, n): n for n in alive}
            for f in as_completed(futs):
                n = futs[f]
                r = f.result()
                if r is not None:
                    n.latency = r
                    lat_ok.append(n)
        if self.stop_flag.is_set() or not lat_ok:
            return None, []
        lat_ok.sort(key=lambda n: n.latency)
        top = lat_ok[:3]
        for n in top:
            n.speed = self.test_speed(n)
            if self.stop_flag.is_set():
                return None, lat_ok
        best = max(top, key=lambda n: (n.speed, -n.latency), default=None)
        if best and best.speed >= QUICK_MIN_SPEED_MBPS:
            return best, lat_ok
        return None, lat_ok

    def update_cache(self, best: Node, runners: list):
        entries = load_cache()
        by_uri = {e["uri"]: e for e in entries}
        for n in [best] + list(runners[:5]):
            if not n.uri or n.speed <= 0:
                continue
            by_uri[n.uri] = {"uri": n.uri, "latency": int(n.latency or 0),
                             "speed": round(n.speed, 2), "ts": time.time()}
        entries = sorted(by_uri.values(), key=lambda e: -float(e.get("speed", 0)))
        save_cache(entries)

    # ---------- اتصال نهایی ----------
    def _alloc_local_port(self, start: int) -> int:
        p = start
        for _ in range(40):
            s = socket.socket()
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                p += 10
            finally:
                s.close()
        return start

    def _read_err_tail(self, path: str, limit: int = 300) -> str:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                return f.read()[-limit:].strip()
        except Exception:
            return ""

    def connect(self, node: Node) -> bool:
        self.disconnect(restore_proxy=False)
        # پورت‌های آزاد (اگر v2rayN و … روی 10808 بود، تداخل پیش نیاید)
        self.socks_port = self._alloc_local_port(10808)
        self.http_port = self._alloc_local_port(10809)
        cfg = build_xray_config(node, self.socks_port, self.http_port)
        if cfg is None:
            raise RuntimeError("ساخت کانفیگ برای این نود ممکن نشد")
        tmp = os.path.join(tempfile.gettempdir(), "manjarvpn_main.json")
        errlog = os.path.join(tempfile.gettempdir(), "manjarvpn_main_err.log")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self.progress("connect", 1, 1, "راه‌اندازی تونل نهایی…")
        self.proc = self._start_xray(tmp, stderr_path=errlog)
        if not _wait_port(self.socks_port, 5) or not _wait_port(self.http_port, 5):
            tail = self._read_err_tail(errlog)
            self.disconnect(restore_proxy=False)
            raise RuntimeError("هسته Xray بالا نیامد" + (f": {tail}" if tail else ""))
        proxies = {"http": f"http://127.0.0.1:{self.http_port}",
                   "https": f"http://127.0.0.1:{self.http_port}"}
        try:
            r = SESSION.get("http://cp.cloudflare.com/generate_204",
                            proxies=proxies, timeout=10)
            ok = r.status_code < 400
        except Exception:
            ok = False
        if ok and not self._real_site_ok(proxies, timeout=8):
            ok = False
        if not ok:
            tail = self._read_err_tail(errlog)
            self.disconnect(restore_proxy=False)
            raise RuntimeError("تونل پاسخ نداد (سایت واقعی هم باز نشد)"
                               + (f" — {tail}" if tail else ""))
        set_system_proxy(True, port=self.http_port)
        self.current_node = node
        return True

    def disconnect(self, restore_proxy: bool = True):
        if self.proc:
            _kill_proc(self.proc)
            with _ALL_PROCS_LOCK:
                if self.proc in _ALL_PROCS:
                    _ALL_PROCS.remove(self.proc)
            self.proc = None
        if getattr(self, "_err_file", None):
            try:
                self._err_file.close()
            except Exception:
                pass
            self._err_file = None
        if restore_proxy:
            set_system_proxy(False)
        self.current_node = None

    def stop_all(self):
        self.stop_flag.set()
        with self.test_procs_lock:
            procs = list(self.test_procs)
        for p in procs:
            _kill_proc(p)
        self.disconnect()
