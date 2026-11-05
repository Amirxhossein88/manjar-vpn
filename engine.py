# -*- coding: utf-8 -*-
"""
ManjarVPN Engine
================
موتور برنامه: دریافت کانفیگ‌های رایگان از منابع معتبر (جمع‌آوری‌شده از کانال‌های تلگرام)،
پارس و حذف تکراری‌ها، تست پینگ + تست سرعت واقعی با هسته Xray، انتخاب بهترین کانفیگ
و اتصال به آن + روشن/خاموش کردن پروکسی سیستم ویندوز.
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
VERSION = "1.0.0"

# ============================ تنظیمات قابل تغییر ============================
# چند کانفیگ به‌طور تصادفی از کل لیست تست شود (بیشتر = تست کامل‌تر ولی کندتر)
MAX_TEST_NODES = 400
# چند تست همزمان اجرا شود (هر تست یک پروسه Xray جداگانه باز می‌کند)
CONCURRENT_TESTS = 30
# چند کانفیگِ پینگِ پایین‌تر، تست سرعت واقعی شوند
TOP_SPEED_TESTS = 12
CONCURRENT_SPEED_TESTS = 4
LATENCY_TIMEOUT = 6          # ثانیه
SPEED_TIMEOUT = 10           # ثانیه
SPEED_MAX_BYTES = 10_000_000 # حداکثر ۱۰ مگابایت دانلود برای هر تست سرعت
MIN_GOOD_SPEED_MBPS = 0.3    # حداقل سرعت قابل قبول برای انتخاب به‌عنوان بهترین

XRAY_SOCKS_PORT = 10808
XRAY_HTTP_PORT = 10809

UA = {"User-Agent": f"{APP_NAME}/{VERSION}"}
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ============================ منابع کانفیگ (آپدیت خودکار) ============================
# این مخازن، کانفیگ‌های کانال‌های تلگرامی را جمع‌آوری و هر چند دقیقه آپدیت می‌کنند
SUBSCRIPTION_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/mix",
]

# اگر دسترسی مستقیم به گیت‌هاب قطع بود، از این آینه‌ها تلاش می‌کنیم
MIRROR_TEMPLATES = [
    "{url}",
    "https://mirror.ghproxy.com/{url}",
    "https://gh-proxy.com/{url}",
]

SUPPORTED_NETS = {"tcp", "ws", "grpc", "http", "httpupgrade", "xhttp", "h2"}

# ============================ جلسه HTTP ============================
SESSION = requests.Session()
SESSION.trust_env = False  # تحت تأثیر پروکسی/متغیرهای محیطی سیستم قرار نگیر
SESSION.headers.update(UA)

# رمزهای مدرن Shadowsocks (AEAD)
MODERN_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

# ============================ تشخیص خودکار قابلیت‌های هسته ============================
# نسخه‌های جدید Xray بعضی قابلیت‌های قدیمی را حذف کرده‌اند؛ با run -test می‌سنجیم
# تا کانفیگ‌ها با هر نسخه‌ای از هسته درست ساخته شوند.
_FEATURES = {
    "allow_insecure": True,     # tlsSettings.allowInsecure
    "http_transport": True,     # ترنسپورت HTTP (h2)
    "legacy_ss_cipher": True,   # رمزهای قدیمی SS مثل aes-128-cfb
    "plain_vless": True,        # vless بدون TLS/Reality
}
_FEATURES_LOCK = threading.Lock()
_FEATURES_PROBED = [False]


def probe_features(xray_path: str) -> list:
    """یک‌بار قابلیت‌های باینری هسته را می‌سنجد؛ فهرست قابلیت‌های پشتیبانی‌نشده را برمی‌گرداند."""
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
                return True  # اگر نتوانستیم بسنجیم، فرض کن پشتیبانی می‌شود
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
    """کانفیگ‌هایی که هسته فعلی از آن‌ها پشتیبانی نمی‌کند را حذف می‌کند."""
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


# ============================ مدل داده ============================
@dataclass
class Node:
    proto: str                 # vmess | vless | trojan | ss
    name: str
    server: str
    port: int
    extra: dict = field(default_factory=dict)
    latency: float | None = None   # میلی‌ثانیه
    speed: float = 0.0             # مگابیت بر ثانیه

    def key(self):
        ident = self.extra.get("id") or self.extra.get("password") or \
            (self.extra.get("method", "") + ":" + self.extra.get("password", ""))
        return (self.proto, self.server.lower(), self.port, ident)

    def display(self):
        n = re.sub(r"[\x00-\x1f]+", "", self.name or "").strip() or f"{self.proto}://{self.server}"
        return n[:60]


# ============================ ابزارهای پایه ============================
def _b64d(s: str) -> str:
    """دیکد base64 مقاوم (استاندارد و url-safe)."""
    s = "".join(s.split())
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def _split_hostport(hp: str):
    hp = hp.strip().strip("/")
    if hp.startswith("["):  # IPv6
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
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.08)
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
    """پارس مشترک vless / trojan:  scheme://userinfo@host:port?params#name"""
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
        if q.get("plugin"):  # پلاگین‌های obfs/v2ray-plugin پشتیبانی نمی‌شوند
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
    """یک لینک کانفیگ را به Node تبدیل می‌کند؛ ناموفق → None"""
    if not uri:
        return None
    uri = uri.strip()
    if not uri or uri.startswith("#") or uri.startswith("//"):
        return None
    low = uri.lower()
    try:
        if low.startswith("vmess://"):
            return _parse_vmess(uri[8:])
        if low.startswith("vless://"):
            return _parse_userinfo_scheme("vless", uri[8:])
        if low.startswith("trojan://"):
            return _parse_userinfo_scheme("trojan", uri[9:], default_sec="tls")
        if low.startswith("ss://"):
            return _parse_ss(uri[5:])
    except Exception:
        return None
    return None


def decode_subscription(text: str) -> list:
    """محتوای اشتراک (ساده یا base64) را به لیست لینک تبدیل می‌کند."""
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


# ============================ پروکسی سیستم ویندوز ============================
_PROXY_SET_FLAG = [False]
_ALL_PROCS: list = []
_ALL_PROCS_LOCK = threading.Lock()


def set_system_proxy(enable: bool, port: int = XRAY_HTTP_PORT):
    """روشن/خاموش کردن پروکسی سیستم ویندوز (Internet Settings)."""
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
        # اطلاع‌رسانی به ویندوز تا مرورگرها فوراً متوجه شوند
        import ctypes
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        internet_set_option(None, 37, None, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


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


# ============================ موتور اصلی ============================
class VpnEngine:
    def __init__(self, log_cb=None, progress_cb=None):
        self.log_cb = log_cb
        self.progress_cb = progress_cb
        self.stop_flag = threading.Event()
        self.xray_path: str | None = None
        self.proc: subprocess.Popen | None = None
        self.current_node: Node | None = None
        self.test_procs: list = []
        self.test_procs_lock = threading.Lock()
        self._port_counter = itertools.count(1)
        self._port_lock = threading.Lock()
        self._features_logged = False

    def ensure_features(self):
        xray = self.ensure_xray()
        unsupported = probe_features(xray)
        if unsupported and not self._features_logged:
            self._features_logged = True
            self.log(f"ℹ هسته Xray از این قابلیت‌ها پشتیبانی نمی‌کند (رد می‌شوند): "
                     f"{', '.join(unsupported)}")

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

    # ---------- زیرساخت تست ----------
    def ensure_xray(self) -> str:
        if not self.xray_path:
            self.xray_path = find_xray()
        return self.xray_path

    def _next_port(self) -> int:
        with self._port_lock:
            return 30000 + (next(self._port_counter) % 20000)

    def _start_xray(self, cfg_path: str) -> subprocess.Popen:
        xray = self.ensure_xray()
        proc = subprocess.Popen(
            [xray, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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

    # ---------- بررسی اینترنت مستقیم ----------
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

    # ---------- دریافت منابع ----------
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

    def fetch_all(self, max_nodes: int = 6000) -> list:
        try:
            self.ensure_features()
        except Exception:
            pass
        uris = []
        total = len(SUBSCRIPTION_SOURCES)
        for i, src in enumerate(SUBSCRIPTION_SOURCES, 1):
            if self.stop_flag.is_set():
                break
            self.progress("fetch", i, total, f"دریافت منبع {i}/{total} …")
            text = self._fetch_url(src)
            if text is None:
                self.log(f"✗ منبع در دسترس نبود: {src}")
                continue
            got = decode_subscription(text)
            self.log(f"✓ منبع {i}/{total}: {len(got)} کانفیگ")
            uris.extend(got)
        nodes = []
        seen = set()
        for u in uris:
            n = parse_uri(u)
            if n is None:
                continue
            k = n.key()
            if k in seen:
                continue
            seen.add(k)
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
            if not _wait_port(port, 2.5):
                return None
            proxies = {"http": f"socks5h://127.0.0.1:{port}",
                       "https": f"socks5h://127.0.0.1:{port}"}
            t0 = time.time()
            r = SESSION.get("http://cp.cloudflare.com/generate_204",
                            proxies=proxies, timeout=LATENCY_TIMEOUT)
            if r.status_code >= 400:
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
            if not _wait_port(port, 2.5):
                return 0.0
            proxies = {"http": f"socks5h://127.0.0.1:{port}",
                       "https": f"socks5h://127.0.0.1:{port}"}
            t0 = time.time()
            total = 0
            with SESSION.get("https://speed.cloudflare.com/__down?bytes=10000000",
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
            if elapsed <= 0.05 or total < 100_000:  # کمتر از ۱۰۰KB یعنی نامعتبر
                return 0.0
            return total * 8.0 / elapsed / 1e6  # Mbps
        except Exception:
            return 0.0
        finally:
            if proc:
                self._stop_xray(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------- اسکن کامل ----------
    def scan(self, nodes: list):
        """مرحله ۱: پینگ موازی همه؛ مرحله ۲: تست سرعت بهترین‌ها. خروجی: (بهترین، سالم‌ها)"""
        try:
            self.ensure_features()
        except Exception:
            pass
        if len(nodes) > MAX_TEST_NODES:
            nodes = random.sample(nodes, MAX_TEST_NODES)
            self.log(f"→ نمونه‌گیری تصادفی: تست {len(nodes)} کانفیگ")

        # مرحله پینگ
        lat_ok = []
        done = 0
        with ThreadPoolExecutor(max_workers=CONCURRENT_TESTS) as ex:
            futs = {ex.submit(self.test_latency, n): n for n in nodes}
            for f in as_completed(futs):
                if self.stop_flag.is_set():
                    break
                n = futs[f]
                r = f.result()
                done += 1
                if r is not None:
                    n.latency = r
                    lat_ok.append(n)
                if done % 10 == 0 or done == len(nodes):
                    self.progress("latency", done, len(nodes),
                                  f"تست پینگ {done}/{len(nodes)} — {len(lat_ok)} کانفیگ سالم")
        if self.stop_flag.is_set():
            return None, lat_ok
        lat_ok.sort(key=lambda n: n.latency)
        self.log(f"✓ پینگ تمام شد: {len(lat_ok)} کانفیگ سالم از {len(nodes)}")

        # مرحله سرعت
        top = lat_ok[:TOP_SPEED_TESTS]
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
            for n in top:
                self.log(f"   {n.display():<40} پینگ {int(n.latency):>4}ms  سرعت {n.speed:>6.1f} Mbps")

        # انتخاب بهترین
        fast = [n for n in top if n.speed >= MIN_GOOD_SPEED_MBPS]
        if fast:
            best = max(fast, key=lambda n: (n.speed, -n.latency))
        elif top:
            best = top[0]
        else:
            best = None
        return best, lat_ok

    # ---------- اتصال نهایی ----------
    def connect(self, node: Node) -> bool:
        self.disconnect(restore_proxy=False)
        cfg = build_xray_config(node, XRAY_SOCKS_PORT, XRAY_HTTP_PORT)
        if cfg is None:
            raise RuntimeError("ساخت کانفیگ برای این نود ممکن نشد")
        tmp = os.path.join(tempfile.gettempdir(), "manjarvpn_main.json")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self.progress("connect", 1, 1, "راه‌اندازی تونل نهایی…")
        self.proc = self._start_xray(tmp)
        if not _wait_port(XRAY_SOCKS_PORT, 5) or not _wait_port(XRAY_HTTP_PORT, 5):
            self.disconnect(restore_proxy=False)
            raise RuntimeError("هسته Xray بالا نیامد")
        try:
            r = SESSION.get("http://cp.cloudflare.com/generate_204",
                            proxies={"http": f"http://127.0.0.1:{XRAY_HTTP_PORT}",
                                     "https": f"http://127.0.0.1:{XRAY_HTTP_PORT}"},
                            timeout=10)
            ok = r.status_code < 400
        except Exception:
            ok = False
        if not ok:
            self.disconnect(restore_proxy=False)
            raise RuntimeError("تونل بالا آمد ولی پاسخ نداد")
        set_system_proxy(True)
        self.current_node = node
        return True

    def disconnect(self, restore_proxy: bool = True):
        if self.proc:
            _kill_proc(self.proc)
            with _ALL_PROCS_LOCK:
                if self.proc in _ALL_PROCS:
                    _ALL_PROCS.remove(self.proc)
            self.proc = None
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
