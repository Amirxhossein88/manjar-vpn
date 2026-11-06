# -*- coding: utf-8 -*-
"""
ManjarVPN Engine v1.8
=====================
مشکلِ نسخه‌ی قبل: برنامه می‌گفت «هیچ سروری کار نمی‌کند» در حالی که اکثر سرورها سالم بودند —
خودِ «قیفِ تست» همه‌چیز را رد می‌کرد. v1.7 قیف را از پایه درست می‌کند:

  ۱) «باز شدن سایت» یعنی «هر پاسخ HTTP» — حتی ۴۰۳/۴۲۹ (اینستاگرام به IP دیتاسنتر
     ۴۰۳ می‌دهد ولی همین پاسخ هم یعنی تونل TLS تا مقصد می‌رسد؛ قبلاً ردِ کاذب بود)
  ۲) سرعت از ۴ اندپوینتِ مستقل (کلادفلر + گوگل + هتزنر + OVH) سنجیده می‌شود؛
     کانفیگ‌هایی که از پشتِ کلادفلر خارج می‌شوند speed.cloudflare.com را
     ۴۰۳/۴۲۹ می‌گیرند — قبلاً این یعنی «سرعت صفر» و رد؛ حالا اندپوینت بعدی
     امتحان می‌شود و بهترین اندازه ملاک است (دروازه‌ی اتصال و نگهبان هم همین‌طور)
  ۳) همزمانیِ تست پینگ ۴۸ → ۱۴ (۴۸ Xrayِ همزمان روی لینک ایرانی خودش تایم‌اوت می‌سازد)
     + ردهایِ پینگ یک بار دیگر امتحان می‌شوند
  ۴) «هیچ‌کدام کار نمی‌کند» دیگر بن‌بست نیست: اگر هیچ کاندیدی سرعتِ تأییدشده نداشت،
     برنامه به کم‌پینگ‌ترینِ سالم‌ها وصل می‌شود (حالت اضطراری، دروازه‌ی شُل‌تر) و
     نگهبانِ سرعت اگر عملاً بی‌سرعت بود خودش عوضش می‌کند
  ۵) گزارشِ «قیف» با دلیلِ رد در هر مرحله: دریافت ← زنده ← پینگ ← سایت ← سرعت
     (+ دلایل: 403، تایم‌اوت، کم‌سرعت …) — دیگر نمی‌شود نپرسید «کجا رد شدند؟»
  ۶) تستِ سلامتِ ابزارِ تست قبل از اسکن + فایلِ کانفیگِ شخصی (my_configs.txt)
  ۷) «نجات با هوش مصنوعی» دیگر خودکار نیست — سوییچ در رابط (پیش‌فرض خاموش):
     مدلِ زبانی کانفیگِ زنده نمی‌شناسد و اکثراً UUID ساختگی می‌دهد؛ تصمیمِ نهایی
     را تستِ واقعی می‌گیرد، نه مدل

v1.8: تونلِ نهایی حالا یک اینباندِ API آمار هم دارد (StatsService) تا مصرفِ حجمِ کاربر
دقیق شمارش شود — read_traffic_counters() هر چند ثانیه از همین هسته می‌پرسد (بدون
واسطِ اضافه روی مسیر ترافیک) و محاسبه‌گرِ حجمِ رابط را پر می‌کند.

از v1.5 حفظ شد: سرعت شرطِ اتصال است و نودِ «فقط‌پینگی» در چهار لایه لو می‌رود:
  ۱) تست عمیق: سرعتِ «پایدار» (۳ دانلود موازی، بدون یک‌وَک اولیه) زیر حداقل → رد
  ۲) اسکن: هیچ کاندیدِ بدونِ حداقلِ سرعت انتخاب نمی‌شود
  ۳) دروازه‌ی اتصال: قبل از روشن‌کردن پروکسی سیستم، سرعت تونل سنجیده می‌شود
  ۴) نگهبان: اگر سرعت تونل چند نمونه‌ی متوالی عملاً صفر باشد → تعویض بی‌صدای سرور
موتور: دریافت موازی کانفیگ‌ها از ۳۹ منبع زنده، پیش‌فیلتر TCP، تست پینگ،
«تست عمیق» هر کاندید با یک هسته Xray: باز کردن واقعی یوتوب/اینستاگرام/تلگرام
از داخل همان تونل + سرعت واقعی دانلود/آپلود، حافظه‌ی سرورهای خوب،
انتخاب بهترین + پروکسی سیستم ویندوز + نگهبان با تعمیر بی‌صدا.
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
VERSION = "1.8.0"

# ============================ تنظیمات قابل تغییر ============================
MAX_TEST_NODES = 1200         # حداکثر کانفیگ برای پیش‌فیلتر TCP
TCP_PREFILTER_WORKERS = 200   # اتصال‌های همزمان TCP (خیلی سبک است)
TCP_PREFILTER_TIMEOUT = 2.0   # v1.7: ۱.۵ → ۲ ثانیه (تایم‌اوتِ کوتاه = ردِ کاذب روی لینک شلوغ)
MAX_XRAY_LATENCY_TESTS = 320  # بعد از پیش‌فیلتر، حداکثر تست پینگ واقعی
CONCURRENT_TESTS = 14         # v1.7: ۴۸ → ۱۴ (۴۸ Xrayِ همزمان روی لینک ایرانی خودش تایم‌اوت می‌سازد)
LATENCY_RETRY_MAX = 80        # v1.7: ردهایِ پینگ یک بار دیگر امتحان می‌شوند (سقف)
TOP_SPEED_TESTS = 8           # بهترین‌های پینگ برای تست سرعت
EXTRA_SPEED_SAMPLES = 3       # + چند نمونه تصادفی سالم برای تنوع
CONCURRENT_SPEED_TESTS = 6
LATENCY_TIMEOUT = 5
SPEED_TIMEOUT = 7
SPEED_MAX_BYTES = 6_000_000
GOOD_SPEED_EARLY = 12.0       # Mbps — اگر برسد دیگر لازم نیست صبر کامل کنیم

# ===== سرعت دیگر «تزئینی» نیست؛ شرطِ اتصال است =====
MIN_GOOD_SPEED_MBPS = 2.0     # حداقل سرعتِ «خوب» (یوتوب/اینستا راحت بالا می‌آید)
MIN_USABLE_SPEED_MBPS = 0.6   # کفِ مطلق — زیرِ این تونل عملاً بی‌استفاده است و رد می‌شود
CONNECT_GATE_MBPS = 1.0       # دروازه‌ی اتصال نهایی: قبل از فعال‌شدن پروکسی سیستم سنجیده می‌شود

EMERGENCY_GATE_MBPS = 0.3     # v1.7: دروازه در «حالت اضطراری» — وصل‌شدنِ ضعیف بهتر از بی‌اتصالی

# نگهبان اتصال (main.py): «فقط‌پینگی» را وسط کار هم می‌گیرد
LIVE_MIN_SPEED_MBPS = 0.5     # نمونه‌ی سرعت زیر این = تونل عملاً مرده
LIVE_SLOW_LIMIT = 3           # چند نمونه‌ی متوالی مرده → تعویض بی‌صدای سرور

# ===== تست سرعتِ «پایدار» مثل مرورگر واقعی =====
# ۳ دانلودِ موازی، ۶ ثانیه، سرعت فقط از ثانیه‌ی ۱.۵ به بعد — تا اثر slow-start حذف شود.
# v1.7 — چهار اندپوینتِ مستقل (کلادفلر + گوگل + هتزنر + OVH، سه CDN جدا):
# کانفیگ‌های پشتِ کلادفلر (اکثر کانفیگ‌های ws رایگان!) از speed.cloudflare.com
# خیلی وقت‌ها ۴۰۳/۴۲۹ می‌گیرند — قبلاً این یعنی «سرعت صفر» و ردِ کاذبِ همه‌چیز.
# حالا اگر اندپوینتی هیچ داده‌ای نداد، اندپوینتِ بعدی امتحان می‌شود (تا ۲ اندپوینت).
SUSTAIN_SECONDS = 6.0         # مدت تست
SUSTAIN_WARMUP = 1.5          # یک‌وَک اولیه از محاسبه حذف می‌شود
SPEED_ENDPOINTS = [
    "https://speed.cloudflare.com/__down?bytes=25000000",
    # فایل بزرگ از CDN گوگل — همان خانواده‌ی لبه‌هایی که ترافیک یوتوب از آن رد می‌شود
    "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    "https://nbg1-speed.hetzner.com/100MB.bin",
    "https://proof.ovh.net/files/100Mb.dat",
]
SPEED_ENDPOINT_ATTEMPTS = 2   # حداکثر چند اندپوینت برای هر نود امتحان شود
SPEED_MIN_VALID_BYTES = 150_000  # کمتر از این در ۶ ثانیه = اندپوینت/تونل مشکوک → اندپوینتِ بعدی
SUSTAIN_ENDPOINTS = SPEED_ENDPOINTS   # سازگاری با نامِ قدیمی
# تست واقعی: علاوه بر 204، یک سایت واقعی TLS هم باید باز شود (ضد «وصل شد ولی کار نمی‌کند»)
REAL_SITE_URL = "https://www.wikipedia.org/static/favicon/wikipedia.ico"
UPLOAD_TEST_URL = "https://speed.cloudflare.com/__up"

# ====== تست عمیق هر کاندید (دقیقا طبق خواسته‌ی کاربر) ======
# برنامه با هر کاندیدِ کم‌پینگ، یک هسته Xray بالا می‌آورد و از داخل همان تونل:
#   ۱) یوتوب و اینستاگرام و تلگرام را واقعا باز می‌کند (حداقل ۲ تا از ۳ باید باز شود)
#   ۲) سرعت دانلود واقعی (Cloudflare) را می‌سنجد
#   ۳) سرعت آپلود واقعی را می‌سنجد
# بعد بین کاندیدهایی که سایت‌ها را باز کردند، بهترین (بیشترین سرعت، بعد کم‌ترین پینگ) وصل می‌شود.
SITE_TARGETS = [
    ("یوتوب",      "https://www.youtube.com/generate_204"),
    ("اینستاگرام", "https://www.instagram.com/robots.txt"),
    ("تلگرام",     "https://web.telegram.org/k/"),
]
SITE_MIN_PASS = 2             # حداقل چند سایت از ۳ باید باز شود تا کاندید تایید شود
DEEP_POOL = 40                # کم‌پینگ‌ترین‌ها که تست عمیق می‌شوند
DEEP_ROUNDS = 3               # اگر دور اول هیچ کاندیدی تایید نکرد، ۴۰ تای بعدی هم تست می‌شوند (تا ۳ دور)
DEEP_TARGET = 12              # به‌محض این تعداد نتیجه‌ی کامل، بقیه رها می‌شوند
DEEP_WORKERS = 4              # چند کاندید همزمان تست عمیق شوند (v1.7: ۳ → ۴ — همزمانیِ پینگ کم شد، اینجا می‌شود بیشتر)
SITE_TIMEOUT = 6              # ثانیه برای هر سایت
UPLOAD_PROBE_BYTES = 400_000  # حجم نمونه آپلود هر کاندید

# چک سبکِ مرحله‌ی پینگ: یک 204 واقعی روی TLS (سریع — فقط برای ردکردن کانفیگ‌های مرده)
LIGHT_TLS_URL = "https://www.gstatic.com/generate_204"

# برای سازگاری با کدهای قبلی
VERIFY_TARGETS = SITE_TARGETS
VERIFY_POOL = DEEP_POOL
VERIFY_TARGET_COUNT = DEEP_TARGET
VERIFY_WORKERS = DEEP_WORKERS
VERIFY_TIMEOUT = SITE_TIMEOUT

# حافظه‌ی سرورهای خوب (اتصال سریع در اجراهای بعدی)
CACHE_MAX = 20
CACHE_TTL_DAYS = 7
QUICK_MIN_SPEED_MBPS = 2.0

XRAY_SOCKS_PORT = 10808
XRAY_HTTP_PORT = 10809

UA = {"User-Agent": f"{APP_NAME}/{VERSION}"}
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ============================ منابع کانفیگ (۳۹ منبع زنده) ============================
SUBSCRIPTION_SOURCES = [
    # barry-far — دسته‌های اصلی
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub9.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub10.txt",
    # barry-far — تفکیک بر اساس پروتکل
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    # جمع‌کننده‌ها
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    # V2RayRoot
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/trojan.txt",
    # ircfspace/tvc
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/mix",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/reality",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vless",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vmess",
    "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/trojan",
    # ===== v1.6 — منابع تازه‌تر (همه تست‌شده و زنده) =====
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_servers.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
    # ===== v1.7 — منابع فعال تازه (تست‌شده؛ ۳۷ منبع قبلی هم همگی زنده‌اند) =====
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
]

MIRROR_TEMPLATES = [
    "{url}",
    "https://ghfast.top/{url}",
    "https://gh-proxy.com/{url}",
    "https://mirror.ghproxy.com/{url}",
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


# ============================ نجاتِ هوشمند (v1.6 / پیش‌فرضِ خاموش از v1.7) ============
# اگر هیچ سروری جواب نداد، برنامه وضعیت را در یک پرامت خلاصه می‌کند، به یک
# هوش مصنوعی می‌دهد و کانفیگ‌های تازه‌اش را می‌گیرد، کامل تست می‌کند و وصل می‌شود.
# این کانفیگ‌ها «موقت»‌اند: extra["ai"]=True → در حافظه‌ی سرورهای خوب ذخیره نمی‌شوند.
# v1.7: این ثابت یعنی «قابلیت در دسترس است»؛ خاموش/روشنِ هر نشست با سوییچِ رابط کاربر
# تعیین می‌شود و در prefs.json ماندگار است (پیش‌فرضِ اولیه: خاموش).
AI_RESCUE_ENABLED = True
AI_RESCUE_MAX_ROUNDS = 2          # چند دور از هوش مصنوعی بپرسیم (پرامتِ هر دور کمی متفاوت است)
AI_RESCUE_MAX_URIS = 60           # سقف کانفیگ استخراجی از هر پاسخ
AI_RESCUE_MAX_LINKS = 3           # حداکثر لینک اشتراک عمومی که در پاسخ دنبال می‌شود
AI_RESCUE_TIMEOUT = 90            # ثانیه برای پاسخ مدل
AI_FREE_RETRY_WAIT = 47           # سرویسِ رایگان: ۱ پاسخ در ۴۵ ثانیه — بین دورها صبر می‌کنیم
POLLINATIONS_URL = "https://text.pollinations.ai/"
# نکته (تست واقعی ۲۰۲۶-۱۱): فقط مدلِ «openai-fast» روی سرویس رایگان مانده و
# مدل‌های استدلالی بدون reasoning_effort=low خطای token-limit می‌دهند.
POLLINATIONS_MODEL = "openai-fast"
AI_SETTINGS_FILE = "ai_settings.json"   # اختیاری: endpoint سازگار با OpenAI (OpenRouter و …)

_AI_URI_RE = re.compile(r"\b(?:vless|vmess|trojan|ss|ssr)://[^\s\"'<>\\]+", re.I)
_AI_SUB_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)


def load_ai_settings() -> dict:
    """تنظیمات اختیاری کاربر برای endpoint سازگار با OpenAI.
    فایل: %APPDATA%/ManjarVPN/ai_settings.json →
      {"base_url": "https://.../v1", "api_key": "...", "model": "..."}
    اگر نباشد، سرویس رایگان Pollinations (بدون کلید) استفاده می‌شود."""
    try:
        with open(os.path.join(_cache_dir(), AI_SETTINGS_FILE), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def build_rescue_prompt(diag: dict, round_no: int = 0) -> str:
    """پرامتِ نجات: شرحِ وضعیت + درخواستِ فهرستِ منابعِ تازه و چند کانفیگ نمونه.
    لحنِ خنثی و فنی (تستِ واقعی: درخواستِ «دور زدن فیلتر» از بعضی مدل‌ها رد می‌شود؛
    درخواستِ «منابع عمومیِ به‌روز برای کلاینت اوپن‌سورس» پاسخ می‌گیرد).
    مدل‌ها ممکن است کانفیگ‌های غلط بدهند — مهم نیست: برنامه همه را کامل تست می‌کند."""
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [
        f"I maintain an open-source, personal VPN client (parses vless:// vmess:// trojan:// ss:// URIs). Today, {when}, its automated test run failed:",
        f"- {diag.get('fetched', '?')} configs fetched from public aggregator feeds, "
        f"{diag.get('tcp_alive', '?')} reachable by TCP, {diag.get('latency_ok', '?')} passed ping, "
        f"{diag.get('verified', '?')} opened real sites, {diag.get('usable', '?')} had usable download speed.",
    ]
    reasons = diag.get("reasons") or {}
    if reasons:
        rs = ", ".join(f"{k}={v}" for k, v in list(reasons.items())[:5])
        lines.append(f"- Speed-test rejection reasons: {rs}.")
    lines += [
        "- The public subscription feeds it reads were all stale or dead today.",
        "",
        "Please reply with:",
        "1) Public GitHub repositories or raw.githubusercontent.com subscription URLs that are ACTIVELY "
        "UPDATED (ideally daily, by automation) and publish free vless/vmess/trojan/shadowsocks config lists.",
        "2) Up to 10 example config URIs from such public lists, in standard URI format "
        "(vless://... vmess://... trojan://... ss://...).",
    ]
    if round_no:
        lines.append("Prefer less-known sources than the usual big Telegram aggregators.")
    lines += [
        "",
        "Output format: one item per line (URLs and URIs mixed). No explanations, no markdown, no code fences.",
    ]
    return "\n".join(lines)


# ============================ تنظیماتِ برنامه (سوییچ‌های رابط) ============================
def load_prefs() -> dict:
    """تنظیماتِ سبکِ برنامه (مثل وضعیت سوییچ هوش مصنوعی) — prefs.json در پوشه‌ی کش."""
    try:
        with open(os.path.join(_cache_dir(), "prefs.json"), encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_prefs(**kw):
    try:
        d = load_prefs()
        d.update(kw)
        with open(os.path.join(_cache_dir(), "prefs.json"), "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


# ============================ کانفیگِ شخصیِ کاربر (v1.7) ============================
MY_CONFIGS_FILE = "my_configs.txt"   # %APPDATA%/ManjarVPN/my_configs.txt


def load_my_configs(max_nodes: int = 100) -> list:
    """فایلِ شخصیِ کاربر: هر خط یک کانفیگ (vless://…) یا یک لینک اشتراک (http…).
    # = توضیح. این کانفیگ‌ها همیشه تست می‌شوند و هرگز حذفِ نمونه‌گیری نمی‌شوند.
    پایدارترین مسیر: کانفیگِ سرورِ شخصی (اگر VPS دارید) اینجا بگذارید."""
    path = os.path.join(_cache_dir(), MY_CONFIGS_FILE)
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f.read().splitlines()
                     if l.strip() and not l.strip().startswith("#")]
    except Exception:
        return []
    if not lines:
        return []
    uris = []
    for l in lines:
        if l.lower().startswith(("http://", "https://")):
            txt = fetch_text(l)
            if txt:
                uris.extend(decode_subscription(txt)[:500])
        else:
            uris.append(l)
    nodes = []
    for u in uris[:max_nodes * 4]:
        n = parse_uri(u)
        if n is not None:
            n.extra["my"] = True
            nodes.append(n)
        if len(nodes) >= max_nodes:
            break
    return filter_supported(nodes)


def fetch_text(url: str, timeout: float = 12) -> str | None:
    """دانلود یک URL با آینه‌های گیت‌هاب (ماژول‌سطح — برای فایلِ شخصی هم استفاده می‌شود)."""
    for tpl in MIRROR_TEMPLATES:
        try:
            r = SESSION.get(tpl.format(url=url), timeout=timeout)
            if r.status_code == 200 and r.text.strip():
                return r.text
        except Exception:
            continue
    return None


def extract_uris_from_ai(text: str, max_uris: int = AI_RESCUE_MAX_URIS) -> tuple:
    """از پاسخِ مدل (حتی اگر داخل توضیح/markdown باشد): کانفیگ‌ها + لینک‌های اشتراک."""
    uris, subs = [], []
    for m in _AI_URI_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;)")
        if u not in uris:
            uris.append(u)
    for m in _AI_SUB_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;)")
        if "pollinations" in u or "github.com/XTLS" in u:
            continue
        if u not in subs:
            subs.append(u)
    return uris[:max_uris], subs[:AI_RESCUE_MAX_LINKS]


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
    up_speed: float = 0.0

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
        stream["xhttpSettings"] = {"path": e.get("path") or "/",
                                   "host": e.get("host") or sni,
                                   "mode": e.get("mode") or "auto"}

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


def build_xray_config(node: Node, socks_port: int, http_port: int | None = None,
                      api_port: int | None = None):
    """کانفیگ Xray. اگر api_port داده شود، سرویسِ آمار (StatsService) هم اضافه می‌شود تا
    مصرفِ حجمِ تونلِ نهایی دقیق شمارش شود (فقط برای اتصالِ اصلی — تست‌ها سبک می‌مانند)."""
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
    cfg = {"log": {"loglevel": "warning"},
           "inbounds": inbounds,
           "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}]}
    if api_port:
        inbounds.append({"tag": "api", "listen": "127.0.0.1", "port": api_port,
                         "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}})
        cfg["stats"] = {}
        cfg["api"] = {"tag": "api", "services": ["StatsService"]}
        cfg["policy"] = {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                       "statsOutboundUplink": True, "statsOutboundDownlink": True},
        }
        cfg["routing"] = {"rules": [{"type": "field",
                                     "inboundTag": ["api"], "outboundTag": "api"}]}
    return cfg


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
    """اگر از اجرای قبلی (کرش/بسته‌شدن اجباری) پروکسی سیستم روشن مانده و مرده است، پاکش می‌کند.
    هر 127.0.0.1:پورت در بازه‌ی 10000-19999 که هیچ برنامه‌ای رویش گوش نمی‌دهد = پروکسی مرده."""
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
        if not enabled:
            return False
        stale = False
        for part in str(server).split(";"):
            part = part.strip()
            if "=" in part:                      # فرمت http=host:port;https=...
                part = part.split("=", 1)[1].strip()
            if part.startswith("127.0.0.1:"):
                try:
                    port = int(part.split(":", 1)[1])
                except ValueError:
                    continue
                if 10000 <= port <= 19999 and not _wait_port(port, 0.4):
                    stale = True                 # هیچ‌کس گوش نمی‌دهد → پروکسی مرده
                    break
        if stale:
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
        self.conn_epoch = 0          # با هر اتصال +۱؛ نگهبانِ قدیمی با epoch قدیمی خارج می‌شود
        self.test_procs: list = []
        self.test_procs_lock = threading.Lock()
        self._port_counter = itertools.count(1)
        self._port_lock = threading.Lock()
        self.scan_stats: dict = {}          # آمار آخرین اسکن — برای گزارشِ قیف و پرامتِ نجات
        self._features_logged = False
        self._ep_cursor = 0                 # v1.7: چرخشِ اندپوینتِ سرعت بین نودها (پخشِ بار)
        self._gate_ep: str | None = None    # v1.7: اندپوینتِ سالمِ اتصالِ فعلی (کشِ دروازه/نگهبان)
        self._last_sites_detail = ""        # آخرین جزئیاتِ بازشدن سایت‌ها (برای گزارشِ دلیل رد)
        self.api_port: int | None = None    # v1.8: پورتِ API آمار برای شمارشِ مصرفِ حجم

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

    # ---------- سلامتِ ابزارِ تست (v1.7) ----------
    def check_test_rig(self) -> dict:
        """قبل از اسکن، اندپوینت‌های سرعت را «مستقیم» (بدون تونل) یک بار چک می‌کند.
        اگر خودِ شبکه به اندپوینت‌ها نرسد، اعدادِ داخلِ تونل هم مشکوک‌اند و باید دیده شود.
        خروجی: {url: "200، 300KB، ۸۰۰ms" یا نامِ خطا} — فقط لاگ می‌شود، تصمیم نمی‌گیرد."""
        out = {}

        def probe(url: str) -> str:
            try:
                t0 = time.time()
                hdrs = dict(SESSION.headers)
                if "speed.cloudflare.com" in url:
                    u = "https://speed.cloudflare.com/__down?bytes=300000"
                else:
                    u = url
                    hdrs["Range"] = "bytes=0-299999"
                with SESSION.get(u, stream=True, timeout=(3, 5), headers=hdrs) as r:
                    first = next(r.iter_content(65536), b"")
                    ms = int((time.time() - t0) * 1000)
                    if first:
                        return f"{r.status_code}، {len(first) // 1024}KB، {ms}ms"
                    return f"{r.status_code}، پاسخ خالی"
            except Exception as e:
                return type(e).__name__

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(probe, u): u for u in SPEED_ENDPOINTS}
            for f in as_completed(futs):
                out[futs[f]] = f.result()
        good = [k for k, v in out.items() if v.startswith("2")]
        host = lambda u: u.split("/")[2]          # noqa: E731
        self.log("🔧 سلامت ابزار تست (مستقیم، بدون تونل): " +
                 " • ".join(f"{host(u)}: {out[u]}" for u in SPEED_ENDPOINTS))
        if not good:
            self.log("⚠ هیچ اندپوینتِ سرعتی از خودِ شبکه در دسترس نیست — اعدادِ تست ممکن است نیم‌بنده؛")
            self.log("  اگر اینترنت‌تان روی سایتی مثل dl.google.com هم مشکل دارد، اول آن را چک کنید.")
        return out

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
                r = SESSION.get(tpl.format(url=url), timeout=12)
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
            try:
                r = SESSION.get("http://cp.cloudflare.com/generate_204",
                                proxies=proxies, timeout=LATENCY_TIMEOUT)
            except Exception:
                if self.stop_flag.is_set():
                    return None
                r = SESSION.get("https://www.gstatic.com/generate_204",
                                proxies=proxies, timeout=LATENCY_TIMEOUT)  # اندپوینتِ دوم (v1.7)
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
        """تست سرعتِ ساده (مسیرِ رزرو). v1.7: تا ۲ اندپوینتِ مستقل — ۴۰۳ِ کلادفلر
        دیگر «سرعت صفر» معنی نمی‌دهد؛ بهترین اندازه برمی‌گردد."""
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
            best = 0.0
            for k in range(SPEED_ENDPOINT_ATTEMPTS):
                if self.stop_flag.is_set():
                    break
                url = SPEED_ENDPOINTS[(self._ep_cursor + k) % len(SPEED_ENDPOINTS)]
                t0 = time.time()
                total = 0
                try:
                    with SESSION.get(url, stream=True, proxies=proxies,
                                     timeout=(5, SPEED_TIMEOUT)) as r:
                        if r.status_code >= 400:
                            continue        # اندپوینت این نود را بلاک کرده — بعدی
                        for chunk in r.iter_content(65536):
                            total += len(chunk)
                            if total >= SPEED_MAX_BYTES or time.time() - t0 > SPEED_TIMEOUT:
                                break
                except Exception:
                    continue
                el = time.time() - t0
                if el > 0.05 and total >= 100_000:
                    best = max(best, total * 8.0 / el / 1e6)
                    if best >= MIN_GOOD_SPEED_MBPS:
                        self._ep_cursor = (self._ep_cursor + k + 1) % len(SPEED_ENDPOINTS)
                        break               # کافی است
            return best
        finally:
            if proc:
                self._stop_xray(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    # ---------- تست‌های تکمیلی ----------
    def _real_site_ok(self, proxies: dict, timeout: float = 6.0) -> bool:
        """باز شدن یک سایت واقعی TLS از داخل تونل (ضد «وصل شد ولی کار نمی‌کند»).
        v1.7: هر پاسخ HTTP کافی است — حتی ۴۰۳/۴۲۹؛ پاسخ گرفتن یعنی تونل TLS را تا مقصد
        می‌رساند. شرطِ status<400 کانفیگ‌های سالم را بی‌جهت رد می‌کرد."""
        try:
            r = SESSION.get(REAL_SITE_URL, proxies=proxies, stream=True,
                            timeout=(4, timeout))
            r.close()
            return True
        except Exception:
            return False

    def _light_tls_ok(self, proxies: dict, timeout: float = 6.0) -> bool:
        """چک سبکِ TLS در مرحله‌ی پینگ: یک 204 واقعی روی https (سریع)."""
        try:
            r = SESSION.get(LIGHT_TLS_URL, proxies=proxies, timeout=(3, timeout))
            return r.status_code < 400
        except Exception:
            return False

    # ---------- باز کردن واقعی یوتوب / اینستاگرام / تلگرام از داخل تونل ----------
    _BROWSER_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

    def check_sites(self, proxies: dict, timeout: float = SITE_TIMEOUT) -> list:
        """سایت‌های واقعی را یکی‌یکی با این تونل باز می‌کند؛ لیست بازشده‌ها برمی‌گردد.
        v1.7 — تغییرِ مهم: «باز شدن» یعنی «هر پاسخ HTTP»، حتی ۴۰۳/۴۲۹/۵xx.
        هدف فقط این است که بفهمیم تونل TLS را تا مقصدِ واقعی می‌رساند؛ اینستاگرام به
        IPهای دیتاسنتر خیلی وقت‌ها ۴۰۳/۴۲۹ می‌دهد ولی همین پاسخ هم یعنی تونل سالم است.
        قبلاً status<400 شرط بود و همین، کانفیگ‌های سالم را بی‌جهت رد می‌کرد.
        جزئیاتِ هر سایت (کد یا نوع خطا) در _last_sites_detail می‌ماند برای گزارشِ قیف."""
        opened, detail = [], []
        for name, url in SITE_TARGETS:
            if self.stop_flag.is_set():
                break
            try:
                r = SESSION.get(url, proxies=proxies, stream=True,
                                timeout=(4, timeout), headers=self._BROWSER_UA)
                code = r.status_code
                r.close()
                opened.append(name)
                detail.append(f"{name}={code}")
            except Exception as e:
                et = type(e).__name__
                detail.append(f"{name}={'تایم‌اوت' if 'Timeout' in et else et}")
        self._last_sites_detail = "، ".join(detail)
        return opened

    # ---------- تست عمیق: یک Xray برای همه‌ی سنجه‌ها (سایت‌ها + دان + آپ) ----------
    def _funnel(self, key: str, reason: str | None = None):
        """شمارنده‌ی قیفِ تست: هر رد/قبول با دلیل ثبت می‌شود (گزارشِ آخرِ اسکن)."""
        st = self.scan_stats
        st[key] = st.get(key, 0) + 1
        if reason:
            rd = st.setdefault("reasons", {})
            rd[reason] = rd.get(reason, 0) + 1

    def deep_test(self, node: Node):
        """یک کانفیگ را کامل می‌سنجد؛ اگر حداقل SITE_MIN_PASS سایت باز کند,
        خود Node با latency/speed/up_speed/verified پر شده برمی‌گردد، وگرنه None.
        فقط «یک» هسته Xray برای همه‌ی سنجه‌ها بالا می‌آید (سریع‌تر از دو مرحله‌ی جدا).
        هر رد، در قیفِ تست با دلیل ثبت می‌شود (v1.7)."""
        if self.stop_flag.is_set():
            return None
        port = self._next_port()
        cfg = build_xray_config(node, port)
        if cfg is None:
            return None
        tmp = os.path.join(tempfile.gettempdir(),
                           f"manjarvpn_deep_{os.getpid()}_{port}.json")
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

            # ۱) سایت‌های واقعی باید باز شوند (v1.7: هر پاسخ HTTP = باز شده)
            opened = self.check_sites(proxies)
            node.extra["sites_detail"] = self._last_sites_detail
            if self.stop_flag.is_set():
                return None
            if len(opened) < SITE_MIN_PASS:
                self._funnel("site_fail",
                             "تایم‌اوتِ سایت" if "تایم‌اوت" in self._last_sites_detail else "سایت‌ها پاسخ ندادند")
                self.log(f"✗ رد شد: {node.display()} — سایت‌ها: {self._last_sites_detail or 'هیچ پاسخی'}")
                return None
            node.extra["opened"] = "،".join(opened)
            self._funnel("site_ok")

            # ۲) سرعتِ دانلودِ «پایدار» — v1.7: آبشارِ اندپوینت (کلادفلر↔گوگل↔هتزنر↔OVH)
            node.speed, sp_detail, sp_reason = self._dl_speed_on_port(proxies)

            # ۳) نودِ «فقط‌پینگی»: سایت‌ها باز شدند ولی داده‌ی واقعی رد نمی‌شود → رد
            if node.speed < MIN_USABLE_SPEED_MBPS:
                self._funnel("speed_fail", sp_reason)
                node.extra["dead_data"] = True
                node.extra["speed_detail"] = sp_detail
                self.log(f"✗ رد شد: {node.display()} — سایت‌ها باز شدند ولی سرعتِ پایدار "
                         f"{node.speed:.1f} Mbps است ({sp_detail}) — فقط‌پینگی")
                return None

            # تایید فقط بعد از سالم‌بودن سرعت ثبت می‌شود تا نودِ بی‌سرعت در رتبه‌بندی بالا نِشیند
            node.extra["verified"] = True
            self._funnel("speed_ok")

            # ۴) سرعت آپلود واقعی از داخل همان تونل
            if not self.stop_flag.is_set():
                node.up_speed = self._ul_speed_on_port(proxies)
            return node
        except Exception:
            return None
        finally:
            if proc:
                self._stop_xray(proc)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _sustain_probe(self, proxies: dict, url: str, timeout: float) -> tuple:
        """یک اندپوینت، ۳ دانلودِ موازی مثل مرورگر واقعی؛ سرعت فقط از پسِ warmup.
        خروجی: (mbps، کلِ بایتِ دانلودشده، دلیلِ کوتاه) — دلیل برای گزارشِ قیف."""
        lock = threading.Lock()
        samples = []                      # هر نخ: لیستِ (زمان، بایتِ تجمعی)
        got_total = [0]
        reasons = []
        t_start = time.time()
        deadline = t_start + timeout

        def worker():
            got = 0
            pts = [(t_start, 0.0)]
            try:
                with SESSION.get(url, stream=True, proxies=proxies,
                                 timeout=(5, timeout + 3)) as r:
                    if r.status_code >= 400:
                        with lock:
                            reasons.append(f"http_{r.status_code}")
                        return
                    for chunk in r.iter_content(65536):
                        got += len(chunk)
                        now = time.time()
                        if now - pts[-1][0] >= 0.3:
                            pts.append((now, float(got)))
                        if now >= deadline:
                            break
            except Exception as e:
                et = type(e).__name__
                with lock:
                    reasons.append("تایم‌اوت" if "Timeout" in et else et)
            finally:
                pts.append((time.time(), float(got)))
                with lock:
                    samples.append(pts)
                    got_total[0] += got

        ths = [threading.Thread(target=worker, daemon=True) for _ in range(3)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(timeout + 4.0)
        t_end = time.time()
        t_cut = t_start + SUSTAIN_WARMUP
        total_after = 0.0
        total_all = 0.0
        any_data = False
        for pts in samples:
            if not pts:
                continue
            b_cut = 0.0
            for t, b in pts:
                if t <= t_cut:
                    b_cut = b               # آخرین نمونه‌ی قبل از پایان warmup
            b_end = pts[-1][1]
            total_all += b_end
            if b_end - b_cut > 0:
                any_data = True
            total_after += max(0.0, b_end - b_cut)
        span = t_end - t_cut
        # حالتِ لینکِ خیلی سریع: کلِ فایل در همان warmup تمام شده — با میانگینِ warmup گزارش می‌شود
        mbps = 0.0
        if total_after >= 120_000 and any_data and span > 0.2:
            mbps = total_after * 8.0 / span / 1e6
        elif total_all >= 3_000_000:
            mbps = total_all * 8.0 / max(SUSTAIN_WARMUP, 0.1) / 1e6
        with lock:
            rsn = reasons[0] if reasons else ""
        if not rsn:
            rsn = "ok" if got_total[0] > 0 else "پاسخِ بی‌داده"
        return mbps, got_total[0], rsn

    def _dl_speed_on_port(self, proxies: dict, timeout: float = SUSTAIN_SECONDS) -> tuple:
        """تست سرعتِ دانلودِ «پایدار» روی یک تونل مشخص.
        v1.7 — آبشارِ اندپوینت: کانفیگ‌های پشتِ کلادفلر از speed.cloudflare.com خیلی
        وقت‌ها ۴۰۳/۴۲۹ می‌گیرند (خروجِ کلادفلری، نه تونلِ مرده) — قبلاً این یعنی
        «سرعت صفر» و ردِ کاذب. حالا اگر اندپوینتی دیتای معتبر نداد، اندپوینتِ بعدی
        (گوگل/هتزنر/OVH) امتحان می‌شود (تا SPEED_ENDPOINT_ATTEMPTS)؛ اگر دیتای معتبر
        آمد، همان عدد ملاک است — کندیِ واقعی تونل پنهان نمی‌شود.
        خروجی: (mbps، جزئیاتِ فارسی برای لاگ، دلیلِ کوتاه برای قیف)"""
        if self.stop_flag.is_set():
            return 0.0, "لغو شد", "لغو"
        idx = self._ep_cursor
        best, best_detail, best_reason = 0.0, "", ""
        for k in range(SPEED_ENDPOINT_ATTEMPTS):
            url = SPEED_ENDPOINTS[(idx + k) % len(SPEED_ENDPOINTS)]
            host = url.split("/")[2]
            mbps, got, reason = self._sustain_probe(proxies, url, timeout)
            if mbps > best:
                best, best_reason = mbps, reason
                best_detail = f"{mbps:.1f}Mbps از {host}"
            if got >= SPEED_MIN_VALID_BYTES:
                # دیتای معتبر رد شد → عدد واقعیِ تونل است؛ کندی از اندپوینت نیست
                self._ep_cursor = (idx + k + 1) % len(SPEED_ENDPOINTS)
                final_reason = "کم‌سرعت" if best < MIN_USABLE_SPEED_MBPS else "ok"
                return best, (best_detail or f"{host}: دیتای ناچیز"), final_reason
            if not best_detail:
                best_detail = f"{host}: {reason}"
            if reason not in ("ok",) and not best_reason:
                best_reason = reason
        self._ep_cursor = (idx + 1) % len(SPEED_ENDPOINTS)
        return best, (best_detail or "بدون داده"), (best_reason or "بدون داده")

    def _ul_speed_on_port(self, proxies: dict, timeout: float = 10.0) -> float:
        """تست سرعت آپلود روی یک تونل مشخص (Mbps)."""
        payload = b"x" * UPLOAD_PROBE_BYTES
        try:
            t0 = time.time()
            with SESSION.post(UPLOAD_TEST_URL, data=payload, proxies=proxies,
                              timeout=(5, timeout)) as r:
                if r.status_code >= 400:
                    return 0.0
            el = time.time() - t0
            if el <= 0.05:
                return 0.0
            return len(payload) * 8.0 / el / 1e6
        except Exception:
            return 0.0

    def deep_pool_test(self, pool: list, target: int = DEEP_TARGET) -> list:
        """به ترتیبِ پینگ (کم‌پینگ‌تر اول) کاندیدها را تست عمیق می‌کند؛
        به‌محض رسیدن به «target» نتیجه‌ی کامل، بقیه رها می‌شوند تا وقت تلف نشود.
        خروجی: تاییدشده‌ها — مرتب به همان ترتیب پینگ."""
        if not pool:
            return []
        done_evt = threading.Event()

        def guarded(n):
            if done_evt.is_set() or self.stop_flag.is_set():
                return None
            return self.deep_test(n)

        verified = []
        done = 0
        ex = ThreadPoolExecutor(max_workers=DEEP_WORKERS)
        try:
            futs = {ex.submit(guarded, n): n for n in pool}
            for f in as_completed(futs):
                done += 1
                r = f.result()
                if r is not None:
                    verified.append(r)
                    self.log(f"✓ تست کامل: {r.display()} — پینگ {int(r.latency or 0)}ms • "
                             f"دان {r.speed:.1f} • آپ {r.up_speed:.1f} Mbps • "
                             f"باز شد: {r.extra.get('opened', '')}")
                self.progress("deep", done, len(pool),
                              f"تست عمیق کاندیدها {done}/{len(pool)} — {len(verified)} تایید شد")
                if len(verified) >= target:
                    done_evt.set()
                    break
        finally:
            done_evt.set()
            ex.shutdown(wait=False)
        order = {id(n): i for i, n in enumerate(pool)}
        verified.sort(key=lambda n: order.get(id(n), 10 ** 9))
        return verified

    def measure_upload(self, seconds: float = 6.0) -> float:
        """اندازه‌گیری سرعت آپلود از داخل تونل فعال (Mbps) — بعد از اتصال نهایی."""
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
        """پیش‌فیلتر TCP → پینگ موازی (+ یک تلاشِ مجدد) → تست عمیق (تا ۳ دور) → بهترین.
        v1.7: گزارشِ «قیف» با دلیلِ رد در هر مرحله + حالتِ اضطراری (به‌جای «هیچ‌کدام کار نمی‌کند»
        به کم‌پینگ‌ترینِ سالم‌ها وصل می‌شود و نگهبان بقیه‌اش را می‌گیرد).
        خروجی: (بهترین، سالم‌ها)"""
        stats = {"fetched": len(nodes), "reasons": {}}
        self.scan_stats = stats
        try:
            self.ensure_features()
        except Exception:
            pass
        # v1.7: کانفیگ‌های شخصی (my_configs.txt) هرگز حذفِ نمونه‌گیری نمی‌شوند
        mine = [n for n in nodes if n.extra.get("my")]
        if len(nodes) > MAX_TEST_NODES:
            keep = mine[:20]
            rest = [n for n in nodes if not n.extra.get("my")]
            nodes = keep + random.sample(rest, max(0, MAX_TEST_NODES - len(keep)))
            self.log(f"→ نمونه‌گیری تصادفی: بررسی {len(nodes)} کانفیگ"
                     + (f" (شامل {len(keep)} کانفیگِ شخصی)" if keep else ""))

        alive = self.tcp_prefilter(nodes)
        stats["tcp_alive"] = len(alive)
        if self.stop_flag.is_set():
            return None, []
        self.log(f"⚡ پیش‌فیلتر: {len(alive)} سرور از {len(nodes)} زنده — شروع تست پینگ")
        if len(alive) > MAX_XRAY_LATENCY_TESTS:
            alive = random.sample(alive, MAX_XRAY_LATENCY_TESTS)

        def _latency_pass(pool, label):
            ok_list, fail_list = [], []
            done = 0
            with ThreadPoolExecutor(max_workers=CONCURRENT_TESTS) as ex:
                futs = {ex.submit(self.test_latency, n): n for n in pool}
                for f in as_completed(futs):
                    if self.stop_flag.is_set():
                        break
                    n = futs[f]
                    r = f.result()
                    done += 1
                    if r is not None:
                        n.latency = r
                        ok_list.append(n)
                    else:
                        fail_list.append(n)
                    if done % 10 == 0 or done == len(pool):
                        self.progress("latency", done, len(pool),
                                      f"تست پینگ {done}/{len(pool)} — {len(ok_list)} کانفیگ سالم")
            return ok_list, fail_list

        lat_ok, lat_fail = _latency_pass(alive, "اصلی")
        # v1.7: ردهایِ پینگ یک بار دیگر امتحان می‌شوند — تایم‌اوتِ لحظه‌ی شلوغی = ردِ کاذب
        if lat_fail and len(lat_fail) <= LATENCY_RETRY_MAX and not self.stop_flag.is_set():
            self.log(f"↻ {len(lat_fail)} کانفیگِ ردشده یک بار دیگر امتحان می‌شوند…")
            ok2, _ = _latency_pass(lat_fail, "تلاشِ مجدد")
            lat_ok.extend(ok2)
            stats["latency_retry_ok"] = len(ok2)
        if self.stop_flag.is_set():
            return None, lat_ok
        lat_ok.sort(key=lambda n: n.latency)
        stats["latency_ok"] = len(lat_ok)
        self.log(f"✓ پینگ تمام شد: {len(lat_ok)} کانفیگ سالم از {len(alive)}"
                 + (f" (با تلاشِ مجدد: {stats.get('latency_retry_ok', 0)} نجات یافت)"
                    if stats.get("latency_retry_ok") else ""))

        # ---- مرحله‌ی «تست عمیق»: با کم‌پینگ‌ترین‌ها، یوتوب/اینستاگرام/تلگرام ----
        # واقعا باز می‌شوند + سرعت دانلود و آپلود واقعی هر کدام سنجیده می‌شود.
        # اگر دور اول هیچ کاندیدی تایید نکرد، ۴۰ کاندید بعدی هم امتحان می‌شوند (تا DEEP_ROUNDS دور).
        verified = []
        pool_start = 0
        for rnd in range(DEEP_ROUNDS):
            pool = lat_ok[pool_start:pool_start + DEEP_POOL]
            if not pool:
                break
            if rnd:
                self.log(f"↻ دور {rnd + 1}: {len(pool)} کاندیدِ بعدی هم تست عمیق می‌شوند…")
            verified.extend(self.deep_pool_test(pool, target=DEEP_TARGET))
            if verified:
                break
            pool_start += DEEP_POOL
        stats["verified"] = len(verified)
        if self.stop_flag.is_set():
            return None, lat_ok
        if verified:
            self.log(f"✓ {len(verified)} کاندید سایت‌ها را باز کردند — بهترین از نظر سرعت انتخاب می‌شود")
        else:
            self.log("⚠ هیچ کاندیدی سایت‌ها را باز نکرد — روش قدیمی (تست سرعت ساده) ادامه می‌دهد")

        best = None
        if verified:
            # سرعتِ پایدار اجباری است — دیگر هیچ‌وقت به نودِ بی‌سرعت وصل نمی‌شویم
            fast = [n for n in verified if n.speed >= MIN_GOOD_SPEED_MBPS]
            usable = [n for n in verified if n.speed >= MIN_USABLE_SPEED_MBPS]
            stats["usable"] = len(usable)
            if fast:
                best = max(fast, key=lambda n: (n.speed, -(n.latency or 0)))
                self.log(f"✓ انتخاب شد: {best.display()} — دانِ پایدار {best.speed:.1f} • "
                         f"آپ {best.up_speed:.1f} Mbps — پینگ {int(best.latency or 0)}ms")
            elif usable:
                best = max(usable, key=lambda n: (n.speed, -(n.latency or 0)))
                self.log(f"⚠ هیچ کاندیدِ سریعی نبود — بهترینِ قابل‌استفاده انتخاب شد: "
                         f"{best.display()} ({best.speed:.1f} Mbps)")

        if best is None:
            # fallback: هیچ کاندیدی تایید نشد → همان مسیر قدیمی (تست سرعت ساده)
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
            usable = [n for n in top if n.speed >= MIN_USABLE_SPEED_MBPS]
            stats["usable"] = stats.get("usable", 0) or len(usable)
            if fast:
                best = max(fast, key=lambda n: (n.speed, -n.latency))
            elif usable:
                best = max(usable, key=lambda n: (n.speed, -n.latency))
                self.log(f"⚠ بهترینِ قابل‌استفاده (سرعت پایین): {best.display()} — {best.speed:.1f} Mbps")

        if best is None and lat_ok and not self.stop_flag.is_set():
            # ===== v1.7 — حالتِ اضطراری: بن‌بستِ «هیچ‌کدام کار نمی‌کند» حذف شد =====
            # هیچ کاندیدی سرعتِ تأییدشده نداشت، ولی چند تونلِ زنده داریم؛ به کم‌پینگ‌ترین
            # وصل می‌شویم (دروازه‌ی شُل‌تر) — اگر عملاً بی‌سرعت بود، نگهبان خودش عوضش می‌کند.
            best = min(lat_ok, key=lambda n: n.latency)
            best.extra["emergency"] = True
            self.log(f"⚠ حالت اضطراری: هیچ کاندیدی سرعتِ تأییدشده نداشت — اتصال به کم‌پینگ‌ترینِ "
                     f"سالم‌ها: {best.display()} (پینگ {int(best.latency or 0)}ms)")
            self.log("  اگر سرعت عملاً صفر باشد، نگهبانِ برنامه خودش سرور را عوض می‌کند.")

        # ---- گزارشِ قیفِ تست (v1.7): دقیقاً کجا رد شدند؟ ----
        rs = stats.get("reasons") or {}
        rs_txt = "، ".join(f"{k}={v}" for k, v in sorted(rs.items(), key=lambda x: -x[1])[:5])
        self.log(f"📊 قیف تست: دریافت {stats['fetched']} ← زنده {stats.get('tcp_alive', 0)} ← "
                 f"پینگ {stats.get('latency_ok', 0)} ← سایت {stats.get('site_ok', 0)} ← "
                 f"سرعتِ تأیید {stats.get('verified', 0)}"
                 + (f" — دلایلِ رد: {rs_txt}" if rs_txt else ""))

        if best is None:
            self.log("✗ حتی یک تونلِ پاسخ‌گو هم نبود — اتصال انجام نمی‌شود")
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
                n.up_speed = float(e.get("up_speed", 0) or 0)
                if e.get("verified"):
                    n.extra["verified"] = True
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
        # تست عمیق موازیِ سه کاندید برتر: سایت‌ها + دان + آپ — یک Xray برای هر کدام
        ex = ThreadPoolExecutor(max_workers=3)
        try:
            futs = {ex.submit(self.deep_test, n): n for n in top}
            for f in as_completed(futs):
                f.result()
        finally:
            ex.shutdown(wait=False)
        if self.stop_flag.is_set():
            return None, lat_ok
        ok = [n for n in top if n.extra.get("verified") and n.speed >= QUICK_MIN_SPEED_MBPS]
        if ok:
            best = max(ok, key=lambda n: (n.speed, -(n.latency or 0)))
            self.log(f"★ بهترین حافظه: {best.display()} — دان {best.speed:.1f} • "
                     f"آپ {best.up_speed:.1f} Mbps • {best.extra.get('opened', '')}")
            return best, lat_ok
        return None, lat_ok

    def update_cache(self, best: Node, runners: list):
        entries = load_cache()
        by_uri = {e["uri"]: e for e in entries}
        for n in [best] + list(runners[:5]):
            if n is None or n.extra.get("ai"):
                continue            # کانفیگ‌های موقتِ هوش مصنوعی ذخیره نمی‌شوند (موقعیتِ فعلی فقط)
            if not n.uri or n.speed <= 0:
                continue
            by_uri[n.uri] = {"uri": n.uri, "latency": int(n.latency or 0),
                             "speed": round(n.speed, 2),
                             "up_speed": round(n.up_speed, 2),
                             "verified": bool(n.extra.get("verified")),
                             "ts": time.time()}
        entries = sorted(by_uri.values(), key=lambda e: -float(e.get("speed", 0)))
        save_cache(entries)

    # ---------- نجاتِ هوشمند: گرفتن کانفیگ تازه از هوش مصنوعی (v1.6) ----------
    def _ai_ask(self, prompt: str, settings: dict, timeout: float = AI_RESCUE_TIMEOUT) -> str | None:
        """پرامت را به هوش مصنوعی می‌دهد. ترتیب:
        ۱) endpoint شخصیِ سازگار با OpenAI (اگر کاربر در ai_settings.json ست کرده باشد)
        ۲) سرویس رایگان Pollinations — بدون کلید (مدل‌های openai و mistral پشت‌سرهم امتحان می‌شوند)"""
        base = (settings.get("base_url") or "").strip().rstrip("/")
        if base:
            try:
                headers = {"Content-Type": "application/json"}
                key = (settings.get("api_key") or "").strip()
                if key:
                    headers["Authorization"] = f"Bearer {key}"
                body = {"model": settings.get("model") or "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.8}
                r = SESSION.post(f"{base}/chat/completions", json=body,
                                 headers=headers, timeout=(10, timeout))
                if r.status_code < 400:
                    txt = r.json()["choices"][0]["message"]["content"]
                    if txt and txt.strip():
                        self.log(f"🤖 پاسخ از endpoint شخصی گرفته شد ({settings.get('model') or 'gpt-4o-mini'})")
                        return txt
                else:
                    self.log(f"✗ endpoint شخصی خطا داد ({r.status_code}) — سرویس رایگان امتحان می‌شود")
            except Exception as e:
                self.log(f"✗ endpoint شخصی جواب نداد ({type(e).__name__}) — سرویس رایگان امتحان می‌شود")
        for model in (POLLINATIONS_MODEL, "openai"):
            if self.stop_flag.is_set():
                return None
            try:
                body = {
                    "messages": [{"role": "user", "content": prompt}],
                    "model": model,
                    "referrer": APP_NAME,
                    "seed": random.randint(1, 10 ** 6),
                }
                if model == POLLINATIONS_MODEL:
                    body["reasoning_effort"] = "low"   # مدل‌های استدلالی بدون این، token-limit می‌خورند
                r = SESSION.post(POLLINATIONS_URL, json=body,
                                 headers={"Content-Type": "application/json"}, timeout=(10, timeout))
                if r.status_code < 400 and r.text.strip():
                    self.log(f"🤖 پاسخ از هوش مصنوعی رایگان گرفته شد (مدل: {model})")
                    return r.text
                # خطاهای رایج: ۴۰۲ محدودیتِ رایگان (۱ پاسخ / ۴۵ ثانیه)، ۴۰۰ token-limit
                msg = ""
                try:
                    msg = r.json().get("error", {}).get("message", "") or r.text[:120]
                except Exception:
                    msg = r.text[:120]
                self.log(f"✗ هوش مصنوعی رایگان ({model}) خطا {r.status_code}: {msg}")
            except Exception:
                continue
        return None

    def ai_rescue(self, diag: dict, existing_keys: set | None = None) -> list:
        """وضعیت را به هوش مصنوعی می‌دهد، کانفیگ‌های تازه (و لینک‌های اشتراکش) را
        استخراج و parse می‌کند. خروجی: نودهای تازه با extra["ai"]=True (موقت — کش نمی‌شوند)."""
        settings = load_ai_settings()
        if settings.get("base_url"):
            self.log("🤖 endpoint شخصیِ هوش مصنوعی پیدا شد — استفاده می‌شود")
        existing_keys = existing_keys or set()
        all_nodes = []
        for rnd in range(AI_RESCUE_MAX_ROUNDS):
            if self.stop_flag.is_set():
                break
            if rnd and not settings.get("base_url"):
                # سرویس رایگان: ۱ پاسخ در ۴۵ ثانیه — قبل از دور بعد صبر
                self.log(f"⏳ {AI_FREE_RETRY_WAIT} ثانیه صبر (محدودیتِ سرویس رایگان: ۱ پاسخ در ۴۵ ثانیه)…")
                if self.stop_flag.wait(AI_FREE_RETRY_WAIT):
                    break
            prompt = build_rescue_prompt(diag, rnd)
            self.log(f"🤖 درخواست کانفیگ تازه از هوش مصنوعی (دور {rnd + 1}/{AI_RESCUE_MAX_ROUNDS})…")
            text = self._ai_ask(prompt, settings)
            if self.stop_flag.is_set():
                break
            if not text:
                self.log("✗ هوش مصنوعی پاسخ نداد")
                continue
            uris, subs = extract_uris_from_ai(text)
            self.log(f"🤖 در پاسخ: {len(uris)} کانفیگ + {len(subs)} لینک اشتراک")
            fresh = []

            def _mark(n, name):
                if n is None or n.key() in existing_keys:
                    return None
                n.extra["ai"] = True
                if name and not str(n.name or "").startswith("🤖"):
                    n.name = f"🤖 {name}"
                return n

            for u in uris:
                n = parse_uri(u)
                if _mark(n, (n.name if n else "")) is not None:
                    fresh.append(n)
            for su in subs:                       # لینک اشتراک در پاسخ؟ دانلود و استخراج
                txt = self._fetch_url(su)
                if not txt:
                    continue
                got = decode_subscription(txt)[:200]
                self.log(f"🤖 لینک اشتراک: {len(got)} کانفیگ")
                for u2 in got:
                    n2 = parse_uri(u2)
                    if _mark(n2, "کانفیگ تازه") is not None:
                        fresh.append(n2)
            fresh = filter_supported(fresh)
            all_nodes.extend(fresh)
            if all_nodes:
                break                             # کافی است — تستِ واقعی خودش غربال می‌کند
        # بدون تکرار
        uniq, seen = [], set()
        for n in all_nodes:
            if n.key() in seen:
                continue
            seen.add(n.key())
            uniq.append(n)
        return uniq[:AI_RESCUE_MAX_URIS]

    # ---------- نگهبان اتصال: چک سبک (بدون دانلود سنگین) ----------
    def health_check(self, timeout: float = 7.0) -> bool:
        """چک سبک: آیا تونل زنده است؟ فقط یک درخواست 204 — بدون دانلود حجمی.
        (باگ قطع‌های کاذب: قبلا هر ۳ ثانیه ۱۲۸KB دانلود می‌شد که روی سرورهای شلوغ
        تایم‌اوت می‌شد و برنامه اتصالِ سالم را قطع می‌کرد.)"""
        if not self.proc or self.proc.poll() is not None:
            return False
        proxies = {"http": f"http://127.0.0.1:{self.http_port}",
                   "https": f"http://127.0.0.1:{self.http_port}"}
        for url in ("http://cp.cloudflare.com/generate_204",
                    "http://www.gstatic.com/generate_204"):
            try:
                r = SESSION.get(url, proxies=proxies, timeout=timeout)
                if r.status_code < 500:
                    return True
            except Exception:
                continue
        return False

    def light_speed(self, bytes_to: int = 262144, timeout: float = 8.0) -> float:
        """نمونه‌گیری سبک سرعت دانلود از داخل تونل فعال (دروازه‌ی اتصال + نگهبان).
        ضد «صفرِ کاذب»: اگر لینک آن‌قدر سریع باشد که حجم اولیه در کمتر از ۰.۱۵ ثانیه
        تمام شود، یک‌بار دیگر با حجم بزرگ‌تر اندازه می‌گیریم.
        v1.7: اگر اندپوینتِ اول پاسخ ≥۴۰۰ داد (کلادفلر به خروجِ کلادفلری ۴۰۳ می‌دهد)،
        اندپوینتِ بعدی امتحان می‌شود؛ اندپوینتِ سالم برای کل اتصال کش می‌شود."""
        if not self.proc or self.proc.poll() is not None:
            return 0.0
        proxies = {"http": f"http://127.0.0.1:{self.http_port}",
                   "https": f"http://127.0.0.1:{self.http_port}"}
        order = []
        if self._gate_ep in SPEED_ENDPOINTS:
            order.append(self._gate_ep)
        order += [u for u in SPEED_ENDPOINTS if u not in order]

        def fetch(url: str, size: int):
            total = 0
            t0 = time.time()
            u = url if "speed.cloudflare.com" not in url \
                else f"https://speed.cloudflare.com/__down?bytes={size}"
            with SESSION.get(u, stream=True, proxies=proxies, timeout=(5, timeout)) as r:
                if r.status_code >= 400:
                    return 0, 0.0
                for chunk in r.iter_content(65536):
                    total += len(chunk)
                    if total >= size or time.time() - t0 > timeout:
                        break
            return total, time.time() - t0

        best = 0.0
        for url in order[:SPEED_ENDPOINT_ATTEMPTS]:
            if self.stop_flag.is_set() or not self.proc or self.proc.poll() is not None:
                break
            try:
                total, el = fetch(url, bytes_to)
                if el < 0.15 and total >= bytes_to and bytes_to < 8_388_608 \
                        and not self.stop_flag.is_set() \
                        and self.proc and self.proc.poll() is None:
                    total, el = fetch(url, min(bytes_to * 8, 8_388_608))   # لینک خیلی سریع — دوباره
                if el > 0.05 and total >= 50_000:
                    mbps = total * 8.0 / el / 1e6
                    if mbps > best:
                        best = mbps
                        self._gate_ep = url
                    if best >= 0.1:
                        return best        # یک اندپوینت جواب داد — کافی است
            except Exception:
                continue
        return best

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

    def read_traffic_counters(self) -> int | None:
        """v1.8 — مجموعِ بایتِ ردشده از اینباند‌های کاربر (socks + http) از API آمارِ Xray.
        uplink + downlink؛ اینباندِ api خودش شمرده نمی‌شود. خروجیِ None یعنی خواندن ممکن نشد.
        سبک است (یک subprocess چند-millisecond) — رابط هر چند ثانیه می‌پرسد."""
        if not self.api_port or not self.xray_path:
            return None
        if not self.proc or self.proc.poll() is not None:
            return None
        try:
            p = subprocess.run(
                [self.xray_path, "api", "statsquery",
                 f"--server=127.0.0.1:{self.api_port}", "-pattern", "inbound"],
                capture_output=True, text=True, timeout=6,
                creationflags=CREATE_NO_WINDOW)
            if p.returncode != 0:
                return None
            d = json.loads(p.stdout or "{}")
            total = 0
            for s in d.get("stat", []):
                name = str(s.get("name", ""))
                if ">>>api>>>" in name:       # ترافیکِ خودِ API شمرده نشود
                    continue
                try:
                    total += int(s.get("value", 0))
                except (TypeError, ValueError):
                    pass
            return total
        except Exception:
            return None

    def connect(self, node: Node) -> bool:
        self.disconnect(restore_proxy=False)
        # پورت‌های آزاد (اگر v2rayN و … روی 10808 بود، تداخل پیش نیاید)
        self.socks_port = self._alloc_local_port(10808)
        self.http_port = self._alloc_local_port(10809)
        self.api_port = self._alloc_local_port(15432)     # v1.8: API آمار
        cfg = build_xray_config(node, self.socks_port, self.http_port, api_port=self.api_port)
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
        # ===== دروازه‌ی سرعت (قبل از فعال‌کردن پروکسی سیستم) =====
        # نودِ «فقط‌پینگی» اینجا هم اگر سرعت واقعی نداشته باشد رد می‌شود و
        # _connect_with_fallback خودش سراغ کاندید بعدی می‌رود.
        # v1.7: کاندیدِ تأییدشده ← دروازه‌ی کامل؛ کاندیدِ اضطراریِ بدون تأیید ← دروازه‌ی شُل‌تر
        # (وصل‌شدنِ ضعیف بهتر از پیامِ «هیچ‌کدام کار نمی‌کند» است؛ نگهبان بقیه‌اش را می‌گیرد)
        self._gate_ep = None
        if ok:
            gate_limit = CONNECT_GATE_MBPS if node.extra.get("verified") else EMERGENCY_GATE_MBPS
            gate = self.light_speed(bytes_to=1_000_000, timeout=8)
            if gate < gate_limit:
                tail = self._read_err_tail(errlog)
                self.disconnect(restore_proxy=False)
                raise RuntimeError(
                    f"تونل وصل شد ولی سرعت واقعی {gate:.1f} Mbps است "
                    f"(کمتر از حداقل {gate_limit}) — رد شد، رفتن به کاندید بعدی"
                    + (f" — {tail}" if tail else ""))
        if not ok:
            tail = self._read_err_tail(errlog)
            self.disconnect(restore_proxy=False)
            raise RuntimeError("تونل پاسخ نداد (سایت واقعی هم باز نشد)"
                               + (f" — {tail}" if tail else ""))
        set_system_proxy(True, port=self.http_port)
        self.current_node = node
        self.conn_epoch += 1          # فقط اتصال موفق — نگهبان‌های قدیمی‌تر خودبه‌خود متوقف می‌شوند
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
        self.api_port = None

    def stop_all(self):
        self.stop_flag.set()
        with self.test_procs_lock:
            procs = list(self.test_procs)
        for p in procs:
            _kill_proc(p)
        self.disconnect()
