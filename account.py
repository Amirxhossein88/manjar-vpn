# -*- coding: utf-8 -*-
"""
ManjarVPN v1.8 — حسابِ اعتبارِ حجم
====================================
محاسبه‌گر مصرف حجم + کدهای شارژ + گردونه‌ی هدیه.

- اعتبارِ پیش‌فرض: ۵۰۰ مگابایت
- گردونه‌ی هدیه (فقط یک‌بار برای هر سیستم): اعتبارِ اولیه = ۵۰۰ تا ۶۰۰ مگابایت
- کدِ خریدار  «Manjar172026»       → +۷ گیگابایت
- کدِ مدیر    «Manjar172026Admin»  → +۲۰ گیگابایت (هر بار که اشتراک تمام شد دوباره قابل استفاده)
- وقتی اعتبار تمام شود برنامه اجازه‌ی اتصال نمی‌دهد و پیام «باید اشتراک خود را تامین کنید» می‌دهد.

همه‌چیز در پوشه‌ی ManjarVPN داخل APPDATA ذخیره می‌شود — پس حتی اگر exe از اول نصب شود،
گردونه و مصرفِ قبلی برای همان سیستم تکرار نمی‌شود.
"""
from __future__ import annotations

import json
import os
import threading
import time

from engine import APP_NAME, _cache_dir

DEFAULT_CREDIT_MB = 500.0                 # اعتبار پیش‌فرض
BUYER_CODE = "Manjar172026"               # کد خریدار → +۷ گیگ
BUYER_BONUS_MB = 7 * 1024
ADMIN_CODE = "Manjar172026Admin"          # کد مدیر → +۲۰ گیگ (قابل استفاده‌ی مکرر)
ADMIN_BONUS_MB = 20 * 1024


class Account:
    """اعتبار و مصرفِ حجم — thread-safe با ذخیره‌ی اتمیک."""

    def __init__(self):
        self._lock = threading.RLock()
        self.path = os.path.join(_cache_dir(), "account.json")
        self.used_bytes = 0
        self.credit_mb = DEFAULT_CREDIT_MB
        self.wheel_done = False
        self.wheel_prize_mb = 0.0
        self.redemptions: dict = {}
        self._load()

    # ---------------- فایل ----------------
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d, dict):
                return
            self.used_bytes = max(0, int(d.get("used_bytes", 0) or 0))
            self.credit_mb = max(0.0, float(d.get("credit_mb", DEFAULT_CREDIT_MB) or DEFAULT_CREDIT_MB))
            self.wheel_done = bool(d.get("wheel_done", False))
            self.wheel_prize_mb = max(0.0, float(d.get("wheel_prize_mb", 0) or 0))
            r = d.get("redemptions")
            self.redemptions = r if isinstance(r, dict) else {}
        except Exception:
            pass

    def save(self):
        try:
            d = {
                "used_bytes": int(self.used_bytes),
                "credit_mb": round(float(self.credit_mb), 1),
                "wheel_done": bool(self.wheel_done),
                "wheel_prize_mb": round(float(self.wheel_prize_mb), 1),
                "redemptions": self.redemptions,
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
        except Exception:
            pass

    # ---------------- محاسبات ----------------
    def credit_bytes(self) -> float:
        with self._lock:
            return self.credit_mb * 1024 * 1024

    def remaining_bytes(self) -> float:
        with self._lock:
            return max(0.0, self.credit_mb * 1024 * 1024 - self.used_bytes)

    def is_blocked(self) -> bool:
        return self.remaining_bytes() <= 0

    def snapshot(self) -> dict:
        """وضعیت لحظه‌ای برای رابط کاربری."""
        with self._lock:
            total = self.credit_mb
            used_mb = self.used_bytes / (1024 * 1024)
            return {
                "used_mb": used_mb,
                "credit_mb": total,
                "remaining_mb": max(0.0, total - used_mb),
                "frac": (used_mb / total) if total > 0 else 1.0,
            }

    def consume(self, delta_bytes: int) -> dict:
        """مصرفِ تازه را ثبت می‌کند و اسنپ‌شات برمی‌گرداند."""
        if delta_bytes and delta_bytes > 0:
            with self._lock:
                self.used_bytes += int(delta_bytes)
                self.save()
        return self.snapshot()

    # ---------------- شارژ ----------------
    def add_credit(self, mb: float, source: str = "", replace: bool = False) -> dict:
        with self._lock:
            self.credit_mb = mb if replace else self.credit_mb + mb
            if source:
                self.redemptions[source] = self.redemptions.get(source, 0) + 1
            self.save()
            return self.snapshot()

    def set_wheel_done(self, prize_mb: float):
        with self._lock:
            self.wheel_done = True
            self.wheel_prize_mb = prize_mb
            self.save()

    def redeem(self, code: str):
        """کد شارژ را بررسی و اعتبار اضافه می‌کند.
        خروجی: (موفق؟، پیامِ فارسی، مقدارِ اضافه‌شده به مگابایت)"""
        c = (code or "").strip().lower()
        if not c:
            return False, "کد را وارد کنید", 0.0
        if c == BUYER_CODE.lower():
            self.add_credit(BUYER_BONUS_MB, source="buyer")
            return True, f"✓ کد خریدار فعال شد — {BUYER_BONUS_MB // 1024} گیگابایت اعتبار اضافه شد", BUYER_BONUS_MB
        if c == ADMIN_CODE.lower():
            self.add_credit(ADMIN_BONUS_MB, source="admin")
            return True, (f"✓ کد مدیر فعال شد — {ADMIN_BONUS_MB // 1024} گیگابایت اعتبار اضافه شد "
                          f"(دفعات استفاده: {self.redemptions.get('admin', 0)})"), ADMIN_BONUS_MB
        return False, "✗ کد معتبر نیست", 0.0


ACCOUNT = Account()
