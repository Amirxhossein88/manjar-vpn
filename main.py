# -*- coding: utf-8 -*-
"""
ManjarVPN v1.4 — رابط گرافیکی
اسپلش انیمیشنی • کارت وضعیت • کارت سرور (متن وسط‌چین) • کارت‌های آمار
دکمه گرادیانی سفارشی (متن همیشه نمایان) • نگهبان سبک + تعمیر بی‌صدا
پنل «سرورهای تست‌شده» داخل پنجره‌ی اصلی (بدون پنجره‌ی جدا — رفع لیست خالی/هنگ)
+ دکمه‌ی بستن مشخص (✕) و کلید Escape
خروج بدون خطا با دکمه‌ی ضربدر — حتی وقتی پروسه‌های تست در جریان‌اند
جریان اتصال: پینگ ← باز کردن واقعی یوتوب/اینستاگرام/تلگرام ← سرعت دانلود/آپلود ← بهترین
"""
from __future__ import annotations

import math
import os
import queue
import re
import threading
import time
import tkinter as tk
import tkinter.font as tkfont

import customtkinter as ctk

from engine import (APP_NAME, VERSION, VpnEngine, Node, SESSION,
                    SUBSCRIPTION_SOURCES, cleanup_stale_proxy,
                    decode_subscription, filter_supported, find_logo,
                    parse_uri)

try:
    from PIL import Image as PILImage, ImageDraw, ImageTk
except Exception:
    PILImage = None
    ImageTk = None

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG = "#0c1022"
CARD = "#141a33"
CARD_H = "#1a2140"
BORDER = "#232c52"
TXT = "#eef1fb"
TXT_DIM = "#8b93b8"
GREEN = "#22c55e"
GREEN_DIM = "#16a34a"
BLUE = "#3b82f6"
VIOLET = "#8b5cf6"
AMBER = "#d97706"
AMBER_H = "#b45309"
RED = "#dc2626"
RED_H = "#b91c1c"
CYAN = "#7dd3fc"
FONT = "Segoe UI"

FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")


def _blend(c1: str, c2: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _load_logo(size: int):
    if PILImage is None:
        return None
    try:
        path = find_logo()
        if not path:
            return None
        img = PILImage.open(path).convert("RGBA")
        return ctk.CTkImage(light_image=img, dark_image=img, size=(size, size))
    except Exception:
        return None


def _flag_of(name: str) -> str:
    m = FLAG_RE.search(name or "")
    return m.group(0) if m else "🌐"


# ============================ دکمه گرادیانی سفارشی ============================
class PillButton(tk.Canvas):
    """دکمه قرصی گرادیانی روی Canvas.
    رفع باگ «دکمه متن ندارد»: در CustomTkinter 6 وقتی دکمه image دارد، لیبل متن
    نمایش داده نمی‌شود (mapped=0). اینجا متن یک آیتم جداگانه‌ی Canvas است و
    هیچ‌وقت ناپدید نمی‌شود. انیمیشن نفس‌کشیدن هم داخل همین کلاس است."""

    MODES = {
        "idle":      {"text": "اتصال خودکار",     "c1": (59, 130, 246),  "c2": (139, 92, 246)},
        "busy":      {"text": "لغو تست و اتصال",   "c1": (202, 110, 5),   "c2": (245, 158, 11)},
        "connected": {"text": "قطع اتصال",         "c1": (220, 38, 38),   "c2": (239, 68, 68)},
    }
    DIM = {"c1": (38, 46, 74), "c2": (48, 58, 92)}

    def __init__(self, master, on_click=None, height=62):
        super().__init__(master, height=height, highlightthickness=0,
                         bg=BG, cursor="hand2", bd=0)
        self._on_click = on_click
        self._mode = "idle"
        self._enabled = True
        self._hover = False
        self._cache = {}
        self._img_item = None
        self._txt_item = None
        self._bucket = None
        self._text = self.MODES["idle"]["text"]
        self.bind("<Configure>", lambda e: self._render(force=True))
        self.bind("<Button-1>", self._clicked)
        self.bind("<Enter>", lambda e: self._hover_change(True))
        self.bind("<Leave>", lambda e: self._hover_change(False))

    # ---------------- API ----------------
    def set_mode(self, mode: str):
        if mode == "disabled":
            self._enabled = False
            self.configure(cursor="arrow")
        else:
            self._enabled = True
            self.configure(cursor="hand2")
            if mode in self.MODES:
                self._text = self.MODES[mode]["text"]
                self._mode = mode
        self._bucket = None
        self._render(force=True)

    def is_enabled(self) -> bool:
        return self._enabled

    def tick(self, t: float):
        """انیمیشن نفس‌کشیدن — فقط وقتی پله‌ی روشنایی عوض شود رندر می‌کند."""
        if not self._enabled:
            return
        period = 1.6 if self._mode == "idle" else 2.4
        f = 0.5 - 0.5 * math.cos((t % period) / period * 2 * math.pi)
        b = round(f * 8)
        if b != self._bucket:
            self._bucket = b
            self._render(bright=0.90 + 0.18 * (b / 8.0))

    # ---------------- داخلی ----------------
    def _hover_change(self, on: bool):
        self._hover = on
        if self._enabled:
            self._bucket = None
            self._render(force=True)

    def _clicked(self, _e=None):
        if self._enabled and self._on_click:
            self._on_click()

    def _photo(self, w, h, c1, c2, bright):
        key = (w, h, c1, c2, round(bright * 20), self._hover)
        if key in self._cache:
            return self._cache[key]
        img = PILImage.new("RGB", (w, h))
        dr = ImageDraw.Draw(img)
        for x in range(w):
            t = x / max(1, w - 1)
            dr.line([(x, 0), (x, h)],
                    fill=tuple(min(255, int((c1[i] + (c2[i] - c1[i]) * t) * bright))
                               for i in range(3)))
        mask = PILImage.new("L", (w, h), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1],
                                               radius=max(8, h // 2), fill=255)
        out = PILImage.new("RGBA", (w, h), (0, 0, 0, 0))
        out.paste(img, (0, 0), mask)
        ph = ImageTk.PhotoImage(out)
        self._cache[key] = ph
        if len(self._cache) > 90:
            self._cache.clear()
        return ph

    def _render(self, force: bool = False, bright: float = 1.0):
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        w, h = self.winfo_width(), self.winfo_height()
        if w < 60 or h < 20:
            return
        if PILImage is None or ImageTk is None:   # fallback نادر بدون Pillow
            self.delete("all")
            c = self.DIM["c1"] if not self._enabled else self.MODES.get(
                self._mode, self.MODES["idle"])["c1"]
            self.create_rectangle(0, 0, w, h, fill="#%02x%02x%02x" % c, width=0)
            self.create_text(w // 2, h // 2, text=self._text,
                             font=(FONT, 15, "bold"),
                             fill="#8891b4" if not self._enabled else "#ffffff")
            return
        if not self._enabled:
            c1, c2, bright = self.DIM["c1"], self.DIM["c2"], 1.0
        else:
            m = self.MODES.get(self._mode, self.MODES["idle"])
            c1, c2 = m["c1"], m["c2"]
        ph = self._photo(w, h, c1, c2, bright)
        if self._img_item is None or force:
            self.delete("all")
            self._img_item = self.create_image(0, 0, image=ph, anchor="nw")
            fill = "#8891b4" if not self._enabled else "#ffffff"
            self._txt_item = self.create_text(
                w // 2, h // 2, text=self._text, font=(FONT, 15, "bold"), fill=fill)
            self._icon_items = self._draw_icon(w, h, fill)
        else:
            self.itemconfigure(self._img_item, image=ph)
            self.coords(self._txt_item, w // 2, h // 2)

    def _draw_icon(self, w, h, color):
        """آیکن کنار متن — با primitives خود Canvas (بدون وابستگی به فونت ایموجی).
        idle = دکمه پاور، busy/connected = مربع استاپ."""
        try:
            tw = tkfont.Font(family=FONT, size=15, weight="bold").measure(self._text)
        except Exception:
            tw = 120
        cx = w // 2 + tw // 2 + 24       # سمت راست متن (راست‌چین)
        cy = h // 2
        items = []
        if self._mode == "idle" and self._enabled:
            r = 8
            items.append(self.create_arc(cx - r, cy - r, cx + r, cy + r,
                                         start=50, extent=280, style="arc",
                                         width=3, outline=color))
            items.append(self.create_line(cx, cy - r - 3, cx, cy - 1,
                                          width=3, capstyle="round", fill=color))
        else:
            s = 7
            items.append(self.create_rectangle(cx - s, cy - s, cx + s, cy + s,
                                               fill=color, width=0))
        return items


# ============================ اسپلش ============================
class Splash(ctk.CTkToplevel):
    def __init__(self, master, warmup, on_done):
        super().__init__(master, fg_color=BG)
        self.on_done = on_done
        self.warmup = warmup
        self._closing = False
        self._ready = False
        w, h = 430, 470
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        self.overrideredirect(True)
        self.attributes("-topmost", True)

        self.logo_img = _load_logo(128)
        ctk.CTkLabel(self, text="" if self.logo_img else "🛡",
                     image=self.logo_img).pack(pady=(62, 4))
        ctk.CTkLabel(self, text="ManjarVPN",
                     font=ctk.CTkFont(family=FONT, size=30, weight="bold"),
                     text_color=TXT).pack()
        ctk.CTkLabel(self, text="────────  اتصال امن، ساده و سریع  ────────",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).pack(pady=(2, 24))

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack()
        self.dots = [ctk.CTkLabel(row, text="●", width=22,
                                  font=ctk.CTkFont(family=FONT, size=16)) for _ in range(3)]
        for d in self.dots:
            d.pack(side="left", padx=3)

        self.sweep = ctk.CTkProgressBar(self, width=240, height=6,
                                        progress_color=BLUE, fg_color="#1a2140")
        self.sweep.pack(pady=(28, 8))
        ctk.CTkLabel(self, text="در حال آماده‌سازی…",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).pack()
        ctk.CTkLabel(self, text=f"v{VERSION}",
                     font=ctk.CTkFont(family=FONT, size=10),
                     text_color="#5d6a7e").pack(side="bottom", pady=12)

        self.attributes("-alpha", 0.0)
        self._t0 = time.time()
        self._alpha = 0.0
        self.bind("<Button-1>", lambda e: self._finish())
        self.after(30, self._fade_in)
        threading.Thread(target=self._work, daemon=True).start()

    def _fade_in(self):
        self._alpha = min(1.0, self._alpha + 0.10)
        try:
            self.attributes("-alpha", self._alpha)
        except Exception:
            pass
        if self._alpha < 1.0:
            self.after(20, self._fade_in)
        else:
            self._tick()

    def _tick(self):
        if self._closing:
            return
        t = time.time() - self._t0
        for i, d in enumerate(self.dots):
            b = 0.25 + 0.75 * max(0.0, math.sin(t * 4.2 - i * 0.9))
            d.configure(text_color=_blend("#243048", CYAN, b))
        self.sweep.set(0.5 - 0.5 * math.cos((t % 1.6) / 1.6 * 2 * math.pi))
        if not self._ready and time.time() - self._t0 < 3.2:
            self.after(45, self._tick)
        else:
            self._finish()

    def _work(self):
        err = None
        try:
            self.warmup()
        except Exception as e:
            err = str(e)
        self._err = err
        self._ready = True

    def _finish(self):
        if self._closing:
            return
        self._closing = True
        try:
            self.attributes("-alpha", 0.0)
        except Exception:
            pass
        self.destroy()
        try:
            self.on_done(getattr(self, "_err", None))
        except Exception:
            pass


# ============================ پنجره اصلی ============================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("720x560")
        self.minsize(640, 540)
        self.configure(fg_color=BG)
        try:
            ico = find_logo()
            if ico and ico.endswith(".ico"):
                self.iconbitmap(ico)
        except Exception:
            pass

        self.q: queue.Queue = queue.Queue()
        self.engine = VpnEngine(
            log_cb=lambda m: self.q.put(("log", m)),
            progress_cb=lambda p, d, t, m: self.q.put(("progress", (p, d, t, m))),
        )
        self.app_state = "starting"   # starting | idle | busy | connected
        self.top_nodes: list = []
        self._fail_attempts = 0
        self._closing = False
        self._bar_target = 0.0
        self._eq_h = [6] * 6
        self._tick_i = 0
        self._report_open = False
        self._servers_open = False
        self._shutdown_thread: threading.Thread | None = None
        self._conn_lock = threading.Lock()       # فقط یک جریان اتصال در هر لحظه
        self._abort_repair = threading.Event()   # قطع دستی → تعمیر خودکار لغو شود

        self._build_ui()
        # دکمه‌ی ضربدر باید از همان اول کار کند (حتی وسط اسپلش)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI ----------------
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(9, weight=1)

        # هدر
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, pady=(16, 0))
        self.logo_small = _load_logo(52)
        ctk.CTkLabel(head, text="" if self.logo_small else "🛡",
                     image=self.logo_small).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(head, text="ManjarVPN",
                     font=ctk.CTkFont(family=FONT, size=28, weight="bold"),
                     text_color=TXT).pack(side="left")
        ctk.CTkLabel(self, text="────────  اتصال امن، ساده و سریع  ────────",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=1, column=0, pady=(2, 12))

        # کارت وضعیت
        st = ctk.CTkFrame(self, fg_color=CARD, corner_radius=18,
                          border_width=1, border_color="#1f7a6a")
        st.grid(row=2, column=0, padx=20, pady=(2, 10), sticky="ew")
        st.grid_columnconfigure(0, weight=1)
        inner = ctk.CTkFrame(st, fg_color="transparent")
        inner.grid(row=0, column=0, pady=14)
        self.dot_lbl = ctk.CTkLabel(inner, text="●", text_color=GREEN, width=26,
                                    font=ctk.CTkFont(family=FONT, size=20))
        self.dot_lbl.pack(side="left", padx=(0, 8))
        self.status_var = ctk.StringVar(value="در حال آماده‌سازی…")
        self.status_lbl = ctk.CTkLabel(inner, textvariable=self.status_var,
                                       font=ctk.CTkFont(family=FONT, size=18, weight="bold"),
                                       text_color=GREEN)
        self.status_lbl.pack(side="left")
        self.spinner = self._make_spinner(st)
        self.spinner.place(relx=0.06, rely=0.5, anchor="w")

        # کارت سرور (قابل کلیک) — متن وسط‌چین (رفع باگ چپ‌چین بودن)
        self.server_card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=18,
                                        border_width=1, border_color=BORDER, cursor="hand2")
        self.server_card.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.server_card.grid_columnconfigure(0, weight=0)
        self.server_card.grid_columnconfigure(1, weight=1)   # ستون متن → کل عرض بین پرچم و شفرون
        self.server_card.grid_columnconfigure(2, weight=0)
        self.sv_flag = ctk.CTkLabel(self.server_card, text="🌐",
                                    font=ctk.CTkFont(family=FONT, size=26), width=44)
        self.sv_flag.grid(row=0, column=0, padx=(16, 10), pady=12)
        svbox = ctk.CTkFrame(self.server_card, fg_color="transparent")
        svbox.grid(row=0, column=1, sticky="ew")
        self.sv_name = ctk.CTkLabel(svbox, text="انتخاب خودکار بهترین سرور",
                                    font=ctk.CTkFont(family=FONT, size=15, weight="bold"),
                                    text_color=TXT, anchor="center", justify="center")
        self.sv_name.pack(anchor="center", fill="x")
        self.sv_sub = ctk.CTkLabel(svbox,
                                   text=f"{len(SUBSCRIPTION_SOURCES)} منبع زنده • پینگ • "
                                        f"یوتوب/اینستاگرام/تلگرام • سرعت دانلود/آپلود",
                                   font=ctk.CTkFont(family=FONT, size=12),
                                   text_color=TXT_DIM, anchor="center", justify="center")
        self.sv_sub.pack(anchor="center", fill="x")
        self.chev_lbl = ctk.CTkLabel(self.server_card, text="⌄", width=40,
                                     font=ctk.CTkFont(family=FONT, size=22),
                                     text_color=TXT_DIM)
        self.chev_lbl.grid(row=0, column=2, padx=(8, 14))
        for wdg in (self.server_card, self.sv_flag, self.sv_name, self.sv_sub, self.chev_lbl):
            wdg.bind("<Button-1>", lambda e: self._toggle_servers())

        # کارت‌های آمار
        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.grid(row=4, column=0, padx=20, pady=(0, 10), sticky="ew")
        stats.grid_columnconfigure((0, 1, 2), weight=1, uniform="st")
        self.stat_ping = self._stat_card(stats, 0, "پینگ", "−", "#a78bfa")
        self.stat_dl = self._stat_card(stats, 1, "سرعت دانلود", "− Mbps", "#60a5fa")
        self.stat_ul = self._stat_card(stats, 2, "سرعت آپلود", "− Mbps", "#f472b6")

        # نوار پیشرفت
        self.bar = ctk.CTkProgressBar(self, progress_color=BLUE, height=8,
                                      fg_color="#1a2140", corner_radius=4)
        self.bar.grid(row=5, column=0, padx=20, pady=(2, 0), sticky="ew")
        self.bar.set(0)
        self.phase_lbl = ctk.CTkLabel(self, text="", font=ctk.CTkFont(family=FONT, size=11),
                                      text_color=TXT_DIM)
        self.phase_lbl.grid(row=5, column=0, pady=(12, 0))

        # نشان پروکسی سیستم
        pill = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16,
                            border_width=1, border_color=BORDER)
        pill.grid(row=6, column=0, padx=20, pady=(10, 10), sticky="ew")
        self.pill_lbl = ctk.CTkLabel(pill, text="○  پروکسی سیستم خاموش",
                                     font=ctk.CTkFont(family=FONT, size=13),
                                     text_color=TXT_DIM)
        self.pill_lbl.pack(pady=9)
        self.eq = self._make_eq(pill)
        self.eq.place(relx=0.08, rely=0.5, anchor="w")

        # دکمه اصلی — سفارشی (متن همیشه نمایان)
        self.btn = PillButton(self, on_click=self._on_button, height=62)
        self.btn.grid(row=7, column=0, padx=20, pady=(4, 6), sticky="ew")

        # لینک‌های پایین
        links = ctk.CTkFrame(self, fg_color="transparent")
        links.grid(row=8, column=0, pady=(2, 4))
        self.report_btn = ctk.CTkButton(links, text="📄  نمایش گزارش اتصال",
                                        command=self._toggle_report, width=200, height=28,
                                        fg_color="transparent", hover_color=CARD,
                                        text_color=TXT_DIM,
                                        font=ctk.CTkFont(family=FONT, size=12))
        self.report_btn.pack(side="left", padx=8)
        ctk.CTkButton(links, text="＋ کانفیگ دستی", command=self._open_custom,
                      width=130, height=28, fg_color="transparent", hover_color=CARD,
                      text_color=TXT_DIM, font=ctk.CTkFont(family=FONT, size=12)
                      ).pack(side="left", padx=8)

        # گزارش (لاگ) — پیش‌فرض مخفی
        self.log_box = ctk.CTkTextbox(self, fg_color="#080b18", text_color="#9fb0c8",
                                      font=ctk.CTkFont(family=FONT, size=12), wrap="word")
        self.log_box.grid(row=9, column=0, padx=20, pady=(2, 14), sticky="nsew")
        self.log_box.grid_remove()
        self._log(f"{APP_NAME} v{VERSION} آماده است.")

        # ---- پنل «سرورهای تست‌شده» — داخل پنجره‌ی اصلی، بدون پنجره‌ی جدا ----
        # (پنجره‌ی جدا CTkToplevel روی بعضی ویندوزها خالی/معلق می‌شد — رفع باگ «هیچی نمایش نمی‌دهد»)
        # دکمه‌ی بستن مشخص (✕) + کلید Escape هم دارد.
        self.servers_panel = ctk.CTkFrame(self, fg_color="#0f1430", corner_radius=14,
                                          border_width=1, border_color=BORDER)
        self.servers_panel.grid(row=9, column=0, padx=20, pady=(2, 14), sticky="nsew")
        self.servers_panel.grid_remove()
        phead = ctk.CTkFrame(self.servers_panel, fg_color="transparent")
        phead.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkButton(phead, text="✕  بستن", width=88, height=28,
                      corner_radius=9, fg_color=CARD_H, hover_color="#232c52",
                      text_color=TXT,
                      font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                      command=self._toggle_servers).pack(side="left", padx=(4, 8))
        ctk.CTkLabel(phead, text="سرورهای تست‌شده — برای اتصال انتخاب کنید",
                     font=ctk.CTkFont(family=FONT, size=15, weight="bold"),
                     text_color=TXT).pack(side="left", expand=True, fill="x")
        wrap = tk.Frame(self.servers_panel, bg="#0f1430", highlightthickness=0)
        wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.servers_canvas = tk.Canvas(wrap, bg="#0f1430", highlightthickness=0, bd=0)
        sb = tk.Scrollbar(wrap, orient="vertical", command=self.servers_canvas.yview,
                          troughcolor="#0f1430", background=CARD_H, width=12)
        self.servers_list_inner = tk.Frame(self.servers_canvas, bg="#0f1430")
        self.servers_canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="left", fill="y")
        self.servers_canvas.pack(side="right", fill="both", expand=True)
        self._servers_win = self.servers_canvas.create_window(
            (0, 0), window=self.servers_list_inner, anchor="nw")
        self.servers_list_inner.bind(
            "<Configure>", lambda e: self.servers_canvas.configure(
                scrollregion=self.servers_canvas.bbox("all")))
        self.servers_canvas.bind(
            "<Configure>", lambda e: self.servers_canvas.itemconfigure(
                self._servers_win, width=e.width))

        def _wheel(e):
            if self._servers_open:
                try:
                    self.servers_canvas.yview_scroll(int(-e.delta / 120), "units")
                except Exception:
                    pass
        self.bind_all("<MouseWheel>", _wheel, add="+")
        self.bind("<Escape>", lambda e: self._servers_open and self._toggle_servers())

    def _stat_card(self, parent, col, label, value, color):
        c = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16,
                         border_width=1, border_color=BORDER)
        c.grid(row=0, column=col, padx=(0 if col == 0 else 8, 0), sticky="ew")
        ctk.CTkLabel(c, text=label, font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).pack(pady=(10, 0))
        v = ctk.CTkLabel(c, text=value, font=ctk.CTkFont(family=FONT, size=19, weight="bold"),
                         text_color=TXT)
        v.pack(pady=(0, 12))
        return v

    def _make_spinner(self, parent):
        c = tk.Canvas(parent, width=28, height=28, bg=CARD, highlightthickness=0)
        self._spin_arc = c.create_arc(4, 4, 24, 24, start=0, extent=250,
                                      style="arc", width=3, outline=CYAN)
        c.place_forget()
        return c

    def _make_eq(self, parent):
        c = tk.Canvas(parent, width=64, height=20, bg=CARD, highlightthickness=0)
        self._eq_bars = []
        for i in range(5):
            x = 2 + i * 12
            self._eq_bars.append(c.create_rectangle(x, 19, x + 8, 19,
                                                    fill=GREEN, width=0))
        c.place_forget()
        return c

    # ---------------- helpers ----------------
    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}]  {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_status(self, text, color, bold_color=None):
        self.status_var.set(text)
        self._dot_color = color
        self.status_lbl.configure(text_color=bold_color or color)

    def _set_button_visual(self, mode: str):
        self.btn.set_mode(mode)

    def _update_server_card(self, node: Node | None):
        if node is None:
            self.sv_flag.configure(text="🌐")
            self.sv_name.configure(text="انتخاب خودکار بهترین سرور")
            self.sv_sub.configure(
                text=f"{len(SUBSCRIPTION_SOURCES)} منبع زنده • پینگ • "
                     f"یوتوب/اینستاگرام/تلگرام • سرعت دانلود/آپلود")
            return
        self.sv_flag.configure(text=_flag_of(node.display()))
        self.sv_name.configure(text=node.display())
        bits = [node.proto.upper()]
        if node.latency:
            bits.append(f"پینگ {int(node.latency)}ms")
        if node.speed:
            bits.append(f"دان {node.speed:.1f}Mbps")
        if node.up_speed:
            bits.append(f"آپ {node.up_speed:.1f}Mbps")
        if node.extra.get("opened"):
            bits.append(f"✓ {node.extra['opened']}")
        self.sv_sub.configure(text=" • ".join(bits) + f" • {node.server}:{node.port}")

    # ---------------- دکمه ----------------
    def _on_button(self):
        if self.app_state == "idle":
            if not self.btn.is_enabled():
                return
            self.engine.stop_flag.clear()
            self._fail_attempts = 0
            self._abort_repair.clear()
            self._go_busy()
            threading.Thread(target=self._flow, daemon=True).start()
        elif self.app_state == "busy":
            self._set_status("در حال لغو…", AMBER)
            self.engine.stop_all()
        elif self.app_state == "connected":
            self._set_status("در حال قطع…", AMBER)
            threading.Thread(target=self._disconnect_flow, daemon=True).start()

    def _disconnect_flow(self):
        self._abort_repair.set()          # تعمیر خودکارِ در جریان را لغو کن
        try:
            self.engine.disconnect()
        except Exception:
            pass
        self.q.put(("disconnected", None))

    def _go_busy(self, msg="در حال تست…"):
        self.app_state = "busy"
        self._set_button_visual("busy")
        self._set_status(msg, AMBER)
        self.spinner.place(relx=0.06, rely=0.5, anchor="w")
        self.eq.place_forget()
        self._update_server_card(None)

    # ---------------- فلو اصلی ----------------
    def _flow(self):
        eng = self.engine
        try:
            with self._conn_lock:
                if self._abort_repair.is_set() or eng.stop_flag.is_set():
                    return
                self.q.put(("status", ("در حال بررسی اینترنت…", AMBER)))
                ok, lat = eng.check_internet()
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if not ok:
                    self.q.put(("error", "اتصال اینترنت پیدا نشد! وای‌فای یا کابل را چک کنید."))
                    return
                self.q.put(("log", f"✓ اینترنت برقرار (پینگ مستقیم {lat}ms)"))

                # مسیر سریع: سرورهای خوب قبلی (با کاندیدهای جایگزین)
                best, quick_ok = eng.quick_connect_check()
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if best is not None:
                    ranked = self._rank(quick_ok)
                    others = [n for n in ranked if n.key() != best.key()]
                    self.q.put(("topnodes", ([best] + others)[:12]))
                    self.q.put(("log", f"★ بهترین: {best.display()} [{best.proto}] — "
                                       f"پینگ {int(best.latency or 0)}ms، سرعت {best.speed:.1f}Mbps"))
                    actual = self._connect_with_fallback(best, others)
                    self.q.put(("connected", actual))
                    return

                # مسیر کامل
                self.q.put(("status", ("دریافت کانفیگ‌های رایگان دنیا…", AMBER)))
                nodes = eng.fetch_all()
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if not nodes:
                    self.q.put(("error", "هیچ کانفیگی دریافت نشد — کمی بعد دوباره تلاش کنید."))
                    return
                self.q.put(("log", f"✓ {len(nodes)} کانفیگ یکتا از {len(SUBSCRIPTION_SOURCES)} منبع — "
                                   f"پینگ ← یوتوب/اینستاگرام/تلگرام ← سرعت دانلود/آپلود"))
                best, ok_list = eng.scan(nodes)
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if best is None:
                    self.q.put(("error", "هیچ کانفیگ سالمی پیدا نشد — چند دقیقه دیگر تلاش کنید."))
                    return
                ranked = self._rank(ok_list)
                self.q.put(("topnodes", ranked[:12]))
                self.q.put(("log", f"★ بهترین: {best.display()} [{best.proto}] — "
                                   f"پینگ {int(best.latency or 0)}ms، سرعت {best.speed:.1f}Mbps"))
                actual = self._connect_with_fallback(best, ranked)
                self.q.put(("connected", actual))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    def _rank(self, ok_list):
        """تاییدشده‌ها (یوتوب/اینستا/تلگرام واقعا باز کردند) اول؛ بعد سرعت بیشتر؛ بعد پینگ کمتر."""
        def vkey(n):
            return (0 if n.extra.get("verified") else 1,
                    -(n.speed if n.speed > 0 else 0.0),
                    n.latency if n.latency else 9e9)
        return sorted(ok_list, key=vkey)

    def _connect_with_fallback(self, best, extras=None):
        """به بهترین وصل می‌شود؛ اگر رد شد، سراغ کاندیدهای بعدی می‌رود."""
        eng = self.engine
        cands = [best]
        for n in (extras or []):
            if len(cands) >= 4:
                break
            if n.key() != best.key() and all(n.key() != c.key() for c in cands):
                cands.append(n)
        last_err = None
        for i, cand in enumerate(cands):
            if eng.stop_flag.is_set() or self._abort_repair.is_set():
                raise RuntimeError("لغو شد")
            try:
                if i:
                    self.q.put(("log", f"↻ تلاش با کاندید {i + 1}: {cand.display()}"))
                eng.connect(cand)
                eng.update_cache(cand, [cand])
                return cand
            except Exception as e:
                last_err = e
                self.q.put(("log", f"✗ اتصال به {cand.display()} رد شد: {e}"))
        raise last_err or RuntimeError("اتصال ممکن نشد")

    # ---------------- اتصال مستقیم به یک نود (انتخاب سرور) ----------------
    def _connect_node_flow(self, node: Node):
        eng = self.engine
        try:
            with self._conn_lock:
                if self._abort_repair.is_set():
                    return
                self.q.put(("status", (f"اتصال به {node.display()}…", AMBER)))
                actual = self._connect_with_fallback(node, self.top_nodes)
                self.q.put(("connected", actual))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    # ---------------- کانفیگ دستی ----------------
    def _custom_flow(self, text: str):
        eng = self.engine
        try:
            with self._conn_lock:
                if self._abort_repair.is_set():
                    return
                self.q.put(("status", ("بررسی کانفیگ دستی…", AMBER)))
                nodes = []
                for line in [l.strip() for l in text.splitlines() if l.strip()]:
                    if line.startswith(("http://", "https://")):
                        txt = eng._fetch_url(line)
                        if txt:
                            nodes += [n for n in (parse_uri(u) for u in decode_subscription(txt)) if n]
                    else:
                        n = parse_uri(line)
                        if n:
                            nodes.append(n)
                nodes = filter_supported(nodes)[:150]
                if not nodes:
                    self.q.put(("error", "کانفیگ معتبری پیدا نشد — لینک را چک کنید."))
                    return
                self.q.put(("log", f"✓ {len(nodes)} کانفیگ دستی دریافت شد — تست…"))
                best, ok_list = eng.scan(nodes)
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if best is None:
                    self.q.put(("error", "این کانفیگ‌ها جواب ندادند."))
                    return
                ranked = self._rank(ok_list)
                self.q.put(("topnodes", ranked[:12]))
                actual = self._connect_with_fallback(best, ranked)
                self.q.put(("connected", actual))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    # ---------------- نگهبان اتصال (چک سبک + تعمیر بی‌صدا) ----------------
    def _live_monitor(self, epoch: int):
        """هر ۴ ثانیه فقط یک چک ۲۰۴ سبک (نه دانلود ۱۲۸KB!). ۵ شکست پشت‌سرهم +
        سالم بودن اینترنتِ اصلی → تعمیر بی‌صدای تونل (بدون رفتن به حالت تست کامل).
        قطع‌های کاذبِ نسخه قبل از اینجا می‌آمد: دانلود حجمی هر ۳ ثانیه روی سرورهای
        شلوغ تایم‌اوت می‌شد و اتصال سالم قطع می‌شد."""
        eng = self.engine
        fails = 0
        checks = 0
        uploaded = False
        time.sleep(5)
        while not self._closing and eng.current_node is not None:
            if eng.conn_epoch != epoch:
                return                      # اتصال جدیدتری جایگزین شده
            ok = eng.health_check(timeout=7)
            if self._closing or eng.conn_epoch != epoch:
                return
            if ok:
                if fails >= 2:
                    self.q.put(("log", "✓ اتصال دوباره پایدار شد"))
                    self.q.put(("status", ("متصل", GREEN)))
                fails = 0
                checks += 1
                # نمونه سرعت سبک فقط هر ~۲۰ ثانیه (بدون فشار به سرور)
                if checks % 5 == 0:
                    mbps = eng.light_speed()
                    if mbps > 0 and not self._closing and eng.conn_epoch == epoch:
                        self.q.put(("livespeed", mbps))
                if not uploaded:
                    uploaded = True
                    up = eng.measure_upload()
                    if up > 0 and not self._closing:
                        self.q.put(("upspeed", up))
            else:
                # اگر اینترنتِ اصلی قطع است، تقصیر تونل نیست — شمارش نکن
                direct_ok, _ = eng.check_internet()
                if self._closing or eng.conn_epoch != epoch:
                    return
                if direct_ok:
                    fails += 1
                    if fails <= 4:
                        self.q.put(("log", f"⚠ پاسخ تونل قطع/کند ({fails}/۵) — صبر…"))
                        self.q.put(("status", (f"ناپایداری اتصال ({fails}/۵)…", AMBER)))
                else:
                    self.q.put(("log", "⚠ اینترنت اصلی مختل است — تونل سالم است، صبر…"))
            if fails >= 5:
                if not self._closing and eng.conn_epoch == epoch:
                    self.q.put(("repair", epoch))
                return
            time.sleep(4)

    def _on_repair(self, epoch):
        if self._closing or self.app_state != "connected":
            return
        if self.engine.conn_epoch != epoch:
            return
        self._set_status("بازیابی اتصال…", AMBER)
        threading.Thread(target=self._repair_flow, args=(epoch,), daemon=True).start()

    def _repair_flow(self, epoch):
        """تعمیر بی‌صدا: اول همان سرور، بعد سرورهای جایگزین شناخته‌شده.
        فقط اگر همه شکست خوردند اسکن کامل انجام می‌شود (autofail)."""
        eng = self.engine
        time.sleep(1.2)
        cands = []
        cur = eng.current_node
        if cur is not None:
            cands.append(cur)
        for n in self.top_nodes:
            if len(cands) >= 4:
                break
            if cur is not None and n.key() == cur.key():
                continue
            if all(n.key() != c.key() for c in cands):
                cands.append(n)
        for i, cand in enumerate(cands):
            if self._closing or self._abort_repair.is_set() or eng.conn_epoch != epoch:
                return
            with self._conn_lock:
                if self._closing or self._abort_repair.is_set() or eng.conn_epoch != epoch:
                    return
                try:
                    if i == 0:
                        self.q.put(("log", "🔧 بازسازی تونل با همان سرور…"))
                    else:
                        self.q.put(("log", f"↻ تلاش با سرور جایگزین: {cand.display()}"))
                    eng.connect(cand)
                    if self._abort_repair.is_set() or self._closing:
                        eng.disconnect()
                        return
                    eng.update_cache(cand, [cand])
                    self.q.put(("repaired", cand))
                    return
                except Exception:
                    self.q.put(("log", f"✗ {cand.display()} جواب نداد"))
            time.sleep(0.6)
        if not self._closing and not self._abort_repair.is_set():
            self.q.put(("autofail", None))

    def _on_repaired(self, node):
        if self._closing:
            return
        self.app_state = "connected"
        self._fail_attempts = 0
        self._set_status("متصل", GREEN)
        self._update_server_card(node)
        self.stat_ping.configure(text=f"{int(node.latency or 0)} ms")
        self.stat_dl.configure(text=f"{node.speed:.1f} Mbps" if node.speed else "— Mbps")
        self.stat_ul.configure(text=f"{node.up_speed:.1f} Mbps" if node.up_speed else "— Mbps")
        self.pill_lbl.configure(
            text=f"✓  پروکسی سیستم فعال  (HTTP: {self.engine.http_port} / SOCKS: {self.engine.socks_port})",
            text_color=GREEN)
        self._log(f"✓ اتصال دوباره برقرار شد: {node.display()}")
        threading.Thread(target=self._live_monitor,
                         args=(self.engine.conn_epoch,), daemon=True).start()

    def _on_autofail(self):
        if self._closing:
            return
        if self.app_state == "connected":
            return                     # تعمیر در نهایت موفق شده
        if self._fail_attempts >= 3:
            self.engine.disconnect()
            self.q.put(("error", "اتصال ۳ بار پایدار نشد — دوباره تلاش کنید یا از "
                                 "«کانفیگ دستی» سرور شخصی اضافه کنید."))
            return
        self._fail_attempts += 1
        self._go_busy(f"بازسازی اتصال ({self._fail_attempts}/3)…")
        threading.Thread(target=self._flow, daemon=True).start()

    # ---------------- صف رویدادها ----------------
    def _poll(self):
        if self._closing:
            return
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "status":
                    self._set_status(payload[0], payload[1])
                elif kind == "progress":
                    self._progress(*payload)
                elif kind == "connected":
                    self._on_connected(payload)
                elif kind == "livespeed":
                    self.stat_dl.configure(text=f"{payload:.1f} Mbps")
                elif kind == "upspeed":
                    self.stat_ul.configure(text=f"{payload:.1f} Mbps")
                elif kind == "topnodes":
                    self.top_nodes = payload
                    if self._servers_open:
                        self._render_servers()      # لیست زنده — وسط تست هم پر می‌شود
                elif kind == "repair":
                    self._on_repair(payload)
                elif kind == "repaired":
                    self._on_repaired(payload)
                elif kind == "disconnected":
                    self._log("✓ اتصال قطع شد و پروکسی سیستم خاموش شد")
                    self._set_idle()
                elif kind == "autofail":
                    self._on_autofail()
                elif kind == "error":
                    self._log(f"✗ {payload}")
                    self._set_status("خطا در اتصال", RED, RED)
                    self._set_idle()
                elif kind == "idle":
                    self._set_idle()
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _progress(self, phase, done, total, msg):
        total = max(total, 1)
        ratio = max(done, 0) / total
        if phase == "fetch":
            v = 0.12 * ratio
        elif phase == "tcp":
            v = 0.12 + 0.15 * ratio
        elif phase == "latency":
            v = 0.27 + 0.33 * ratio
        elif phase == "deep":
            v = 0.60 + 0.32 * ratio
        elif phase == "speed":
            v = 0.92 + 0.03 * ratio
        elif phase == "connect":
            v = 0.95 + 0.05 * ratio
        else:
            v = self._bar_target
        self._bar_target = min(v, 1.0)
        self.phase_lbl.configure(text=msg)

    def _on_connected(self, node):
        self.app_state = "connected"
        self._fail_attempts = 0
        self._bar_target = 1.0
        self.phase_lbl.configure(text="متصل ✓")
        self.spinner.place_forget()
        self.eq.place(relx=0.08, rely=0.5, anchor="w")
        self._set_status("متصل", GREEN)
        self._set_button_visual("connected")
        self._update_server_card(node)
        self.stat_ping.configure(text=f"{int(node.latency or 0)} ms")
        self.stat_dl.configure(text=f"{node.speed:.1f} Mbps" if node.speed else "— Mbps")
        self.stat_ul.configure(text=f"{node.up_speed:.1f} Mbps" if node.up_speed else "— Mbps")
        if node.extra.get("opened"):
            self._log(f"✓ با این سرور باز شد: {node.extra['opened']}")
        self.pill_lbl.configure(
            text=f"✓  پروکسی سیستم فعال  (HTTP: {self.engine.http_port} / SOCKS: {self.engine.socks_port})",
            text_color=GREEN)
        self._log("✓ متصل شد — پروکسی سیستم روشن شد. مرورگر و اکثر برنامه‌ها از این مسیر می‌روند.")
        self._log("ℹ برنامه‌هایی که پروکسی سیستم را نادیده می‌گیرند (مثل تلگرام دسکتاپ) باید دستی روی "
                  f"127.0.0.1:{self.engine.socks_port} (SOCKS5) تنظیم شوند.")
        threading.Thread(target=self._live_monitor,
                         args=(self.engine.conn_epoch,), daemon=True).start()

    def _set_idle(self):
        self.app_state = "idle"
        self.spinner.place_forget()
        self.eq.place_forget()
        self._set_button_visual("idle")
        self._set_status("آماده اتصال", GREEN)
        self.pill_lbl.configure(text="○  پروکسی سیستم خاموش", text_color=TXT_DIM)
        self.stat_dl.configure(text="— Mbps")
        if not self.engine.current_node:
            self._bar_target = 0.0
            self.phase_lbl.configure(text="")

    # ---------------- پنل سرورهای تست‌شده (داخل پنجره اصلی) ----------------
    def _toggle_servers(self):
        self._servers_open = not self._servers_open
        self.chev_lbl.configure(text="⌃" if self._servers_open else "⌄")
        if self._servers_open and self._report_open:
            self._report_open = False
            self.log_box.grid_remove()
            self.report_btn.configure(text="📄  نمایش گزارش اتصال")
        if self._servers_open:
            self._render_servers()
            self.servers_panel.grid()
        else:
            self.servers_panel.grid_remove()
        self.geometry("720x860" if (self._servers_open or self._report_open) else "720x560")

    def _render_servers(self):
        """لیست سرورها هر بار تازه ساخته می‌شود — حتی وسط تست (نتایج زنده پر می‌شوند)."""
        for w in self.servers_list_inner.winfo_children():
            w.destroy()
        self.servers_canvas.yview_moveto(0)
        if not self.top_nodes:
            msg = ("تست در جریان است… به‌محض تایید هر سرور، همین‌جا نمایش داده می‌شود."
                   if self.app_state == "busy"
                   else "هنوز تستی انجام نشده — اول «اتصال خودکار» را بزنید.")
            ctk.CTkLabel(self.servers_list_inner, text=msg,
                         text_color=TXT_DIM,
                         font=ctk.CTkFont(family=FONT, size=13)).pack(pady=24, padx=20)
            return
        for n in self.top_nodes:
            title = f"{_flag_of(n.display())}  {n.display()}"
            bits = [n.proto.upper(), f"پینگ {int(n.latency or 0)}ms"]
            if n.speed:
                bits.append(f"دان {n.speed:.1f}Mbps")
            if n.up_speed:
                bits.append(f"آپ {n.up_speed:.1f}Mbps")
            if n.extra.get("opened"):
                bits.append(f"✓ {n.extra['opened']}")
            ctk.CTkButton(self.servers_list_inner,
                          text=f"{title}\n{' • '.join(bits)}",
                          anchor="center",
                          height=54, corner_radius=12,
                          fg_color="#10162c", hover_color=CARD_H,
                          text_color=TXT,
                          font=ctk.CTkFont(family=FONT, size=13),
                          command=lambda nn=n: self._pick_server(nn)).pack(
                              fill="x", pady=4, padx=4)

    def _pick_server(self, node: Node):
        if self.app_state == "busy":
            return
        if self._servers_open:
            self._toggle_servers()
        self.engine.stop_flag.clear()
        self._fail_attempts = 0
        self._abort_repair.clear()
        self._go_busy(f"اتصال به {node.display()}…")
        threading.Thread(target=self._connect_node_flow, args=(node,), daemon=True).start()

    # ---------------- دیالوگ کانفیگ دستی ----------------
    def _open_custom(self):
        if self.app_state == "busy":
            return
        dlg = ctk.CTkToplevel(self, fg_color=BG)
        dlg.title("کانفیگ دستی")
        dlg.geometry("560x460")
        dlg.attributes("-topmost", True)
        dlg.grid_columnconfigure(0, weight=1)
        dlg.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(dlg, text="افزودن کانفیگ یا اشتراک دستی",
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).grid(row=0, column=0, pady=(14, 4))
        ctk.CTkLabel(dlg, text="لینک VLESS/VMess/Trojan/SS یا لینک اشتراک (هر خط یکی):",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=1, column=0, pady=(0, 4))
        box = ctk.CTkTextbox(dlg, fg_color="#080b18", text_color=TXT,
                             font=ctk.CTkFont(family="Consolas", size=12))
        box.grid(row=2, column=0, padx=16, pady=8, sticky="nsew")
        hint = ("⚠ سرور شخصی (مثل VLESS+Reality روی پورت ۴۴۳) خیلی پایدارتر از کانفیگ‌های رایگان "
                "عمومی است. کانفیگ‌های دستیِ سالم به حافظه اضافه می‌شوند.")
        ctk.CTkLabel(dlg, text=hint, font=ctk.CTkFont(family=FONT, size=11),
                     text_color="#7c8aa8", wraplength=520, justify="right"
                     ).grid(row=3, column=0, padx=16, pady=(0, 4))

        def submit():
            text = box.get("1.0", "end").strip()
            if not text:
                return
            dlg.destroy()
            self.engine.stop_flag.clear()
            self._fail_attempts = 0
            self._abort_repair.clear()
            self._go_busy("بررسی کانفیگ دستی…")
            threading.Thread(target=self._custom_flow, args=(text,), daemon=True).start()

        ctk.CTkButton(dlg, text="⚡  تست و اتصال", command=submit, height=44,
                      corner_radius=14, fg_color=BLUE, hover_color="#2563eb",
                      font=ctk.CTkFont(family=FONT, size=15, weight="bold")
                      ).grid(row=4, column=0, padx=16, pady=(4, 14), sticky="ew")

    # ---------------- گزارش ----------------
    def _toggle_report(self):
        self._report_open = not self._report_open
        if self._report_open and self._servers_open:
            self._servers_open = False
            self.servers_panel.grid_remove()
            self.chev_lbl.configure(text="⌄")
        if self._report_open:
            self.log_box.grid()
            self.report_btn.configure(text="📄  بستن گزارش اتصال")
        else:
            self.log_box.grid_remove()
            self.report_btn.configure(text="📄  نمایش گزارش اتصال")
        self.geometry("720x860" if (self._servers_open or self._report_open) else "720x560")

    # ---------------- حلقه انیمیشن ----------------
    def _ui_tick(self):
        if self._closing:
            return
        self._tick_i += 1
        t = time.time()
        self.btn.tick(t)                    # نفس‌کشیدن دکمه (داخل کلاس دکمه)
        if self.app_state == "busy":
            self.spinner.itemconfigure(self._spin_arc, start=(self._tick_i * 11) % 360)
        if self.app_state == "busy":
            base, hot = "#b98a2f", "#f5c563"
        elif self.app_state in ("connected", "idle"):
            base, hot = (GREEN_DIM, GREEN) if self.app_state == "connected" else ("#166534", GREEN)
        else:
            base, hot = None, None
        if base:
            f = 0.5 - 0.5 * math.cos((t % 1.2) / 1.2 * 2 * math.pi)
            self.dot_lbl.configure(text_color=_blend(base, hot, f))
        cur = self.bar.get()
        diff = self._bar_target - cur
        if abs(diff) > 0.0015:
            self.bar.set(cur + diff * 0.22)
        if self.app_state == "connected" and self._tick_i % 2 == 0:
            for i, r in enumerate(self._eq_bars):
                target = 4 + abs(math.sin(t * 3.1 + i * 1.3)) * 14 * self._live_factor()
                self._eq_h[i] = self._eq_h[i] * 0.55 + target * 0.45
                h = max(2, min(18, self._eq_h[i]))
                x = 2 + i * 12
                self.eq.coords(r, x, 19 - h, x + 8, 19)
                self.eq.itemconfigure(r, fill=_blend("#166534", GREEN, h / 18))
        self.after(50, self._ui_tick)

    def _live_factor(self):
        try:
            txt = self.stat_dl.cget("text")
            v = float(txt.split()[0])
            return min(1.0, max(0.15, v / 10.0))
        except Exception:
            return 0.4

    # ---------------- شروع با اسپلش ----------------
    def start_with_splash(self):
        self.withdraw()

        def warmup():
            self.engine.ensure_xray()
            self.engine.ensure_features()
            if cleanup_stale_proxy():
                self.q.put(("log", "✓ پروکسی خراب‌مانده از اجرای قبلی پاک شد"))

        self.splash = Splash(self, warmup, self._after_splash)

    def _after_splash(self, err=None):
        if self._closing:
            return
        self.deiconify()
        try:
            self.attributes("-alpha", 0.0)
        except Exception:
            pass

        def fade(a=0.0):
            if self._closing:
                return
            a = min(1.0, a + 0.10)
            try:
                self.attributes("-alpha", a)
            except Exception:
                pass
            if a < 1.0:
                self.after(18, lambda: fade(a))
        fade()
        self.after(80, self._poll)
        self.after(50, self._ui_tick)
        self.app_state = "idle"
        if err:
            self._log(f"✗ {err}")
            self._set_status("هسته Xray پیدا نشد", RED, RED)
            self.btn.set_mode("disabled")
        else:
            self._set_status("آماده اتصال", GREEN)
            self._log("✓ هسته Xray آماده است")

    # ---------------- خروج ----------------
    def _on_close(self):
        """دکمه‌ی ضربدر — همیشه سریع بسته می‌شود؛ حتی وقتی تست/اتصال در جریان است.
        (باگ قبلی: کشتن ده‌ها پروسه‌ی Xray روی تردِ رابط انجام می‌شد و پنجره معلق می‌شد.)"""
        if self._closing:
            return
        self._closing = True
        self._abort_repair.set()
        try:
            self.engine.stop_flag.set()
        except Exception:
            pass
        # پروکسی سیستم + Xray اصلی — سریع است و همین‌جا انجام می‌شود تا هیچ‌وقت پروکسی روشن نماند
        try:
            self.engine.disconnect()
        except Exception:
            pass
        self.withdraw()          # پنجره فورا از دید خارج می‌شود
        self._shutdown_thread = threading.Thread(
            target=self._shutdown_worker, daemon=True)
        self._shutdown_thread.start()
        self.after(80, self._finish_exit)

    def _shutdown_worker(self):
        """پروسه‌های تست در ترد جدا بسته می‌شوند تا رابط هیچ‌وقت هنگ نکند."""
        try:
            self.engine.stop_all()
        except Exception:
            pass

    def _finish_exit(self):
        try:
            self.destroy()
        except Exception:
            pass


def main():
    app = App()
    app.start_with_splash()
    app.mainloop()
    # خروج تمیز: اگر پروسه‌های تست هنوز در حال بسته‌شدن‌اند، حداکثر ۶ ثانیه فرصت
    try:
        t = getattr(app, "_shutdown_thread", None)
        if t is not None:
            t.join(timeout=6)
        app.engine.disconnect()
    except Exception:
        pass
    os._exit(0)          # همه‌ی ترد‌های daemon بلافاصله تمام — بدون فرایند رها


if __name__ == "__main__":
    main()
