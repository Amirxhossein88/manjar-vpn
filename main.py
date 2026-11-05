# -*- coding: utf-8 -*-
"""
ManjarVPN v1.2 — رابط گرافیکی (ری‌دیزاین مطابق ماکت)
اسپلش انیمیشنی • کارت وضعیت • کارت سرور (انتخاب سرور) • کارت‌های آمار
گرادیان آبی-بنفش • نمایش گزارش • فیلور خودکار • کانفیگ دستی
"""
from __future__ import annotations

import math
import queue
import re
import threading
import time

import customtkinter as ctk

from engine import (APP_NAME, VERSION, VpnEngine, Node, SESSION,
                    cleanup_stale_proxy, decode_subscription, filter_supported,
                    find_logo, parse_uri)

try:
    from PIL import Image as PILImage, ImageDraw
except Exception:
    PILImage = None

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


def _gradient_button_image(w: int, h: int, bright: bool):
    """گرادیان افقی آبی→بنفش با گوشه گرد (برای دکمه اصلی)"""
    if PILImage is None:
        return None
    try:
        c1 = (59, 130, 246) if bright else (37, 99, 235)
        c2 = (167, 139, 250) if bright else (124, 58, 237)
        img = PILImage.new("RGB", (w, h))
        d = ImageDraw.Draw(img)
        for x in range(w):
            t = x / max(1, w - 1)
            d.line([(x, 0), (x, h)],
                   fill=tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3)))
        mask = PILImage.new("L", (w, h), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=h // 2, fill=255)
        out = PILImage.new("RGBA", (w, h), (0, 0, 0, 0))
        out.paste(img, (0, 0), mask)
        return ctk.CTkImage(light_image=out, dark_image=out, size=(w, h))
    except Exception:
        return None


def _flag_of(name: str) -> str:
    m = FLAG_RE.search(name or "")
    return m.group(0) if m else "🌐"


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
        if not self._ready and time.time() - self._t0 < 6.0:
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
        self._grad_dim = _gradient_button_image(680, 60, bright=False)
        self._grad_bright = _gradient_button_image(680, 60, bright=True)

        self._build_ui()

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

        # کارت سرور (قابل کلیک)
        self.server_card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=18,
                                        border_width=1, border_color=BORDER, cursor="hand2")
        self.server_card.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.server_card.grid_columnconfigure(1, weight=1)
        self.sv_flag = ctk.CTkLabel(self.server_card, text="🌐",
                                    font=ctk.CTkFont(family=FONT, size=26), width=44)
        self.sv_flag.grid(row=0, column=0, padx=(16, 10), pady=12)
        svbox = ctk.CTkFrame(self.server_card, fg_color="transparent")
        svbox.grid(row=0, column=1, sticky="w")
        self.sv_name = ctk.CTkLabel(svbox, text="انتخاب خودکار بهترین سرور",
                                    font=ctk.CTkFont(family=FONT, size=15, weight="bold"),
                                    text_color=TXT, anchor="e")
        self.sv_name.pack(anchor="e")
        self.sv_sub = ctk.CTkLabel(svbox, text="۱۷ منبع زنده • هزاران کانفیگ • تست پینگ و سرعت",
                                   font=ctk.CTkFont(family=FONT, size=12),
                                   text_color=TXT_DIM, anchor="e")
        self.sv_sub.pack(anchor="e")
        ctk.CTkLabel(self.server_card, text="⌄", width=40,
                     font=ctk.CTkFont(family=FONT, size=22),
                     text_color=TXT_DIM).grid(row=0, column=2, padx=(8, 14))
        for wdg in (self.server_card, self.sv_flag, self.sv_name, self.sv_sub):
            wdg.bind("<Button-1>", lambda e: self._open_servers())

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

        # دکمه اصلی گرادیانی
        self.btn = ctk.CTkButton(self, text="🔗  اتصال خودکار", command=self._on_button,
                                 height=62, corner_radius=31, compound="center",
                                 font=ctk.CTkFont(family=FONT, size=19, weight="bold"),
                                 fg_color="transparent", hover_color=CARD_H,
                                 text_color="#ffffff",
                                 image=self._grad_dim)
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
        import tkinter as tk
        c = tk.Canvas(parent, width=28, height=28, bg=CARD, highlightthickness=0)
        self._spin_arc = c.create_arc(4, 4, 24, 24, start=0, extent=250,
                                      style="arc", width=3, outline=CYAN)
        c.place_forget()
        return c

    def _make_eq(self, parent):
        import tkinter as tk
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
        if mode == "idle":
            self.btn.configure(text="🔗  اتصال خودکار", image=self._grad_dim,
                               fg_color="transparent", hover_color=CARD_H)
        elif mode == "busy":
            self.btn.configure(text="⏹  لغو تست و اتصال", image=None,
                               fg_color=AMBER, hover_color=AMBER_H)
        elif mode == "connected":
            self.btn.configure(text="⏹  قطع اتصال", image=None,
                               fg_color=RED, hover_color=RED_H)

    def _update_server_card(self, node: Node | None):
        if node is None:
            self.sv_flag.configure(text="🌐")
            self.sv_name.configure(text="انتخاب خودکار بهترین سرور")
            self.sv_sub.configure(text="۱۷ منبع زنده • هزاران کانفیگ • تست پینگ و سرعت")
            return
        self.sv_flag.configure(text=_flag_of(node.display()))
        self.sv_name.configure(text=node.display())
        bits = [node.proto.upper()]
        if node.latency:
            bits.append(f"پینگ {int(node.latency)}ms")
        if node.speed:
            bits.append(f"{node.speed:.1f}Mbps")
        self.sv_sub.configure(text=" • ".join(bits) + f" • {node.server}:{node.port}")

    # ---------------- دکمه ----------------
    def _on_button(self):
        if self.app_state == "idle":
            self.engine.stop_flag.clear()
            self._fail_attempts = 0
            self._go_busy()
            threading.Thread(target=self._flow, daemon=True).start()
        elif self.app_state == "busy":
            self._set_status("در حال لغو…", AMBER)
            self.engine.stop_all()
        elif self.app_state == "connected":
            self.engine.disconnect()
            self._log("✓ اتصال قطع شد و پروکسی سیستم خاموش شد")
            self._set_idle()

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
            self.q.put(("status", ("در حال بررسی اینترنت…", AMBER)))
            ok, lat = eng.check_internet()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if not ok:
                self.q.put(("error", "اتصال اینترنت پیدا نشد! وای‌فای یا کابل را چک کنید."))
                return
            self.q.put(("log", f"✓ اینترنت برقرار (پینگ مستقیم {lat}ms)"))

            best, _ = eng.quick_connect_check()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if best is not None:
                self.q.put(("topnodes", [best]))
            if best is None:
                self.q.put(("status", ("دریافت کانفیگ‌های رایگان دنیا…", AMBER)))
                nodes = eng.fetch_all()
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if not nodes:
                    self.q.put(("error", "هیچ کانفیگی دریافت نشد — کمی بعد دوباره تلاش کنید."))
                    return
                self.q.put(("log", f"✓ {len(nodes)} کانفیگ یکتا از ۱۷ منبع — تست هوشمند"))
                best, ok_list = eng.scan(nodes)
                if eng.stop_flag.is_set():
                    self.q.put(("idle", None)); return
                if best is None:
                    self.q.put(("error", "هیچ کانفیگ سالمی پیدا نشد — چند دقیقه دیگر تلاش کنید."))
                    return
                self.q.put(("topnodes", self._rank(ok_list)[:12]))

            self.q.put(("log", f"★ بهترین: {best.display()} [{best.proto}] — "
                               f"پینگ {int(best.latency)}ms، سرعت {best.speed:.1f}Mbps"))
            self._connect_with_fallback(best)

            self.q.put(("connected", best))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    def _rank(self, ok_list):
        with_speed = [n for n in ok_list if n.speed > 0]
        without = [n for n in ok_list if n.speed <= 0]
        with_speed.sort(key=lambda n: -n.speed)
        without.sort(key=lambda n: n.latency)
        return with_speed + without

    def _connect_with_fallback(self, best, extras=None):
        """به بهترین وصل می‌شود؛ اگر رد شد، سراغ کاندیدهای بعدی می‌رود."""
        eng = self.engine
        cands = [best] + (extras or [])[:2]
        last_err = None
        for i, cand in enumerate(cands):
            if eng.stop_flag.is_set():
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
            self.q.put(("status", (f"اتصال به {node.display()}…", AMBER)))
            self._connect_with_fallback(node, self.top_nodes)
            self.q.put(("connected", eng.current_node))
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
            self.q.put(("topnodes", self._rank(ok_list)[:12]))
            self._connect_with_fallback(best)
            self.q.put(("connected", best))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    # ---------------- نگهبان اتصال + سرعت زنده ----------------
    def _live_monitor(self):
        eng = self.engine
        fails = 0
        while not self._closing and eng.current_node is not None:
            try:
                t0 = time.time()
                r = SESSION.get("https://speed.cloudflare.com/__down?bytes=131072",
                                proxies={"http": f"http://127.0.0.1:{eng.http_port}",
                                         "https": f"http://127.0.0.1:{eng.http_port}"},
                                timeout=6)
                el = time.time() - t0
                if r.status_code < 400 and el > 0:
                    fails = 0
                    mbps = (131072 * 8.0) / el / 1e6
                    if not self._closing:
                        self.q.put(("livespeed", mbps))
                else:
                    fails += 1
            except Exception:
                fails += 1
            if fails >= 3 and eng.current_node is not None:
                self.q.put(("log", "⚠ تونل قطع شد — بازسازی خودکار اتصال…"))
                eng.disconnect(restore_proxy=False)
                if not self._closing:
                    self.q.put(("autofail", None))
                break
            time.sleep(3)

        # تست آپلود یک‌باره
        if eng.current_node is not None and not self._closing:
            up = eng.measure_upload()
            if up > 0:
                self.q.put(("upspeed", up))

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

    def _on_autofail(self):
        if self._closing:
            return
        if self._fail_attempts >= 3:
            self.q.put(("error", "اتصال‌ها پایدار نیستند (۳ تلاش ناموفق). دوباره امتحان کنید."))
            return
        self._fail_attempts += 1
        self._go_busy(f"بازسازی اتصال ({self._fail_attempts}/3)…")
        threading.Thread(target=self._flow, daemon=True).start()

    def _progress(self, phase, done, total, msg):
        total = max(total, 1)
        ratio = max(done, 0) / total
        if phase == "fetch":
            v = 0.12 * ratio
        elif phase == "tcp":
            v = 0.12 + 0.15 * ratio
        elif phase == "latency":
            v = 0.27 + 0.50 * ratio
        elif phase == "speed":
            v = 0.77 + 0.18 * ratio
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
        self.stat_ping.configure(text=f"{int(node.latency)} ms")
        self.stat_dl.configure(text=f"{node.speed:.1f} Mbps" if node.speed else "— Mbps")
        self.stat_ul.configure(text="— Mbps")
        self.pill_lbl.configure(
            text=f"✓  پروکسی سیستم فعال  (HTTP: {self.engine.http_port} / SOCKS: {self.engine.socks_port})",
            text_color=GREEN)
        self._log("✓ متصل شد — پروکسی سیستم روشن شد. مرورگر و اکثر برنامه‌ها از این مسیر می‌روند.")
        self._log("ℹ برنامه‌هایی که پروکسی سیستم را نادیده می‌گیرند (مثل تلگرام دسکتاپ) باید دستی روی "
                  f"127.0.0.1:{self.engine.socks_port} (SOCKS5) تنظیم شوند.")
        threading.Thread(target=self._live_monitor, daemon=True).start()

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

    # ---------------- دیالوگ انتخاب سرور ----------------
    def _open_servers(self):
        if self.app_state == "busy":
            return
        dlg = ctk.CTkToplevel(self, fg_color=BG)
        dlg.title("سرورهای تست‌شده")
        dlg.geometry("560x480")
        dlg.attributes("-topmost", True)
        dlg.grid_columnconfigure(0, weight=1)
        dlg.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(dlg, text="سرورهای تست‌شده — برای اتصال انتخاب کنید",
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).grid(row=0, column=0, pady=(14, 8))
        box = ctk.CTkScrollableFrame(dlg, fg_color=CARD, corner_radius=14)
        box.grid(row=1, column=0, padx=14, pady=(0, 14), sticky="nsew")
        if not self.top_nodes:
            ctk.CTkLabel(box, text="هنوز تستی انجام نشده — اول «اتصال خودکار» را بزنید.",
                         text_color=TXT_DIM).pack(pady=20)
        for n in self.top_nodes:
            txt = f"{_flag_of(n.display())}  {n.display()}"
            sub = f"{n.proto.upper()} • پینگ {int(n.latency)}ms"
            if n.speed:
                sub += f" • {n.speed:.1f}Mbps"
            rowb = ctk.CTkButton(box, text=f"{txt}\n{sub}", anchor="e", justify="right",
                                 height=54, corner_radius=12, fg_color="#10162c",
                                 hover_color=CARD_H, text_color=TXT,
                                 font=ctk.CTkFont(family=FONT, size=13),
                                 command=lambda nn=n: (dlg.destroy(), self._pick_server(nn)))
            rowb.pack(fill="x", pady=4)

    def _pick_server(self, node: Node):
        if self.app_state == "busy":
            return
        self.engine.stop_flag.clear()
        self._fail_attempts = 0
        self._go_busy(f"اتصال به {node.display()}…")
        threading.Thread(target=self._connect_node_flow, args=(node,), daemon=True).start()

    # ---------------- دیالوگ کانفیگ دستی ----------------
    def _open_custom(self):
        if self.app_state == "busy":
            return
        dlg = ctk.CTkToplevel(self, fg_color=BG)
        dlg.title("کانفیگ دستی")
        dlg.geometry("560x420")
        dlg.attributes("-topmost", True)
        dlg.grid_columnconfigure(0, weight=1)
        dlg.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(dlg, text="افزودن کانفیگ یا اشتراک دستی",
                     font=ctk.CTkFont(family=FONT, size=16, weight="bold"),
                     text_color=TXT).grid(row=0, column=0, pady=(14, 6))
        ctk.CTkLabel(dlg, text="لینک VLESS/VMess/Trojan/SS یا لینک اشتراک (هر خط یکی):",
                     font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=0, column=0, pady=(36, 4))
        box = ctk.CTkTextbox(dlg, fg_color="#080b18", text_color=TXT,
                             font=ctk.CTkFont(family="Consolas", size=12))
        box.grid(row=1, column=0, padx=16, pady=8, sticky="nsew")
        hint = ("⚠ سرور شخصی (مثل VLESS+Reality روی پورت ۴۴۳) خیلی پایدارتر از کانفیگ‌های رایگان "
                "عمومی است. کانفیگ‌های دستیِ سالم به حافظه اضافه می‌شوند.")
        ctk.CTkLabel(dlg, text=hint, font=ctk.CTkFont(family=FONT, size=11),
                     text_color="#7c8aa8", wraplength=520, justify="right"
                     ).grid(row=2, column=0, padx=16, pady=(0, 4))

        def submit():
            text = box.get("1.0", "end").strip()
            if not text:
                return
            dlg.destroy()
            self.engine.stop_flag.clear()
            self._fail_attempts = 0
            self._go_busy("بررسی کانفیگ دستی…")
            threading.Thread(target=self._custom_flow, args=(text,), daemon=True).start()

        ctk.CTkButton(dlg, text="⚡  تست و اتصال", command=submit, height=44,
                      corner_radius=14, fg_color=BLUE, hover_color="#2563eb",
                      font=ctk.CTkFont(family=FONT, size=15, weight="bold")
                      ).grid(row=3, column=0, padx=16, pady=(4, 14), sticky="ew")

    # ---------------- گزارش ----------------
    def _toggle_report(self):
        self._report_open = not self._report_open
        if self._report_open:
            self.log_box.grid()
            self.geometry("720x860")
            self.report_btn.configure(text="📄  بستن گزارش اتصال")
        else:
            self.log_box.grid_remove()
            self.geometry("720x560")
            self.report_btn.configure(text="📄  نمایش گزارش اتصال")

    # ---------------- حلقه انیمیشن ----------------
    def _ui_tick(self):
        if self._closing:
            return
        self._tick_i += 1
        t = time.time()
        if self.app_state == "idle" and self._grad_bright:
            # نفس‌کش دکمه گرادیانی: تعویض دو تصویر گرادیان
            f = 0.5 - 0.5 * math.cos((t % 1.6) / 1.6 * 2 * math.pi)
            self.btn.configure(image=self._grad_bright if f > 0.5 else self._grad_dim)
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
                self.q.put(("staleclean", True))

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
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._poll)
        self.after(50, self._ui_tick)
        self.app_state = "idle"
        if err:
            self._log(f"✗ {err}")
            self._set_status("هسته Xray پیدا نشد", RED, RED)
            self.btn.configure(state="disabled")
        else:
            self._set_status("آماده اتصال", GREEN)
            self._log("✓ هسته Xray آماده است")

    # ---------------- خروج ----------------
    def _on_close(self):
        self._closing = True
        try:
            self.engine.stop_all()
        except Exception:
            pass
        self.destroy()


def main():
    app = App()
    app.start_with_splash()
    app.mainloop()


if __name__ == "__main__":
    main()
