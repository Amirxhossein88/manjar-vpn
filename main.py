# -*- coding: utf-8 -*-
"""
ManjarVPN v1.1 — رابط گرافیکی
اسپلش انیمیشنی + لوگو + اسپینر + دکمه نفس‌کش + نوار پیشرفت نرم + نمایشگر سرعت زنده
یک دکمه: خودش اینترنت را چک می‌کند، کانفیگ‌ها را تست می‌کند، به بهترین وصل می‌شود.
"""
from __future__ import annotations

import math
import queue
import threading
import time

import customtkinter as ctk

from engine import (APP_NAME, VERSION, VpnEngine, XRAY_HTTP_PORT,
                    find_logo, find_xray, SESSION)

try:
    from PIL import Image as PILImage
except Exception:
    PILImage = None

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG = "#0f1420"
CARD = "#171e2c"
TXT = "#e6ebf2"
TXT_DIM = "#93a0b4"
GREEN, GREEN_H = "#2f9e63", "#278a55"
GREEN_BR = "#46c47e"
RED, RED_H = "#cf4b4b", "#b03d3d"
AMBER, AMBER_H = "#d68910", "#b87409"
DOT_IDLE, DOT_OK, DOT_BAD, DOT_WARN = "#8a8f98", "#3ddc84", "#ff5252", "#f0c674"
FONT = "Segoe UI"


def _blend(c1: str, c2: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _load_logo(size: int):
    """برمی‌گرداند CTkImage یا None"""
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


# ============================ اسپلش انیمیشنی ============================
class Splash(ctk.CTkToplevel):
    def __init__(self, master, warmup, on_done):
        super().__init__(master, fg_color="#0b0f18")
        self.on_done = on_done
        self.warmup = warmup
        self._closing = False
        w, h = 430, 470
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        try:
            ico = find_logo()
            if ico and ico.endswith(".ico"):
                self.iconbitmap(ico)
        except Exception:
            pass

        self.logo_img = _load_logo(132)
        self.logo_lbl = ctk.CTkLabel(self, text="" if self.logo_img else "🛡",
                                     image=self.logo_img,
                                     font=ctk.CTkFont(family=FONT, size=64))
        self.logo_lbl.pack(pady=(64, 6))
        ctk.CTkLabel(self, text="ManjarVPN",
                     font=ctk.CTkFont(family=FONT, size=30, weight="bold"),
                     text_color=TXT).pack()
        ctk.CTkLabel(self, text="امن • سریع • هوشمند",
                     font=ctk.CTkFont(family=FONT, size=13),
                     text_color=TXT_DIM).pack(pady=(2, 26))

        # سه نقطه‌ی موجی
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack()
        self.dots = [ctk.CTkLabel(row, text="●", width=22,
                                  font=ctk.CTkFont(family=FONT, size=17))
                     for _ in range(3)]
        for d in self.dots:
            d.pack(side="left", padx=3)

        self.sweep = ctk.CTkProgressBar(self, width=240, height=6,
                                        progress_color="#38bdf8", fg_color="#1a2233")
        self.sweep.pack(pady=(30, 8))
        self.msg = ctk.CTkLabel(self, text="در حال آماده‌سازی…",
                                font=ctk.CTkFont(family=FONT, size=12), text_color=TXT_DIM)
        self.msg.pack()
        ctk.CTkLabel(self, text=f"v{VERSION} — ساخته‌شده با GitHub Actions",
                     font=ctk.CTkFont(family=FONT, size=10),
                     text_color="#5d6a7e").pack(side="bottom", pady=12)

        self.attributes("-alpha", 0.0)
        self._t0 = time.time()
        self._alpha = 0.0
        self._thread = threading.Thread(target=self._work, daemon=True)
        self.bind("<Button-1>", lambda e: self._finish())
        self.after(30, self._fade_in)
        self._thread.start()

    # --- انیمیشن‌ها ---
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
        # موج نقطه‌ها
        for i, d in enumerate(self.dots):
            b = 0.25 + 0.75 * max(0.0, math.sin(t * 4.2 - i * 0.9))
            d.configure(text_color=_blend("#243048", "#7dd3fc", b))
        # نوار رفت‌وبرگشتی
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
        self.geometry("680x760")
        self.minsize(600, 680)
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
        self.app_state = "idle"   # idle | busy | connected
        self._closing = False
        self._bar_target = 0.0
        self._eq_h = [6] * 6
        self._tick_i = 0

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI ----------------
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, pady=(16, 0))
        self.logo_small = _load_logo(56)
        ctk.CTkLabel(head, text="" if self.logo_small else "🛡",
                     image=self.logo_small).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(head, text="ManjarVPN",
                     font=ctk.CTkFont(family=FONT, size=30, weight="bold"),
                     text_color=TXT).pack(side="left")

        ctk.CTkLabel(self, text="بررسی اینترنت → تست هوشمند کانفیگ‌ها → اتصال به بهترین",
                     font=ctk.CTkFont(family=FONT, size=13),
                     text_color=TXT_DIM).grid(row=1, column=0, pady=(2, 12))

        # کارت وضعیت + اسپینر
        card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14)
        card.grid(row=2, column=0, padx=18, sticky="ew")
        card.grid_columnconfigure(2, weight=1)
        self.dot_lbl = ctk.CTkLabel(card, text="●", text_color=DOT_IDLE,
                                    font=ctk.CTkFont(family=FONT, size=22), width=26)
        self.dot_lbl.grid(row=0, column=0, padx=(14, 4), pady=10)
        self.spinner = self._make_spinner(card)
        self.spinner.grid(row=0, column=1, padx=(0, 8))
        self.eq = self._make_eq(card)
        self.status_var = ctk.StringVar(value="در حال آماده‌سازی…")
        ctk.CTkLabel(card, textvariable=self.status_var, anchor="w", justify="left",
                     font=ctk.CTkFont(family=FONT, size=14),
                     text_color=TXT).grid(row=0, column=2, padx=(0, 12), sticky="ew")

        # نوار پیشرفت
        self.bar = ctk.CTkProgressBar(self, progress_color="#3b82f6", height=10)
        self.bar.grid(row=3, column=0, padx=18, pady=(14, 0), sticky="ew")
        self.bar.set(0)
        self.phase_lbl = ctk.CTkLabel(self, text="", font=ctk.CTkFont(family=FONT, size=12),
                                      text_color=TXT_DIM)
        self.phase_lbl.grid(row=3, column=0, pady=(26, 0))

        # لاگ
        self.log_box = ctk.CTkTextbox(self, fg_color="#0b0f18", text_color="#a8b3c4",
                                      font=ctk.CTkFont(family=FONT, size=12), wrap="word")
        self.log_box.grid(row=4, column=0, padx=18, pady=(12, 8), sticky="nsew")
        self.log_box.configure(state="disabled")

        # کارت نتیجه
        res = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14)
        res.grid(row=5, column=0, padx=18, pady=(4, 10), sticky="ew")
        res.grid_columnconfigure(1, weight=1)
        res.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(res, text="سرور:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=0, column=0, padx=(14, 4), pady=(10, 0), sticky="w")
        self.res_name = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12, weight="bold"),
                                     text_color=TXT)
        self.res_name.grid(row=0, column=1, columnspan=3, padx=4, pady=(10, 0), sticky="ew")
        ctk.CTkLabel(res, text="پروتکل:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=1, column=0, padx=(14, 4), pady=2, sticky="w")
        self.res_proto = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12), text_color=TXT)
        self.res_proto.grid(row=1, column=1, padx=4, pady=2, sticky="w")
        ctk.CTkLabel(res, text="پینگ:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=1, column=2, padx=(16, 4), pady=2, sticky="e")
        self.res_ping = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12), text_color=TXT)
        self.res_ping.grid(row=1, column=3, padx=4, pady=2, sticky="w")
        ctk.CTkLabel(res, text="سرعت تست:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=2, column=0, padx=(14, 4), pady=2, sticky="w")
        self.res_speed = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12), text_color=TXT)
        self.res_speed.grid(row=2, column=1, padx=4, pady=2, sticky="w")
        ctk.CTkLabel(res, text="سرعت لحظه‌ای:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=2, column=2, padx=(16, 4), pady=2, sticky="e")
        self.res_live = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12),
                                     text_color=TXT_DIM)
        self.res_live.grid(row=2, column=3, padx=4, pady=2, sticky="w")
        ctk.CTkLabel(res, text="پروکسی سیستم:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=3, column=0, padx=(14, 4), pady=(2, 10), sticky="w")
        self.res_proxy = ctk.CTkLabel(res, text="خاموش", font=ctk.CTkFont(family=FONT, size=12),
                                      text_color=TXT_DIM)
        self.res_proxy.grid(row=3, column=1, padx=4, pady=(2, 10), sticky="w")
        self.eq.grid(row=3, column=2, columnspan=2, padx=(16, 10), pady=(0, 8), sticky="e")

        # دکمه اصلی
        self.btn = ctk.CTkButton(self, text="🔌  اتصال خودکار", command=self._on_button,
                                 height=58, corner_radius=14,
                                 font=ctk.CTkFont(family=FONT, size=20, weight="bold"),
                                 fg_color=GREEN, hover_color=GREEN_H, text_color="#ffffff")
        self.btn.grid(row=6, column=0, padx=18, pady=(2, 18), sticky="ew")

        self._log(f"{APP_NAME} v{VERSION} آماده است.")

    # --- ویجت‌های انیمیشنی ---
    def _make_spinner(self, parent):
        import tkinter as tk
        c = tk.Canvas(parent, width=30, height=30, bg=CARD, highlightthickness=0)
        self._spin_arc = c.create_arc(4, 4, 26, 26, start=0, extent=250,
                                      style="arc", width=4, outline="#38bdf8")
        c.grid_remove()
        return c

    def _make_eq(self, parent):
        import tkinter as tk
        c = tk.Canvas(parent, width=70, height=22, bg=CARD, highlightthickness=0)
        self._eq_bars = []
        for i in range(6):
            x = 2 + i * 11
            r = c.create_rectangle(x, 20, x + 7, 20, fill="#3ddc84", width=0)
            self._eq_bars.append(r)
        c.grid_remove()
        return c

    # ---------------- helpers ----------------
    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}]  {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_status(self, text: str, color: str):
        self.status_var.set(text)
        self._dot_color = color

    def _set_button(self, text, fg, hover):
        self.btn.configure(text=text, fg_color=fg, hover_color=hover)

    def _clear_result(self):
        for lbl in (self.res_name, self.res_proto, self.res_ping, self.res_speed, self.res_live):
            lbl.configure(text="—")
        self.res_proxy.configure(text="خاموش", text_color=TXT_DIM)

    # ---------------- دکمه ----------------
    def _on_button(self):
        if self.app_state == "idle":
            self.engine.stop_flag.clear()
            self.app_state = "busy"
            self.spinner.grid()
            self.eq.grid_remove()
            self._set_button("⏹  لغو تست و اتصال", AMBER, AMBER_H)
            self._clear_result()
            self.worker = threading.Thread(target=self._flow, daemon=True)
            self.worker.start()
        elif self.app_state == "busy":
            self._set_status("در حال لغو…", DOT_WARN)
            self.engine.stop_all()
        elif self.app_state == "connected":
            self.engine.disconnect()
            self._log("✓ اتصال قطع شد و پروکسی سیستم خاموش شد")
            self._set_idle()

    # ---------------- کار اصلی (in thread) ----------------
    def _flow(self):
        eng = self.engine
        try:
            self.q.put(("status", ("در حال بررسی اتصال اینترنت…", DOT_WARN)))
            ok, lat = eng.check_internet()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if not ok:
                self.q.put(("error", "اتصال اینترنت پیدا نشد! وای‌فای یا کابل شبکه را چک کنید."))
                return
            self.q.put(("log", f"✓ اینترنت برقرار است (پینگ مستقیم {lat} میلی‌ثانیه)"))

            # مسیر سریع: سرورهای خوب قبلی
            best, _ = eng.quick_connect_check()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if best is not None:
                self.q.put(("log", f"⚡ سرور خوب از حافظه: {best.display()} — "
                                   f"{best.speed:.1f}Mbps — اتصال سریع…"))
                eng.connect(best)
                eng.update_cache(best, [best])
                self.q.put(("connected", best))
                return

            self.q.put(("status", ("دریافت کانفیگ‌های رایگان دنیا…", DOT_WARN)))
            nodes = eng.fetch_all()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if not nodes:
                self.q.put(("error", "هیچ کانفیگی دریافت نشد (احتمالاً اختلال فیلترینگ). کمی بعد دوباره تلاش کنید."))
                return
            self.q.put(("log", f"✓ {len(nodes)} کانفیگ یکتا از ۱۷ منبع — شروع تست هوشمند"))

            best, ok_list = eng.scan(nodes)
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if best is None:
                self.q.put(("error", "هیچ کانفیگ سالمی پیدا نشد. چند دقیقه دیگر دوباره امتحان کنید."))
                return

            self.q.put(("log", f"★ بهترین: {best.display()} [{best.proto}] — "
                               f"پینگ {int(best.latency)}ms، سرعت {best.speed:.1f}Mbps"))
            self.q.put(("status", ("در حال اتصال به بهترین کانفیگ…", DOT_WARN)))
            eng.connect(best)
            eng.update_cache(best, ok_list)
            self.q.put(("connected", best))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    # ---------------- نمایشگر سرعت زنده + نگهبان اتصال ----------------
    def _live_monitor(self):
        eng = self.engine
        fails = 0
        while not self._closing and eng.current_node is not None:
            try:
                t0 = time.time()
                r = SESSION.get("https://speed.cloudflare.com/__down?bytes=131072",
                                proxies={"http": f"http://127.0.0.1:{XRAY_HTTP_PORT}",
                                         "https": f"http://127.0.0.1:{XRAY_HTTP_PORT}"},
                                timeout=6)
                el = time.time() - t0
                if r.status_code < 400 and el > 0:
                    mbps = (131072 * 8.0) / el / 1e6
                    fails = 0
                    if not self._closing:
                        self.q.put(("livespeed", mbps))
                else:
                    fails += 1
            except Exception:
                fails += 1
            if fails >= 3:
                if not self._closing:
                    self.q.put(("log", "⚠ اتصال قطع به نظر می‌رسد! دکمه را بزنید تا دوباره وصل شود."))
                    self.q.put(("status", ("اتصال قطع شده — دوباره اتصال بزنید", DOT_BAD)))
                break
            time.sleep(3)

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
                    self.res_live.configure(text=f"{payload:.1f} Mbps", text_color=DOT_OK)
                elif kind == "error":
                    self._log(f"✗ {payload}")
                    self._set_status(payload, DOT_BAD)
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
        self._bar_target = 1.0
        self.phase_lbl.configure(text="متصل ✓")
        self.spinner.grid_remove()
        self.eq.grid()
        self._set_status("متصل — کل ترافیک سیستم از طریق ManjarVPN می‌گذرد ✓", DOT_OK)
        self._set_button("⏹  قطع اتصال", RED, RED_H)
        self.res_name.configure(text=node.display())
        self.res_proto.configure(text=f"{node.proto.upper()}  ({node.server}:{node.port})")
        self.res_ping.configure(text=f"{int(node.latency)} ms")
        self.res_speed.configure(text=f"{node.speed:.1f} Mbps" if node.speed else "—")
        self.res_proxy.configure(text="روشن ✓ (127.0.0.1:10809)", text_color=DOT_OK)
        self._log("✓ متصل شد — پروکسی سیستم ویندوز روشن شد (HTTP: 10809 / SOCKS: 10808)")
        threading.Thread(target=self._live_monitor, daemon=True).start()

    def _set_idle(self):
        self.app_state = "idle"
        self.spinner.grid_remove()
        self.eq.grid_remove()
        self._set_button("🔌  اتصال خودکار", GREEN, GREEN_H)
        self._set_status("آماده — دکمه «اتصال خودکار» را بزنید", DOT_IDLE)
        self.res_live.configure(text="—", text_color=TXT_DIM)
        if not self.engine.current_node:
            self._bar_target = 0.0
            self.phase_lbl.configure(text="")

    # ---------------- حلقه انیمیشن واحد ----------------
    def _ui_tick(self):
        if self._closing:
            return
        self._tick_i += 1
        t = time.time()
        # دکمه نفس‌کش (فقط در حالت آماده)
        if self.app_state == "idle":
            f = 0.5 - 0.5 * math.cos((t % 1.8) / 1.8 * 2 * math.pi)
            self.btn.configure(fg_color=_blend(GREEN, GREEN_BR, 0.45 * f))
        # اسپینر چرخان
        if self.app_state == "busy":
            self.spinner.itemconfigure(self._spin_arc, start=(self._tick_i * 11) % 360)
        # نبض نقطه وضعیت
        if self.app_state == "busy":
            base, hot = "#b98a2f", DOT_WARN
        elif self.app_state == "connected":
            base, hot = "#27b06a", DOT_OK
        else:
            base, hot = None, None
        if base:
            f = 0.5 - 0.5 * math.cos((t % 1.2) / 1.2 * 2 * math.pi)
            self.dot_lbl.configure(text_color=_blend(base, hot, f))
        # نوار پیشرفت نرم
        cur = self.bar.get()
        diff = self._bar_target - cur
        if abs(diff) > 0.0015:
            self.bar.set(cur + diff * 0.22)
        # اکولایزر متصل
        if self.app_state == "connected" and self._tick_i % 2 == 0:
            for i, r in enumerate(self._eq_bars):
                target = 4 + abs(math.sin(t * 3.1 + i * 1.3)) * 15 * min(1.0, self._live_factor())
                self._eq_h[i] = self._eq_h[i] * 0.55 + target * 0.45
                h = max(2, min(20, self._eq_h[i]))
                x = 2 + i * 11
                self.eq.coords(r, x, 21 - h, x + 7, 21)
                self.eq.itemconfigure(r, fill=_blend("#1f7a4d", "#3ddc84", h / 20))
        self.after(50, self._ui_tick)

    def _live_factor(self):
        try:
            txt = self.res_live.cget("text")
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

        def on_done(err):
            if err:
                self.after(0, lambda: self._after_splash(err))
            else:
                self.after(0, self._after_splash)

        self.splash = Splash(self, warmup, on_done)

    def _after_splash(self, err=None):
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
        if err:
            self._log(f"✗ {err}")
            self._set_status("هسته Xray پیدا نشد — برنامه را از بیلد Actions اجرا کنید", DOT_BAD)
            self.btn.configure(state="disabled")
        else:
            self._log("✓ هسته Xray آماده است")
            self._set_status("آماده — دکمه «اتصال خودکار» را بزنید", DOT_IDLE)

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
