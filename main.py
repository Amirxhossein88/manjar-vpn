# -*- coding: utf-8 -*-
"""
ManjarVPN — رابط گرافیکی
یک دکمه: خودش اینترنت را چک می‌کند، همه کانفیگ‌ها را تست می‌کند، به بهترین وصل می‌شود.
"""
from __future__ import annotations

import queue
import sys
import threading
import time

import customtkinter as ctk

from engine import (APP_NAME, VERSION, VpnEngine, find_xray)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG = "#0f1420"
CARD = "#171e2c"
TXT = "#e6ebf2"
TXT_DIM = "#93a0b4"
GREEN, GREEN_H = "#2f9e63", "#278a55"
RED, RED_H = "#cf4b4b", "#b03d3d"
AMBER, AMBER_H = "#d68910", "#b87409"
DOT_IDLE, DOT_OK, DOT_BAD, DOT_WARN = "#8a8f98", "#3ddc84", "#ff5252", "#f0c674"
FONT = "Segoe UI"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("660x740")
        self.minsize(580, 660)
        self.configure(fg_color=BG)

        self.q: queue.Queue = queue.Queue()
        self.engine = VpnEngine(
            log_cb=lambda m: self.q.put(("log", m)),
            progress_cb=lambda p, d, t, m: self.q.put(("progress", (p, d, t, m))),
        )
        self.app_state = "idle"   # idle | busy | connected
        self.worker: threading.Thread | None = None

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll)

        # وضعیت هسته Xray
        try:
            self.engine.ensure_xray()
            self._log("✓ هسته Xray آماده است")
        except Exception as e:
            self._log(f"✗ {e}")
            self.status_var.set("هسته Xray پیدا نشد — برنامه را از بیلد Actions اجرا کنید")
            self.dot_lbl.configure(text_color=DOT_BAD)
            self.btn.configure(state="disabled")

    # ---------------- UI ----------------
    def _build_ui(self):
        for i in range(1):
            self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(self, text="🛡 ManjarVPN",
                     font=ctk.CTkFont(family=FONT, size=34, weight="bold"),
                     text_color=TXT).grid(row=0, column=0, pady=(18, 2))
        ctk.CTkLabel(self,
                     text="بررسی اینترنت → تست خودکار کانفیگ‌های رایگان → اتصال به بهترین",
                     font=ctk.CTkFont(family=FONT, size=13),
                     text_color=TXT_DIM).grid(row=1, column=0, pady=(0, 12))

        # کارت وضعیت
        card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14)
        card.grid(row=2, column=0, padx=18, sticky="ew")
        card.grid_columnconfigure(1, weight=1)
        self.dot_lbl = ctk.CTkLabel(card, text="●", text_color=DOT_IDLE,
                                    font=ctk.CTkFont(family=FONT, size=22))
        self.dot_lbl.grid(row=0, column=0, padx=(14, 6), pady=12)
        self.status_var = ctk.StringVar(value="آماده — دکمه «اتصال خودکار» را بزنید")
        ctk.CTkLabel(card, textvariable=self.status_var, anchor="w", justify="left",
                     font=ctk.CTkFont(family=FONT, size=14),
                     text_color=TXT).grid(row=0, column=1, padx=(0, 12), sticky="ew")

        # نوار پیشرفت
        self.bar = ctk.CTkProgressBar(self, progress_color="#3b82f6", height=10)
        self.bar.grid(row=3, column=0, padx=18, pady=(14, 2), sticky="ew")
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
        ctk.CTkLabel(res, text="سرور انتخاب‌شده:", font=ctk.CTkFont(family=FONT, size=12),
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
        ctk.CTkLabel(res, text="سرعت تست‌شده:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=2, column=0, padx=(14, 4), pady=(2, 10), sticky="w")
        self.res_speed = ctk.CTkLabel(res, text="—", font=ctk.CTkFont(family=FONT, size=12), text_color=TXT)
        self.res_speed.grid(row=2, column=1, padx=4, pady=(2, 10), sticky="w")
        ctk.CTkLabel(res, text="پروکسی سیستم:", font=ctk.CTkFont(family=FONT, size=12),
                     text_color=TXT_DIM).grid(row=2, column=2, padx=(16, 4), pady=(2, 10), sticky="e")
        self.res_proxy = ctk.CTkLabel(res, text="خاموش", font=ctk.CTkFont(family=FONT, size=12),
                                      text_color=TXT_DIM)
        self.res_proxy.grid(row=2, column=3, padx=4, pady=(2, 10), sticky="w")

        # دکمه اصلی
        self.btn = ctk.CTkButton(self, text="🔌  اتصال خودکار", command=self._on_button,
                                 height=58, corner_radius=14,
                                 font=ctk.CTkFont(family=FONT, size=20, weight="bold"),
                                 fg_color=GREEN, hover_color=GREEN_H, text_color="#ffffff")
        self.btn.grid(row=6, column=0, padx=18, pady=(2, 18), sticky="ew")

        self._log(f"{APP_NAME} v{VERSION} آماده است.")

    # ---------------- helpers ----------------
    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}]  {msg}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_status(self, text: str, color: str):
        self.status_var.set(text)
        self.dot_lbl.configure(text_color=color)

    def _set_button(self, text: str, fg: str, hover: str):
        self.btn.configure(text=text, fg_color=fg, hover_color=hover)

    # ---------------- دکمه ----------------
    def _on_button(self):
        if self.app_state == "idle":
            self.engine.stop_flag.clear()
            self.app_state = "busy"
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

            self.q.put(("status", ("دریافت کانفیگ‌های رایگان دنیا از منابع…", DOT_WARN)))
            nodes = eng.fetch_all()
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if not nodes:
                self.q.put(("error", "هیچ کانفیگی دریافت نشد (احتمالاً اختلال فیلترینگ). کمی بعد دوباره تلاش کنید."))
                return
            self.q.put(("log", f"✓ {len(nodes)} کانفیگ یکتا دریافت شد — شروع تست هوشمند"))

            best, ok_list = eng.scan(nodes)
            if eng.stop_flag.is_set():
                self.q.put(("idle", None)); return
            if best is None:
                self.q.put(("error", "هیچ کانفیگ سالمی پیدا نشد. چند دقیقه دیگر دوباره امتحان کنید."))
                return

            self.q.put(("log", f"★ بهترین کانفیگ: {best.display()} [{best.proto}] — "
                               f"پینگ {int(best.latency)}ms، سرعت {best.speed:.1f}Mbps"))
            self.q.put(("status", ("در حال اتصال به بهترین کانفیگ…", DOT_WARN)))
            eng.connect(best)
            self.q.put(("connected", best))
        except Exception as e:
            if not eng.stop_flag.is_set():
                self.q.put(("error", f"خطا: {e}"))
        finally:
            if self.engine.proc is None and self.engine.stop_flag.is_set():
                self.q.put(("idle", None))

    # ---------------- صف رویدادها ----------------
    def _poll(self):
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
                elif kind == "error":
                    self._log(f"✗ {payload}")
                    self._set_status(payload, DOT_BAD)
                    self._set_idle()
                elif kind == "idle":
                    self._set_idle()
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _progress(self, phase, done, total, msg):
        total = max(total, 1)
        ratio = max(done, 0) / total
        if phase == "fetch":
            v = 0.15 * ratio
        elif phase == "latency":
            v = 0.15 + 0.60 * ratio
        elif phase == "speed":
            v = 0.75 + 0.20 * ratio
        elif phase == "connect":
            v = 0.95 + 0.05 * ratio
        else:
            v = self.bar.get()
        self.bar.set(min(v, 1.0))
        self.phase_lbl.configure(text=msg)

    def _clear_result(self):
        for lbl in (self.res_name, self.res_proto, self.res_ping, self.res_speed):
            lbl.configure(text="—")
        self.res_proxy.configure(text="خاموش", text_color=TXT_DIM)

    def _on_connected(self, node):
        self.app_state = "connected"
        self.bar.set(1.0)
        self.phase_lbl.configure(text="متصل ✓")
        self._set_status(f"متصل — کل ترافیک سیستم از طریق ManjarVPN می‌گذرد ✓", DOT_OK)
        self._set_button("⏹  قطع اتصال", RED, RED_H)
        self.res_name.configure(text=node.display())
        self.res_proto.configure(text=f"{node.proto.upper()}  ({node.server}:{node.port})")
        self.res_ping.configure(text=f"{int(node.latency)} ms")
        self.res_speed.configure(text=f"{node.speed:.1f} Mbps" if node.speed else "—")
        self.res_proxy.configure(text="روشن ✓ (127.0.0.1:10809)", text_color=DOT_OK)
        self._log("✓ متصل شد — پروکسی سیستم ویندوز روشن شد (SOCKS: 10808 / HTTP: 10809)")

    def _set_idle(self):
        self.app_state = "idle"
        self._set_button("🔌  اتصال خودکار", GREEN, GREEN_H)
        self._set_status("آماده — دکمه «اتصال خودکار» را بزنید", DOT_IDLE)
        if not self.engine.current_node:
            self.bar.set(0)
            self.phase_lbl.configure(text="")

    # ---------------- خروج ----------------
    def _on_close(self):
        try:
            self.engine.stop_all()
        except Exception:
            pass
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
