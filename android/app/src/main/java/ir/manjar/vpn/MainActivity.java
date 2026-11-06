package ir.manjar.vpn;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.Settings;
import android.view.View;
import android.view.Window;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;

/**
 * ManjarVPN v1.8 — رابط (WebView) + پلِ جاوااسکریپت
 * همه‌چیز وسطِ صفحه، راست‌چین — مثل نسخه‌ی ویندوز.
 */
public class MainActivity extends Activity {

    private static final int REQ_VPN = 401;
    private static final int REQ_NOTIF = 402;
    private static final int REQ_WRITE_SETTINGS = 403;

    private WebView web;
    private ManjarVpnService svc;
    private VpnEngine engine;
    private AccountStore account;
    private boolean bound = false;
    private String pendingAction = null;   // auto | custom | node
    private String pendingCustomText = null;
    private Subs.Node pendingNode = null;
    private Runnable pendingWsTask = null; // v1.8.3 — بعد از برگشت از صفحه‌ی WRITE_SETTINGS
    private final JSONArray logBuffer = new JSONArray();

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            ManjarVpnService.LocalBinder lb = (ManjarVpnService.LocalBinder) service;
            svc = lb.getService();
            engine = lb.getEngine();
            engine.setVpnService(svc);
            account = engine.account;
            engine.setListener((type, payload) -> dispatchEvent(type, payload), r -> runOnUiThread(r));
            pushLogsToJs();
            web.post(() -> web.evaluateJavascript("if(window.appReady)appReady();", null));
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            svc = null;
        }
    };

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Window w = getWindow();
        w.setBackgroundDrawableResource(android.R.color.transparent);

        account = new AccountStore(this);

        web = new WebView(this);
        setContentView(web);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(true);
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);
        s.setTextZoom(100);
        web.setBackgroundColor(0xFF0C1022);
        web.setWebViewClient(new WebViewClient());
        web.addJavascriptInterface(new Bridge(), "Manjar");
        web.loadUrl("file:///android_asset/index.html");
        web.setOnApplyWindowInsetsListener((v, insets) -> insets);

        // سرویس: start + bind — تا وقتی برنامه باز است موتور زنده بماند
        Intent si = new Intent(this, ManjarVpnService.class);
        startService(si);
        bound = bindService(si, conn, Context.BIND_AUTO_CREATE);

        if (Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }
    }

    @Override
    protected void onDestroy() {
        if (bound) unbindService(conn);
        bound = false;
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        if (web != null) {
            web.evaluateJavascript(
                    "if(window.handleBack)handleBack();", null);
            return;
        }
        super.onBackPressed();
    }

    // ---------------- پلِ جاوااسکریپت ----------------
    private class Bridge {

        private void ui(Runnable r) { runOnUiThread(r); }

        @JavascriptInterface
        public String state() {
            try {
                JSONObject d = new JSONObject();
                d.put("version", Subs.VERSION);
                d.put("account", account.snapshot());
                d.put("wheelDone", account.wheelDone);
                d.put("blocked", account.isBlocked());
                d.put("aiRescue", engine != null && engine.aiRescueOn);
                d.put("hasConsent", ManjarVpnService.hasConsent(getApplicationContext()));
                d.put("tunnelUp", svc != null && svc.isTunnelUp());
                d.put("sources", Subs.SUBSCRIPTION_SOURCES.length);
                d.put("busy", engine != null && engine.busy);
                d.put("connected", engine != null && engine.currentNode != null);
                if (engine != null && engine.currentNode != null)
                    d.put("node", engine.nodeToJson(engine.currentNode));
                return d.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public String redeem(String code) {
            final JSONObject r = account.redeem(code);
            ui(() -> {
                pushEvent("redeemed", r);
                if (r.optBoolean("ok")) {
                    // اگر قبلا مسدود بود، حالا دوباره می‌تواند وصل شود
                    if (!account.isBlocked()) pushEvent("unblocked", new JSONObject());
                }
            });
            return r.toString();
        }

        @JavascriptInterface
        public void wheelClaim(final double mb) {
            ui(() -> {
                account.addCredit(mb, "wheel", true);
                account.setWheelDone(mb);
                if (engine != null)
                    engine.log("🎁 جایزه‌ی گردونه فعال شد — اعتبار اولیه شارژ شد.");
                pushEvent("usage", account.snapshot());
                // v1.8.3 — ذخیره‌ی ماندگار: با مجوزِ WRITE_SETTINGS در Settings.System
                // هم نوشته می‌شود تا بعد از حذفِ نصب، گردونه/اعتبار برنگردد.
                ensureWriteSettings(account::save);
            });
        }

        @JavascriptInterface
        public void wheelSkip() {
            ui(() -> {
                account.setWheelDone(0);
                if (engine != null)
                    engine.log("ℹ گردونه رد شد — اعتبار پیش‌فرض ۵۰۰ مگابایت فعال است.");
                ensureWriteSettings(account::save);
            });
        }

        @JavascriptInterface
        public void setAi(final boolean on) {
            ui(() -> {
                if (engine != null) {
                    engine.aiRescueOn = on;
                    engine.log("🤖 نجات با هوش مصنوعی " +
                            (on ? "فعال شد — فقط وقتی هیچ سروری جواب ندهد استفاده می‌شود" : "خاموش شد"));
                }
            });
        }

        @JavascriptInterface
        public void connectAuto() {
            ui(() -> {
                if (engine == null) return;
                if (account.isBlocked()) return;
                if (engine.busy) return;
                if (!ManjarVpnService.hasConsent(MainActivity.this)) {
                    pendingAction = "auto";
                    tryStartVpnConsent();
                    return;
                }
                engine.connectAutoFlow();
            });
        }

        @JavascriptInterface
        public void connectCustom(final String text) {
            ui(() -> {
                if (engine == null || engine.busy) return;
                if (account.isBlocked()) return;
                String t = text == null ? "" : text.trim();
                if (t.isEmpty()) return;
                if (!ManjarVpnService.hasConsent(MainActivity.this)) {
                    pendingAction = "custom";
                    pendingCustomText = t;
                    tryStartVpnConsent();
                    return;
                }
                engine.connectCustomFlow(t);
            });
        }

        @JavascriptInterface
        public void connectNode(final String uri) {
            ui(() -> {
                if (engine == null || engine.busy) return;
                if (account.isBlocked()) return;
                Subs.Node n = Subs.parseUri(uri);
                if (n == null) return;
                if (!ManjarVpnService.hasConsent(MainActivity.this)) {
                    pendingAction = "node";
                    pendingNode = n;
                    tryStartVpnConsent();
                    return;
                }
                engine.connectNodeFlow(n);
            });
        }

        @JavascriptInterface
        public void disconnect() {
            ui(() -> { if (engine != null) engine.disconnectFlow(); });
        }

        @JavascriptInterface
        public void cancel() {
            ui(() -> {
                if (engine == null) return;
                engine.cancelAll();
                engine.disconnectInternal(false);
                engine.idleNow();
            });
        }

        @JavascriptInterface
        public String topNodes() {
            try {
                if (engine == null) return "[]";
                return engine.nodesToJson(new ArrayList<>(engine.topNodes)).toString();
            } catch (Exception e) { return "[]"; }
        }

        @JavascriptInterface
        public String logs() {
            synchronized (logBuffer) { return logBuffer.toString(); }
        }

        @JavascriptInterface
        public void openUrl(String u) {
            ui(() -> {
                try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(u))); }
                catch (Exception ignored) {}
            });
        }

        @JavascriptInterface
        public void minimize() {
            ui(() -> moveTaskToBack(true));
        }
    }

    private void tryStartVpnConsent() {
        Intent i = ManjarVpnService.consentIntent(this);
        if (i != null) {
            startActivityForResult(i, REQ_VPN);
        } else {
            dispatchPending();
        }
    }

    /** v1.8.3 — اگر مجوزِ WRITE_SETTINGS نیست، یک‌بار صفحه‌ی رسمی اندروید باز می‌شود؛
     *  این مجوزِ «مخصوص» است و برخلاف مجوزهای معمولی، بعد از حذفِ نصبِ داده‌ها را
     *  در Settings.System زنده نگه می‌دارد. اگر کاربر نپذیرد، همون لایه‌های قبلی استفاده می‌شود. */
    private void ensureWriteSettings(Runnable after) {
        try {
            if (Settings.System.canWrite(this)) {
                after.run();
                return;
            }
            pendingWsTask = after;
            Intent i = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS,
                    Uri.parse("package:" + getPackageName()));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivityForResult(i, REQ_WRITE_SETTINGS);
        } catch (Exception e) {
            pendingWsTask = null;
            after.run();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) {
                dispatchPending();
            } else {
                if (engine != null) {
                    engine.log("✗ اجازه‌ی VPN داده نشد — بدون آن تونل فعال نمی‌شود.");
                    engine.idleNow();
                }
                pendingAction = null;
                pendingCustomText = null;
                pendingNode = null;
            }
        } else if (requestCode == REQ_WRITE_SETTINGS) {
            Runnable r = pendingWsTask;
            pendingWsTask = null;
            if (r != null) r.run();   // حتی اگر رد شد — save() فقط لایه‌های معمولی می‌نویسد
        }
    }

    private void dispatchPending() {
        if (engine == null) return;
        String action = pendingAction;
        pendingAction = null;
        if ("auto".equals(action)) {
            engine.connectAutoFlow();
        } else if ("custom".equals(action)) {
            String t = pendingCustomText;
            pendingCustomText = null;
            if (t != null) engine.connectCustomFlow(t);
        } else if ("node".equals(action)) {
            Subs.Node n = pendingNode;
            pendingNode = null;
            if (n != null) engine.connectNodeFlow(n);
        }
    }

    // ---------------- رویدادها → WebView ----------------
    private void dispatchEvent(String type, JSONObject payload) {
        synchronized (logBuffer) {
            if ("log".equals(type)) {
                String msg = payload.optString("msg");
                String ts = new java.text.SimpleDateFormat("HH:mm:ss",
                        java.util.Locale.US).format(new java.util.Date());
                logBuffer.put("[" + ts + "]  " + msg);
                while (logBuffer.length() > 400) logBuffer.remove(0);
            }
        }
        pushEvent(type, payload);
    }

    private void pushLogsToJs() {
        synchronized (logBuffer) {
            JSONObject p = new JSONObject();
            try { p.put("lines", logBuffer); } catch (Exception ignored) {}
            pushEvent("logs", p);
        }
    }

    private void pushEvent(String type, JSONObject payload) {
        if (web == null) return;
        final String js;
        try {
            String pl = payload == null ? "{}" : payload.toString();
            js = "window.dispatchEvent(new MessageEvent('manjar',{data:{type:'" + type + "',payload:" + pl + "}}));";
        } catch (Exception e) { return; }
        web.post(() -> {
            if (web != null) web.evaluateJavascript(js, null);
        });
    }
}
