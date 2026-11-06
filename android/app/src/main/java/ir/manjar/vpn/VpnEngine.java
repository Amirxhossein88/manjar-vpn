package ir.manjar.vpn;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * ManjarVPN v1.8 — موتورِ اندروید — پورتِ کاملِ جریانِ ویندوز:
 * اینترنت ← مسیرِ سریع (حافظه‌ی سرورهای خوب) ← دریافتِ منابع ← پیش‌فیلتر TCP
 * ← پینگ موازی (+ تلاش مجدد) ← تستِ عمیق (یوتوب/اینستاگرام/تلگرام + سرعت دان/آپ)
 * ← بهترین ← دروازه‌ی سرعت ← تونلِ VPN + نگهبان + تعمیرِ بی‌صدا + شمارشِ حجم
 * ← نجاتِ هوش مصنوعی (فقط با سوییچِ کاربر).
 */
public class VpnEngine {

    public interface Listener {
        void onEvent(String type, JSONObject payload);
    }

    public interface Ui { void runOnUiThread(Runnable r); }

    public static final int SOCKS_PORT = 10808;
    public static final int API_PORT = 15432;
    public static final int RELAY_PORT = 10810;
    public static final double MIN_GOOD_SPEED_MBPS = 2.0;
    public static final double MIN_USABLE_SPEED_MBPS = 0.6;
    public static final int TCP_PREFILTER_WORKERS = 64;      // ویندوز ۲۰۰ — موبایلِ محافظه‌کارتر
    public static final double TCP_PREFILTER_TIMEOUT = 2.0;
    public static final int MAX_TEST_NODES = 1200;
    public static final int MAX_XRAY_LATENCY_TESTS = 320;
    public static final int CONCURRENT_TESTS = 6;            // ویندوز ۱۴ — روی موبایل حافظه‌ی کمتر → Xrayِ همزمانِ کمتر (هر هسته ~۳۶MB)
    public static final double XRAY_START_TIMEOUT = 4.0;     // ویندوز ۲ — فلشِ کندِ گوشی + بارِ صفحه‌ی ۳۶ مگابایتی → صبرِ بیشتر
    public static final int LATENCY_RETRY_MAX = 80;
    public static final double LATENCY_TIMEOUT = 5.0;
    public static final int DEEP_POOL = 40;
    public static final int DEEP_ROUNDS = 3;
    public static final int DEEP_TARGET = 12;
    public static final int DEEP_WORKERS = 3;
    public static final double SITE_TIMEOUT = 6.0;
    public static final int TOP_SPEED_TESTS = 8;
    public static final int EXTRA_SPEED_SAMPLES = 3;
    public static final int CONCURRENT_SPEED_TESTS = 4;
    public static final int DL_TEST_CAP_BYTES = 3_000_000;   // موبایل: سقفِ دانلودِ تستِ هر کاندید
    public static final int UPLOAD_PROBE_BYTES = 200_000;

    private static final String BROWSER_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/124.0 Safari/537.36";

    public final Context ctx;
    public final AccountStore account;
    private Listener listener;      // روی تردِ اصلیِ رابط
    private Ui ui;

    public volatile boolean stopFlag = false;
    public String xrayPath;
    public volatile Process mainProc;
    public volatile String lastXrayErr = "";   // آخرین خطای stderr هسته — برای تشخیصِ دقیق روی گوشی
    private volatile boolean xrayStartFailLogged = false;
    public volatile int socksPort = SOCKS_PORT;
    public volatile int apiPort = API_PORT;
    public volatile int relayPort = RELAY_PORT;
    public volatile Subs.Node currentNode = null;
    public volatile int connEpoch = 0;
    public final Map<String, Integer> scanStats = new ConcurrentHashMap<>();
    public volatile boolean aiRescueOn = false;
    public volatile int aiRescueUsed = 0;
    public List<Subs.Node> topNodes = Collections.synchronizedList(new ArrayList<>());
    public volatile boolean busy = false;

    private ManjarVpnService vpnSvc;   // برای protect() و راه‌اندازی TUN
    private ProtRelay relay;
    private Thread healthThread, usageThread;
    private final AtomicInteger testPortCounter = new AtomicInteger(1);
    private final Object connLock = new Object();
    private final AtomicBoolean abortRepair = new AtomicBoolean(false);
    private final List<Process> testProcs = Collections.synchronizedList(new ArrayList<>());
    private final Random rnd = new Random();
    private SSLContext sslCtx;
    private volatile double gateEndpointSpeed = 0;
    private volatile String lastSitesDetail = "";

    public VpnEngine(Context ctx, AccountStore account) {
        this.ctx = ctx.getApplicationContext();
        this.account = account;
        try { sslCtx = SSLContext.getInstance("TLS"); sslCtx.init(null, null, null); }
        catch (Exception e) { sslCtx = null; }
        try {
            xrayPath = new File(ctx.getApplicationInfo().nativeLibraryDir, "libxray.so").getAbsolutePath();
        } catch (Exception e) { xrayPath = null; }
    }

    public void setListener(Listener l, Ui ui) { this.listener = l; this.ui = ui; }
    public void setVpnService(ManjarVpnService s) { this.vpnSvc = s; }
    public boolean hasVpnService() { return vpnSvc != null; }

    private void ev(String type, String key, Object val) {
        Listener l = listener;
        if (l == null || ui == null) return;
        JSONObject p = new JSONObject();
        try { if (key != null) p.put(key, val == null ? JSONObject.NULL : val); } catch (Exception ignored) {}
        try { ui.runOnUiThread(() -> l.onEvent(type, p)); } catch (Exception ignored) {}
    }

    public void log(String m) { ev("log", "msg", m); }
    public void status(String m, String color) {
        JSONObject p = new JSONObject();
        try { p.put("msg", m); p.put("color", color); } catch (Exception ignored) {}
        Listener l = listener;
        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("status", p));
    }
    public void progress(String phase, int done, int total, String msg) {
        JSONObject p = new JSONObject();
        try { p.put("phase", phase); p.put("done", done); p.put("total", total); p.put("msg", msg); }
        catch (Exception ignored) {}
        Listener l = listener;
        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("progress", p));
    }

    private void funnel(String key) { scanStats.put(key, scanStats.containsKey(key) ? scanStats.get(key) + 1 : 1); }
    private void funnel(String key, String reason) {
        funnel(key);
        if (reason != null) {
            Map<String, Integer> rd = new HashMap<>();
            try {
                // reasons داخل scanStats به‌صورت map نگه داشته نمی‌شود؛ ساده: در فیلد جدا
            } catch (Exception ignored) {}
            reasonsMap.put(reason, reasonsMap.containsKey(reason) ? reasonsMap.get(reason) + 1 : 1);
        }
    }
    public final Map<String, Integer> reasonsMap = new ConcurrentHashMap<>();

    // ============================ زیرساخت ============================
    public boolean ensureXray() {
        if (xrayPath == null) return false;
        File f = new File(xrayPath);
        return f.exists() && f.canExecute();
    }

    private int nextTestPort() {
        return 30000 + (testPortCounter.getAndIncrement() % 20000);
    }

    private static int findFreePort(int start) {
        for (int p = start; p < start + 40; p++) {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress("127.0.0.1", p));
                return p;
            } catch (Exception ignored) {}
        }
        return start;
    }

    private Process startXray(String cfgPath, String logTag) {
        try {
            ProcessBuilder pb = new ProcessBuilder(xrayPath, "run", "-c", cfgPath);
            pb.redirectErrorStream(false);
            Process p = pb.start();
            // مصرفِ خروجی‌ها تا بلاک نشود — stderr برای تشخیصِ خطا نگه داشته می‌شود
            drain(p.getInputStream());
            drainErr(p.getErrorStream());
            return p;
        } catch (Exception e) {
            lastXrayErr = "exec: " + e.getClass().getSimpleName() +
                    (e.getMessage() != null ? " (" + e.getMessage() + ")" : "");
            log("✗ اجرای هسته Xray ممکن نشد: " + lastXrayErr);
            return null;
        }
    }

    private void drain(final InputStream is) {
        if (is == null) return;
        Thread t = new Thread(() -> {
            byte[] b = new byte[4096];
            try { while (is.read(b) >= 0) { /* discard */ } } catch (Exception ignored) {}
        });
        t.setDaemon(true);
        t.start();
    }

    /** stderr هسته را جمع می‌کند تا اگر Xray بالا نیامد، علتِ واقعی دیده شود. */
    private void drainErr(final InputStream is) {
        if (is == null) return;
        Thread t = new Thread(() -> {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[2048];
            try {
                int n;
                while ((n = is.read(b)) >= 0) {
                    bos.write(b, 0, n);
                    if (bos.size() > 16384) bos.reset();
                }
            } catch (Exception ignored) {}
            String s = new String(bos.toByteArray(), StandardCharsets.UTF_8).trim();
            if (!s.isEmpty()) {
                int nl = s.indexOf('\n');
                if (nl > 0) s = s.substring(0, nl);
                lastXrayErr = s.length() > 300 ? s.substring(0, 300) : s;
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void killProc(Process p) {
        if (p == null) return;
        try { p.destroy(); } catch (Exception ignored) {}
        try { p.waitFor(1500, java.util.concurrent.TimeUnit.MILLISECONDS); } catch (Exception ignored) {}
        try { p.destroyForcibly(); } catch (Exception ignored) {}
    }

    private boolean waitPort(int port, double timeoutSec) {
        long end = System.currentTimeMillis() + (long) (timeoutSec * 1000);
        while (System.currentTimeMillis() < end) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), 250);
                return true;
            } catch (Exception ignored) {}
            try { Thread.sleep(50); } catch (Exception ignored) {}
        }
        return false;
    }

    // ============================ شبکه: HTTP مستقیم ============================
    public String fetchUrl(String url) {
        for (String tpl : Subs.MIRROR_TEMPLATES) {
            if (stopFlag) return null;
            String u = tpl.replace("{url}", url);
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(12000);
                c.setReadTimeout(12000);
                c.setRequestProperty("User-Agent", Subs.APP_NAME + "/" + Subs.VERSION);
                c.setInstanceFollowRedirects(true);
                int code = c.getResponseCode();
                if (code == 200) {
                    InputStream is = c.getInputStream();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
                    is.close();
                    String text = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                    if (!text.trim().isEmpty()) return text;
                }
                c.disconnect();
            } catch (Exception ignored) {}
        }
        return null;
    }

    public boolean checkInternet() {
        String[] urls = {"http://cp.cloudflare.com/generate_204", "https://www.gstatic.com/generate_204"};
        for (String u : urls) {
            try {
                long t0 = System.currentTimeMillis();
                HttpURLConnection c = (HttpURLConnection) new URL(u).openConnection();
                c.setConnectTimeout(6000);
                c.setReadTimeout(6000);
                c.setRequestProperty("User-Agent", BROWSER_UA);
                int code = c.getResponseCode();
                c.disconnect();
                if (code < 500) {
                    lastDirectLatency = (int) (System.currentTimeMillis() - t0);
                    return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }
    public volatile int lastDirectLatency = 0;

    // ============================ شبکه: SOCKS5 ============================
    public static Socket socksConnect(Socket base, String dstHost, int dstPort) throws Exception {
        OutputStream os = base.getOutputStream();
        InputStream is = base.getInputStream();
        os.write(new byte[]{5, 1, 0});
        os.flush();
        byte[] r = readN(is, 2);
        if (r.length < 2 || r[0] != 5 || r[1] != 0) throw new Exception("socks handshake failed");
        byte[] dst = dstHost.getBytes(StandardCharsets.UTF_8);
        os.write(new byte[]{5, 1, 0, 3, (byte) dst.length});
        os.write(dst);
        os.write(new byte[]{(byte) ((dstPort >> 8) & 0xff), (byte) (dstPort & 0xff)});
        os.flush();
        byte[] hdr = readN(is, 4);
        if (hdr.length < 4 || hdr[1] != 0) throw new Exception("socks connect refused");
        int atyp = hdr[3];
        if (atyp == 1) readN(is, 4);
        else if (atyp == 4) readN(is, 16);
        else if (atyp == 3) { int len = readN(is, 1)[0]; readN(is, len); }
        readN(is, 2);
        return base;
    }

    private static byte[] readN(InputStream is, int n) throws Exception {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int r = is.read(b, off, n - off);
            if (r < 0) throw new Exception("socks eof");
            off += r;
        }
        return b;
    }

    /** GET ساده (HTTP غیر رمز) از داخل تونل — کدِ پاسخ برمی‌گردد (هر پاسخ = باز شده). */
    public static int httpGetViaSocks(int socksPort, String host, String path, String hostHeader, int timeoutMs) throws Exception {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("127.0.0.1", socksPort), timeoutMs);
            s.setSoTimeout(timeoutMs);
            socksConnect(s, host, 80);
            OutputStream os = s.getOutputStream();
            String req = "GET " + path + " HTTP/1.1\r\nHost: " + hostHeader +
                    "\r\nUser-Agent: " + BROWSER_UA + "\r\nConnection: close\r\n\r\n";
            os.write(req.getBytes(StandardCharsets.UTF_8));
            os.flush();
            InputStream is = s.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) > 0 && bos.size() < 65536) bos.write(buf, 0, n);
            String head = new String(bos.toByteArray(), StandardCharsets.UTF_8);
            int sp = head.indexOf(' ');
            if (sp < 0) throw new Exception("bad response");
            return Integer.parseInt(head.substring(sp + 1, sp + 4));
        } finally {
            try { s.close(); } catch (Exception ignored) {}
        }
    }

    /** HTTPS (TLS) از داخل تونل — کدِ پاسخ؛ هر پاسخِ HTTP یعنی تونل تا مقصد می‌رسد. */
    public int httpsGetViaSocks(int socksPort, String host, String path, int timeoutMs) throws Exception {
        Socket socks = new Socket();
        try {
            socks.connect(new InetSocketAddress("127.0.0.1", socksPort), timeoutMs);
            socks.setSoTimeout(timeoutMs + 1000);
            socksConnect(socks, host, 443);
            SSLSocketFactory f = sslCtx != null ? sslCtx.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket ts = (SSLSocket) f.createSocket(socks, host, 443, true);
            OutputStream os = ts.getOutputStream();
            String req = "GET " + path + " HTTP/1.1\r\nHost: " + host +
                    "\r\nUser-Agent: " + BROWSER_UA + "\r\nConnection: close\r\n\r\n";
            os.write(req.getBytes(StandardCharsets.UTF_8));
            os.flush();
            InputStream is = ts.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0 && bos.size() < 65536) bos.write(buf, 0, n);
            String head = new String(bos.toByteArray(), StandardCharsets.UTF_8);
            int sp = head.indexOf(' ');
            if (sp < 0) throw new Exception("bad response");
            return Integer.parseInt(head.substring(sp + 1, sp + 4));
        } finally {
            try { socks.close(); } catch (Exception ignored) {}
        }
    }

    /** سرعتِ دانلود از داخل تونل (HTTPS) — ضد «صفرِ کاذب» مثل ویندوز. */
    public double dlSpeedViaSocks(int socksPort, String endpointUrl, int bytesTo, double timeoutSec) {
        String host = "speed.cloudflare.com";
        String path = "/__down?bytes=" + bytesTo;
        boolean isCloudflare = endpointUrl.contains("speed.cloudflare.com");
        if (!isCloudflare) {
            try {
                URL u = new URL(endpointUrl);
                host = u.getHost();
                path = u.getPath() + (u.getQuery() != null ? "?" + u.getQuery() : "");
            } catch (Exception e) { return 0; }
        }
        Socket socks = null;
        SSLSocket ts = null;
        try {
            socks = new Socket();
            socks.connect(new InetSocketAddress("127.0.0.1", socksPort), 5000);
            socks.setSoTimeout((int) (timeoutSec * 1000) + 2000);
            socksConnect(socks, host, 443);
            SSLSocketFactory f = sslCtx != null ? sslCtx.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
            ts = (SSLSocket) f.createSocket(socks, host, 443, true);
            OutputStream os = ts.getOutputStream();
            String req = "GET " + path + " HTTP/1.1\r\nHost: " + host +
                    "\r\nUser-Agent: " + BROWSER_UA + "\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            os.write(req.getBytes(StandardCharsets.UTF_8));
            os.flush();
            InputStream is = ts.getInputStream();
            // هدر تا \r\n\r\n
            ByteArrayOutputStream hb = new ByteArrayOutputStream();
            int prev = -1, cur;
            while ((cur = is.read()) >= 0) {
                hb.write(cur);
                if (prev == 13 && cur == 10 && hb.size() >= 4) {
                    byte[] arr = hb.toByteArray();
                    if (arr.length >= 4 && arr[arr.length - 4] == 13 && arr[arr.length - 3] == 10) break;
                }
                prev = cur;
            }
            String head = new String(hb.toByteArray(), StandardCharsets.UTF_8);
            int sp = head.indexOf(' ');
            int code = sp >= 0 ? Integer.parseInt(head.substring(sp + 1, sp + 4)) : 999;
            if (code >= 400) return -1;           // اندپوینتِ بعدی
            long total = 0;
            long t0 = System.currentTimeMillis();
            byte[] buf = new byte[65536];
            int n;
            while ((n = is.read(buf)) > 0) {
                total += n;
                if (total >= bytesTo || (System.currentTimeMillis() - t0) > timeoutSec * 1000) break;
            }
            double el = (System.currentTimeMillis() - t0) / 1000.0;
            if (el < 0.15 && total >= bytesTo && bytesTo < 8_388_608) {
                // لینک خیلی سریع — دوباره با حجم بزرگ‌تر
                return dlSpeedRetry(socksPort, host, bytesTo * 4, timeoutSec);
            }
            if (el > 0.05 && total >= 50_000) {
                double mbps = total * 8.0 / el / 1e6;
                if (mbps > gateEndpointSpeed) gateEndpointSpeed = mbps;
                return mbps;
            }
            return 0;
        } catch (Exception e) {
            return 0;
        } finally {
            try { if (ts != null) ts.close(); } catch (Exception ignored) {}
            try { if (socks != null) socks.close(); } catch (Exception ignored) {}
        }
    }

    private double dlSpeedRetry(int socksPort, String host, int bytes, double timeoutSec) {
        Socket socks = null; SSLSocket ts = null;
        try {
            socks = new Socket();
            socks.connect(new InetSocketAddress("127.0.0.1", socksPort), 5000);
            socks.setSoTimeout((int) (timeoutSec * 1000) + 2000);
            socksConnect(socks, host, 443);
            SSLSocketFactory f = sslCtx != null ? sslCtx.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
            ts = (SSLSocket) f.createSocket(socks, host, 443, true);
            OutputStream os = ts.getOutputStream();
            String path = host.equals("speed.cloudflare.com") ? "/__down?bytes=" + bytes : "/100MB.bin";
            os.write(("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + BROWSER_UA +
                    "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            os.flush();
            InputStream is = ts.getInputStream();
            ByteArrayOutputStream hb = new ByteArrayOutputStream();
            int prev = -1, cur;
            while ((cur = is.read()) >= 0) {
                hb.write(cur);
                byte[] arr = hb.toByteArray();
                if (arr.length >= 4 && arr[arr.length - 4] == 13 && arr[arr.length - 3] == 10 &&
                        arr[arr.length - 2] == 13 && arr[arr.length - 1] == 10) break;
                prev = cur;
            }
            String head = new String(hb.toByteArray(), StandardCharsets.UTF_8);
            int sp = head.indexOf(' ');
            int code = sp >= 0 ? Integer.parseInt(head.substring(sp + 1, sp + 4)) : 999;
            if (code >= 400) return 0;
            long total = 0;
            long t0 = System.currentTimeMillis();
            byte[] buf = new byte[65536];
            int n;
            while ((n = is.read(buf)) > 0) {
                total += n;
                if (total >= bytes || (System.currentTimeMillis() - t0) > timeoutSec * 1000) break;
            }
            double el = (System.currentTimeMillis() - t0) / 1000.0;
            if (el > 0.05 && total >= 50_000) return total * 8.0 / el / 1e6;
            return 0;
        } catch (Exception e) {
            return 0;
        } finally {
            try { if (ts != null) ts.close(); } catch (Exception ignored) {}
            try { if (socks != null) socks.close(); } catch (Exception ignored) {}
        }
    }

    /** سرعت آپلود از داخل تونل — POST به speed.cloudflare.com/__up */
    public double uploadSpeedViaSocks(int socksPort, int bytes) {
        Socket socks = null; SSLSocket ts = null;
        try {
            byte[] payload = new byte[bytes];
            rnd.nextBytes(payload);
            socks = new Socket();
            socks.connect(new InetSocketAddress("127.0.0.1", socksPort), 5000);
            socks.setSoTimeout(10000);
            socksConnect(socks, "speed.cloudflare.com", 443);
            SSLSocketFactory f = sslCtx != null ? sslCtx.getSocketFactory() : (SSLSocketFactory) SSLSocketFactory.getDefault();
            ts = (SSLSocket) f.createSocket(socks, "speed.cloudflare.com", 443, true);
            OutputStream os = ts.getOutputStream();
            String head = "POST /__up HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: " + BROWSER_UA +
                    "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + bytes +
                    "\r\nConnection: close\r\n\r\n";
            os.write(head.getBytes(StandardCharsets.UTF_8));
            long t0 = System.currentTimeMillis();
            os.write(payload);
            os.flush();
            InputStream is = ts.getInputStream();
            byte[] b = new byte[4096];
            // ignore body
            while (is.read(b) > 0) { }
            double el = (System.currentTimeMillis() - t0) / 1000.0;
            if (el > 0.05) return bytes * 8.0 / el / 1e6;
            return 0;
        } catch (Exception e) {
            return 0;
        } finally {
            try { if (ts != null) ts.close(); } catch (Exception ignored) {}
            try { if (socks != null) socks.close(); } catch (Exception ignored) {}
        }
    }

    // ============================ تستِ یک نود ============================
    /** پینگ واقعی از داخل تونلِ همین کانفیگ (هر پاسخِ HTTP = زنده) — مثل test_latency ویندوز. */
    public Double testLatency(Subs.Node node) {
        if (stopFlag) return null;
        int port = nextTestPort();
        JSONObject cfg;
        try { cfg = Subs.buildXrayConfig(withResolvedIp(node), port, 0, node.server, node.port); }
        catch (Exception e) { return null; }
        if (cfg == null) return null;
        File tmp = new File(ctx.getCacheDir(), "manjarvpn_lat_" + port + ".json");
        Process proc = null;
        try {
            writeJson(cfg, tmp);
            proc = startXray(tmp.getAbsolutePath(), "lat");
            if (proc == null) return null;
            testProcs.add(proc);
            if (!waitPort(port, XRAY_START_TIMEOUT)) {
                funnel("xray_start_fail", lastXrayErr.isEmpty() ? "هسته بالا نیامد" : lastXrayErr);
                if (!xrayStartFailLogged) {
                    xrayStartFailLogged = true;
                    log("✗ هسته‌ی Xray بالا نیامد" + (lastXrayErr.isEmpty() ? "" : ": " + lastXrayErr));
                }
                return null;
            }
            long t0 = System.currentTimeMillis();
            try {
                int code = httpGetViaSocks(port, "cp.cloudflare.com", "/generate_204", "cp.cloudflare.com",
                        (int) (LATENCY_TIMEOUT * 1000));
                if (code < 500) return (double) (System.currentTimeMillis() - t0);
            } catch (Exception e) {
                if (stopFlag) return null;
            }
            // اندپوینتِ دوم (v1.7)
            try {
                long t1 = System.currentTimeMillis();
                int code = httpsGetViaSocks(port, "www.gstatic.com", "/generate_204",
                        (int) (LATENCY_TIMEOUT * 1000));
                if (code < 500) return (double) (System.currentTimeMillis() - t1);
            } catch (Exception ignored) {}
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            if (proc != null) killProc(proc);
            testProcs.remove(proc);
            try { tmp.delete(); } catch (Exception ignored) {}
        }
    }

    /** سایت‌های واقعی — «باز شدن» یعنی هر پاسخِ HTTP (حتی ۴۰۳/۴۲۹) — مثل check_sites ویندوز. */
    public List<String> checkSites(int socksPort) {
        List<String> opened = new ArrayList<>();
        List<String> detail = new ArrayList<>();
        for (String[] target : Subs.SITE_TARGETS) {
            if (stopFlag) break;
            String name = target[0], url = target[1];
            try {
                URL u = new URL(url);
                boolean https = u.getProtocol().equals("https");
                int port = u.getPort() > 0 ? u.getPort() : (https ? 443 : 80);
                int code;
                long t0 = System.currentTimeMillis();
                if (https) {
                    code = httpsGetViaSocks(socksPort, u.getHost(), u.getPath().isEmpty() ? "/" : u.getPath(),
                            (int) (SITE_TIMEOUT * 1000));
                } else {
                    code = httpGetViaSocks(socksPort, u.getHost(), u.getPath().isEmpty() ? "/" : u.getPath(),
                            u.getHost(), (int) (SITE_TIMEOUT * 1000));
                }
                opened.add(name);
                detail.add(name + "=" + code);
            } catch (Exception e) {
                detail.add(name + "=تایم‌اوت");
            }
        }
        lastSitesDetail = Subs.join("، ", detail);
        return opened;
    }

    private static String hostOf(String url) {
        try { return new URL(url).getHost(); } catch (Exception e) { return url; }
    }

    /** پورتِ deep_test ویندوز: سایت‌ها + سرعتِ پایدار + آپ. */
    public Subs.Node deepTest(Subs.Node node) {
        if (stopFlag) return null;
        int port = nextTestPort();
        JSONObject cfg;
        try { cfg = Subs.buildXrayConfig(withResolvedIp(node), port, 0, node.server, node.port); }
        catch (Exception e) { return null; }
        if (cfg == null) return null;
        File tmp = new File(ctx.getCacheDir(), "manjarvpn_deep_" + port + ".json");
        Process proc = null;
        try {
            writeJson(cfg, tmp);
            proc = startXray(tmp.getAbsolutePath(), "deep");
            if (proc == null) return null;
            testProcs.add(proc);
            if (!waitPort(port, XRAY_START_TIMEOUT)) {
                funnel("xray_start_fail", lastXrayErr.isEmpty() ? "هسته بالا نیامد" : lastXrayErr);
                return null;
            }

            // ۱) سایت‌های واقعی
            List<String> opened = checkSites(port);
            node.extra.put("sites_detail", lastSitesDetail);
            if (stopFlag) return null;
            if (opened.size() < Subs.SITE_MIN_PASS) {
                funnel("site_fail", lastSitesDetail.contains("تایم‌اوت") ? "تایم‌اوتِ سایت" : "سایت‌ها پاسخ ندادند");
                log("✗ رد شد: " + node.display() + " — سایت‌ها: " + (lastSitesDetail.isEmpty() ? "هیچ پاسخی" : lastSitesDetail));
                return null;
            }
            node.extra.put("opened", Subs.join("، ", opened));
            funnel("site_ok");

            // ۲) سرعتِ دانلودِ پایدار — آبشارِ اندپوینت
            double speed = 0, spMomentum = 0;
            String spDetail = "", spReason = "سرعتِ پایدار ثبت نشد";
            for (int i = 0; i < Subs.SPEED_ENDPOINT_ATTEMPTS && i < Subs.SPEED_ENDPOINTS.length; i++) {
                if (stopFlag) break;
                String ep = Subs.SPEED_ENDPOINTS[i];
                double mbps = dlSpeedViaSocks(port, ep, DL_TEST_CAP_BYTES, 6.0);
                if (mbps > 0) {
                    if (mbps > speed) { speed = mbps; spDetail = String.format(java.util.Locale.US, "%.1f Mbps (%s)", mbps, hostOf(ep)); }
                    if (speed >= 0.1) break;
                } else if (mbps < 0) {
                    spDetail = "اندپوینت ≥۴۰۰ (" + hostOf(ep) + ")";
                    spReason = "اندپوینت 403/429";
                } else {
                    spDetail = "دانلود ناقص (" + hostOf(ep) + ")";
                    spReason = "تایم‌اوت/ناقص";
                }
            }
            node.speed = speed;
            node.extra.put("speed_detail", spDetail);

            // ۳) نودِ «فقط‌پینگی» → رد
            if (speed < MIN_USABLE_SPEED_MBPS) {
                funnel("speed_fail", spReason);
                node.extra.put("dead_data", "1");
                log("✗ رد شد: " + node.display() + " — سایت‌ها باز شدند ولی سرعتِ پایدار " +
                        String.format(java.util.Locale.US, "%.1f", speed) + " Mbps است (" + spDetail + ") — فقط‌پینگی");
                return null;
            }
            node.extra.put("verified", "1");
            funnel("speed_ok");

            // ۴) آپلود واقعی از داخل همان تونل
            if (!stopFlag) node.upSpeed = uploadSpeedViaSocks(port, UPLOAD_PROBE_BYTES);
            return node;
        } catch (Exception e) {
            return null;
        } finally {
            if (proc != null) killProc(proc);
            testProcs.remove(proc);
            try { tmp.delete(); } catch (Exception ignored) {}
        }
    }

    // ============================ دریافتِ منابع ============================
    public List<Subs.Node> fetchAll() {
        int total = Subs.SUBSCRIPTION_SOURCES.length;
        Map<Integer, List<String>> byIndex = new HashMap<>();
        AtomicInteger done = new AtomicInteger();
        ExecutorService ex = Executors.newFixedThreadPool(10);
        for (int i = 0; i < total; i++) {
            final int idx = i;
            final String src = Subs.SUBSCRIPTION_SOURCES[i];
            ex.submit(() -> {
                if (stopFlag) return;
                String text = fetchUrl(src);
                int d = done.incrementAndGet();
                if (text == null) {
                    log("✗ منبع در دسترس نبود: " + src);
                } else {
                    List<String> got = Subs.decodeSubscription(text);
                    byIndex.put(idx, got);
                    log("✓ منبع " + (idx + 1) + "/" + total + ": " + got.size() + " کانفیگ");
                }
                progress("fetch", d, total, "دریافت " + d + "/" + total + " منبع …");
            });
        }
        ex.shutdown();
        try { ex.awaitTermination(90, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        List<String> uris = new ArrayList<>();
        for (int i : new java.util.TreeSet<>(byIndex.keySet())) uris.addAll(byIndex.get(i));
        List<Subs.Node> parsed = new ArrayList<>();
        for (String u : uris) {
            if (stopFlag) break;
            Subs.Node n = Subs.parseUri(u);
            if (n != null) parsed.add(n);
        }
        return Subs.dedupeNodes(parsed, 8000);
    }

    // ============================ پیش‌فیلتر TCP ============================
    /**
     * اتصال TCP به سرور — و مهم‌تر: دی‌ان‌اس را همین‌جا در جاوا حل می‌کنیم (کارتِ سیستم،
     * مطمئن) و آی‌پی را در extra["ip"] نگه می‌داریم تا کانفیگِ Xray با آی‌پی ساخته شود
     * و وابسته‌ی دی‌ان‌اسِ داخلِ زیرپروسه‌ی هسته نباشد. خروجی: آی‌پی یا null.
     */
    private String tcpAliveResolve(String server, int port) {
        String pick = null;
        try {
            InetAddress[] all = InetAddress.getAllByName(server);
            for (InetAddress a : all) if (a instanceof Inet4Address) { pick = a.getHostAddress(); break; }
            if (pick == null && all.length > 0) pick = all[0].getHostAddress();
        } catch (Exception e) {
            pick = server;   // شاید هاستِ واقعی مستقیم کار کند — به پیش‌فیلتر سپرده می‌شود
        }
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(pick, port), (int) (TCP_PREFILTER_TIMEOUT * 1000));
            return pick;
        } catch (Exception e) {
            return null;
        }
    }

    public List<Subs.Node> tcpPrefilter(List<Subs.Node> nodes) {
        List<Subs.Node> alive = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger done = new AtomicInteger();
        int total = nodes.size();
        ExecutorService ex = Executors.newFixedThreadPool(TCP_PREFILTER_WORKERS);
        for (Subs.Node n : nodes) {
            ex.submit(() -> {
                if (stopFlag) return;
                String ip = tcpAliveResolve(n.server, n.port);
                if (ip != null) { n.extra.put("ip", ip); alive.add(n); }
                int d = done.incrementAndGet();
                if (d % 50 == 0 || d == total)
                    progress("tcp", d, total, "پیش‌فیلتر سرورها " + d + "/" + total + " — " + alive.size() + " سرور زنده");
            });
        }
        ex.shutdown();
        try { ex.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        return new ArrayList<>(alive);
    }

    // ============================ اسکن کامل ============================
    /**
     * کپیِ نود با آی‌پیِ حل‌شده (extra["ip"]) به‌جای دامنه در فیلدِ اتصالِ خروجیِ Xray —
     * SNI/Host/Reality همان دامنه‌ی اصلی می‌مانند. اگر آی‌پی نبود، همان نود برمی‌گردد.
     */
    private Subs.Node withResolvedIp(Subs.Node n) {
        String ip = n.extra.get("ip");
        if (ip == null || ip.isEmpty() || ip.equals(n.server)) return n;
        Subs.Node c = new Subs.Node(n.proto, n.name, ip, n.port);
        c.uri = n.uri; c.latency = n.latency; c.speed = n.speed; c.upSpeed = n.upSpeed;
        c.extra.putAll(n.extra);
        if (c.extra.get("sni") == null || c.extra.get("sni").isEmpty()) c.extra.put("sni", n.server);
        return c;
    }

    public Subs.Node scan(List<Subs.Node> nodesIn) {
        scanStats.clear();
        reasonsMap.clear();
        xrayStartFailLogged = false;
        scanStats.put("fetched", nodesIn.size());
        List<Subs.Node> nodes = nodesIn;
        // کانفیگ‌های شخصی هرگز حذف نمی‌شوند
        List<Subs.Node> mine = new ArrayList<>();
        for (Subs.Node n : nodes) if ("1".equals(n.extra.get("my"))) mine.add(n);
        if (nodes.size() > MAX_TEST_NODES) {
            List<Subs.Node> keep = new ArrayList<>(mine.subList(0, Math.min(20, mine.size())));
            List<Subs.Node> rest = new ArrayList<>();
            for (Subs.Node n : nodes) if (!"1".equals(n.extra.get("my"))) rest.add(n);
            Collections.shuffle(rest, rnd);
            nodes = new ArrayList<>(keep);
            nodes.addAll(rest.subList(0, Math.max(0, MAX_TEST_NODES - keep.size())));
            log("→ نمونه‌گیری تصادفی: بررسی " + nodes.size() + " کانفیگ" +
                    (keep.isEmpty() ? "" : " (شامل " + keep.size() + " کانفیگِ شخصی)"));
        }

        List<Subs.Node> alive = tcpPrefilter(nodes);
        scanStats.put("tcp_alive", alive.size());
        if (stopFlag) return null;
        log("⚡ پیش‌فیلتر: " + alive.size() + " سرور از " + nodes.size() + " زنده — شروع تست پینگ");
        if (alive.size() > MAX_XRAY_LATENCY_TESTS) {
            Collections.shuffle(alive, rnd);
            alive = alive.subList(0, MAX_XRAY_LATENCY_TESTS);
        }

        List<Subs.Node> latOk = latencyPass(alive);
        if (stopFlag) return null;
        latOk.sort((a, b) -> Double.compare(a.latency, b.latency));
        scanStats.put("latency_ok", latOk.size());
        log("✓ پینگ تمام شد: " + latOk.size() + " کانفیگ سالم از " + alive.size());

        // تست عمیق تا ۳ دور
        List<Subs.Node> verified = new ArrayList<>();
        int poolStart = 0;
        for (int round = 0; round < DEEP_ROUNDS; round++) {
            if (stopFlag) break;
            int end = Math.min(poolStart + DEEP_POOL, latOk.size());
            if (poolStart >= end) break;
            List<Subs.Node> pool = new ArrayList<>(latOk.subList(poolStart, end));
            if (round > 0)
                log("↻ دور " + (round + 1) + ": " + pool.size() + " کاندیدِ بعدی هم تست عمیق می‌شوند…");
            verified.addAll(deepPoolTest(pool, DEEP_TARGET));
            if (!verified.isEmpty()) break;
            poolStart += DEEP_POOL;
        }
        scanStats.put("verified", verified.size());
        if (stopFlag) return null;
        if (!verified.isEmpty())
            log("✓ " + verified.size() + " کاندید سایت‌ها را باز کردند — بهترین از نظر سرعت انتخاب می‌شود");
        else
            log("⚠ هیچ کاندیدی سایت‌ها را باز نکرد — روش قدیمی (تست سرعت ساده) ادامه می‌دهد");

        Subs.Node best = null;
        if (!verified.isEmpty()) {
            List<Subs.Node> fast = new ArrayList<>(), usable = new ArrayList<>();
            for (Subs.Node n : verified) {
                if (n.speed >= MIN_GOOD_SPEED_MBPS) fast.add(n);
                else if (n.speed >= MIN_USABLE_SPEED_MBPS) usable.add(n);
            }
            scanStats.put("usable", usable.size());
            if (!fast.isEmpty()) {
                best = maxBySpeed(fast);
                log("✓ انتخاب شد: " + best.display() + " — دانِ پایدار " +
                        String.format(java.util.Locale.US, "%.1f", best.speed) + " • آپ " +
                        String.format(java.util.Locale.US, "%.1f", best.upSpeed) + " Mbps — پینگ " +
                        (int) (double) best.latency + "ms");
            } else if (!usable.isEmpty()) {
                best = maxBySpeed(usable);
                log("⚠ هیچ کاندیدِ سریعی نبود — بهترینِ قابل‌استفاده انتخاب شد: " +
                        best.display() + " (" + String.format(java.util.Locale.US, "%.1f", best.speed) + " Mbps)");
            }
        }

        if (best == null) {
            // همان مسیر قدیمی: تست سرعت ساده روی بهترین‌های پینگ
            List<Subs.Node> top = new ArrayList<>(latOk.subList(0, Math.min(TOP_SPEED_TESTS, latOk.size())));
            List<Subs.Node> rest = latOk.size() > TOP_SPEED_TESTS
                    ? new ArrayList<>(latOk.subList(TOP_SPEED_TESTS, latOk.size())) : new ArrayList<>();
            if (!rest.isEmpty()) {
                Collections.shuffle(rest, rnd);
                top.addAll(rest.subList(0, Math.min(EXTRA_SPEED_SAMPLES, rest.size())));
            }
            if (!top.isEmpty()) {
                AtomicInteger sdone = new AtomicInteger();
                ExecutorService ex = Executors.newFixedThreadPool(CONCURRENT_SPEED_TESTS);
                for (Subs.Node n : top) {
                    ex.submit(() -> {
                        if (stopFlag) return;
                        double sp = simpleSpeedTest(n);
                        n.speed = sp;
                        int d = sdone.incrementAndGet();
                        progress("speed", d, top.size(), "تست سرعت " + d + "/" + top.size() +
                                " — " + n.display() + " (" + String.format(java.util.Locale.US, "%.1f", sp) + " Mbps)");
                    });
                }
                ex.shutdown();
                try { ex.awaitTermination(180, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
                List<Subs.Node> sorted = new ArrayList<>(top);
                sorted.sort((a, b) -> Double.compare(b.speed, a.speed));
                for (Subs.Node n : sorted)
                    log("   " + n.display() + " — پینگ " + (int) (double) n.latency + "ms — سرعت " +
                            String.format(java.util.Locale.US, "%.1f", n.speed) + " Mbps");
                List<Subs.Node> fast = new ArrayList<>(), usable = new ArrayList<>();
                for (Subs.Node n : top) {
                    if (n.speed >= MIN_GOOD_SPEED_MBPS) fast.add(n);
                    else if (n.speed >= MIN_USABLE_SPEED_MBPS) usable.add(n);
                }
                if (scanStats.get("usable") == null) scanStats.put("usable", usable.size());
                if (!fast.isEmpty()) best = maxBySpeed(fast);
                else if (!usable.isEmpty()) {
                    best = maxBySpeed(usable);
                    log("⚠ بهترینِ قابل‌استفاده (سرعت پایین): " + best.display() + " — " +
                            String.format(java.util.Locale.US, "%.1f", best.speed) + " Mbps");
                }
            }
        }

        if (best == null && !latOk.isEmpty() && !stopFlag) {
            // حالتِ اضطراری — مثل v1.7
            best = latOk.get(0); // کم‌پینگ‌ترین (لیست مرتب است)
            best.extra.put("emergency", "1");
            log("⚠ حالت اضطراری: هیچ کاندیدی سرعتِ تأییدشده نداشت — اتصال به کم‌پینگ‌ترینِ " +
                    "سالم‌ها: " + best.display() + " (پینگ " + (int) (double) best.latency + "ms)");
            log("  اگر سرعت عملاً صفر باشد، نگهبانِ برنامه خودش سرور را عوض می‌کند.");
        }

        // گزارشِ قیف
        StringBuilder rs = new StringBuilder();
        List<Map.Entry<String, Integer>> rl = new ArrayList<>(reasonsMap.entrySet());
        rl.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        for (int i = 0; i < Math.min(5, rl.size()); i++) {
            if (rs.length() > 0) rs.append("، ");
            rs.append(rl.get(i).getKey()).append("=").append(rl.get(i).getValue());
        }
        log("📊 قیف تست: دریافت " + scanStats.get("fetched") + " ← زنده " + scanStats.get("tcp_alive") +
                " ← پینگ " + scanStats.get("latency_ok") + " ← سایت " + scanStats.get("site_ok") +
                " ← سرعتِ تأیید " + scanStats.get("verified") +
                (rs.length() > 0 ? " — دلایلِ رد: " + rs : ""));

        if (best == null) log("✗ حتی یک تونلِ پاسخ‌گو هم نبود — اتصال انجام نمی‌شود");
        return best;
    }

    private Subs.Node maxBySpeed(List<Subs.Node> list) {
        Subs.Node best = null;
        for (Subs.Node n : list) {
            if (best == null) { best = n; continue; }
            double a = n.speed, b = best.speed;
            double la = n.latency == null ? 9e9 : n.latency, lb = best.latency == null ? 9e9 : best.latency;
            if (a > b || (a == b && la < lb)) best = n;
        }
        return best;
    }

    private double simpleSpeedTest(Subs.Node node) {
        int port = nextTestPort();
        JSONObject cfg;
        try { cfg = Subs.buildXrayConfig(withResolvedIp(node), port, 0, node.server, node.port); }
        catch (Exception e) { return 0; }
        if (cfg == null) return 0;
        File tmp = new File(ctx.getCacheDir(), "manjarvpn_sp_" + port + ".json");
        Process proc = null;
        try {
            writeJson(cfg, tmp);
            proc = startXray(tmp.getAbsolutePath(), "sp");
            if (proc == null) return 0;
            testProcs.add(proc);
            if (!waitPort(port, XRAY_START_TIMEOUT)) {
                funnel("xray_start_fail", lastXrayErr.isEmpty() ? "هسته بالا نیامد" : lastXrayErr);
                return 0;
            }
            double v = dlSpeedViaSocks(port, Subs.SPEED_ENDPOINTS[0], DL_TEST_CAP_BYTES, 8.0);
            return Math.max(0, v);
        } catch (Exception e) {
            return 0;
        } finally {
            if (proc != null) killProc(proc);
            testProcs.remove(proc);
            try { tmp.delete(); } catch (Exception ignored) {}
        }
    }

    private List<Subs.Node> latencyPass(List<Subs.Node> pool) { return latencyPass(pool, 0); }

    private List<Subs.Node> latencyPass(List<Subs.Node> pool, int depth) {
        List<Subs.Node> okList = Collections.synchronizedList(new ArrayList<>());
        List<Subs.Node> failList = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger done = new AtomicInteger();
        ExecutorService ex = Executors.newFixedThreadPool(CONCURRENT_TESTS);
        for (Subs.Node n : pool) {
            ex.submit(() -> {
                if (stopFlag) return;
                Double r = testLatency(n);
                int d = done.incrementAndGet();
                if (r != null) {
                    n.latency = r;
                    okList.add(n);
                } else failList.add(n);
                if (d % 10 == 0 || d == pool.size())
                    progress("latency", d, pool.size(), "تست پینگ " + d + "/" + pool.size() + " — " + okList.size() + " کانفیگ سالم");
            });
        }
        ex.shutdown();
        try { ex.awaitTermination(600, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        // v1.7: ردها یک بار دیگر امتحان می‌شوند (فقط یک‌بار — نه بازگشتی)
        if (!failList.isEmpty() && failList.size() <= LATENCY_RETRY_MAX && !stopFlag && depth == 0) {
            log("↻ " + failList.size() + " کانفیگِ ردشده یک بار دیگر امتحان می‌شوند…");
            List<Subs.Node> ok2 = latencyPass(failList, 1);
            okList.addAll(ok2);
            scanStats.put("latency_retry_ok", ok2.size());
        }
        return new ArrayList<>(okList);
    }

    private List<Subs.Node> deepPoolTest(List<Subs.Node> pool, int target) {
        List<Subs.Node> verified = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger done = new AtomicInteger();
        ExecutorService ex = Executors.newFixedThreadPool(DEEP_WORKERS);
        for (Subs.Node n : pool) {
            ex.submit(() -> {
                if (stopFlag) return;
                Subs.Node r = deepTest(n);
                int d = done.incrementAndGet();
                if (r != null) {
                    verified.add(r);
                    log("✓ تست کامل: " + r.display() + " — پینگ " + (int) (double) r.latency + "ms • دان " +
                            String.format(java.util.Locale.US, "%.1f", r.speed) + " • آپ " +
                            String.format(java.util.Locale.US, "%.1f", r.upSpeed) + " Mbps • باز شد: " +
                            r.extra.get("opened"));
                }
                progress("deep", d, pool.size(), "تست عمیق کاندیدها " + d + "/" + pool.size() + " — " +
                        verified.size() + " تایید شد");
            });
        }
        ex.shutdown();
        try { ex.awaitTermination(900, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        List<Subs.Node> out = new ArrayList<>(verified);
        Map<String, Integer> order = new HashMap<>();
        for (int i = 0; i < pool.size(); i++) order.put(pool.get(i).key(), i);
        out.sort((a, b) -> Integer.compare(order.getOrDefault(a.key(), 1_000_000_000),
                order.getOrDefault(b.key(), 1_000_000_000)));
        return out;
    }

    // ============================ حافظه‌ی سرورهای خوب ============================
    private List<JSONObject> loadCache() {
        List<JSONObject> out = new ArrayList<>();
        try {
            String s = ctx.getSharedPreferences("manjar_engine", Context.MODE_PRIVATE)
                    .getString("known_good", null);
            if (s == null) return out;
            JSONArray arr = new JSONArray(s);
            long cutoff = System.currentTimeMillis() - Subs.CACHE_TTL_DAYS * 86400_000L;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject e = arr.optJSONObject(i);
                if (e != null && e.optString("uri", "").length() > 0 && e.optLong("ts", 0) >= cutoff)
                    out.add(e);
            }
        } catch (Exception ignored) {}
        return out;
    }

    public void updateCache(Subs.Node best, List<Subs.Node> runners) {
        try {
            Map<String, JSONObject> byUri = new HashMap<>();
            for (JSONObject e : loadCache()) byUri.put(e.optString("uri"), e);
            List<Subs.Node> all = new ArrayList<>();
            if (best != null) all.add(best);
            if (runners != null) for (int i = 0; i < Math.min(5, runners.size()); i++) all.add(runners.get(i));
            for (Subs.Node n : all) {
                if (n == null || "1".equals(n.extra.get("ai"))) continue;
                if (n.uri == null || n.uri.isEmpty() || n.speed <= 0) continue;
                JSONObject e = new JSONObject();
                e.put("uri", n.uri);
                e.put("latency", (int) (double) (n.latency == null ? 0 : n.latency));
                e.put("speed", Math.round(n.speed * 100.0) / 100.0);
                e.put("up_speed", Math.round(n.upSpeed * 100.0) / 100.0);
                e.put("verified", "1".equals(n.extra.get("verified")));
                e.put("ts", System.currentTimeMillis());
                byUri.put(n.uri, e);
            }
            List<JSONObject> entries = new ArrayList<>(byUri.values());
            entries.sort((a, b) -> Double.compare(b.optDouble("speed", 0), a.optDouble("speed", 0)));
            while (entries.size() > Subs.CACHE_MAX) entries.remove(entries.size() - 1);
            JSONArray arr = new JSONArray();
            for (JSONObject e : entries) arr.put(e);
            ctx.getSharedPreferences("manjar_engine", Context.MODE_PRIVATE)
                    .edit().putString("known_good", arr.toString()).apply();
        } catch (Exception ignored) {}
    }

    // ============================ نجات هوش مصنوعی ============================
    private String aiAsk(String prompt) {
        for (String model : new String[]{Subs.POLLINATIONS_MODEL, "openai"}) {
            if (stopFlag) return null;
            try {
                URL u = new URL(Subs.POLLINATIONS_URL);
                HttpURLConnection c = (HttpURLConnection) u.openConnection();
                c.setRequestMethod("POST");
                c.setConnectTimeout(10000);
                c.setReadTimeout(Subs.AI_RESCUE_TIMEOUT_MS);
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                JSONObject body = new JSONObject();
                body.put("messages", new JSONArray().put(
                        new JSONObject().put("role", "user").put("content", prompt)));
                body.put("model", model);
                body.put("referrer", Subs.APP_NAME);
                body.put("seed", rnd.nextInt(1_000_000) + 1);
                if (model.equals(Subs.POLLINATIONS_MODEL)) body.put("reasoning_effort", "low");
                OutputStream os = c.getOutputStream();
                os.write(body.toString().getBytes(StandardCharsets.UTF_8));
                os.close();
                int code = c.getResponseCode();
                if (code < 400) {
                    InputStream is = code < 400 ? c.getInputStream() : c.getErrorStream();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while (is != null && (n = is.read(buf)) > 0) bos.write(buf, 0, n);
                    if (is != null) is.close();
                    String text = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                    if (!text.trim().isEmpty()) {
                        log("🤖 پاسخ از هوش مصنوعی رایگان گرفته شد (مدل: " + model + ")");
                        return text;
                    }
                } else {
                    String msg = "";
                    try {
                        InputStream es = c.getErrorStream();
                        if (es != null) {
                            ByteArrayOutputStream bos = new ByteArrayOutputStream();
                            byte[] buf = new byte[4096];
                            int n;
                            while ((n = es.read(buf)) > 0) bos.write(buf, 0, n);
                            es.close();
                            msg = new String(bos.toByteArray(), StandardCharsets.UTF_8);
                            try { msg = new JSONObject(msg).optJSONObject("error").optString("message"); }
                            catch (Exception ignored) { if (msg.length() > 120) msg = msg.substring(0, 120); }
                        }
                    } catch (Exception ignored) {}
                    log("✗ هوش مصنوعی رایگان (" + model + ") خطا " + code + ": " + msg);
                }
                c.disconnect();
            } catch (Exception ignored) {}
        }
        return null;
    }

    public List<Subs.Node> aiRescue(int fetched, int tcpAlive, int latencyOk, int verified,
                                    int usable, Set<String> existingKeys) {
        List<Subs.Node> allNodes = new ArrayList<>();
        for (int round = 0; round < Subs.AI_RESCUE_MAX_ROUNDS; round++) {
            if (stopFlag) break;
            if (round > 0) {
                log("⏳ " + Subs.AI_FREE_RETRY_WAIT + " ثانیه صبر (محدودیتِ سرویس رایگان: ۱ پاسخ در ۴۵ ثانیه)…");
                long end = System.currentTimeMillis() + Subs.AI_FREE_RETRY_WAIT * 1000L;
                while (System.currentTimeMillis() < end && !stopFlag) {
                    try { Thread.sleep(300); } catch (Exception ignored) {}
                }
                if (stopFlag) break;
            }
            String prompt = Subs.buildRescuePrompt(fetched, tcpAlive, latencyOk, verified, usable,
                    reasonsMap, round);
            log("🤖 درخواست کانفیگ تازه از هوش مصنوعی (دور " + (round + 1) + "/" + Subs.AI_RESCUE_MAX_ROUNDS + ")…");
            String text = aiAsk(prompt);
            if (stopFlag) break;
            if (text == null || text.isEmpty()) { log("✗ هوش مصنوعی پاسخ نداد"); continue; }
            List<String>[] ex = Subs.extractUrisFromAi(text);
            log("🤖 در پاسخ: " + ex[0].size() + " کانفیگ + " + ex[1].size() + " لینک اشتراک");
            List<Subs.Node> fresh = new ArrayList<>();
            for (String u : ex[0]) {
                Subs.Node n = Subs.parseUri(u);
                if (n != null && !existingKeys.contains(n.key())) {
                    n.extra.put("ai", "1");
                    if (!n.name.startsWith("🤖")) n.name = "🤖 " + n.name;
                    fresh.add(n);
                }
            }
            for (String su : ex[1]) {
                String txt = fetchUrl(su);
                if (txt == null) continue;
                List<String> got = Subs.decodeSubscription(txt);
                if (got.size() > 200) got = got.subList(0, 200);
                log("🤖 لینک اشتراک: " + got.size() + " کانفیگ");
                for (String u2 : got) {
                    Subs.Node n2 = Subs.parseUri(u2);
                    if (n2 != null && !existingKeys.contains(n2.key())) {
                        n2.extra.put("ai", "1");
                        if (!n2.name.startsWith("🤖")) n2.name = "🤖 کانفیگ تازه";
                        fresh.add(n2);
                    }
                }
            }
            allNodes.addAll(fresh);
            if (!allNodes.isEmpty()) break;
        }
        List<Subs.Node> uniq = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Subs.Node n : allNodes) {
            if (seen.contains(n.key())) continue;
            seen.add(n.key());
            uniq.add(n);
            if (uniq.size() >= Subs.AI_RESCUE_MAX_URIS) break;
        }
        return uniq;
    }

    // ============================ مسیرهای اتصال ============================
    public void cancelAll() {
        stopFlag = true;
        synchronized (testProcs) {
            for (Process p : new ArrayList<>(testProcs)) killProc(p);
            testProcs.clear();
        }
    }

    /** جریانِ اصلی «اتصال خودکار» — در تردِ پس‌زمینه اجرا می‌شود. */
    public void connectAutoFlow() {
        Thread t = new Thread(() -> {
            try {
                synchronized (connLock) {
                    stopFlag = false;
                    abortRepair.set(false);
                    busy = true;
                    ev("busy", null, null);
                    status("در حال بررسی اینترنت…", "amber");
                    if (!checkInternet()) {
                        errorAndIdle("اتصال اینترنت پیدا نشد! وای‌فای یا دیتا را چک کنید.");
                        return;
                    }
                    log("✓ اینترنت برقرار (پینگ مستقیم " + lastDirectLatency + "ms)");

                    // مسیر سریع
                    Subs.Node best = quickConnectCheck();
                    if (stopFlag) { idle(); return; }
                    if (best != null) {
                        List<Subs.Node> others = new ArrayList<>();
                        for (Subs.Node n : new ArrayList<>(topNodes))
                            if (!n.key().equals(best.key())) others.add(n);
                        Subs.Node actual = connectWithFallback(best, others);
                        if (actual != null) return;   // connected event زده شد
                        if (stopFlag) { idle(); return; }
                    }

                    // مسیر کامل
                    List<Subs.Node> myNodes = loadMyConfigs();
                    if (!myNodes.isEmpty())
                        log("★ " + myNodes.size() + " کانفیگ شخصی از my_configs.txt — اول این‌ها تست می‌شوند");
                    status("دریافت کانفیگ‌های رایگان دنیا…", "amber");
                    List<Subs.Node> nodes = fetchAll();
                    if (stopFlag) { idle(); return; }
                    nodes.addAll(0, myNodes);
                    if (nodes.isEmpty()) {
                        errorAndIdle("هیچ کانفیگی دریافت نشد — کمی بعد دوباره تلاش کنید.");
                        return;
                    }
                    log("✓ " + nodes.size() + " کانفیگ یکتا از " + Subs.SUBSCRIPTION_SOURCES.length +
                            " منبع — پینگ ← یوتوب/اینستاگرام/تلگرام ← سرعت دانلود/آپلود");
                    best = scan(nodes);
                    if (stopFlag) { idle(); return; }
                    if (best == null) {
                        // نجات هوش مصنوعی — فقط با سوییچِ کاربر
                        if (aiRescueOn && aiRescueUsed < 2) {
                            aiRescueUsed++;
                            status("هیچ سروری جواب نداد — کانفیگ تازه از هوش مصنوعی…", "amber");
                            Set<String> keys = new LinkedHashSet<>();
                            for (Subs.Node n : nodes) keys.add(n.key());
                            List<Subs.Node> aiNodes = aiRescue(
                                    or(scanStats.get("fetched"), nodes.size()),
                                    or(scanStats.get("tcp_alive"), 0),
                                    or(scanStats.get("latency_ok"), 0),
                                    or(scanStats.get("verified"), 0),
                                    or(scanStats.get("usable"), 0), keys);
                            if (stopFlag) { idle(); return; }
                            if (!aiNodes.isEmpty()) {
                                log("🤖 " + aiNodes.size() + " کانفیگ تازه گرفتم — تست کامل (پینگ ← سایت‌ها ← سرعت)…");
                                Subs.Node best2 = scan(aiNodes);
                                if (stopFlag) { idle(); return; }
                                if (best2 != null) {
                                    Subs.Node actual = connectWithFallback(best2, new ArrayList<>(topNodes));
                                    if (actual != null) return;
                                    if (stopFlag) { idle(); return; }
                                }
                            }
                            log("✗ کانفیگ‌های هوش مصنوعی هم جواب نداد");
                        }
                        errorAndIdle(null);
                        return;
                    }
                    Subs.Node actual = connectWithFallback(best, new ArrayList<>(topNodes));
                    if (actual == null && !stopFlag) errorAndIdle(null);
                }
            } catch (Exception e) {
                if (!stopFlag) errorAndIdle("خطا: " + e.getClass().getSimpleName());
            } finally {
                busy = false;
            }
        }, "manjar-flow");
        t.setDaemon(true);
        t.start();
    }

    private static int or(Integer v, int def) { return v == null ? def : v; }

    public void connectNodeFlow(Subs.Node node) {
        Thread t = new Thread(() -> {
            try {
                synchronized (connLock) {
                    stopFlag = false;
                    abortRepair.set(false);
                    busy = true;
                    ev("busy", null, null);
                    status("اتصال به " + node.display() + "…", "amber");
                    Subs.Node actual = connectWithFallback(node, new ArrayList<>(topNodes));
                    if (actual == null && !stopFlag) errorAndIdle(null);
                }
            } catch (Exception e) {
                if (!stopFlag) errorAndIdle("خطا: " + e.getClass().getSimpleName());
            } finally {
                busy = false;
            }
        }, "manjar-node");
        t.setDaemon(true);
        t.start();
    }

    public void connectCustomFlow(String text) {
        Thread t = new Thread(() -> {
            try {
                synchronized (connLock) {
                    stopFlag = false;
                    abortRepair.set(false);
                    busy = true;
                    ev("busy", null, null);
                    status("بررسی کانفیگ دستی…", "amber");
                    List<Subs.Node> nodes = new ArrayList<>();
                    for (String line : text.split("\n")) {
                        String l = line.trim();
                        if (l.isEmpty()) continue;
                        if (l.startsWith("http://") || l.startsWith("https://")) {
                            String txt = fetchUrl(l);
                            if (txt != null)
                                for (String u : Subs.decodeSubscription(txt)) {
                                    Subs.Node n = Subs.parseUri(u);
                                    if (n != null) nodes.add(n);
                                }
                        } else {
                            Subs.Node n = Subs.parseUri(l);
                            if (n != null) { n.extra.put("my", "1"); nodes.add(n); }
                        }
                    }
                    nodes = Subs.dedupeNodes(nodes, 150);
                    if (nodes.isEmpty()) {
                        errorAndIdle("کانفیگ معتبری پیدا نشد — لینک را چک کنید.");
                        return;
                    }
                    log("✓ " + nodes.size() + " کانفیگ دستی دریافت شد — تست…");
                    Subs.Node best = scan(nodes);
                    if (stopFlag) { idle(); return; }
                    if (best == null) {
                        errorAndIdle("این کانفیگ‌ها جواب ندادند.");
                        return;
                    }
                    Subs.Node actual = connectWithFallback(best, new ArrayList<>(topNodes));
                    if (actual == null && !stopFlag) errorAndIdle(null);
                }
            } catch (Exception e) {
                if (!stopFlag) errorAndIdle("خطا: " + e.getClass().getSimpleName());
            } finally {
                busy = false;
            }
        }, "manjar-custom");
        t.setDaemon(true);
        t.start();
    }

    /** کانفیگ‌های شخصی — فایل my_configs.txt در حافظه‌ی برنامه. */
    public List<Subs.Node> loadMyConfigs() {
        try {
            File f = new File(ctx.getFilesDir(), "my_configs.txt");
            if (!f.exists()) return new ArrayList<>();
            byte[] b = new byte[(int) Math.min(f.length(), 512 * 1024)];
            java.io.FileInputStream fis = new java.io.FileInputStream(f);
            int got = fis.read(b);
            fis.close();
            if (got <= 0) return new ArrayList<>();
            List<Subs.Node> out = new ArrayList<>();
            int count = 0;
            for (String l : new String(b, 0, got, StandardCharsets.UTF_8).split("\n")) {
                String t = l.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                if (t.startsWith("http://") || t.startsWith("https://")) {
                    String txt = fetchUrl(t);
                    if (txt != null)
                        for (String u : Subs.decodeSubscription(txt)) {
                            Subs.Node n = Subs.parseUri(u);
                            if (n != null) { n.extra.put("my", "1"); out.add(n); }
                            if (out.size() >= 100) break;
                        }
                } else {
                    Subs.Node n = Subs.parseUri(t);
                    if (n != null) { n.extra.put("my", "1"); out.add(n); }
                }
                if (++count >= 100) break;
            }
            return out;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private Subs.Node quickConnectCheck() {
        List<JSONObject> entries = loadCache();
        if (entries.isEmpty()) return null;
        List<Subs.Node> nodes = new ArrayList<>();
        for (JSONObject e : entries) {
            Subs.Node n = Subs.parseUri(e.optString("uri"));
            if (n != null) {
                n.speed = e.optDouble("speed", 0);
                n.upSpeed = e.optDouble("up_speed", 0);
                if (e.optBoolean("verified")) n.extra.put("verified", "1");
                nodes.add(n);
            }
        }
        if (nodes.isEmpty()) return null;
        log("⚡ " + nodes.size() + " سرور خوب قبلی در حافظه — تست سریع…");
        List<Subs.Node> alive = tcpPrefilter(nodes);
        if (stopFlag || alive.isEmpty()) return null;
        List<Subs.Node> latOk = Collections.synchronizedList(new ArrayList<>());
        ExecutorService ex = Executors.newFixedThreadPool(Math.min(20, CONCURRENT_TESTS + 6));
        for (Subs.Node n : alive) {
            ex.submit(() -> {
                if (stopFlag) return;
                Double r = testLatency(n);
                if (r != null) { n.latency = r; latOk.add(n); }
            });
        }
        ex.shutdown();
        try { ex.awaitTermination(240, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        if (stopFlag || latOk.isEmpty()) return null;
        latOk.sort((a, b) -> Double.compare(a.latency, b.latency));
        List<Subs.Node> top = latOk.subList(0, Math.min(3, latOk.size()));
        ExecutorService dex = Executors.newFixedThreadPool(3);
        for (Subs.Node n : new ArrayList<>(top)) {
            dex.submit(() -> { if (!stopFlag) deepTest(n); });
        }
        dex.shutdown();
        try { dex.awaitTermination(600, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception ignored) {}
        if (stopFlag) return null;
        List<Subs.Node> ok = new ArrayList<>();
        for (Subs.Node n : top)
            if ("1".equals(n.extra.get("verified")) && n.speed >= Subs.QUICK_MIN_SPEED_MBPS) ok.add(n);
        if (!ok.isEmpty()) {
            Subs.Node best = ok.get(0);
            for (Subs.Node n : ok)
                if (n.speed > best.speed ||
                        (n.speed == best.speed && (n.latency != null && best.latency != null && n.latency < best.latency)))
                    best = n;
            log("★ بهترین حافظه: " + best.display() + " — دان " +
                    String.format(java.util.Locale.US, "%.1f", best.speed) + " • آپ " +
                    String.format(java.util.Locale.US, "%.1f", best.upSpeed) + " Mbps • " +
                    best.extra.get("opened"));
            // topNodes برای پنل سرورها
            List<Subs.Node> ranked = new ArrayList<>(latOk);
            rankVerifiedFirst(ranked);
            topNodes.clear();
            topNodes.addAll(ranked.subList(0, Math.min(12, ranked.size())));
            ev("topnodes", "nodes", nodesToJson(topNodes));
            return best;
        }
        // حافظه جواب نداد → این لیست برای پنل سرورها به‌عنوان شناخته‌شده‌ها ثبت شود
        List<Subs.Node> ranked = new ArrayList<>(latOk);
        rankVerifiedFirst(ranked);
        topNodes.clear();
        topNodes.addAll(ranked.subList(0, Math.min(12, ranked.size())));
        return null;
    }

    private void rankVerifiedFirst(List<Subs.Node> list) {
        list.sort((a, b) -> {
            int va = "1".equals(a.extra.get("verified")) ? 0 : 1;
            int vb = "1".equals(b.extra.get("verified")) ? 0 : 1;
            if (va != vb) return Integer.compare(va, vb);
            if (a.speed != b.speed) return Double.compare(b.speed, a.speed);
            double la = a.latency == null ? 9e9 : a.latency, lb = b.latency == null ? 9e9 : b.latency;
            return Double.compare(la, lb);
        });
    }

    // ============================ اتصال نهایی ============================
    private Subs.Node connectWithFallback(Subs.Node best, List<Subs.Node> extras) {
        List<Subs.Node> cands = new ArrayList<>();
        cands.add(best);
        if (extras != null)
            for (Subs.Node n : extras) {
                if (cands.size() >= 4) break;
                if (!n.key().equals(best.key()) && !containsKey(cands, n)) cands.add(n);
            }
        Exception lastErr = null;
        for (int i = 0; i < cands.size(); i++) {
            Subs.Node cand = cands.get(i);
            if (stopFlag || abortRepair.get()) return null;
            try {
                if (i > 0) log("↻ تلاش با کاندید " + (i + 1) + ": " + cand.display());
                connectFinal(cand);
                updateCache(cand, null);
                return cand;
            } catch (Exception e) {
                lastErr = e;
                log("✗ اتصال به " + cand.display() + " رد شد: " + e.getMessage());
            }
        }
        if (lastErr != null && !stopFlag) {
            errorAndIdle(null);
        }
        return null;
    }

    private boolean containsKey(List<Subs.Node> list, Subs.Node n) {
        for (Subs.Node x : list) if (x.key().equals(n.key())) return true;
        return false;
    }

    private void writeJson(JSONObject o, File f) throws Exception {
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(o.toString().getBytes(StandardCharsets.UTF_8));
        fos.close();
    }

    /** اتصالِ نهایی به یک نود — مثل connect() ویندوز: هسته + دروازه‌ی سرعت + TUN. */
    private void connectFinal(Subs.Node node) throws Exception {
        disconnectInternal(false);
        socksPort = findFreePort(SOCKS_PORT);
        apiPort = findFreePort(API_PORT);
        relayPort = findFreePort(RELAY_PORT);
        if (!ensureXray()) throw new Exception("هسته Xray پیدا نشد");
        // رله‌ی محافظ — سوکتِ واقعی با protect باز می‌شود
        relay = new ProtRelay(new ProtRelay.Protector() {
            @Override public boolean protect(Socket s) {
                return vpnSvc != null && vpnSvc.protectSocket(s);
            }
            @Override public boolean protect(DatagramSocket s) {
                return vpnSvc != null && vpnSvc.protectSocket(s);
            }
        }, node.server, node.port, relayPort);
        JSONObject cfg = Subs.buildXrayConfig(node, socksPort, apiPort, "127.0.0.1", relayPort);
        if (cfg == null) throw new Exception("ساخت کانفیگ برای این نود ممکن نشد");
        File tmp = new File(ctx.getCacheDir(), "manjarvpn_main.json");
        writeJson(cfg, tmp);
        progress("connect", 1, 2, "راه‌اندازی تونل نهایی…");
        relay.start();
        mainProc = startXray(tmp.getAbsolutePath(), "main");
        if (mainProc == null) throw new Exception("هسته Xray بالا نیامد");
        if (!waitPort(socksPort, 6.0)) {
            disconnectInternal(false);
            throw new Exception("هسته Xray بالا نیامد");
        }
        // تأیید: 204 + سایت واقعی
        boolean ok = false;
        try {
            int code = httpGetViaSocks(socksPort, "cp.cloudflare.com", "/generate_204",
                    "cp.cloudflare.com", 10000);
            ok = code < 400;
        } catch (Exception ignored) {}
        if (ok) {
            try {
                int code = httpsGetViaSocks(socksPort, "www.wikipedia.org",
                        "/static/favicon/wikipedia.ico", 8000);
                if (code >= 500) ok = false;   // هر پاسخِ HTTP خوب است
            } catch (Exception ignored) {
                // سایت واقعی باز نشد — مثل ویندوز سخت‌گیرانه: تلاش دوم نداریم؛ رد
                ok = false;
            }
        }
        // دروازه‌ی سرعت
        if (ok) {
            double gateLimit = "1".equals(node.extra.get("verified"))
                    ? Subs.CONNECT_GATE_MBPS : Subs.EMERGENCY_GATE_MBPS;
            double gate = lightSpeedOnPort(socksPort, 1_000_000, 8.0);
            if (gate < gateLimit) {
                disconnectInternal(false);
                throw new Exception("تونل وصل شد ولی سرعت واقعی " +
                        String.format(java.util.Locale.US, "%.1f", gate) + " Mbps است (کمتر از حداقل " +
                        gateLimit + ") — رد شد، رفتن به کاندید بعدی");
            }
        }
        if (!ok) {
            disconnectInternal(false);
            throw new Exception("تونل پاسخ نداد (سایت واقعی هم باز نشد)");
        }
        // TUN — در سرویس VPN
        progress("connect", 2, 2, "فعال‌سازی تونل VPN…");
        if (vpnSvc == null) throw new Exception("سرویس VPN در دسترس نیست");
        vpnSvc.establishTunnel();          // IOException/SecurityException اگر اجازه نباشد
        currentNode = node;
        connEpoch++;
        log("✓ متصل شد — تونل VPN فعال شد. همه‌ی برنامه‌ها از این مسیر می‌روند.");
        status("متصل", "green");
        JSONObject np = new JSONObject();
        try { np.put("node", nodeToJson(node)); } catch (Exception ignored) {}
        Listener l = listener;
        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("connected", np));
        startMonitors(connEpoch);
    }

    public double lightSpeedOnPort(int port, int bytesTo, double timeoutSec) {
        double best = 0;
        for (int i = 0; i < Subs.SPEED_ENDPOINT_ATTEMPTS; i++) {
            if (stopFlag) break;
            double v = dlSpeedViaSocks(port, Subs.SPEED_ENDPOINTS[i], bytesTo, timeoutSec);
            if (v > 0) {
                if (v > best) best = v;
                if (best >= 0.1) break;
            }
        }
        return best;
    }

    // ============================ نگهبان‌ها ============================
    private void startMonitors(final int epoch) {
        stopMonitors();
        healthThread = new Thread(() -> liveMonitor(epoch), "manjar-health");
        healthThread.setDaemon(true);
        healthThread.start();
        usageThread = new Thread(() -> usageMonitor(epoch), "manjar-usage");
        usageThread.setDaemon(true);
        usageThread.start();
    }

    public void stopMonitors() {
        if (healthThread != null) healthThread.interrupt();
        if (usageThread != null) usageThread.interrupt();
        healthThread = null;
        usageThread = null;
    }

    private void liveMonitor(int epoch) {
        int fails = 0, slow = 0, checks = 0;
        boolean uploaded = false;
        try { Thread.sleep(5000); } catch (Exception ignored) { return; }
        while (!Thread.currentThread().isInterrupted() && currentNode != null) {
            if (connEpoch != epoch) return;
            boolean ok = healthCheck(7000);
            if (Thread.currentThread().isInterrupted() || connEpoch != epoch) return;
            if (ok) {
                if (fails >= 2) {
                    log("✓ اتصال دوباره پایدار شد");
                    status("متصل", "green");
                }
                fails = 0;
                checks++;
                if (checks % 2 == 0) {
                    double mbps = lightSpeedOnPort(socksPort, 262144, 8.0);
                    if (Thread.currentThread().isInterrupted() || connEpoch != epoch) return;
                    if (mbps >= Subs.LIVE_MIN_SPEED_MBPS) {
                        slow = 0;
                        JSONObject p = new JSONObject();
                        try { p.put("v", Math.round(mbps * 10.0) / 10.0); } catch (Exception ignored) {}
                        Listener l = listener;
                        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("livespeed", p));
                    } else {
                        slow++;
                        if (slow == 1) log("⚠ سرعت تونل افت کرد — زیر نظر…");
                        else if (slow == Subs.LIVE_SLOW_LIMIT - 1) log("⚠ سرعت تقریباً صفر است…");
                    }
                    if (slow >= Subs.LIVE_SLOW_LIMIT) {
                        log("⚠ تونل «فقط‌پینگی» شد (پینگ دارد، سرعت ندارد) — تعویض بی‌صدای سرور…");
                        status("تعویض سرور — سرعت صفر است…", "amber");
                        repairFlow(epoch);
                        return;
                    }
                }
                if (!uploaded) {
                    uploaded = true;
                    double up = uploadSpeedViaSocks(socksPort, UPLOAD_PROBE_BYTES);
                    if (up > 0 && !Thread.currentThread().isInterrupted()) {
                        JSONObject p = new JSONObject();
                        try { p.put("v", Math.round(up * 10.0) / 10.0); } catch (Exception ignored) {}
                        Listener l = listener;
                        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("upspeed", p));
                    }
                }
            } else {
                boolean directOk = checkInternet();
                if (Thread.currentThread().isInterrupted() || connEpoch != epoch) return;
                if (directOk) {
                    fails++;
                    if (fails <= 4) {
                        log("⚠ پاسخ تونل قطع/کند (" + fails + "/۵) — صبر…");
                        status("ناپایداری اتصال (" + fails + "/۵)…", "amber");
                    }
                } else {
                    log("⚠ اینترنت اصلی مختل است — تونل سالم است، صبر…");
                }
            }
            if (fails >= 5) {
                if (connEpoch == epoch && !Thread.currentThread().isInterrupted()) repairFlow(epoch);
                return;
            }
            try { Thread.sleep(4000); } catch (Exception ignored) { return; }
        }
    }

    private boolean healthCheck(int timeoutMs) {
        if (mainProc == null) return false;
        try {
            int code = httpGetViaSocks(socksPort, "cp.cloudflare.com", "/generate_204",
                    "cp.cloudflare.com", timeoutMs);
            return code < 500;
        } catch (Exception ignored) {}
        try {
            int code = httpGetViaSocks(socksPort, "www.gstatic.com", "/generate_204",
                    "www.gstatic.com", timeoutMs);
            return code < 500;
        } catch (Exception ignored) {}
        return false;
    }

    private void repairFlow(int epoch) {
        try { Thread.sleep(1200); } catch (Exception ignored) {}
        List<Subs.Node> cands = new ArrayList<>();
        Subs.Node cur = currentNode;
        if (cur != null) cands.add(cur);
        for (Subs.Node n : new ArrayList<>(topNodes)) {
            if (cands.size() >= 4) break;
            if (cur != null && n.key().equals(cur.key())) continue;
            if (!containsKey(cands, n)) cands.add(n);
        }
        for (int i = 0; i < cands.size(); i++) {
            Subs.Node cand = cands.get(i);
            if (Thread.currentThread().isInterrupted() || abortRepair.get() || connEpoch != epoch) return;
            synchronized (connLock) {
                if (Thread.currentThread().isInterrupted() || abortRepair.get() || connEpoch != epoch) return;
                try {
                    if (i == 0) log("🔧 بازسازی تونل با همان سرور…");
                    else log("↻ تلاش با سرور جایگزین: " + cand.display());
                    connectFinal(cand);
                    if (abortRepair.get() || Thread.currentThread().isInterrupted()) {
                        disconnectInternal(true);
                        return;
                    }
                    updateCache(cand, null);
                    JSONObject p = new JSONObject();
                    try { p.put("node", nodeToJson(cand)); } catch (Exception ignored) {}
                    Listener l = listener;
                    if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("repaired", p));
                    return;
                } catch (Exception e) {
                    log("✗ " + cand.display() + " جواب نداد");
                }
            }
            try { Thread.sleep(600); } catch (Exception ignored) { return; }
        }
        if (!abortRepair.get()) {
            Listener l = listener;
            if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("autofail", new JSONObject()));
        }
    }

    /** مانیتورِ مصرف — پرس‌وجو از API آمار Xray هر ۲.۵ ثانیه (مثل ویندوز). */
    private void usageMonitor(int epoch) {
        Double last = null;
        boolean first = true;
        while (!Thread.currentThread().isInterrupted()) {
            if (connEpoch != epoch || mainProc == null || currentNode == null) break;
            Long total = readTrafficCounters();
            if (total == null) {
                if (mainProc == null || connEpoch != epoch) break;
                try { Thread.sleep(2500); } catch (Exception ignored) { break; }
                continue;
            }
            if (first) {
                first = false;
                pushUsage(account.snapshot());
            } else if (last != null && total >= last && total - last > 0) {
                JSONObject snap = account.consume((long) (double) (total - last));
                pushUsage(snap);
                if (account.remainingBytes() <= 0) {
                    Listener l = listener;
                    if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("quota_exhausted", new JSONObject()));
                    break;
                }
            }
            last = (double) total;
            try { Thread.sleep(2500); } catch (Exception ignored) { break; }
        }
    }

    private void pushUsage(final JSONObject snap) {
        Listener l = listener;
        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("usage", snap));
    }

    public Long readTrafficCounters() {
        if (apiPort == 0 || xrayPath == null) return null;
        if (mainProc == null) return null;
        try {
            ProcessBuilder pb = new ProcessBuilder(xrayPath, "api", "statsquery",
                    "--server=127.0.0.1:" + apiPort, "-pattern", "inbound");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            InputStream is = p.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            p.waitFor(6, java.util.concurrent.TimeUnit.SECONDS);
            p.destroy();
            JSONObject d = new JSONObject(new String(bos.toByteArray(), StandardCharsets.UTF_8));
            long total = 0;
            JSONArray stats = d.optJSONArray("stat");
            if (stats != null) {
                for (int i = 0; i < stats.length(); i++) {
                    JSONObject s = stats.optJSONObject(i);
                    if (s == null) continue;
                    String name = s.optString("name", "");
                    if (name.contains(">>>api>>>")) continue;
                    total += s.optLong("value", 0);
                }
            }
            return total;
        } catch (Exception e) {
            return null;
        }
    }

    // ============================ قطع اتصال ============================
    public void disconnectInternal(boolean notify) {
        stopMonitors();
        try { if (relay != null) relay.stop(); } catch (Exception ignored) {}
        relay = null;
        killProc(mainProc);
        mainProc = null;
        currentNode = null;
        if (vpnSvc != null) vpnSvc.teardownTunnel();
        if (notify) {
            log("✓ اتصال قطع شد و تونل بسته شد");
            idle();
        }
    }

    public void disconnectFlow() {
        Thread t = new Thread(() -> {
            abortRepair.set(true);
            disconnectInternal(true);
        }, "manjar-disc");
        t.setDaemon(true);
        t.start();
    }

    public void stopAll() {
        stopFlag = true;
        cancelAll();
        disconnectInternal(false);
    }

    // ============================ رویدادهای وضعیت ============================
    private void idle() {
        Listener l = listener;
        if (l != null && ui != null) ui.runOnUiThread(() -> l.onEvent("idle", new JSONObject()));
    }

    /** فراخوانی از رابط — وضعیت به «آماده اتصال» برمی‌گردد. */
    public void idleNow() { idle(); }

    private void errorAndIdle(String msg) {
        if (msg != null) log("✗ " + msg);
        JSONObject p = new JSONObject();
        try { p.put("msg", msg == null ? JSONObject.NULL : msg); } catch (Exception ignored) {}
        Listener l = listener;
        if (l != null && ui != null) {
            final JSONObject pp = p;
            ui.runOnUiThread(() -> l.onEvent("error", pp));
        }
    }

    public JSONObject nodeToJson(Subs.Node n) {
        try {
            JSONObject d = new JSONObject();
            d.put("display", n.display());
            d.put("flag", n.flag());
            d.put("proto", n.proto == null ? "" : n.proto.toUpperCase());
            d.put("ping", n.latency == null ? 0 : (int) (double) n.latency);
            d.put("speed", Math.round(n.speed * 10.0) / 10.0);
            d.put("up", Math.round(n.upSpeed * 10.0) / 10.0);
            d.put("opened", n.extra.get("opened") == null ? "" : n.extra.get("opened"));
            d.put("server", n.server + ":" + n.port);
            d.put("uri", n.uri);
            return d;
        } catch (Exception e) { return new JSONObject(); }
    }

    public JSONArray nodesToJson(List<Subs.Node> list) {
        JSONArray arr = new JSONArray();
        for (Subs.Node n : list) arr.put(nodeToJson(n));
        return arr;
    }
}
