package ir.manjar.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import hev.htproxy.TProxyService;

/**
 * ManjarVPN v1.8 — سرویس VPN
 * TUN (VpnService) → hev-socks5-tunnel → Xray (socks محلی) → رله‌ی محافظ → سرور واقعی
 */
public class ManjarVpnService extends VpnService {

    private static VpnEngine engine;
    private final Binder binder = new LocalBinder();
    private volatile boolean tunnelUp = false;
    private String pendingNodeAction = null; // "auto" | "custom"
    private Subs.Node pendingNode = null;

    public class LocalBinder extends Binder {
        public ManjarVpnService getService() { return ManjarVpnService.this; }
        public VpnEngine getEngine() {
            if (engine == null) engine = new VpnEngine(ManjarVpnService.this, new AccountStore(ManjarVpnService.this));
            return engine;
        }
    }

    public static VpnEngine getEngineStatic() { return engine; }

    @Override
    public IBinder onBind(Intent intent) {
        VpnEngine e = ((LocalBinder) binder).getEngine();
        e.setVpnService(this);
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (engine == null) {
            engine = new VpnEngine(this, new AccountStore(this));
            engine.setVpnService(this);
        }
        // v1.8.4 — ارتقای فوری به foreground service:
        // اسکنِ «اتصال خودکار» ۲ تا ۵ دقیقه طول می‌کشد؛ بدونِ foreground،
        // اندروید ۱۲+ ممکن است پروسه را وسطِ اسکن فریز/بکشد (ظاهراً «کار نمی‌کند»)
        // — حالا سرویس از همان شروع، foreground است و بعداً با متنِ «متصل» به‌روز می‌شود.
        startForegroundCompat(getString(R.string.notif_preparing));
        // سرویس started می‌ماند تا وقتی فعالیت بسته شد موتور زنده بماند
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (engine != null) engine.stopAll();
        engine = null;
    }

    public boolean protectSocket(java.net.Socket s) {
        try { return protect(s); } catch (Exception e) { return false; }
    }

    public boolean protectSocket(java.net.DatagramSocket s) {
        try { return protect(s); } catch (Exception e) { return false; }
    }

    /** آیا اجازه‌ی VPN هست؟ */
    public static boolean hasConsent(android.content.Context ctx) {
        return VpnService.prepare(ctx) == null;
    }

    public static Intent consentIntent(android.content.Context ctx) {
        return VpnService.prepare(ctx);
    }

    /**
     * TUN را برپا می‌کند و hev-socks5-tunnel را روی fd اجرا می‌کند.
     * باید بعد از بالا آمدنِ Xray و رله صدا زده شود.
     */
    public synchronized void establishTunnel() throws Exception {
        if (tunnelUp) return;
        if (engine == null) throw new Exception("موتور در دسترس نیست");
        Builder b = new Builder()
                .setMtu(8500)
                .addAddress("198.18.0.1", 32)
                // v1.8.3: IPv6 واقعا داخلِ تونل سرو می‌شود (قبلا مسیرِ ::/0 باز بود ولی hev
                // آدرسِ v6 نداشت → بسته‌های v6 سیاه‌چاله می‌شدند → اپ‌های v6-پسند کند/گرفتار)
                .addAddress("fdfe:dcba:9876::1", 126)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .setSession("ManjarVPN");
        // خودِ برنامه از تونل مستثنی باشد (رابط و تست‌ها مستقیم کار کنند)
        try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignored) {}
        int fd;
        try {
            android.os.ParcelFileDescriptor pfd = b.establish();
            if (pfd == null) throw new Exception("اجازه‌ی VPN داده نشد");
            fd = pfd.getFd();
            // pfd را نگه می‌داریم تا زنده بماند (GC نبندد)
            tunFdHolder = pfd;
        } catch (SecurityException se) {
            throw new Exception("اجازه‌ی VPN داده نشد");
        }
        // کانفیگ hev
        StringBuilder y = new StringBuilder();
        y.append("tunnel:\n");
        y.append("  name: hev-tun\n");
        y.append("  mtu: 8500\n");
        y.append("  ipv4: 198.18.0.1\n");
        // v1.8.3: کتابخانه‌ی hev موجود از IPv6 پشتیبانی می‌کند (hev_config_get_tunnel_ipv6_address)
        y.append("  ipv6: fdfe:dcba:9876::1\n");
        y.append("socks5:\n");
        y.append("  port: ").append(engine.socksPort).append("\n");
        y.append("  address: 127.0.0.1\n");
        y.append("  udp: 'udp'\n");
        y.append("misc:\n");
        y.append("  log-level: warn\n");
        y.append("  task-stack-size: 24576\n");
        y.append("  connect-timeout: 10000\n");
        File cfgFile = new File(getFilesDir(), "hev_tun.yaml");
        FileOutputStream fos = new FileOutputStream(cfgFile);
        fos.write(y.toString().getBytes(StandardCharsets.UTF_8));
        fos.close();
        boolean ok;
        try {
            ok = TProxyService.TProxyStartService(cfgFile.getAbsolutePath(), fd);
        } catch (Throwable t) {
            ok = false;
        }
        if (!ok) {
            try { tunFdHolder.close(); } catch (Exception ignored) {}
            tunFdHolder = null;
            throw new Exception("راه‌اندازی تونل ممکن نشد");
        }
        tunnelUp = true;
        startForegroundNotif();
    }

    private android.os.ParcelFileDescriptor tunFdHolder;

    public synchronized void teardownTunnel() {
        if (!tunnelUp) {
            try { if (tunFdHolder != null) tunFdHolder.close(); } catch (Exception ignored) {}
            tunFdHolder = null;
            return;
        }
        try { TProxyService.TProxyStopService(); } catch (Throwable ignored) {}
        try { if (tunFdHolder != null) tunFdHolder.close(); } catch (Exception ignored) {}
        tunFdHolder = null;
        tunnelUp = false;
        stopForegroundCompat();
    }

    public boolean isTunnelUp() { return tunnelUp; }

    private void startForegroundNotif() {
        startForegroundCompat(getString(R.string.notif_connected));
    }

    /** نوتیفِ foreground — متن‌پذیر (آماده‌سازی ← متصل) — بدونِ کرش حتی اگر نوتیف بسته باشد */
    private void startForegroundCompat(String text) {
        String channelId = "manjar_vpn";
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(channelId,
                    getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("وضعیت تونل ManjarVPN");
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 1, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder nb;
        if (Build.VERSION.SDK_INT >= 26)
            nb = new Notification.Builder(this, channelId);
        else
            nb = new Notification.Builder(this);
        nb.setContentTitle("ManjarVPN")
          .setContentText(text)
          .setSmallIcon(R.drawable.ic_stat_notify)
          .setOngoing(true)
          .setContentIntent(pi);
        Notification n = nb.build();
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(1001, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(1001, n);
            }
        } catch (Exception ignored) {
            // اگر startForeground ممکن نشد (محدودیتِ سازنده و…) — اپ همچنان کار می‌کند
        }
    }

    private void stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= 24) {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
    }
}
