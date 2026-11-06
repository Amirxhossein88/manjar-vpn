package ir.manjar.vpn;

import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * ManjarVPN v1.8 — حسابِ اعتبارِ حجم — پورتِ کاملِ account.py
 * اعتبار پیش‌فرض ۵۰۰ مگ • کد خریدار +۷ گیگ • کد مدیر +۲۰ گیگ (مکرر)
 * اتمامِ اعتبار = مسدود • گردونه فقط یک‌بار برای هر سیستم.
 * ذخیره: SharedPreferences + نسخه‌ی آینه‌ای عمومی (برای ماندگاری بعد از نصبِ مجدد).
 */
public class AccountStore {

    public static final double DEFAULT_CREDIT_MB = 500.0;
    public static final String BUYER_CODE = "Manjar172026";
    public static final double BUYER_BONUS_MB = 7 * 1024;
    public static final String ADMIN_CODE = "Manjar172026Admin";
    public static final double ADMIN_BONUS_MB = 20 * 1024;

    private static final String PREFS = "manjar_account";
    private static final String KEY = "account_json";

    private final Context ctx;
    private final Object lock = new Object();

    public long usedBytes = 0;
    public double creditMb = DEFAULT_CREDIT_MB;
    public boolean wheelDone = false;
    public double wheelPrizeMb = 0.0;
    public java.util.Map<String, Integer> redemptions = new java.util.HashMap<>();
    public String updated = "";

    public AccountStore(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        load();
    }

    // ---------------- ذخیره/بارگذاری ----------------
    private JSONObject toJson() {
        try {
            JSONObject d = new JSONObject();
            d.put("used_bytes", usedBytes);
            d.put("credit_mb", Math.round(creditMb * 10.0) / 10.0);
            d.put("wheel_done", wheelDone);
            d.put("wheel_prize_mb", Math.round(wheelPrizeMb * 10.0) / 10.0);
            d.put("redemptions", new JSONObject(redemptions));
            d.put("updated", updated);
            return d;
        } catch (Exception e) { return new JSONObject(); }
    }

    private void fromJson(JSONObject d) {
        if (d == null) return;
        try { usedBytes = Math.max(0, d.optLong("used_bytes", 0)); } catch (Exception ignored) {}
        try {
            double c = d.optDouble("credit_mb", DEFAULT_CREDIT_MB);
            creditMb = Math.max(0.0, c);
        } catch (Exception ignored) {}
        wheelDone = d.optBoolean("wheel_done", false);
        try { wheelPrizeMb = Math.max(0.0, d.optDouble("wheel_prize_mb", 0)); } catch (Exception ignored) {}
        try {
            JSONObject r = d.optJSONObject("redemptions");
            if (r != null) {
                redemptions = new java.util.HashMap<>();
                java.util.Iterator<String> it = r.keys();
                while (it.hasNext()) {
                    String k = it.next();
                    redemptions.put(k, r.optInt(k, 0));
                }
            }
        } catch (Exception ignored) {}
        updated = d.optString("updated", "");
    }

    private void load() {
        synchronized (lock) {
            String mine = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null);
            if (mine != null) {
                try { fromJson(new JSONObject(mine)); } catch (Exception ignored) {}
            }
            // نسخه‌ی آینه‌ای عمومی — اگر تازه‌تر بود (مثلا بعد از نصبِ مجدد) همان معتبر است
            JSONObject mirror = readPublicMirror();
            if (mirror != null) {
                String mu = mirror.optString("updated", "");
                if (!mu.isEmpty() && (updated.isEmpty() || mu.compareTo(updated) > 0)) {
                    double newCredit = mirror.optDouble("credit_mb", 0);
                    double oldCredit = creditMb;
                    fromJson(mirror);
                    // اعتبار هرگز کم نشود (ترکیبِ امن)
                    if (newCredit > oldCredit) creditMb = newCredit;
                    usedBytes = Math.max(usedBytes, mirror.optLong("used_bytes", 0));
                    wheelDone = wheelDone || mirror.optBoolean("wheel_done", false);
                }
            }
            save();
        }
    }

    public void save() {
        synchronized (lock) {
            try {
                ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                        .edit().putString(KEY, toJson().toString()).apply();
            } catch (Exception ignored) {}
            writePublicMirror();
        }
    }

    // ---------- آینه‌ی عمومی (ماندگاری بعد از نصب مجدد — حدِ امکاناتِ اندروید) ----------
    private void writePublicMirror() {
        String data = toJson().toString();
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                String relPath = Environment.DIRECTORY_DOWNLOADS + "/ManjarVPN";
                // به‌روزرسانی فایل موجود
                android.database.Cursor c = ctx.getContentResolver().query(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        new String[]{MediaStore.MediaColumns._ID},
                        MediaStore.MediaColumns.RELATIVE_PATH + "=? AND " +
                                MediaStore.MediaColumns.DISPLAY_NAME + "=?",
                        new String[]{relPath, "account.json"}, null);
                long id = -1;
                if (c != null) {
                    if (c.moveToFirst()) id = c.getLong(0);
                    c.close();
                }
                ContentValues cv = new ContentValues();
                cv.put(MediaStore.MediaColumns.DISPLAY_NAME, "account.json");
                cv.put(MediaStore.MediaColumns.MIME_TYPE, "application/json");
                cv.put(MediaStore.MediaColumns.RELATIVE_PATH, relPath);
                cv.put(MediaStore.MediaColumns.IS_PENDING, 0);
                Uri uri;
                if (id >= 0) {
                    uri = Uri.parse(MediaStore.Downloads.EXTERNAL_CONTENT_URI.toString() + "/" + id);
                    ctx.getContentResolver().update(uri, cv, null, null);
                } else {
                    uri = ctx.getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                }
                if (uri != null) {
                    OutputStream os = ctx.getContentResolver().openOutputStream(uri, "wt");
                    if (os != null) {
                        os.write(data.getBytes(StandardCharsets.UTF_8));
                        os.close();
                    }
                }
            } catch (Exception ignored) {}
        } else {
            try {
                File dir = new File(Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS), "ManjarVPN");
                if (!dir.exists()) dir.mkdirs();
                File f = new File(dir, "account.json");
                FileOutputStream fos = new FileOutputStream(f);
                fos.write(data.getBytes(StandardCharsets.UTF_8));
                fos.close();
            } catch (Exception ignored) {}
        }
    }

    private JSONObject readPublicMirror() {
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                String relPath = Environment.DIRECTORY_DOWNLOADS + "/ManjarVPN";
                android.database.Cursor c = ctx.getContentResolver().query(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        new String[]{MediaStore.MediaColumns._ID},
                        MediaStore.MediaColumns.RELATIVE_PATH + "=? AND " +
                                MediaStore.MediaColumns.DISPLAY_NAME + "=?",
                        new String[]{relPath, "account.json"}, null);
                if (c != null) {
                    JSONObject out = null;
                    if (c.moveToFirst()) {
                        long id = c.getLong(0);
                        Uri uri = Uri.parse(MediaStore.Downloads.EXTERNAL_CONTENT_URI.toString() + "/" + id);
                        InputStream is = ctx.getContentResolver().openInputStream(uri);
                        if (is != null) {
                            ByteArrayOutputStream bos = new ByteArrayOutputStream();
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
                            is.close();
                            out = new JSONObject(new String(bos.toByteArray(), StandardCharsets.UTF_8));
                        }
                    }
                    c.close();
                    return out;
                }
            } catch (Exception ignored) {}
            return null;
        } else {
            try {
                File f = new File(new File(Environment.getExternalStoragePublicDirectory(
                        Environment.DIRECTORY_DOWNLOADS), "ManjarVPN"), "account.json");
                if (!f.exists()) return null;
                FileInputStream fis = new FileInputStream(f);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = fis.read(buf)) > 0) bos.write(buf, 0, n);
                fis.close();
                return new JSONObject(new String(bos.toByteArray(), StandardCharsets.UTF_8));
            } catch (Exception e) { return null; }
        }
    }

    // ---------------- محاسبات ----------------
    public double remainingBytes() {
        synchronized (lock) {
            return Math.max(0.0, creditMb * 1024 * 1024 - usedBytes);
        }
    }

    public boolean isBlocked() { return remainingBytes() <= 0; }

    public JSONObject snapshot() {
        synchronized (lock) {
            try {
                double total = creditMb;
                double usedMb = usedBytes / (1024.0 * 1024.0);
                JSONObject d = new JSONObject();
                d.put("used_mb", Math.round(usedMb * 100.0) / 100.0);
                d.put("credit_mb", Math.round(total * 100.0) / 100.0);
                d.put("remaining_mb", Math.round(Math.max(0.0, total - usedMb) * 100.0) / 100.0);
                d.put("frac", total > 0 ? usedMb / total : 1.0);
                return d;
            } catch (Exception e) { return new JSONObject(); }
        }
    }

    public JSONObject consume(long deltaBytes) {
        if (deltaBytes > 0) {
            synchronized (lock) {
                usedBytes += deltaBytes;
                save();
            }
        }
        return snapshot();
    }

    public JSONObject addCredit(double mb, String source, boolean replace) {
        synchronized (lock) {
            creditMb = replace ? mb : creditMb + mb;
            if (source != null && !source.isEmpty())
                redemptions.put(source, redemptions.containsKey(source) ? redemptions.get(source) + 1 : 1);
            save();
            return snapshot();
        }
    }

    public void setWheelDone(double prizeMb) {
        synchronized (lock) {
            wheelDone = true;
            wheelPrizeMb = prizeMb;
            save();
        }
    }

    /** خروجی: {"ok":…,"msg":…,"added_mb":…} — مثل redeem() در account.py */
    public JSONObject redeem(String code) {
        String c = code == null ? "" : code.trim().toLowerCase();
        JSONObject out = new JSONObject();
        try {
            if (c.isEmpty()) {
                out.put("ok", false).put("msg", "کد را وارد کنید").put("added_mb", 0);
                return out;
            }
            if (c.equals(BUYER_CODE.toLowerCase())) {
                JSONObject snap = addCredit(BUYER_BONUS_MB, "buyer", false);
                out.put("ok", true)
                   .put("msg", "✓ کد خریدار فعال شد — ۷ گیگابایت اعتبار اضافه شد")
                   .put("added_mb", BUYER_BONUS_MB)
                   .put("snapshot", snap);
                return out;
            }
            if (c.equals(ADMIN_CODE.toLowerCase())) {
                JSONObject snap = addCredit(ADMIN_BONUS_MB, "admin", false);
                int uses = redemptions.containsKey("admin") ? redemptions.get("admin") : 1;
                out.put("ok", true)
                   .put("msg", "✓ کد مدیر فعال شد — ۲۰ گیگابایت اعتبار اضافه شد (دفعات استفاده: " + uses + ")")
                   .put("added_mb", ADMIN_BONUS_MB)
                   .put("snapshot", snap);
                return out;
            }
            out.put("ok", false).put("msg", "✗ کد معتبر نیست").put("added_mb", 0);
            return out;
        } catch (Exception e) {
            try { out.put("ok", false).put("msg", "خطا").put("added_mb", 0); } catch (Exception ignored) {}
            return out;
        }
    }

    public static String fmtMb(double mb) {
        if (mb >= 1024) {
            String s = String.format(java.util.Locale.US, "%.2f", mb / 1024.0);
            if (s.endsWith(".00")) s = s.substring(0, s.length() - 3);
            return s + " گیگ";
        }
        return String.valueOf((int) Math.round(mb)) + " مگ";
    }
}
