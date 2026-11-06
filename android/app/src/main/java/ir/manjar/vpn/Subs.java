package ir.manjar.vpn;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ManjarVPN v1.8 — منطقِ خالص (بدون کلاس اندروید) — پورتِ کاملِ engine.py
 * پارس کانفیگ‌ها (vmess/vless/trojan/ss)، ساخت کانفیگ Xray، دیکد اشتراک.
 */
public final class Subs {

    // ===================== ثابت‌ها (یکسان با نسخه ویندوز) =====================
    public static final String APP_NAME = "ManjarVPN";
    public static final String VERSION = "1.8.4";

    public static final String[] SUBSCRIPTION_SOURCES = {
            // barry-far — دسته‌های اصلی
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
            // barry-far — تفکیک بر اساس پروتکل
            "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
            "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
            "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
            "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
            // جمع‌کننده‌ها
            "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
            "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
            "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
            "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
            // V2RayRoot
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt",
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vmess.txt",
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/trojan.txt",
            // ircfspace/tvc
            "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/mix",
            "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/reality",
            "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vless",
            "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/vmess",
            "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/trojan",
            // منابع تازه‌تر
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
            "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
            "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/all_servers.txt",
            "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/main/Configs/All-DukeMehdi-Configs.txt",
            "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/config.txt",
            "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/all_sub.txt",
            "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge_base64.txt",
            "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
            "https://raw.githubusercontent.com/freefq/free/master/v2",
    };

    public static final String[] MIRROR_TEMPLATES = {
            "{url}",
            "https://ghfast.top/{url}",
            "https://gh-proxy.com/{url}",
            "https://mirror.ghproxy.com/{url}",
    };

    public static final Set<String> SUPPORTED_NETS = new LinkedHashSet<>();
    static {
        SUPPORTED_NETS.add("tcp"); SUPPORTED_NETS.add("ws"); SUPPORTED_NETS.add("grpc");
        SUPPORTED_NETS.add("http"); SUPPORTED_NETS.add("httpupgrade");
        SUPPORTED_NETS.add("xhttp"); SUPPORTED_NETS.add("h2");
    }

    public static final String[] MODERN_SS_METHODS = {
            "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
            "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none", "plain",
    };

    // تست عمیق هر کاندید — دقیقا طبق نسخه‌ی ویندوز
    public static final String[][] SITE_TARGETS = {
            {"یوتوب", "https://www.youtube.com/generate_204"},
            {"اینستاگرام", "https://www.instagram.com/robots.txt"},
            {"تلگرام", "https://web.telegram.org/k/"},
    };
    public static final int SITE_MIN_PASS = 2;

    public static final String[] SPEED_ENDPOINTS = {
            "https://speed.cloudflare.com/__down?bytes=25000000",
            "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
            "https://nbg1-speed.hetzner.com/100MB.bin",
            "https://proof.ovh.net/files/100Mb.dat",
    };
    public static final int SPEED_ENDPOINT_ATTEMPTS = 2;
    public static final int SPEED_MIN_VALID_BYTES = 150_000;
    public static final String REAL_SITE_URL = "https://www.wikipedia.org/static/favicon/wikipedia.ico";
    public static final String LIGHT_TLS_URL = "https://www.gstatic.com/generate_204";

    // نجات هوش مصنوعی (سرویس رایگان بدون کلید — مثل ویندوز)
    public static final String POLLINATIONS_URL = "https://text.pollinations.ai/";
    public static final String POLLINATIONS_MODEL = "openai-fast";
    public static final int AI_RESCUE_MAX_ROUNDS = 2;
    public static final int AI_RESCUE_MAX_URIS = 60;
    public static final int AI_RESCUE_MAX_LINKS = 3;
    public static final int AI_RESCUE_TIMEOUT_MS = 90_000;
    public static final int AI_FREE_RETRY_WAIT = 47;

    public static final double CONNECT_GATE_MBPS = 1.0;
    public static final double EMERGENCY_GATE_MBPS = 0.3;
    public static final double LIVE_MIN_SPEED_MBPS = 0.5;
    public static final int LIVE_SLOW_LIMIT = 3;
    public static final double QUICK_MIN_SPEED_MBPS = 2.0;
    public static final int CACHE_MAX = 20;
    public static final long CACHE_TTL_DAYS = 7;

    private static final Pattern AI_URI_RE =
            Pattern.compile("\\b(?:vless|vmess|trojan|ss|ssr)://[^\\s\"'<>\\\\]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern AI_SUB_RE =
            Pattern.compile("https?://[^\\s\"'<>\\\\]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SS_PLAIN_RE =
            Pattern.compile("^(?<method>[^:]+):(?<pw>.*)@(?<host>.+):(?<port>\\d+)$");
    private static final Pattern SS_METHOD_RE = Pattern.compile("^[A-Za-z0-9\\-_]+$");

    // ===================== مدل داده =====================
    public static class Node {
        public String proto;
        public String name;
        public String server;
        public int port;
        public Map<String, String> extra = new HashMap<>();
        public String uri = "";
        public Double latency = null;
        public double speed = 0.0;
        public double upSpeed = 0.0;

        public Node() {}
        public Node(String proto, String name, String server, int port) {
            this.proto = proto; this.name = name; this.server = server; this.port = port;
        }

        public String key() {
            String ident = extra.get("id");
            if (ident == null || ident.isEmpty()) ident = extra.get("password");
            if (ident == null || ident.isEmpty())
                ident = str(extra.get("method")) + ":" + str(extra.get("password"));
            return proto + "|" + server.toLowerCase() + "|" + port + "|" + ident;
        }

        public String display() {
            String n = (name == null ? "" : name.replaceAll("[\\x00-\\x1f]+", "")).trim();
            if (n.isEmpty()) n = proto + "://" + server;
            return n.length() > 60 ? n.substring(0, 60) : n;
        }

        public String flag() {
            java.util.regex.Matcher m = FLAG_RE.matcher(display());
            if (m.find()) return m.group(0);
            return "🌐";
        }

        public static final Pattern FLAG_RE =
                Pattern.compile("[\uD83C\uDDE6-\uD83C\uDDFF]{2}");
    }

    public static String str(Object o) { return o == null ? "" : String.valueOf(o); }

    // ===================== base64 (بدون java.util.Base64 — سازگار با اندروید ۷) =====================
    private static final char[] B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    public static String b64d(String s) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", "");
        s = s.replace('-', '+').replace('_', '/');
        int pad = (4 - s.length() % 4) % 4;
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < pad; i++) sb.append('=');
        s = sb.toString();
        int len = s.length();
        ByteArrayOutputStream out = new ByteArrayOutputStream(len * 3 / 4 + 4);
        int[] buf = new int[4];
        int k = 0, padInGroup = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            int v;
            if (c == '=') { v = 0; padInGroup++; }
            else {
                v = c2i(c);
                if (v < 0) continue;   // مثل base64 پایتون: نویز نادیده گرفته می‌شود
                padInGroup = 0;
            }
            buf[k++] = v;
            if (k == 4) {
                int n = 3 - Math.min(padInGroup, 2);
                if (n > 0) out.write((buf[0] << 2) | (buf[1] >> 4));
                if (n > 1) out.write(((buf[1] & 0xf) << 4) | (buf[2] >> 2));
                if (n > 2) out.write(((buf[2] & 0x3) << 6) | buf[3]);
                k = 0; padInGroup = 0;
            }
        }
        if (k == 2) out.write((buf[0] << 2) | (buf[1] >> 4));
        else if (k == 3) {
            out.write((buf[0] << 2) | (buf[1] >> 4));
            out.write(((buf[1] & 0xf) << 4) | (buf[2] >> 2));
        }
        byte[] arr = out.toByteArray();
        int end = arr.length;
        while (end > 0 && arr[end - 1] == 0) end--;   // احتیاط: صفرهای انتهایی ورودیِ بدون pad
        return new String(arr, 0, end, StandardCharsets.UTF_8);
    }

    private static int c2i(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    public static String b64e(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder();
        int i = 0;
        for (; i + 2 < b.length; i += 3) {
            int v = ((b[i] & 0xff) << 16) | ((b[i + 1] & 0xff) << 8) | (b[i + 2] & 0xff);
            out.append(B64C[(v >> 18) & 63]).append(B64C[(v >> 12) & 63])
               .append(B64C[(v >> 6) & 63]).append(B64C[v & 63]);
        }
        int rem = b.length - i;
        if (rem == 1) {
            int v = (b[i] & 0xff) << 16;
            out.append(B64C[(v >> 18) & 63]).append(B64C[(v >> 12) & 63]).append("==");
        } else if (rem == 2) {
            int v = ((b[i] & 0xff) << 16) | ((b[i + 1] & 0xff) << 8);
            out.append(B64C[(v >> 18) & 63]).append(B64C[(v >> 12) & 63])
               .append(B64C[(v >> 6) & 63]).append('=');
        }
        return out.toString();
    }

    // ===================== پارس کانفیگ‌ها =====================
    public static int[] splitHostPort(String hp) {
        // خروجی: {port} در اندیس 0 و «میزبان» رشته‌ی جدا — برای سادگی دو تابع:
        return null; // استفاده نمی‌شود
    }

    private static class HostPort { String host; int port; }

    private static HostPort splitHostport(String hp) {
        HostPort r = new HostPort();
        hp = hp.trim();
        if (hp.endsWith("/")) hp = hp.substring(0, hp.length() - 1);
        if (hp.startsWith("[")) {
            int close = hp.indexOf(']');
            if (close > 0) {
                r.host = hp.substring(1, close);
                String rest = hp.substring(close + 1);
                if (rest.startsWith(":")) {
                    try { r.port = Integer.parseInt(rest.substring(1)); }
                    catch (Exception e) { r.port = 0; }
                }
            }
            return r;
        }
        int idx = hp.lastIndexOf(':');
        if (idx >= 0 && hp.indexOf(':') == idx) { // یک دونقطه — IPv4/دامنه
            r.host = hp.substring(0, idx);
            try { r.port = Integer.parseInt(hp.substring(idx + 1)); }
            catch (Exception e) { r.port = 0; }
            return r;
        }
        if (idx >= 0) { // IPv6 بدون براکت با پورت؟ نامعتبر — کلش میزبان
            r.host = hp; r.port = 0; return r;
        }
        r.host = hp; r.port = 0;
        return r;
    }

    private static Map<String, String> parseQuery(String qs) {
        Map<String, String> q = new HashMap<>();
        if (qs == null || qs.isEmpty()) return q;
        for (String part : qs.split("&")) {
            if (part.isEmpty()) continue;
            int eq = part.indexOf('=');
            String k, v;
            if (eq < 0) { k = part; v = ""; }
            else { k = part.substring(0, eq); v = part.substring(eq + 1); }
            if (!q.containsKey(k)) q.put(k, v);
        }
        return q;
    }

    private static String urlDecode(String s) {
        if (s == null) return "";
        try { return java.net.URLDecoder.decode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }

    /** مثل unquote() پایتون: فقط %XX — علامت + دست‌نخورده می‌ماند (مهم برای پسوردِ تروجان). */
    private static String pctDecode(String s) {
        if (s == null || s.isEmpty() || s.indexOf('%') < 0) return s == null ? "" : s;
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        byte[] raw = s.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < raw.length; i++) {
            if (raw[i] == '%' && i + 2 < raw.length) {
                int hi = Character.digit((char) raw[i + 1], 16);
                int lo = Character.digit((char) raw[i + 2], 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            out.write(raw[i]);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static Node parseVmess(String payload) {
        JSONObject data = null;
        try { data = new JSONObject(payload); } catch (Exception ignored) {}
        if (data == null) {
            String dec = b64d(payload);
            if (!dec.isEmpty()) {
                try { data = new JSONObject(dec); } catch (Exception ignored) { return null; }
            }
        }
        if (data == null) return null;
        String server = optS(data, "add", "").trim();
        int port = 0;
        try { port = (int) Double.parseDouble(optS(data, "port", "0")); } catch (Exception ignored) {}
        String uid = optS(data, "id", "").trim();
        if (server.isEmpty() || port <= 0 || port >= 65536 || uid.isEmpty()) return null;
        String net = optS(data, "net", "tcp").toLowerCase();
        if (net.isEmpty()) net = "tcp";
        if (net.equals("h2")) net = "http";
        if (!SUPPORTED_NETS.contains(net)) return null;
        Map<String, String> extra = new HashMap<>();
        extra.put("id", uid);
        extra.put("aid", optS(data, "aid", "0").isEmpty() ? "0" : optS(data, "aid", "0"));
        extra.put("scy", optS(data, "scy", "auto").isEmpty() ? "auto" : optS(data, "scy", "auto"));
        extra.put("net", net);
        extra.put("path", optS(data, "path", ""));
        extra.put("host", optS(data, "host", ""));
        extra.put("sec", optS(data, "tls", "").equalsIgnoreCase("tls") ? "tls" : "");
        extra.put("sni", optS(data, "sni", ""));
        extra.put("fp", optS(data, "fp", ""));
        extra.put("alpn", optS(data, "alpn", ""));
        String name = optS(data, "ps", "").trim();
        if (name.isEmpty()) name = "VMess";
        Node n = new Node("vmess", name, server, port);
        n.extra = extra;
        return n;
    }

    /** مثل str(data.get(k) or default) پایتون — مقدارِ null/missing → default. */
    private static String optS(JSONObject d, String k, String def) {
        Object o = d.opt(k);
        if (o == null || o == JSONObject.NULL) return def;
        String s = String.valueOf(o);
        return s == null ? def : s;
    }

    private static Node parseUserInfoScheme(String scheme, String rest, String defaultSec) {
        String body = rest, frag = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) { body = rest.substring(0, hash); frag = rest.substring(hash + 1); }
        int at = body.indexOf('@');
        if (at < 0) return null;
        String userinfo = body.substring(0, at);
        String hostport = body.substring(at + 1);
        Map<String, String> q = new HashMap<>();
        int qm = hostport.indexOf('?');
        if (qm >= 0) {
            q = parseQuery(hostport.substring(qm + 1));
            hostport = hostport.substring(0, qm);
        }
        HostPort hp = splitHostport(hostport);
        if (hp.host == null || hp.host.isEmpty() || hp.port <= 0 || hp.port >= 65536) return null;

        String net = (q.containsKey("type") ? q.get("type") : "tcp").toLowerCase();
        if (net.equals("h2")) net = "http";
        if (net.equals("raw")) net = "tcp";
        if (!SUPPORTED_NETS.contains(net)) return null;
        Map<String, String> extra = new HashMap<>();
        extra.put("net", net);
        extra.put("sec", q.containsKey("security") ? q.get("security").toLowerCase() : "");
        String sniV = q.containsKey("sni") ? q.get("sni") : "";
        if (sniV.isEmpty()) sniV = q.containsKey("peer") ? q.get("peer") : "";
        extra.put("sni", sniV);
        extra.put("fp", q.get("fp") != null ? q.get("fp") : "");
        extra.put("pbk", q.get("pbk") != null ? q.get("pbk") : "");
        extra.put("sid", q.get("sid") != null ? q.get("sid") : "");
        extra.put("spx", q.get("spx") != null ? q.get("spx") : "");
        extra.put("flow", q.get("flow") != null ? q.get("flow") : "");
        extra.put("path", pctDecode(q.get("path") != null ? q.get("path") : ""));
        extra.put("host", pctDecode(q.get("host") != null ? q.get("host") : ""));
        extra.put("serviceName", pctDecode(q.get("serviceName") != null ? q.get("serviceName") : ""));
        extra.put("alpn", q.get("alpn") != null ? q.get("alpn") : "");
        String ident;
        if (scheme.equals("trojan")) {
            extra.put("password", pctDecode(userinfo));
            if (extra.get("sec").isEmpty() && defaultSec != null) extra.put("sec", defaultSec);
            ident = extra.get("password");
        } else {
            extra.put("id", userinfo.trim());
            ident = extra.get("id");
        }
        if (ident == null || ident.isEmpty() || ident.contains(" ")) return null;
        String name = pctDecode(frag).trim();
        if (name.isEmpty()) name = scheme.toUpperCase();
        Node n = new Node(scheme, name, hp.host, hp.port);
        n.extra = extra;
        return n;
    }

    private static Node parseSs(String rest) {
        String body = rest, frag = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) { body = rest.substring(0, hash); frag = rest.substring(hash + 1); }
        int qm = body.indexOf('?');
        if (qm >= 0) {
            Map<String, String> q = parseQuery(body.substring(qm + 1));
            if (q.containsKey("plugin")) return null;
            body = body.substring(0, qm);
        }
        String method = "", password = "", host = "";
        int port = 0;
        int at = body.lastIndexOf('@');
        if (at >= 0) {
            String userinfo = body.substring(0, at);
            String hostport = body.substring(at + 1);
            if (!userinfo.contains(":")) {
                String dec = b64d(userinfo);
                if (!dec.contains(":")) return null;
                userinfo = dec;
            }
            if (!userinfo.contains(":")) userinfo = pctDecode(userinfo);
            int c = userinfo.indexOf(':');
            if (c < 0) return null;
            method = userinfo.substring(0, c);
            password = userinfo.substring(c + 1);
            HostPort hp = splitHostport(hostport);
            host = hp.host; port = hp.port;
        } else {
            String dec = b64d(body);
            Matcher m = SS_PLAIN_RE.matcher(dec);
            if (!m.find()) return null;
            method = m.group("method");
            password = m.group("pw");
            host = m.group("host");
            try { port = Integer.parseInt(m.group("port")); } catch (Exception e) { return null; }
        }
        if (host == null || host.isEmpty() || port <= 0 || port >= 65536
                || method.isEmpty() || password.isEmpty()) return null;
        if (!SS_METHOD_RE.matcher(method).matches()) return null;
        Node n = new Node("ss", pctDecode(frag).trim().isEmpty() ? "Shadowsocks" : pctDecode(frag).trim(), host, port);
        n.extra.put("method", method);
        n.extra.put("password", password);
        return n;
    }

    public static Node parseUri(String uri) {
        if (uri == null) return null;
        uri = uri.trim();
        if (uri.isEmpty() || uri.startsWith("#") || uri.startsWith("//")) return null;
        String low = uri.toLowerCase();
        Node n;
        try {
            if (low.startsWith("vmess://")) n = parseVmess(uri.substring(8));
            else if (low.startsWith("vless://")) n = parseUserInfoScheme("vless", uri.substring(8), "");
            else if (low.startsWith("trojan://")) n = parseUserInfoScheme("trojan", uri.substring(9), "tls");
            else if (low.startsWith("ss://")) n = parseSs(uri.substring(5));
            else return null;
        } catch (Exception e) { return null; }
        if (n != null) n.uri = uri;
        return n;
    }

    public static List<String> decodeSubscription(String text) {
        if (text == null) return new ArrayList<>();
        text = text.trim();
        if (text.isEmpty()) return new ArrayList<>();
        List<String> lines = new ArrayList<>();
        for (String l : text.split("\n")) {
            String t = l.trim();
            if (!t.isEmpty() && !t.startsWith("#") && !t.startsWith("//")) lines.add(t);
        }
        boolean anyScheme = false;
        for (String l : lines) if (l.contains("://")) { anyScheme = true; break; }
        if (anyScheme) {
            List<String> out = new ArrayList<>();
            for (String l : lines) if (l.contains("://")) out.add(l);
            return out;
        }
        StringBuilder joined = new StringBuilder();
        for (String l : lines) joined.append(l);
        String blob = b64d(joined.toString());
        if (blob.contains("://")) {
            List<String> out = new ArrayList<>();
            for (String l : blob.split("\n")) if (l.contains("://")) out.add(l.trim());
            return out;
        }
        List<String> out = new ArrayList<>();
        for (String l : lines) {
            String dec = b64d(l);
            if (dec.contains("://")) {
                for (String x : dec.split("\n")) if (x.contains("://")) out.add(x.trim());
            }
        }
        return out;
    }

    // ===================== ساخت کانفیگ Xray =====================
    /**
     * پورتِ build_outbound — با این تفاوتِ اندروید: اتصالِ خروجیِ Xray به
     * «رله‌ی محافظ» (127.0.0.1:connectPort) می‌رود تا سوکت با VpnService.protect باز شود
     * و حلقه‌ی TUN پیش نیاید. SNI و تنظیماتِ TLS همان سرور واقعی می‌مانند.
     */
    public static JSONObject buildOutbound(Node node, String connectHost, int connectPort) throws Exception {
        return buildOutbound(node, connectHost, connectPort, "proxy");
    }

    /** مثل بالا، با تگِ دلخواه — برای کانفیگِ دسته‌ای (چند نود در یک هسته) لازم است. */
    public static JSONObject buildOutbound(Node node, String connectHost, int connectPort,
                                           String tag) throws Exception {
        Map<String, String> e = node.extra;
        String net = e.get("net");
        if (net == null || net.isEmpty()) net = "tcp";
        if (!SUPPORTED_NETS.contains(net)) return null;
        JSONObject stream = new JSONObject();
        stream.put("network", net);
        stream.put("security", "none");
        String sec = str(e.get("sec")).toLowerCase();
        String sni = e.get("sni") == null || e.get("sni").isEmpty() ? node.server : e.get("sni");
        String fp = e.get("fp") == null || e.get("fp").isEmpty() ? "chrome" : e.get("fp");
        if (node.proto.equals("trojan") && sec.isEmpty()) sec = "tls";
        if (sec.equals("tls")) {
            JSONObject tls = new JSONObject();
            tls.put("serverName", sni);
            tls.put("fingerprint", fp);
            tls.put("allowInsecure", true);
            List<String> alpn = new ArrayList<>();
            if (e.get("alpn") != null)
                for (String a : e.get("alpn").split(",")) if (!a.trim().isEmpty()) alpn.add(a.trim());
            if (!alpn.isEmpty()) tls.put("alpn", new JSONArray(alpn));
            stream.put("security", "tls");
            stream.put("tlsSettings", tls);
        } else if (sec.equals("reality")) {
            if (e.get("pbk") == null || e.get("pbk").isEmpty()) return null;
            JSONObject rs = new JSONObject();
            rs.put("serverName", sni);
            rs.put("fingerprint", fp);
            rs.put("publicKey", e.get("pbk"));
            rs.put("shortId", str(e.get("sid")));
            rs.put("spiderX", e.get("spx") == null || e.get("spx").isEmpty() ? "/" : e.get("spx"));
            stream.put("security", "reality");
            stream.put("realitySettings", rs);
        }
        if (net.equals("ws")) {
            JSONObject w = new JSONObject();
            w.put("path", e.get("path") == null || e.get("path").isEmpty() ? "/" : e.get("path"));
            w.put("headers", new JSONObject().put("Host",
                    e.get("host") == null || e.get("host").isEmpty() ? sni : e.get("host")));
            stream.put("wsSettings", w);
        } else if (net.equals("grpc")) {
            JSONObject g = new JSONObject();
            String svc = e.get("serviceName") != null && !e.get("serviceName").isEmpty()
                    ? e.get("serviceName") : (e.get("path") != null ? e.get("path") : "");
            g.put("serviceName", svc);
            g.put("multiMode", false);
            stream.put("grpcSettings", g);
        } else if (net.equals("http")) {
            JSONObject h = new JSONObject();
            h.put("host", new JSONArray().put(
                    e.get("host") == null || e.get("host").isEmpty() ? sni : e.get("host")));
            h.put("path", e.get("path") == null || e.get("path").isEmpty() ? "/" : e.get("path"));
            stream.put("httpSettings", h);
        } else if (net.equals("httpupgrade")) {
            JSONObject h = new JSONObject();
            h.put("path", e.get("path") == null || e.get("path").isEmpty() ? "/" : e.get("path"));
            h.put("host", e.get("host") == null || e.get("host").isEmpty() ? sni : e.get("host"));
            stream.put("httpupgradeSettings", h);
        } else if (net.equals("xhttp")) {
            JSONObject h = new JSONObject();
            h.put("path", e.get("path") == null || e.get("path").isEmpty() ? "/" : e.get("path"));
            h.put("host", e.get("host") == null || e.get("host").isEmpty() ? sni : e.get("host"));
            h.put("mode", e.get("mode") == null || e.get("mode").isEmpty() ? "auto" : e.get("mode"));
            stream.put("xhttpSettings", h);
        }

        JSONObject out = new JSONObject();
        out.put("tag", tag == null || tag.isEmpty() ? "proxy" : tag);
        JSONObject settings = new JSONObject();
        if (node.proto.equals("vmess")) {
            int aid = 0;
            try { aid = (int) Double.parseDouble(str(e.get("aid"))); } catch (Exception ignored) {}
            JSONObject user = new JSONObject();
            user.put("id", e.get("id"));
            user.put("alterId", aid);
            user.put("security", e.get("scy") == null || e.get("scy").isEmpty() ? "auto" : e.get("scy"));
            user.put("level", 0);
            JSONObject v = new JSONObject();
            v.put("address", connectHost);
            v.put("port", connectPort);
            v.put("users", new JSONArray().put(user));
            settings.put("vnext", new JSONArray().put(v));
            out.put("protocol", "vmess");
            out.put("settings", settings);
            out.put("streamSettings", stream);
            out.put("mux", new JSONObject().put("enabled", false));
            return out;
        }
        if (node.proto.equals("vless")) {
            JSONObject user = new JSONObject();
            user.put("id", e.get("id"));
            user.put("encryption", "none");
            user.put("level", 0);
            String flow = e.get("flow");
            if (flow != null && !flow.isEmpty() && (sec.equals("tls") || sec.equals("reality")) && net.equals("tcp"))
                user.put("flow", flow);
            JSONObject v = new JSONObject();
            v.put("address", connectHost);
            v.put("port", connectPort);
            v.put("users", new JSONArray().put(user));
            settings.put("vnext", new JSONArray().put(v));
            out.put("protocol", "vless");
            out.put("settings", settings);
            out.put("streamSettings", stream);
            return out;
        }
        if (node.proto.equals("trojan")) {
            JSONObject s = new JSONObject();
            s.put("address", connectHost);
            s.put("port", connectPort);
            s.put("password", e.get("password"));
            s.put("level", 0);
            settings.put("servers", new JSONArray().put(s));
            out.put("protocol", "trojan");
            out.put("settings", settings);
            out.put("streamSettings", stream);
            return out;
        }
        if (node.proto.equals("ss")) {
            JSONObject s = new JSONObject();
            s.put("address", connectHost);
            s.put("port", connectPort);
            s.put("method", e.get("method"));
            s.put("password", e.get("password"));
            s.put("uot", true);
            settings.put("servers", new JSONArray().put(s));
            out.put("protocol", "shadowsocks");
            out.put("settings", settings);
            out.put("streamSettings", new JSONObject().put("network", "tcp").put("security", "none"));
            return out;
        }
        return null;
    }

    /** سرور واقعی که رله باید به آن وصل شود (برای ProtRelay). */
    public static String realHost(Node node) { return node.server; }
    public static int realPort(Node node) { return node.port; }

    /** پورتِ build_xray_config — اینباندِ socks + API آمار (v1.8). */
    public static JSONObject buildXrayConfig(Node node, int socksPort, int apiPort,
                                             String connectHost, int connectPort) throws Exception {
        JSONObject outbound = buildOutbound(node, connectHost, connectPort, "proxy");
        if (outbound == null) return null;
        JSONObject sniffing = new JSONObject();
        sniffing.put("enabled", true);
        sniffing.put("destOverride", new JSONArray().put("http").put("tls"));
        JSONArray inbounds = new JSONArray();
        JSONObject socksIn = new JSONObject();
        socksIn.put("tag", "socks-in");
        socksIn.put("listen", "127.0.0.1");
        socksIn.put("port", socksPort);
        socksIn.put("protocol", "socks");
        socksIn.put("settings", new JSONObject().put("auth", "noauth").put("udp", true));
        socksIn.put("sniffing", sniffing);
        inbounds.put(socksIn);
        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "warning"));
        cfg.put("inbounds", inbounds);
        JSONArray outbounds = new JSONArray();
        outbounds.put(outbound);
        outbounds.put(new JSONObject().put("tag", "direct").put("protocol", "freedom"));
        cfg.put("outbounds", outbounds);
        // API آمار — فقط برای اتصالِ اصلی (تست‌ها سبک می‌مانند) — مثل ویندوز
        if (apiPort > 0) {
            JSONObject api = new JSONObject();
            api.put("tag", "api");
            api.put("listen", "127.0.0.1");
            api.put("port", apiPort);
            api.put("protocol", "dokodemo-door");
            api.put("settings", new JSONObject().put("address", "127.0.0.1"));
            inbounds.put(api);
            cfg.put("stats", new JSONObject());
            cfg.put("api", new JSONObject().put("tag", "api")
                    .put("services", new JSONArray().put("StatsService")));
            JSONObject policy = new JSONObject();
            policy.put("levels", new JSONObject().put("0", new JSONObject()
                    .put("statsUserUplink", true).put("statsUserDownlink", true)));
            policy.put("system", new JSONObject()
                    .put("statsInboundUplink", true).put("statsInboundDownlink", true)
                    .put("statsOutboundUplink", true).put("statsOutboundDownlink", true));
            cfg.put("policy", policy);

            // ===== v1.8.3 — معماریِ ویندوز در حالتِ TUN بازسازی شد =====
            // ویندوز پروکسیِ سیستمی (TCP خالص) است: دامنه‌ها سمتِ سرور حل می‌شوند،
            // QUIC اصلا در مسیر نیست. روی اندروید (TUN) باید همان رفتار ساخته شود:
            //  ۱) DNS-hijack پورتِ 53 → ماژولِ DNS با DoH از داخلِ تونل (TCP) —
            //     دیگر وابسته به UDPِ سرور نیست (برای تروجان/سرورهای بدونِ UDP هم کار می‌کند)
            //     و با queryStrategy=UseIPv4 هیچ AAAA برنمی‌گردد → stallِ IPv6 حذف می‌شود.
            //  ۲) بستنِ QUIC (UDP 443) → اپ‌ها فوراً روی TCP/TLS می‌افتند —
            //     پایانِ کندیِ HTTP/3 روی سرورهای رایگان.
            JSONObject dns = new JSONObject();
            dns.put("queryStrategy", "UseIPv4");
            dns.put("disableCache", false);
            JSONArray dservers = new JSONArray();
            dservers.put(new JSONObject().put("address", "https://1.1.1.1/dns-query"));
            dservers.put(new JSONObject().put("address", "https://8.8.8.8/dns-query"));
            dservers.put(new JSONObject().put("address", "https://1.1.1.1/dns-query")
                    .put("detour", "direct"));
            dns.put("servers", dservers);
            cfg.put("dns", dns);

            JSONArray rules = new JSONArray();
            rules.put(new JSONObject().put("type", "field")
                    .put("inboundTag", new JSONArray().put("api"))
                    .put("outboundTag", "api"));
            rules.put(new JSONObject().put("type", "field")
                    .put("port", "53").put("network", "tcp,udp")
                    .put("outboundTag", "dns-out"));
            rules.put(new JSONObject().put("type", "field")
                    .put("port", "443").put("network", "udp")
                    .put("outboundTag", "block"));
            cfg.put("routing", new JSONObject().put("rules", rules));

            JSONArray outs = cfg.getJSONArray("outbounds");
            // «direct» در بدنه‌ی اصلی کانفیگ قبلا اضافه شده است — فقط dns-out و block اضافه می‌شود
            // (تگِ تکراری باعث می‌شود هسته اصلا بالا نیاید: "existing tag found: direct")
            outs.put(new JSONObject().put("tag", "dns-out").put("protocol", "dns"));
            outs.put(new JSONObject().put("tag", "block").put("protocol", "blackhole"));
        }
        return cfg;
    }

    /**
     * v1.8.3 — کانفیگِ «تستِ پینگِ دسته‌ای»: یک هسته‌ی Xray با N اینباند/اوت‌باند.
     * هر نود اینباندِ socks خودش و اوت‌باندِ خودش را دارد و قاعده‌ی routing هر اینباند
     * را به اوت‌باندِ همان نود می‌برد. به‌جای N پروسه‌ی Xray (~۳۶MB هرکدام)، یک پروسه —
     * پینگِ گوشی چند برابر سریع‌تر. نگاشتِ نود→پورت در portOf برگردانده می‌شود
     * (نودهای نامعتبر حذف می‌شوند و پورتی نمی‌گیرند).
     */
    public static JSONObject buildBatchLatencyConfig(List<Node> nodes, int basePort,
                                                     Map<Node, Integer> portOf) throws Exception {
        JSONArray inbounds = new JSONArray();
        JSONArray outbounds = new JSONArray();
        JSONArray rules = new JSONArray();
        JSONObject sniffing = new JSONObject();
        sniffing.put("enabled", true);
        sniffing.put("destOverride", new JSONArray().put("http").put("tls"));
        int kept = 0;
        for (Node node : nodes) {
            if (node == null) continue;
            JSONObject outbound;
            try { outbound = buildOutbound(node, node.server, node.port, "out" + kept); }
            catch (Exception e) { outbound = null; }
            if (outbound == null) continue;      // نودِ نامعتبر — فقط خودش حذف می‌شود
            JSONObject in = new JSONObject();
            in.put("tag", "in" + kept);
            in.put("listen", "127.0.0.1");
            in.put("port", basePort + kept);
            in.put("protocol", "socks");
            in.put("settings", new JSONObject().put("auth", "noauth").put("udp", false));
            in.put("sniffing", sniffing);
            inbounds.put(in);
            outbounds.put(outbound);
            rules.put(new JSONObject().put("type", "field")
                    .put("inboundTag", new JSONArray().put("in" + kept))
                    .put("outboundTag", "out" + kept));
            if (portOf != null) portOf.put(node, basePort + kept);
            kept++;
        }
        if (kept == 0) return null;
        JSONObject cfg = new JSONObject();
        cfg.put("log", new JSONObject().put("loglevel", "error"));
        cfg.put("inbounds", inbounds);
        cfg.put("outbounds", outbounds);
        cfg.put("routing", new JSONObject().put("rules", rules));
        return cfg;
    }

    public static String utcNow() {
        try {
            java.text.SimpleDateFormat f = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm 'UTC'", java.util.Locale.US);
            f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
            return f.format(new java.util.Date());
        } catch (Exception e) { return ""; }
    }

    public static String join(String sep, List<String> parts) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(p);
        }
        return sb.toString();
    }

    // ===================== استخراج کانفیگ از پاسخ هوش مصنوعی =====================
    public static List<String>[] extractUrisFromAi(String text) {
        List<String> uris = new ArrayList<>();
        List<String> subs = new ArrayList<>();
        if (text != null) {
            Matcher m = AI_URI_RE.matcher(text);
            while (m.find()) {
                String u = m.group(0).replaceAll("[.,;)]+$", "");
                if (!uris.contains(u)) uris.add(u);
            }
            m = AI_SUB_RE.matcher(text);
            while (m.find()) {
                String u = m.group(0).replaceAll("[.,;)]+$", "");
                if (u.contains("pollinations") || u.contains("github.com/XTLS")) continue;
                if (!subs.contains(u)) subs.add(u);
            }
        }
        List<String>[] out = new List[2];
        out[0] = uris.size() > AI_RESCUE_MAX_URIS ? uris.subList(0, AI_RESCUE_MAX_URIS) : uris;
        out[1] = subs.size() > AI_RESCUE_MAX_LINKS ? subs.subList(0, AI_RESCUE_MAX_LINKS) : subs;
        return out;
    }

    public static String buildRescuePrompt(int fetched, int tcpAlive, int latencyOk,
                                           int verified, int usable, Map<String, Integer> reasons,
                                           int roundNo) {
        String when = utcNow();
        StringBuilder sb = new StringBuilder();
        sb.append("I maintain an open-source, personal VPN client (parses vless:// vmess:// trojan:// ss:// URIs). Today, ")
          .append(when).append(", its automated test run failed:\n");
        sb.append("- ").append(fetched).append(" configs fetched from public aggregator feeds, ")
          .append(tcpAlive).append(" reachable by TCP, ").append(latencyOk).append(" passed ping, ")
          .append(verified).append(" opened real sites, ").append(usable).append(" had usable download speed.\n");
        if (reasons != null && !reasons.isEmpty()) {
            StringBuilder rs = new StringBuilder();
            int i = 0;
            for (Map.Entry<String, Integer> en : reasons.entrySet()) {
                if (i++ >= 5) break;
                if (rs.length() > 0) rs.append(", ");
                rs.append(en.getKey()).append("=").append(en.getValue());
            }
            sb.append("- Speed-test rejection reasons: ").append(rs).append(".\n");
        }
        sb.append("- The public subscription feeds it reads were all stale or dead today.\n\n");
        sb.append("Please reply with:\n");
        sb.append("1) Public GitHub repositories or raw.githubusercontent.com subscription URLs that are ACTIVELY ")
          .append("UPDATED (ideally daily, by automation) and publish free vless/vmess/trojan/shadowsocks config lists.\n");
        sb.append("2) Up to 10 example config URIs from such public lists, in standard URI format ")
          .append("(vless://... vmess://... trojan://... ss://...).\n");
        if (roundNo != 0)
            sb.append("Prefer less-known sources than the usual big Telegram aggregators.\n");
        sb.append("\nOutput format: one item per line (URLs and URIs mixed). No explanations, no markdown, no code fences.\n");
        return sb.toString();
    }

    /** حداکثر ۳ کانفیگ از هر سرور + حذف تکراری — مثل fetch_all ویندوز. */
    public static List<Node> dedupeNodes(List<Node> parsed, int maxNodes) {
        List<Node> nodes = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        Map<String, Integer> perServer = new HashMap<>();
        for (Node n : parsed) {
            if (n == null) continue;
            String k = n.key();
            if (seen.contains(k)) continue;
            String sk = n.server.toLowerCase() + "|" + n.port;
            Integer c = perServer.get(sk);
            if (c != null && c >= 3) continue;
            seen.add(k);
            perServer.put(sk, c == null ? 1 : c + 1);
            nodes.add(n);
            if (nodes.size() >= maxNodes) break;
        }
        return nodes;
    }

    public static boolean isModernSs(String method) {
        String m = method == null ? "" : method.toLowerCase();
        for (String s : MODERN_SS_METHODS) if (s.equals(m)) return true;
        return false;
    }
}
