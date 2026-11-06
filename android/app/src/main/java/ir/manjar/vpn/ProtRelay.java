package ir.manjar.vpn;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * رله‌ی محافظ (حل‌کننده‌ی حلقه‌ی TUN در اندروید)
 * =============================================
 * هسته‌ی Xray به‌صورت زیرپروسه اجرا می‌شود و نمی‌تواند سوکت‌هایش را با
 * VpnService.protect() از تونل خارج کند؛ بدون این رله، اتصالِ خروجیِ Xray به
 * سرور دوباره وارد TUN می‌شود و حلقه‌ی بی‌پایان می‌سازد.
 * راه‌حل: خروجیِ Xray در کانفیگ به 127.0.0.1:relayPort بازنویسی می‌شود
 * (SNI/Reality همان سرور واقعی می‌مانند) و این رله:
 *   ۱) TCP: پذیرش از Xray → سوکت جدید با protect() → اتصال به سرور واقعی → لوله‌کشی دوسویه
 *   ۲) UDP: انتقال دیتاگرام‌های Shadowsocks-UDP به سرور واقعی با سوکتِ protect شده
 */
public class ProtRelay {

    public interface Protector {
        boolean protect(Socket s);
        boolean protect(DatagramSocket s);
    }

    private final Protector protector;
    private final String realHost;
    private final int realPort;
    private final int listenPort;
    private volatile boolean running = false;
    private ServerSocket server;
    private DatagramSocket udpSock;
    private Thread acceptThread, udpThread;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final Map<String, DatagramSocket> udpPeers = new ConcurrentHashMap<>();

    public ProtRelay(Protector protector, String realHost, int realPort, int listenPort) {
        this.protector = protector;
        this.realHost = realHost;
        this.realPort = realPort;
        this.listenPort = listenPort;
    }

    public int port() { return listenPort; }

    public synchronized void start() throws IOException {
        if (running) return;
        server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress("127.0.0.1", listenPort), 64);
        running = true;
        acceptThread = new Thread(this::acceptLoop, "manjar-relay-tcp");
        acceptThread.setDaemon(true);
        acceptThread.start();
        // UDP relay (فقط برای ss بدون UoT — اکثر پروتکل‌ها UDP را روی TCP می‌برند)
        try {
            udpSock = new DatagramSocket(null);
            udpSock.setReuseAddress(true);
            udpSock.bind(new InetSocketAddress("127.0.0.1", listenPort));
            udpThread = new Thread(this::udpLoop, "manjar-relay-udp");
            udpThread.setDaemon(true);
            udpThread.start();
        } catch (Exception ignored) {
            udpSock = null; // TCP-only
        }
    }

    public synchronized void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (Exception ignored) {}
        try { if (udpSock != null) udpSock.close(); } catch (Exception ignored) {}
        for (DatagramSocket s : udpPeers.values()) {
            try { s.close(); } catch (Exception ignored) {}
        }
        udpPeers.clear();
        pool.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            Socket from;
            try {
                from = server.accept();
            } catch (Exception e) {
                if (running) continue; else break;
            }
            pool.submit(() -> handleTcp(from));
        }
    }

    private void handleTcp(Socket from) {
        Socket to = new Socket();
        try {
            from.setTcpNoDelay(true);
            if (protector != null) protector.protect(to);
            to.connect(new InetSocketAddress(realHost, realPort), 8000);
            to.setTcpNoDelay(true);
            to.setSoTimeout(0);
            InputStream in1 = from.getInputStream(), in2 = to.getInputStream();
            OutputStream o1 = from.getOutputStream(), o2 = to.getOutputStream();
            Thread t1 = new Thread(() -> pipe(in1, o2, from, to));
            Thread t2 = new Thread(() -> pipe(in2, o1, to, from));
            t1.start(); t2.start();
            t1.join();
            t2.join();
        } catch (Exception ignored) {
        } finally {
            try { from.close(); } catch (Exception ignored) {}
            try { to.close(); } catch (Exception ignored) {}
        }
    }

    private void pipe(InputStream in, OutputStream out, Socket a, Socket b) {
        byte[] buf = new byte[65536];
        try {
            int n;
            while (running && (n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (Exception ignored) {
        } finally {
            try { a.close(); } catch (Exception ignored) {}
            try { b.close(); } catch (Exception ignored) {}
        }
    }

    private void udpLoop() {
        byte[] buf = new byte[65535];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        while (running) {
            try {
                udpSock.receive(p);
                if (p.getLength() <= 0) continue;
                final DatagramPacket copy = new DatagramPacket(p.getData(), p.getLength(),
                        p.getAddress(), p.getPort());
                String peer = p.getAddress().getHostAddress() + ":" + p.getPort();
                DatagramSocket up = udpPeers.get(peer);
                if (up == null || up.isClosed()) {
                    up = new DatagramSocket();
                    if (protector != null) protector.protect(up);
                    udpPeers.put(peer, up);
                    final DatagramSocket ref = up;
                    final String key = peer;
                    Thread fwd = new Thread(() -> forwardUdpBack(ref, key));
                    fwd.setDaemon(true);
                    fwd.start();
                }
                InetAddress real = InetAddress.getByName(realHost);
                DatagramPacket outP = new DatagramPacket(copy.getData(), copy.getLength(), real, realPort);
                up.send(outP);
            } catch (SocketTimeoutException ignored) {
            } catch (Exception e) {
                if (!running) break;
            }
        }
    }

    private void forwardUdpBack(DatagramSocket up, String key) {
        byte[] buf = new byte[65535];
        DatagramPacket p = new DatagramPacket(buf, buf.length);
        try {
            while (running && !up.isClosed()) {
                try {
                    up.setSoTimeout(15000);
                    up.receive(p);
                    DatagramPacket back = new DatagramPacket(p.getData(), p.getLength(),
                            InetAddress.getByName("127.0.0.1"), Integer.parseInt(key.split(":")[1]));
                    udpSock.send(back);
                } catch (SocketTimeoutException te) {
                    break;
                }
            }
        } catch (Exception ignored) {
        } finally {
            try { up.close(); } catch (Exception ignored) {}
            udpPeers.remove(key);
        }
    }
}
