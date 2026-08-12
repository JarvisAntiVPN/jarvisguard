package dev.flamingomg.jarvis.detection;

import java.util.concurrent.atomic.AtomicLong;

public final class PrivateIpWatch {

    static final long VENTANA_MS = 3_600_000L;

    private final String consejo;
    private final AtomicLong ultimoAviso = new AtomicLong(0L);

    private volatile String ultimaPrivada = null;
    private volatile long ultimaPrivadaMs = 0L;

    public PrivateIpWatch(String consejo) {
        this.consejo = consejo == null ? "" : consejo;
    }

    public static boolean noEsDeInternet(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String s = ip;
        int pct = s.indexOf('%');
        if (pct >= 0) s = s.substring(0, pct);
        if (s.regionMatches(true, 0, "::ffff:", 0, 7)) s = s.substring(7);

        if (s.indexOf(':') >= 0) {
            String l = s.toLowerCase(java.util.Locale.ROOT);
            if (l.equals("::1") || l.equals("0:0:0:0:0:0:0:1")) return true;
            if (l.equals("::")) return true;
            if (l.startsWith("fe80:")) return true;
            if (l.length() >= 2) {
                char c0 = l.charAt(0), c1 = l.charAt(1);
                if (c0 == 'f' && (c1 == 'c' || c1 == 'd')) return true;
            }
            return false;
        }

        int[] o = octetos(s);
        if (o == null) return false;
        if (o[0] == 10 || o[0] == 127 || o[0] == 0) return true;
        if (o[0] == 192 && o[1] == 168) return true;
        if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
        return o[0] == 169 && o[1] == 254;

    }

    private static int[] octetos(String s) {
        int[] out = new int[4];
        int idx = 0, val = 0, digitos = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                if (digitos == 0 || idx == 3) return null;
                out[idx++] = val;
                val = 0; digitos = 0;
            } else if (c >= '0' && c <= '9') {
                if (++digitos > 3) return null;
                val = val * 10 + (c - '0');
                if (val > 255) return null;
            } else {
                return null;
            }
        }
        if (idx != 3 || digitos == 0) return null;
        out[3] = val;
        return out;
    }

    boolean reclamaTurno(long ahoraMs) {
        long previo = ultimoAviso.get();
        if (previo != 0L && ahoraMs >= previo && ahoraMs - previo < VENTANA_MS) return false;
        return ultimoAviso.compareAndSet(previo, ahoraMs);
    }

    public String[] lineas(String ip, long ahoraMs) {
        if (!noEsDeInternet(ip)) return new String[0];

        ultimaPrivada = ip;
        ultimaPrivadaMs = ahoraMs;
        if (!reclamaTurno(ahoraMs)) return new String[0];
        return new String[]{
                "",
                "=============== JARVIS · CONNECTIONS ARE NOT BEING CHECKED ===============",
                "  We are receiving " + ip + ", which is a private/local address, not the",
                "  player's. Jarvis cannot check those connections and lets them through,",
                "  so right now they are NOT being protected.",
                "  " + consejo,
                "=========================================================================",
                ""
        };
    }

    public String privadaReciente(long ahoraMs, long ventanaMs) {
        String ip = ultimaPrivada;
        long t = ultimaPrivadaMs;
        if (ip == null || t == 0L) return null;
        if (ahoraMs < t) return ip;
        return ahoraMs - t <= ventanaMs ? ip : null;
    }
}
