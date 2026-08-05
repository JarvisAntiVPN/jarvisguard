package dev.flamingomg.jarvis.client;

public final class ClockOffset {

    static final long MIN_APLICABLE_MS = 5_000L;

    static final long MAX_ABSOLUTO_MS = 365L * 86_400_000L;

    static final long MAX_RTT_MS = 10_000L;

    private volatile long offsetMs = 0L;

    public long now() {
        return System.currentTimeMillis() + offsetMs;
    }

    public long offsetMs() {
        return offsetMs;
    }

    static long correccion(long serverTimeMs, long t0, long t1) {
        if (serverTimeMs <= 0L || t1 < t0) return 0L;
        if (t1 - t0 > MAX_RTT_MS) return 0L;
        long delta = serverTimeMs - ((t0 + t1) / 2L);
        if (Math.abs(delta) < MIN_APLICABLE_MS) return 0L;
        if (Math.abs(delta) > MAX_ABSOLUTO_MS) return 0L;
        return delta;
    }

    public synchronized Long aprender(long serverTimeMs, long t0, long t1, long offsetAlEnviar) {
        if (offsetAlEnviar != offsetMs) return null;
        long ajuste = correccion(serverTimeMs, t0, t1);
        if (ajuste == 0L) return null;
        offsetMs += ajuste;
        return offsetMs;
    }

    public static long leerServerTimeMs(String cuerpo) {
        if (cuerpo == null || !cuerpo.contains("stale_timestamp")) return -1L;
        int i = cuerpo.indexOf("\"serverTimeMs\"");
        if (i < 0) return -1L;
        int j = i + "\"serverTimeMs\"".length();
        while (j < cuerpo.length() && (cuerpo.charAt(j) == ':' || cuerpo.charAt(j) == ' ')) j++;
        int k = j;
        while (k < cuerpo.length() && cuerpo.charAt(k) >= '0' && cuerpo.charAt(k) <= '9') k++;
        if (k == j || k - j > 18) return -1L;
        try {
            return Long.parseLong(cuerpo.substring(j, k));
        } catch (NumberFormatException e) {
            return -1L;
        }
    }
}
