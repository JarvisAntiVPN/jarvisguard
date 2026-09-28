package dev.flamingomg.jarvis.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class LocalDenialReporter {

    public interface Sender {
        void send(List<Entry> lote);
    }

    public record Entry(String reason, String ip, String username, int hits) {}

    public static final String FLOOD      = "FLOOD";
    public static final String LOCAL_BAN  = "LOCAL_BAN";
    public static final String MAX_PER_IP = "MAX_PER_IP";

    static final int MAX_KEYS = 2_000;
    static final int MAX_BATCH = 200;
    static final long FLUSH_INTERVAL_MS = 60_000L;

    private static final char SEP = (char) 0x1F;

    private final Map<String, AtomicInteger> counters = new ConcurrentHashMap<>();
    private final AtomicLong descartadas = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Sender sender;
    private final ScheduledExecutorService scheduler;

    public LocalDenialReporter(Sender sender) {
        this.sender = sender;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jarvis-local-denials");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        if (!running.compareAndSet(false, true)) return;
        scheduler.scheduleAtFixedRate(this::flushQuietly,
                FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    public void stop() {
        if (running.compareAndSet(true, false)) flushQuietly();
        scheduler.shutdownNow();
    }

    public void record(String reason, String ip, String username) {
        if (reason == null || ip == null || ip.isEmpty()) return;
        try {
            String name = username == null ? "" : username.toLowerCase(Locale.ROOT);
            String key = reason + SEP + ip + SEP + name;
            AtomicInteger c = counters.get(key);
            if (c != null) { c.incrementAndGet(); return; }
            if (counters.size() >= MAX_KEYS) { descartadas.incrementAndGet(); return; }
            AtomicInteger previo = counters.putIfAbsent(key, new AtomicInteger(1));
            if (previo != null) previo.incrementAndGet();
        } catch (Throwable ignored) {
        }
    }

    public long dropped() { return descartadas.get(); }

    public int pending() { return counters.size(); }

    List<Entry> drain() {
        List<Entry> out = new ArrayList<>();
        for (String key : new ArrayList<>(counters.keySet())) {
            if (out.size() >= MAX_BATCH) break;
            AtomicInteger c = counters.remove(key);
            if (c == null) continue;
            int hits = c.get();
            if (hits <= 0) continue;
            int a = key.indexOf(SEP);
            int b = key.indexOf(SEP, a + 1);
            if (a < 0 || b < 0) continue;
            String name = key.substring(b + 1);
            out.add(new Entry(key.substring(0, a), key.substring(a + 1, b), name.isEmpty() ? null : name, hits));
        }
        return out;
    }

    private void flushQuietly() {
        try {
            List<Entry> lote = drain();
            if (!lote.isEmpty() && sender != null) sender.send(lote);
        } catch (Throwable ignored) {
        }
    }
}
