package dev.flamingomg.jarvis.detection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import dev.flamingomg.jarvis.config.ConfigManager;

import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class BanCache {

    private record Entry(long expiryMs, long writtenAt, boolean deLaLista, String msgKey) {}

    private static final long PERMANENT_MS = Long.MAX_VALUE / 2;

    private final Cache<String, Entry> banned;
    private final ConfigManager config;

    private volatile BanSnapshot snapshot;

    private volatile int defaultTtlSeconds;

    public BanCache(ConfigManager config) {
        this(config, null);
    }

    public BanCache(ConfigManager config, dev.flamingomg.jarvis.util.Log logger) {
        this.config = config;
        if (logger != null && config.getBoolean("bans.persist", true)) {
            BanSnapshot s = new BanSnapshot(config.dataDirectory(), logger);
            s.cargar(licenciaActual(), System.currentTimeMillis());
            this.snapshot = s;
        }
        this.defaultTtlSeconds = Math.max(10, config.getInt("bans.local-ttl-seconds", 300));
        this.banned = Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfter(new Expiry<String, Entry>() {
                    public long expireAfterCreate(String k, Entry e, long now) {
                        long delay = e.expiryMs() - System.currentTimeMillis();
                        return TimeUnit.MILLISECONDS.toNanos(Math.max(delay, 1_000));
                    }
                    public long expireAfterUpdate(String k, Entry e, long now, long dur) {
                        return expireAfterCreate(k, e, now);
                    }
                    public long expireAfterRead(String k, Entry e, long now, long dur) {
                        return dur;
                    }
                })
                .build();
    }

    public void ban(String ip) {

        ban(ip, "vpn_proxy");
    }

    public void ban(String ip, String msgKey) {
        long now = System.currentTimeMillis();
        banned.put(key(ip), new Entry(now + defaultTtlSeconds * 1_000L, now, false, msgKey));
    }

    public void ban(String ip, int ttlSeconds) {
        ban(ip, ttlSeconds, null);
    }

    public void ban(String ip, int ttlSeconds, String msgKey) {
        long now = System.currentTimeMillis();
        long expiryMs = ttlSeconds > 0 ? now + ttlSeconds * 1_000L : PERMANENT_MS;
        banned.put(key(ip), new Entry(expiryMs, now, true, msgKey));
    }

    public String msgKeyDe(String ip) {
        Entry e = banned.getIfPresent(key(ip));
        return e == null ? null : e.msgKey();
    }

    public boolean isBanned(String ip) {
        String k = key(ip);
        if (banned.getIfPresent(k) != null) return true;

        BanSnapshot s = snapshot;
        return s != null && s.cubre(k, licenciaActual());
    }

    public void unban(String ip) {
        String k = key(ip);
        banned.invalidate(k);

        BanSnapshot s = snapshot;
        if (s != null) s.olvidar(k);
    }

    public void unbanTodos(java.util.Collection<String> ips) {
        if (ips == null || ips.isEmpty()) return;
        java.util.List<String> claves = new java.util.ArrayList<>(ips.size());
        for (String ip : ips) {
            if (ip == null) continue;
            String k = key(ip);
            banned.invalidate(k);
            claves.add(k);
        }
        BanSnapshot s = snapshot;
        if (s != null) s.olvidar(claves);
    }

    public void reconciliar(Set<String> backendRawIps, long snapshotTs) {
        java.util.Set<String> keep = new java.util.HashSet<>();
        for (String ip : backendRawIps) keep.add(key(ip));
        banned.asMap().forEach((k, e) -> {
            if (e.deLaLista() && e.writtenAt() < snapshotTs && !keep.contains(k)) {
                banned.invalidate(k);
            }
        });

    }

    private String licenciaActual() {
        return config.getString("backend.license-key", "");
    }

    private static String key(String ip) {
        if (ip == null || ip.indexOf(':') < 0) return ip;
        try {
            return java.net.InetAddress.getByName(ip).getHostAddress();
        } catch (Exception e) {
            return ip;
        }
    }

    public void reconfigure() {
        this.defaultTtlSeconds = Math.max(10, config.getInt("bans.local-ttl-seconds", 300));
    }

    public void listaAplicada(Set<String> ipsDeLaLista, boolean listaCertificada) {
        BanSnapshot s = snapshot;
        if (s == null) return;
        java.util.Set<String> keep = new java.util.HashSet<>();
        for (String ip : ipsDeLaLista) keep.add(key(ip));

        java.util.Map<String, Long> conCaducidad = new java.util.HashMap<>();
        banned.asMap().forEach((k, e) -> { if (keep.contains(k)) conCaducidad.put(k, e.expiryMs()); });

        if (!conCaducidad.isEmpty() || listaCertificada) {
            s.guardar(licenciaActual(), conCaducidad, System.currentTimeMillis());
        }

        s.descartar();
    }

    public void clear() {
        banned.invalidateAll();

        BanSnapshot s = snapshot;
        if (s != null) s.descartar();
    }

    public long size() {
        BanSnapshot s = snapshot;
        return banned.estimatedSize() + (s == null ? 0 : s.vigentes(licenciaActual()));
    }
}
