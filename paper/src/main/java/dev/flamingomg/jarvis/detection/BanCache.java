package dev.flamingomg.jarvis.detection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import dev.flamingomg.jarvis.config.ConfigManager;

import java.util.Set;
import java.util.concurrent.TimeUnit;

public final class BanCache {

    private record Entry(long expiryMs, long writtenAt) {}

    private static final long PERMANENT_MS = Long.MAX_VALUE / 2;

    private final Cache<String, Entry> banned;
    private final int defaultTtlSeconds;

    public BanCache(ConfigManager config) {
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
        long now = System.currentTimeMillis();
        banned.put(key(ip), new Entry(now + defaultTtlSeconds * 1_000L, now));
    }

    public void ban(String ip, int ttlSeconds) {
        long now = System.currentTimeMillis();
        long expiryMs = ttlSeconds > 0 ? now + ttlSeconds * 1_000L : PERMANENT_MS;
        banned.put(key(ip), new Entry(expiryMs, now));
    }

    public boolean isBanned(String ip) {
        return banned.getIfPresent(key(ip)) != null;
    }

    public void unban(String ip) {
        banned.invalidate(key(ip));
    }

    public void reconcilePermanent(Set<String> backendRawIps, long snapshotTs) {
        java.util.Set<String> keep = new java.util.HashSet<>();
        for (String ip : backendRawIps) keep.add(key(ip));
        banned.asMap().forEach((k, e) -> {
            if (e.expiryMs() == PERMANENT_MS && e.writtenAt() < snapshotTs && !keep.contains(k)) {
                banned.invalidate(k);
            }
        });
    }

    private static String key(String ip) {
        if (ip == null || ip.indexOf(':') < 0) return ip;
        try {
            return java.net.InetAddress.getByName(ip).getHostAddress();
        } catch (Exception e) {
            return ip;
        }
    }

    public void clear() {
        banned.invalidateAll();
    }

    public long size() {
        return banned.estimatedSize();
    }
}
