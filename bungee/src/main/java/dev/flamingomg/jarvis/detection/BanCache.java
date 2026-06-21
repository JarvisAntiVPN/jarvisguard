package dev.flamingomg.jarvis.detection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import dev.flamingomg.jarvis.config.ConfigManager;

import java.util.concurrent.TimeUnit;

public final class BanCache {

    private final Cache<String, Long> banned;
    private final int defaultTtlSeconds;

    public BanCache(ConfigManager config) {
        this.defaultTtlSeconds = Math.max(10, config.getInt("bans.local-ttl-seconds", 300));
        this.banned = Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfter(new Expiry<String, Long>() {
                    public long expireAfterCreate(String k, Long expiryMs, long now) {
                        long delay = expiryMs - System.currentTimeMillis();
                        return TimeUnit.MILLISECONDS.toNanos(Math.max(delay, 1_000));
                    }
                    public long expireAfterUpdate(String k, Long v, long now, long dur) {
                        return expireAfterCreate(k, v, now);
                    }
                    public long expireAfterRead(String k, Long v, long now, long dur) {
                        return dur;
                    }
                })
                .build();
    }

    public void ban(String ip) {
        banned.put(key(ip), System.currentTimeMillis() + defaultTtlSeconds * 1_000L);
    }

    public void ban(String ip, int ttlSeconds) {
        long expiryMs = ttlSeconds > 0
                ? System.currentTimeMillis() + ttlSeconds * 1_000L
                : Long.MAX_VALUE / 2;
        banned.put(key(ip), expiryMs);
    }

    public boolean isBanned(String ip) {
        return banned.getIfPresent(key(ip)) != null;
    }

    public void unban(String ip) {
        banned.invalidate(key(ip));
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
