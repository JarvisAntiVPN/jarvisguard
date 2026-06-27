package dev.flamingomg.jarvis.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.flamingomg.jarvis.model.VerdictResponse;

import java.time.Duration;

public final class VerdictCache {

    private final Cache<String, VerdictResponse> cache;

    public VerdictCache(int maxEntries, int ttlSeconds) {
        this.cache = Caffeine.newBuilder()
                .maximumSize(Math.max(0, maxEntries))
                .expireAfterWrite(Duration.ofSeconds(Math.max(0, ttlSeconds)))
                .build();
    }

    public VerdictResponse getIfPresent(String ip) {
        return cache.getIfPresent(ip);
    }

    public void put(String ip, VerdictResponse response) {
        cache.put(ip, response);
    }

    public void invalidate(String ip) {
        cache.invalidate(ip);
    }

    public void invalidateAll() {
        cache.invalidateAll();
    }

    public void invalidateByPrefix(String prefix) {
        cache.asMap().keySet().removeIf(k -> k.startsWith(prefix));
    }

    public long estimatedSize() {
        return cache.estimatedSize();
    }
}
