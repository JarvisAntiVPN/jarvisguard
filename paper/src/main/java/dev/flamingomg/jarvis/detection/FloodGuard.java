package dev.flamingomg.jarvis.detection;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.flamingomg.jarvis.config.ConfigManager;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public final class FloodGuard {

    private final boolean enabled;
    private final int maxConnects;
    private final Cache<String, AtomicInteger> windows;

    public FloodGuard(ConfigManager config) {
        this.enabled = config.getBoolean("flood.enabled", true);
        this.maxConnects = config.getInt("flood.max-connects", 8);
        int windowSecs = Math.max(1, config.getInt("flood.window-seconds", 10));
        this.windows = Caffeine.newBuilder()
                .expireAfterWrite(windowSecs, TimeUnit.SECONDS)
                .maximumSize(50_000)
                .build();
    }

    public boolean checkAndRecord(String ip) {
        if (!enabled) return false;
        AtomicInteger counter = windows.get(ip, k -> new AtomicInteger(0));
        return counter.incrementAndGet() > maxConnects;
    }
}
