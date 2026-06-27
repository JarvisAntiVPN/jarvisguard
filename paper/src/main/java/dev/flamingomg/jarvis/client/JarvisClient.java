package dev.flamingomg.jarvis.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.model.VerdictRequest;
import dev.flamingomg.jarvis.model.VerdictResponse;
import dev.flamingomg.jarvis.model.VerdictType;
import dev.flamingomg.jarvis.security.HmacSigner;
import java.util.logging.Logger;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

public final class JarvisClient {

    private static final Gson GSON = new GsonBuilder().create();

    private enum CbState { CLOSED, OPEN, HALF_OPEN }

    private volatile CbState   cbState    = CbState.CLOSED;
    private final AtomicInteger cbFailures = new AtomicInteger(0);
    private volatile long       cbOpenedAt = 0L;

    private final ConfigManager config;
    private final Logger        logger;
    private volatile HmacSigner signer;
    private volatile String secretForKey = "";
    private volatile boolean warnedNoKey = false;
    private volatile boolean warnedUnsignedBans = false;
    private volatile int maxAccountsPerIp = 0;
    private volatile String locale = "en";
    private final VerdictCache  cache;
    private final HttpClient    http;

    private final java.util.concurrent.ExecutorService httpExecutor =
            HttpExecutors.daemonHttpExecutor("jarvis-http");

    public JarvisClient(ConfigManager config, Logger logger) {
        this.config = config;
        this.logger = logger;
        this.cache  = new VerdictCache(
                config.getInt("cache.max-entries", 10000),
                config.getInt("cache.ttl-seconds", 300));
        int timeoutMs = Math.max(1, config.getInt("backend.timeout-ms", 500));
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(timeoutMs))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .executor(httpExecutor)
                .build();

        String secret = config.getString("backend.shared-secret", "");
        this.signer = new HmacSigner(isBlank(secret) ? "" : secret);

        if (!isBlank(secret)) this.secretForKey = config.getString("backend.license-key", "");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank() || s.equalsIgnoreCase("CHANGE_ME");
    }

    private String fetchSharedSecret() {
        String url = config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
        String key = config.getString("backend.license-key", "");
        if (isBlank(key)) {

            if (!warnedNoKey) {
                warnedNoKey = true;
                logger.warning("[jarvis] You haven't set your license key yet. "
                        + "Type  /antivpn key <yourkey>  in the console to enable protection.");
            }
            return null;
        }
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url + "/client/config"))
                    .timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Bearer " + key)
                    .GET().build();
            HttpResponse<String> resp = this.http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                Map<?, ?> body = GSON.fromJson(resp.body(), Map.class);
                Object mp = body != null ? body.get("maxAccountsPerIp") : null;
                if (mp instanceof Number num) this.maxAccountsPerIp = Math.max(0, num.intValue());
                Object loc = body != null ? body.get("ownerLocale") : null;
                if (loc != null && !String.valueOf(loc).isBlank()) this.locale = dev.flamingomg.jarvis.i18n.Messages.normalize(String.valueOf(loc));
                Object ss = body != null ? body.get("sharedSecret") : null;
                if (ss != null && !String.valueOf(ss).isBlank()) {
                    logger.fine("[jarvis] Connected to backend; configuration fetched automatically.");
                    return String.valueOf(ss);
                }
            }
            logger.warning("[jarvis] Backend didn't return the secret (HTTP " + resp.statusCode() + "). Is the key correct?");
        } catch (Exception e) {
            logger.warning("[jarvis] Couldn't reach the backend to fetch the configuration: " + e.getMessage());
        }
        return null;
    }

    public boolean ensureReady() {
        String configuredKey = config.getString("backend.license-key", "");

        if (signer != null && signer.hasSecret() && configuredKey.equals(secretForKey)) return true;
        String secret = fetchSharedSecret();
        if (secret != null) { this.signer = new HmacSigner(secret); this.secretForKey = configuredKey; return true; }
        return false;
    }

    public HmacSigner signer() { return signer; }

    public int maxAccountsPerIp() { return maxAccountsPerIp; }

    public void setMaxAccountsPerIp(int v) { this.maxAccountsPerIp = Math.max(0, v); }

    public String locale() { return locale; }

    public void setLocale(String v) { this.locale = dev.flamingomg.jarvis.i18n.Messages.normalize(v); }

    public void reportPresence(int online, java.util.List<Map<String, Object>> players) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("online", online);
        payload.put("players", players);
        report("/api/v1/presence", "presence", "", payload, "Error reporting presence");
    }

    private static final char CK_SEP = '\u001e';
    private static String ck(String ip, String username) {
        return ip + CK_SEP + (username == null ? "" : username.toLowerCase());
    }

    public CompletableFuture<VerdictResponse> requestVerdictAsync(String ip, String username, boolean bedrock, boolean premium) {
        VerdictResponse cached = cache.getIfPresent(ck(ip, username));
        if (cached != null) return CompletableFuture.completedFuture(cached);

        if (signer == null || !signer.hasSecret()) return CompletableFuture.completedFuture(unknownVerdict());

        int  failThreshold  = Math.max(1, config.getInt("circuit-breaker.failure-threshold", 5));
        long openDurationMs = Math.max(0L, (long) config.getInt("circuit-breaker.open-duration-ms", 30_000));
        if (cbState == CbState.OPEN) {
            if (System.currentTimeMillis() - cbOpenedAt >= openDurationMs) {
                cbState = CbState.HALF_OPEN;
                logger.fine("[jarvis] Circuit breaker HALF-OPEN, reconnecting...");
            } else {
                return CompletableFuture.completedFuture(unknownVerdict());
            }
        }

        long   ts        = System.currentTimeMillis();
        String body      = GSON.toJson(new VerdictRequest(ip, username, bedrock, ts, premium));
        String sig       = signer.sign(HmacSigner.requestPayload(ts, ip, username));
        String licKey    = config.getString("backend.license-key", "");
        String backendUrl= config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
        int    timeoutMs = Math.max(1, config.getInt("backend.timeout-ms", 500));

        HttpRequest req = HttpRequest.newBuilder(URI.create(backendUrl + "/api/v1/verdict"))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .header("X-Sig-Canon",   "4")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofString()).handle((resp, err) -> {
            if (err == null && resp.statusCode() == 200) {
                try {
                    VerdictResponse verdict = GSON.fromJson(resp.body(), VerdictResponse.class);

                    if (verdict == null || !dev.flamingomg.jarvis.security.VerdictVerifier.verifyV4(
                            verdict.timestamp(), verdict.verdict(), ip, username, verdict.sig())) {
                        logger.warning("[jarvis] Invalid signature for " + ip);
                        return onFailure(ip, failThreshold);
                    }
                    if (!responseFresh(verdict.timestamp())) {
                        logger.warning("[jarvis] Stale/replay response for " + ip + " (ts=" + verdict.timestamp() + ")");
                        return onFailure(ip, failThreshold);
                    }
                    cbFailures.set(0);
                    if (cbState == CbState.HALF_OPEN) {
                        cbState = CbState.CLOSED;
                        logger.fine("[jarvis] Circuit breaker CLOSED, backend recovered.");
                    }

                    if (verdict.message() != null && !dev.flamingomg.jarvis.security.VerdictVerifier.verifyMessage(
                            verdict.timestamp(), verdict.verdict(), verdict.message(), verdict.msgSig())) {
                        logger.warning("[jarvis] Kick message signature mismatch for " + ip + "; using local message");
                        verdict = new VerdictResponse(verdict.verdict(), null, verdict.timestamp(), verdict.sig(), verdict.msgSig());
                    }
                    if (verdict.verdictType() != VerdictType.CHALLENGE) cache.put(ck(ip, username), verdict);
                    return verdict;
                } catch (Exception e) {
                    return onFailure(ip, failThreshold);
                }
            }
            if (err == null) logger.warning("[jarvis] Backend HTTP " + resp.statusCode() + " for " + ip);
            else logger.fine("[jarvis] Error contacting backend for " + ip + ": " + err.getMessage());
            return onFailure(ip, failThreshold);
        });
    }

    private VerdictResponse onFailure(String ip, int failThreshold) {
        int failures = cbFailures.incrementAndGet();
        if (failures >= failThreshold && cbState != CbState.OPEN) {
            cbState    = CbState.OPEN;
            cbOpenedAt = System.currentTimeMillis();
            logger.warning("[jarvis] Circuit breaker OPEN (" + failures + " failures). Degraded mode active.");
        }
        return unknownVerdict();
    }

    private static VerdictResponse unknownVerdict() {
        return new VerdictResponse("UNKNOWN", null, System.currentTimeMillis(), "", null);
    }

    public void invalidateIp(String ip) {
        cache.invalidateByPrefix(ip + CK_SEP);
    }

    public void reportPlayerSeen(String uuid, String username, String ip, boolean bedrock,
                                 String version, String brand, String host,
                                 String locale, Integer viewDistance, String chatMode,
                                 java.util.List<String> channels, boolean premium) {

        VerdictResponse cached = cache.getIfPresent(ck(ip, username));
        String verdictStr = cached != null ? cached.verdict() : "UNKNOWN";
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("uuid", uuid);
        payload.put("username", username);
        payload.put("ip", ip);
        payload.put("bedrock", bedrock);
        payload.put("premium", premium);
        payload.put("verdict", verdictStr);
        if (version != null) payload.put("version", version);
        if (brand != null)   payload.put("brand", brand);
        if (host != null)    payload.put("host", host);
        if (locale != null)       payload.put("locale", locale);
        if (viewDistance != null) payload.put("viewDistance", viewDistance);
        if (chatMode != null)     payload.put("chatMode", chatMode);

        if (channels != null && !channels.isEmpty()) payload.put("channels", channels);
        report("/api/v1/player/seen", ip, username, payload,
                "Error reporting player seen " + username);
    }

    public void reportSessionEnd(String username, String ip, long durationMs) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("ip", ip);
        payload.put("durationMs", durationMs);
        report("/api/v1/session/end", ip, username, payload,
                "Error reporting session end for " + username);
    }

    public void reportChallengeComplete(String username, String ip) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("ip", ip);
        report("/api/v1/challenge/complete", ip, username, payload,
                "Error reporting challenge complete");
    }

    public void fetchAndSyncBans(BanCache banCache) {
        if (signer == null || !signer.hasSecret()) return;
        long   ts        = System.currentTimeMillis();
        String licKey    = config.getString("backend.license-key", "");
        String backendUrl= config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
        String sig       = signer.sign(HmacSigner.requestPayload(ts, "", "bans"));

        HttpRequest req = HttpRequest.newBuilder(URI.create(backendUrl + "/api/v1/bans"))
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .timeout(java.time.Duration.ofSeconds(10))
                .GET().build();

        http.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenAccept(resp -> {
                    if (resp.statusCode() != 200) return;

                    String bansSig = resp.headers().firstValue("X-Bans-Sig").orElse(null);
                    if (bansSig != null) {
                        long bansTs = 0L;
                        try { bansTs = Long.parseLong(resp.headers().firstValue("X-Bans-Ts").orElse("0").trim()); }
                        catch (NumberFormatException ignored) {  }
                        if (Math.abs(System.currentTimeMillis() - bansTs) > 120_000L
                                || !dev.flamingomg.jarvis.security.VerdictVerifier.verifyBans(bansTs, resp.body(), bansSig)) {
                            logger.warning("[jarvis] Bans list signature invalid or stale; skipping this sync cycle.");
                            return;
                        }
                    } else if (!warnedUnsignedBans) {
                        warnedUnsignedBans = true;
                        logger.warning("[jarvis] Backend bans response is unsigned; applying without verification.");
                    }
                    try {
                        long now = System.currentTimeMillis();
                        @SuppressWarnings("unchecked")
                        List<Map<String, Object>> bans = GSON.fromJson(resp.body(), List.class);
                        if (bans == null) return;
                        java.util.Set<String> snapshotIps = new java.util.HashSet<>();
                        int count = 0;
                        for (Map<String, Object> ban : bans) {

                            try {
                                if (!(ban.get("ip") instanceof String banIp) || banIp.isEmpty()) continue;
                                Object expObj = ban.get("expiresAt");
                                int ttlSec;
                                if (expObj == null) {
                                    ttlSec = 0;
                                } else if (expObj instanceof Number num) {
                                    ttlSec = (int) Math.max(0, (num.longValue() - now) / 1000);
                                    if (ttlSec == 0) continue;
                                } else {
                                    continue;
                                }
                                banCache.ban(banIp, ttlSec);
                                snapshotIps.add(banIp);
                                count++;
                            } catch (RuntimeException ignored) {  }
                        }

                        if (!snapshotIps.isEmpty()) banCache.reconcilePermanent(snapshotIps, ts);
                        logger.fine("[jarvis] " + count + " bans synced.");
                    } catch (Exception e) {
                        logger.fine("[jarvis] Error parsing bans: " + e.getMessage());
                    }
                })
                .exceptionally(e -> { logger.fine("[jarvis] Error syncing bans: " + e.getMessage()); return null; });
    }

    public String circuitBreakerStatus() {
        return cbState.name() + " (" + cbFailures.get() + " failures)";
    }

    public VerdictCache cache() { return cache; }

    public void shutdown() {
        HttpExecutors.closeQuietly(http);
        HttpExecutors.shutdownQuietly(httpExecutor);
    }

    private boolean responseFresh(long responseTs) {
        long windowMs = config.getInt("backend.max-response-age-ms", 30_000);
        return isFresh(System.currentTimeMillis(), responseTs, windowMs);
    }

    static boolean isFresh(long now, long responseTs, long windowMs) {
        long delta = now - responseTs;
        return delta <= windowMs && delta >= -windowMs;
    }

    private void report(String endpoint, String ipForSig, String userForSig,
                        Map<String, Object> payload, String errorMsg) {
        if (signer == null || !signer.hasSecret()) return;
        long   ts         = System.currentTimeMillis();
        String licKey     = config.getString("backend.license-key", "");
        String backendUrl = config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
        String sig        = signer.sign(HmacSigner.requestPayload(ts, ipForSig, userForSig));
        payload.put("timestamp", ts);
        sendAsync(backendUrl + endpoint, licKey, ts, sig, GSON.toJson(payload),
                () -> logger.fine("[jarvis] " + errorMsg));
    }

    private void sendAsync(String url, String licKey, long ts, String sig, String body, Runnable onError) {
        int timeoutMs = Math.max(1, config.getInt("backend.timeout-ms", 500));
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .exceptionally(e -> { onError.run(); return null; });
    }
}
