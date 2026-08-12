package dev.flamingomg.jarvis.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.model.VerdictRequest;
import dev.flamingomg.jarvis.model.VerdictResponse;
import dev.flamingomg.jarvis.model.VerdictType;
import dev.flamingomg.jarvis.security.HmacSigner;
import dev.flamingomg.jarvis.util.Log;

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

    private final java.util.concurrent.atomic.AtomicReference<CbState> cbState =
            new java.util.concurrent.atomic.AtomicReference<>(CbState.CLOSED);
    private final AtomicInteger cbFailures = new AtomicInteger(0);
    private volatile long       cbOpenedAt = 0L;

    private final ConfigManager config;
    private final Log           logger;
    private volatile HmacSigner signer;
    private volatile String secretForKey = "";
    private volatile boolean secretFromConfig = false;
    private volatile long lastSecretResetMs = 0L;
    private volatile boolean warnedNoKey = false;
    private volatile boolean warnedNoSecret = false;

    private volatile boolean warnedNoReach = false;
    private volatile boolean keyRejected = false;
    private volatile boolean warnedUnsignedBans = false;
    private volatile int maxAccountsPerIp = 0;
    private volatile String locale = "en";
    private volatile boolean notifyStaff = true;
    private volatile String notifyPermission = "jarvis.admin";

    private volatile int    cbFailureThreshold = 5;
    private volatile long   cbOpenDurationMs   = 30_000L;
    private volatile int    backendTimeoutMs   = 500;
    private volatile int    cbProbeTimeoutMs   = 3_000;
    private volatile long   maxResponseAgeMs   = 30_000L;
    private volatile String licenseKey         = "";
    private final VerdictCache  cache;
    private final HttpClient    http;

    private final java.util.concurrent.ScheduledExecutorService keepAlive =
            java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "jarvis-keepalive");
                t.setDaemon(true);
                return t;
            });

    private final java.util.concurrent.ExecutorService httpExecutor =
            HttpExecutors.daemonHttpExecutor("jarvis-http");

    private final LocalDenialReporter denials = new LocalDenialReporter(this::reportLocalDenials);

    public LocalDenialReporter denials() { return denials; }

    private final ClockOffset clock = new ClockOffset();

    public ClockOffset clock() { return clock; }

    public JarvisClient(ConfigManager config, Log logger) {
        this.config = config;
        this.logger = logger;
        this.cache  = new VerdictCache(
                config.getInt("cache.max-entries", 10000),
                config.getInt("cache.ttl-seconds", 300));
        int timeoutMs = Math.max(1, config.getInt("backend.timeout-ms", 500));

        int connectTimeoutMs = Math.max(timeoutMs, config.getInt("backend.connect-timeout-ms", 8000));
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                .followRedirects(HttpClient.Redirect.NEVER)
                .executor(httpExecutor)
                .build();

        String cfgKey0 = config.getString("backend.license-key", "");
        String secret = config.getString("backend.shared-secret", "");
        this.secretFromConfig = !isBlank(secret);

        if (isBlank(secret)) {
            String cached = config.readCachedSecret(cfgKey0);
            if (!isBlank(cached)) secret = cached;
        }
        this.signer = new HmacSigner(isBlank(secret) ? "" : secret);

        if (!isBlank(secret)) this.secretForKey = config.getString("backend.license-key", "");
        snapshotConfig();
        startKeepAlive();
        denials.start();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank() || s.equalsIgnoreCase("CHANGE_ME");
    }

    private String fetchSharedSecret() {
        String url = ConfigManager.DEFAULT_BACKEND_URL;
        String key = config.getString("backend.license-key", "");
        if (isBlank(key)) {

            if (!warnedNoKey) {
                warnedNoKey = true;
                logger.warn("You haven't set your license key yet. "
                        + "Type  /antivpn key <yourkey>  in the console to enable protection.");
            }
            return null;
        }
        try {

            long cfgTimeoutMs = Math.max(5000L, config.getInt("backend.connect-timeout-ms", 8000) + 5000L);
            HttpRequest req = HttpRequest.newBuilder(URI.create(url + "/client/config"))
                    .timeout(Duration.ofMillis(cfgTimeoutMs))
                    .header("Authorization", "Bearer " + key)
                    .GET().build();
            HttpResponse<String> resp = this.http.send(req, HttpResponse.BodyHandlers.ofString());
            int status = resp.statusCode();
            if (status == 200) {
                Map<?, ?> body = GSON.fromJson(resp.body(), Map.class);
                applyPanelConfig(body);
                Object ss = body != null ? body.get("sharedSecret") : null;
                if (ss != null && !String.valueOf(ss).isBlank()) {
                    logger.debug("Connected to backend; configuration fetched automatically.");
                    String _s = String.valueOf(ss);
                    config.writeCachedSecret(key, _s);
                    this.secretFromConfig = false;
                    this.keyRejected = false;
                    this.warnedNoSecret = false;
                    this.warnedNoReach = false;
                    return _s;
                }
            }

            boolean backendReject = resp.headers().firstValue("X-Jarvis-Reject").isPresent();
            this.keyRejected = (status == 401 || status == 403 || status == 404) && backendReject;
            if (!warnedNoSecret) {
                warnedNoSecret = true;
                logger.warn("No connector secret from backend (HTTP {}). Check your license key; if it's correct and your license has team members, set backend.shared-secret in config.yml (copy it from your panel).", status);
            }
        } catch (Exception e) {
            this.keyRejected = false;
            if (!warnedNoReach) {
                warnedNoReach = true;
                logger.warn("Couldn't reach the backend to fetch the configuration: {}. Retrying in the "
                        + "background; this message won't repeat until it recovers.", e.getMessage());
            } else {
                logger.debug("backend still unreachable: {}", e.getMessage());
            }
        }
        return null;
    }

    public boolean ensureReady() {
        String configuredKey = config.getString("backend.license-key", "");

        if (signer != null && signer.hasSecret() && configuredKey.equals(secretForKey)) return true;
        String secret = fetchSharedSecret();
        if (secret != null) { this.signer = new HmacSigner(secret); this.secretForKey = configuredKey; snapshotConfig(); return true; }
        return false;
    }

    public HmacSigner signer() { return signer; }

    public boolean keyRejected() { return keyRejected; }

    public int maxAccountsPerIp() { return maxAccountsPerIp; }

    public void setMaxAccountsPerIp(int v) { this.maxAccountsPerIp = Math.max(0, v); }

    public String locale() { return locale; }

    public void setLocale(String v) { this.locale = dev.flamingomg.jarvis.i18n.Messages.normalize(v); }

    public boolean notifyStaffEnabled() { return notifyStaff; }

    public String notifyPermission() { return notifyPermission; }

    private void applyPanelConfig(Map<?, ?> body) {
        if (body == null) return;
        Object mp = body.get("maxAccountsPerIp");
        if (mp instanceof Number num) this.maxAccountsPerIp = Math.max(0, num.intValue());
        Object loc = body.get("ownerLocale");
        if (loc != null && !String.valueOf(loc).isBlank()) this.locale = dev.flamingomg.jarvis.i18n.Messages.normalize(String.valueOf(loc));
        Object ns = body.get("notifyStaff");
        if (ns instanceof Boolean b) this.notifyStaff = b;

        Object np = body.get("notifyPermission");
        if (np != null && !String.valueOf(np).isBlank()) this.notifyPermission = String.valueOf(np).trim();
    }

    public void refreshConfig() {
        snapshotConfig();
        String key = config.getString("backend.license-key", "");
        if (isBlank(key)) return;
        try {
            long cfgTimeoutMs = Math.max(5000L, config.getInt("backend.connect-timeout-ms", 8000) + 5000L);
            HttpRequest req = HttpRequest.newBuilder(URI.create(ConfigManager.DEFAULT_BACKEND_URL + "/client/config"))
                    .timeout(Duration.ofMillis(cfgTimeoutMs))
                    .header("Authorization", "Bearer " + key)
                    .GET().build();
            http.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(resp -> { if (resp.statusCode() == 200) {
                        try { applyPanelConfig(GSON.fromJson(resp.body(), Map.class)); } catch (Exception ignore) {}
                    }})
                    .exceptionally(e -> { logger.debug("refreshConfig failed: {}", e.getMessage()); return null; });
        } catch (Exception e) {
            logger.debug("refreshConfig error: {}", e.getMessage());
        }
    }

    public void reportPresence(int online, java.util.List<Map<String, Object>> players) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("online", online);
        payload.put("players", players);
        report("/api/v1/presence", "presence", "", payload, "Error reporting presence");
    }

    private static final char CK_SEP = '\u001e';
    private static String ck(String ip, String username) {
        return canonIp(ip) + CK_SEP + (username == null ? "" : username.toLowerCase(java.util.Locale.ROOT));
    }

    private static String canonIp(String ip) {
        if (ip == null || ip.indexOf(':') < 0) return ip;
        try {
            return java.net.InetAddress.getByName(ip).getHostAddress();
        } catch (Exception e) {
            return ip;
        }
    }

    private void snapshotConfig() {
        this.cbFailureThreshold = Math.max(1, config.getInt("circuit-breaker.failure-threshold", 5));
        this.cbOpenDurationMs   = Math.max(0L, (long) config.getInt("circuit-breaker.open-duration-ms", 30_000));
        this.backendTimeoutMs   = Math.max(1, config.getInt("backend.timeout-ms", 500));
        this.cbProbeTimeoutMs   = Math.max(1, config.getInt("circuit-breaker.probe-timeout-ms", 3000));

        this.maxResponseAgeMs   = Math.max(90_000L, config.getInt("backend.max-response-age-ms", 90_000));
        this.licenseKey         = config.getString("backend.license-key", "");
    }

    public CompletableFuture<VerdictResponse> requestVerdictAsync(String ip, String username, boolean bedrock, boolean premium) {
        VerdictResponse cached = cache.getIfPresent(ck(ip, username));
        if (cached != null) return CompletableFuture.completedFuture(cached);

        if (signer == null || !signer.hasSecret()) return CompletableFuture.completedFuture(unknownVerdict());

        int  failThreshold  = cbFailureThreshold;
        long openDurationMs = cbOpenDurationMs;

        boolean probe = false;
        CbState state = cbState.get();
        if (state == CbState.OPEN) {
            if (System.currentTimeMillis() - cbOpenedAt >= openDurationMs
                    && cbState.compareAndSet(CbState.OPEN, CbState.HALF_OPEN)) {
                cbFailures.set(0);
                probe = true;
                logger.debug("Circuit breaker HALF-OPEN, reconnecting...");
            } else {
                return CompletableFuture.completedFuture(unknownVerdict());
            }
        } else if (state == CbState.HALF_OPEN) {

            if (sondaColgada(System.currentTimeMillis(), cbOpenedAt, openDurationMs, cbProbeTimeoutMs)
                    && cbState.compareAndSet(CbState.HALF_OPEN, CbState.OPEN)) {
                cbOpenedAt = System.currentTimeMillis();
                logger.warn("Circuit breaker: the reconnection probe never answered; reopening to retry.");
            }
            return CompletableFuture.completedFuture(unknownVerdict());
        }

        long   ts        = clock.now();
        long   offsetAlEnviar = clock.offsetMs();
        String body      = GSON.toJson(new VerdictRequest(ip, username, bedrock, ts, premium));
        String sig       = signer.sign(HmacSigner.requestPayload(ts, ip, username));
        String licKey    = licenseKey;
        String backendUrl= ConfigManager.DEFAULT_BACKEND_URL;

        int    timeoutMs = probe ? cbProbeTimeoutMs : backendTimeoutMs;

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
                        logger.warn("Invalid signature for {}", ip);
                        return onFailure(ip, failThreshold);
                    }
                    if (!responseFresh(verdict.timestamp())) {

                        Long total = clock.aprender(verdict.timestamp(), ts, clock.now(), offsetAlEnviar);
                        if (total != null) {
                            logger.warn("This machine's clock is off by {} ms from the Jarvis backend; requests "
                                    + "are now corrected. Fix NTP on this server.", total);
                        }
                        logger.warn("Stale/replay response for {} (ts={})", ip, verdict.timestamp());
                        return onFailure(ip, failThreshold);
                    }
                    cbFailures.set(0);
                    ultimoVeredictoOkMs = System.currentTimeMillis();
                    if (cbState.compareAndSet(CbState.HALF_OPEN, CbState.CLOSED)) {
                        logger.debug("Circuit breaker CLOSED, backend recovered.");
                    }

                    if (verdict.message() != null && !dev.flamingomg.jarvis.security.VerdictVerifier.verifyMessage(
                            verdict.timestamp(), verdict.verdict(), verdict.message(), verdict.msgSig())) {
                        logger.warn("Kick message signature mismatch for {}; using local message", ip);
                        verdict = new VerdictResponse(verdict.verdict(), null, verdict.timestamp(), verdict.sig(), verdict.msgSig());
                    }
                    if (verdict.verdictType() != VerdictType.CHALLENGE) cache.put(ck(ip, username), verdict);
                    return verdict;
                } catch (Exception e) {
                    return onFailure(ip, failThreshold);
                }
            }
            if (err == null && (resp.statusCode() == 401 || resp.statusCode() == 403)) maybeResetSecret(resp.statusCode());

            if (err == null && resp.statusCode() == 400) {
                long serverTimeMs = ClockOffset.leerServerTimeMs(resp.body());
                if (serverTimeMs > 0) {
                    Long total = clock.aprender(serverTimeMs, ts, clock.now(), offsetAlEnviar);
                    if (total != null) {
                        logger.warn("This machine's clock is off by {} ms from the Jarvis backend; requests are "
                                + "now corrected. Fix NTP on this server.", total);
                    }
                }
            }
            if (err == null) logger.warn("Backend HTTP {} for {}", resp.statusCode(), ip);
            else logger.debug("Error contacting backend for {}: {}", ip, err.getMessage());
            return onFailure(ip, failThreshold);
        })

        .completeOnTimeout(VENCIDO, timeoutMs + 4500L, java.util.concurrent.TimeUnit.MILLISECONDS)
        .thenApply(v -> {
            if (v != VENCIDO) return v;
            avisarVencimiento(ip);
            return unknownVerdict();
        });
    }

    private static final VerdictResponse VENCIDO = new VerdictResponse("UNKNOWN", null, 0L, "", null);

    private final java.util.concurrent.atomic.AtomicLong ultimoAvisoVencimiento =
            new java.util.concurrent.atomic.AtomicLong(0L);

    private void avisarVencimiento(String ip) {
        ultimoVeredictoFalloMs = System.currentTimeMillis();
        long ahora = System.currentTimeMillis();
        long previo = ultimoAvisoVencimiento.get();
        if (previo != 0L && ahora >= previo && ahora - previo < 60_000L) return;
        if (!ultimoAvisoVencimiento.compareAndSet(previo, ahora)) return;
        logger.warn("The Jarvis backend accepted the connection but never finished answering; that login was let "
                + "in WITHOUT being checked. If this repeats, check this server's network path to the backend.");
    }

    private static final long SECRET_RESET_MIN_INTERVAL_MS = 60_000L;
    private final java.util.concurrent.atomic.AtomicBoolean secretResetInFlight = new java.util.concurrent.atomic.AtomicBoolean(false);
    private void maybeResetSecret(int status) {
        if (secretFromConfig) return;
        HmacSigner s = signer;
        if (s == null || !s.hasSecret()) return;
        long now = System.currentTimeMillis();
        if (now - lastSecretResetMs < SECRET_RESET_MIN_INTERVAL_MS) return;

        if (!secretResetInFlight.compareAndSet(false, true)) return;
        lastSecretResetMs = now;

        Thread t = new Thread(() -> {
            try {
                String fresh = fetchSharedSecret();
                if (fresh != null && !fresh.isBlank()) {
                    this.signer = new HmacSigner(fresh);
                    this.secretForKey = config.getString("backend.license-key", "");
                } else if (keyRejected) {

                    this.signer = new HmacSigner("");
                    this.secretForKey = "";
                    try { config.clearCachedSecret(); } catch (Exception ignore) {}
                }

            } catch (Exception ignore) {}
            finally { secretResetInFlight.set(false); }
        }, "jarvis-secret-refetch");
        t.setDaemon(true);
        t.start();
    }

    public void onSyncRejected(int status) { maybeResetSecret(status); }

    static boolean sondaColgada(long ahoraMs, long cbOpenedAtMs, long openDurationMs, long probeTimeoutMs) {
        return ahoraMs - cbOpenedAtMs > openDurationMs + probeTimeoutMs + 4_500L + 5_000L;
    }

    private void backendRespondio() {

        if (cbState.get() == CbState.CLOSED) return;
        cbFailures.set(0);
        if (cbState.compareAndSet(CbState.OPEN, CbState.CLOSED)
                || cbState.compareAndSet(CbState.HALF_OPEN, CbState.CLOSED)) {
            logger.info("Jarvis backend reachable again; protection is back to normal.");
        }
    }

    private volatile long ultimoVeredictoOkMs = 0L;
    private volatile long ultimoVeredictoFalloMs = 0L;

    static final long VENTANA_FALLO_MS = 180_000L;

    static boolean veredictosFallando(long ahoraMs, long okMs, long falloMs, long ventanaMs) {
        return falloMs > okMs && ahoraMs - falloMs <= ventanaMs;
    }

    private VerdictResponse onFailure(String ip, int failThreshold) {
        ultimoVeredictoFalloMs = System.currentTimeMillis();
        int failures = cbFailures.incrementAndGet();

        if (cbState.compareAndSet(CbState.HALF_OPEN, CbState.OPEN)) {
            cbOpenedAt = System.currentTimeMillis();
            logger.warn("Circuit breaker OPEN (probe failed). Degraded mode active.");
        } else if (failures >= failThreshold && cbState.compareAndSet(CbState.CLOSED, CbState.OPEN)) {
            cbOpenedAt = System.currentTimeMillis();
            logger.warn("Circuit breaker OPEN ({} failures). Degraded mode active.", failures);
        }
        return unknownVerdict();
    }

    private static VerdictResponse unknownVerdict() {
        return new VerdictResponse("UNKNOWN", null, System.currentTimeMillis(), "", null);
    }

    public void invalidateIps(java.util.Collection<String> ips) {
        if (ips == null || ips.isEmpty()) return;
        java.util.Set<String> prefijos = new java.util.HashSet<>();
        for (String ip : ips) if (ip != null) prefijos.add(canonIp(ip) + CK_SEP);
        cache.invalidateByPrefixes(prefijos, CK_SEP);
    }

    public void invalidateIp(String ip) {
        cache.invalidateByPrefix(canonIp(ip) + CK_SEP);
    }

    public void invalidateUsername(String username) {
        if (username == null || username.isEmpty()) return;
        cache.invalidateBySuffix(CK_SEP + username.toLowerCase(java.util.Locale.ROOT));
    }

    public void reportPlayerSeen(String uuid, String username, String ip, boolean bedrock,
                                 String version, String brand, String host,
                                 String locale, Integer viewDistance, String chatMode,
                                 java.util.List<String> channels, boolean premium,
                                 Integer protocolVersion) {

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
        if (protocolVersion != null) payload.put("protocolVersion", protocolVersion);

        reportConIdentidad("/api/v1/player/seen", ip, username, uuid, premium, payload,
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

    private final java.util.concurrent.atomic.AtomicInteger localDenials404 =
            new java.util.concurrent.atomic.AtomicInteger();
    private static final int LOCAL_DENIALS_404_GIVE_UP = 3;

    private static final int LOCAL_DENIALS_TIMEOUT_MS = 5_000;

    public void reportLocalDenials(java.util.List<LocalDenialReporter.Entry> lote) {
        if (lote == null || lote.isEmpty()) return;
        if (signer == null || !signer.hasSecret()) return;
        if (localDenials404.get() >= LOCAL_DENIALS_404_GIVE_UP) return;
        java.util.List<Map<String, Object>> arr = new java.util.ArrayList<>(lote.size());
        for (LocalDenialReporter.Entry e : lote) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("reason", e.reason());
            m.put("ip", e.ip());
            if (e.username() != null) m.put("username", e.username());
            m.put("hits", e.hits());
            arr.add(m);
        }
        long ts = clock.now();
        String licKey = licenseKey;
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("denials", arr);
        payload.put("timestamp", ts);
        String sig = signer.sign(HmacSigner.requestPayload(ts, "local-denials", licKey));
        HttpRequest req = HttpRequest.newBuilder(URI.create(ConfigManager.DEFAULT_BACKEND_URL + "/api/v1/local-denials"))
                .timeout(Duration.ofMillis(LOCAL_DENIALS_TIMEOUT_MS))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload), StandardCharsets.UTF_8))
                .build();
        http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .thenAccept(resp -> {
                    if (resp.statusCode() == 404) {
                        if (localDenials404.incrementAndGet() == LOCAL_DENIALS_404_GIVE_UP) {
                            logger.debug("[local-denials] endpoint not available; disabled until restart");
                        }
                    } else {
                        localDenials404.set(0);
                    }
                })
                .exceptionally(e -> { logger.debug("[local-denials] report failed: {}", e.toString()); return null; });
    }

    public void reportChallengeComplete(String username, String ip) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("ip", ip);
        report("/api/v1/challenge/complete", ip, username, payload,
                "Error reporting challenge complete");
    }

    private volatile boolean serverIconSent = false;
    private static final int MAX_ICON_BYTES = 145_000;

    public void sendServerIcon() {
        if (serverIconSent || signer == null || !signer.hasSecret()) return;
        serverIconSent = true;
        try {
            CompletableFuture.runAsync(this::doSendServerIcon, httpExecutor);
        } catch (Throwable t) {
            serverIconSent = false;
        }
    }

    private void doSendServerIcon() {
        try {
            byte[] png;
            try (java.io.InputStream in = java.nio.file.Files.newInputStream(java.nio.file.Path.of("server-icon.png"))) {
                png = in.readNBytes(MAX_ICON_BYTES + 1);
            }
            if (png.length == 0 || png.length > MAX_ICON_BYTES) return;
            long   ts        = clock.now();
            String licKey    = licenseKey;
            String backendUrl= ConfigManager.DEFAULT_BACKEND_URL;
            String sig       = signer.sign(HmacSigner.requestPayload(ts, "server-icon", ""));
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("timestamp", ts);
            payload.put("icon", "data:image/png;base64," + java.util.Base64.getEncoder().encodeToString(png));
            HttpRequest req = HttpRequest.newBuilder(URI.create(backendUrl + "/api/v1/server-icon"))
                    .header("Content-Type",  "application/json")
                    .header("X-License-Key", licKey)
                    .header("X-Timestamp",   String.valueOf(ts))
                    .header("X-Signature",   sig)
                    .timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload), StandardCharsets.UTF_8))
                    .build();
            int sc = http.send(req, HttpResponse.BodyHandlers.ofString()).statusCode();
            if (sc >= 500 || sc == 408 || sc == 429) serverIconSent = false;
            logger.debug("[server-icon] sent, HTTP {}", sc);
        } catch (Throwable e) {
            serverIconSent = false;
            logger.debug("[server-icon] send failed: {}", e.toString());
        }
    }

    public void fetchAndSyncBans(BanCache banCache) {
        if (signer == null || !signer.hasSecret()) return;
        long   ts        = clock.now();
        long   offsetAlEnviar = clock.offsetMs();

        long   tsLocal   = ts - offsetAlEnviar;
        String licKey    = licenseKey;
        String backendUrl= ConfigManager.DEFAULT_BACKEND_URL;
        String sig       = signer.sign(HmacSigner.requestPayload(ts, "", "bans"));

        HttpRequest req = HttpRequest.newBuilder(URI.create(backendUrl + "/api/v1/bans"))
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .timeout(java.time.Duration.ofSeconds(10))
                .GET().build();

        http.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                .thenAccept(resp -> {
                    if (resp.statusCode() == 400) {

                        long serverTimeMs = ClockOffset.leerServerTimeMs(resp.body());
                        if (serverTimeMs > 0) {
                            Long total = clock.aprender(serverTimeMs, ts, clock.now(), offsetAlEnviar);
                            if (total != null) {
                                logger.warn("This machine's clock is off by {} ms from the Jarvis backend; requests "
                                        + "are now corrected. Fix NTP on this server.", total);
                            }
                        }
                    }
                    if (resp.statusCode() != 200) return;

                    boolean listaCompletaVerificada = false;
                    String bansSig = resp.headers().firstValue("X-Bans-Sig").orElse(null);
                    if (bansSig != null) {
                        long bansTs = 0L;
                        try { bansTs = Long.parseLong(resp.headers().firstValue("X-Bans-Ts").orElse("0").trim()); }
                        catch (NumberFormatException ignored) {  }

                        if (Math.abs(clock.now() - bansTs) > 120_000L
                                || !dev.flamingomg.jarvis.security.VerdictVerifier.verifyBans(bansTs, resp.body(), bansSig)) {
                            logger.warn("Bans list signature invalid or stale; skipping this sync cycle.");
                            return;
                        }

                        String sig2 = resp.headers().firstValue("X-Bans-Sig-V2").orElse(null);
                        if (sig2 != null) {
                            boolean dice = !"false".equalsIgnoreCase(
                                    resp.headers().firstValue("X-Bans-Complete").orElse("true").trim());
                            if (!dev.flamingomg.jarvis.security.VerdictVerifier.verifyBansV2(
                                    bansTs, licKey, dice, resp.body(), sig2)) {
                                logger.warn("Bans list v2 signature invalid (wrong license or tampered completeness); "
                                        + "skipping this sync cycle.");
                                return;
                            }
                            listaCompletaVerificada = dice;
                        }
                    } else {
                        if (!warnedUnsignedBans) {
                            warnedUnsignedBans = true;
                            logger.warn("Backend bans response is unsigned; applying without verification.");
                        }

                        if (dev.flamingomg.jarvis.security.VerdictVerifier.keyLoaded()) return;
                    }
                    try {

                        long now = clock.now();
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

                                    long ttlLong = Math.max(0L, (num.longValue() - now) / 1000);
                                    ttlSec = (int) Math.min(ttlLong, Integer.MAX_VALUE);
                                    if (ttlSec == 0) continue;
                                } else {
                                    continue;
                                }
                                banCache.ban(banIp, ttlSec);
                                snapshotIps.add(banIp);
                                count++;
                            } catch (RuntimeException ignored) {  }
                        }

                        banCache.listaAplicada(snapshotIps, listaCompletaVerificada);
                        if (listaCompletaVerificada) {
                            banCache.reconciliar(snapshotIps, tsLocal);
                        }
                        logger.debug("{} bans synced.", count);
                    } catch (Exception e) {
                        logger.debug("Error parsing bans: {}", e.getMessage());
                    }
                })
                .exceptionally(e -> { logger.debug("Error syncing bans: {}", e.getMessage()); return null; });
    }

    public String circuitBreakerStatus() {
        return cbState.get().name() + " (" + cbFailures.get() + " failures)";
    }

    public boolean backendHealthy() {
        return cbState.get() == CbState.CLOSED;
    }

    private final dev.flamingomg.jarvis.detection.ProtectionWatch protectionWatch =
            new dev.flamingomg.jarvis.detection.ProtectionWatch();

    public dev.flamingomg.jarvis.model.ProtectionState protectionState() {
        HmacSigner s = signer;
        boolean canSign = s != null && s.hasSecret() && !keyRejected;

        boolean sano = backendHealthy() && !veredictosFallando(
                System.currentTimeMillis(), ultimoVeredictoOkMs, ultimoVeredictoFalloMs, VENTANA_FALLO_MS);
        return dev.flamingomg.jarvis.model.ProtectionState.of(canSign, sano, ipCheckDisabled);
    }

    private volatile boolean ipCheckDisabled = false;

    public void setIpCheckDisabled(boolean v) { this.ipCheckDisabled = v; }

    public VerdictCache cache() { return cache; }

    private void startKeepAlive() {

        long periodMs = Math.max(5_000L, config.getInt("backend.keepalive-ms", 15_000) <= 0
                ? 15_000L : config.getInt("backend.keepalive-ms", 15_000));
        keepAlive.scheduleWithFixedDelay(this::pingBackend, periodMs, periodMs,
                java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private boolean pingDesactivado() { return config.getInt("backend.keepalive-ms", 15_000) <= 0; }

    private void pingBackend() {
        try {

            if (!isBlank(licenseKey)) {
                for (String l : protectionWatch.lineas(protectionState(), System.currentTimeMillis())) logger.warn(l);
            }
            if (isBlank(licenseKey)) return;

            HmacSigner sg = signer;
            if ((sg == null || !sg.hasSecret()) && !keyRejected
                    && secretResetInFlight.compareAndSet(false, true)) {
                Thread bt = new Thread(() -> {
                    try { ensureReady(); } catch (Exception ignore) {}
                    finally { secretResetInFlight.set(false); }
                }, "jarvis-secret-bootstrap");
                bt.setDaemon(true);
                bt.start();
            }
            if (pingDesactivado()) return;
            String url = ConfigManager.DEFAULT_BACKEND_URL;
            int connectMs = Math.max(1, config.getInt("backend.connect-timeout-ms", 8000));
            HttpRequest req = HttpRequest.newBuilder(URI.create(url + "/ready"))
                    .timeout(Duration.ofMillis(connectMs))
                    .GET().build();
            http.sendAsync(req, HttpResponse.BodyHandlers.ofString())
                    .thenAccept(r -> { if (r.statusCode() / 100 == 2) backendRespondio(); })
                    .exceptionally(e -> { logger.debug("keepalive ping failed: {}", e.getMessage()); return null; });
        } catch (Exception e) {
            logger.debug("keepalive error: {}", e.getMessage());
        }
    }

    public void shutdown() {

        HttpExecutors.shutdownQuietly(keepAlive);
        denials.stop();
        HttpExecutors.closeQuietly(http);
        HttpExecutors.shutdownQuietly(httpExecutor);
    }

    private boolean responseFresh(long responseTs) {
        long windowMs = maxResponseAgeMs;

        return isFresh(clock.now(), responseTs, windowMs);
    }

    static boolean isFresh(long now, long responseTs, long windowMs) {
        long delta = now - responseTs;
        return delta <= windowMs && delta >= -windowMs;
    }

    public java.util.concurrent.CompletableFuture<Boolean> blacklistAsync(
            String username, String reason, String actor, boolean remove) {
        if (signer == null || !signer.hasSecret()) {
            return java.util.concurrent.CompletableFuture.completedFuture(false);
        }
        long   ts  = clock.now();
        String sig = signer.sign(HmacSigner.requestPayload(ts, remove ? "unblacklist" : "blacklist",
                username == null ? "" : username));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        if (reason != null && !reason.isEmpty()) payload.put("reason", reason);
        if (actor  != null && !actor.isEmpty())  payload.put("actor", actor);
        if (remove) payload.put("remove", true);
        payload.put("timestamp", ts);
        long timeoutMs = Math.max(5000L, config.getInt("backend.connect-timeout-ms", 8000) + 5000L);
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create(ConfigManager.DEFAULT_BACKEND_URL + "/api/v1/blacklist"))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licenseKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload), StandardCharsets.UTF_8))
                .build();
        return http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .thenApply(r -> r.statusCode() >= 200 && r.statusCode() < 300)
                .exceptionally(e -> { logger.debug("blacklist {}: {}", username, e.toString()); return false; });
    }

    public java.util.concurrent.CompletableFuture<Integer> whitelistAsync(
            String username, String time, String reason, String actor, boolean remove) {
        if (signer == null || !signer.hasSecret()) {
            return java.util.concurrent.CompletableFuture.completedFuture(0);
        }
        long   ts  = clock.now();
        String accion = remove ? "unwhitelist" : ("whitelist:" + (time == null ? "" : time));
        String sig = signer.sign(HmacSigner.requestPayload(ts, accion, username == null ? "" : username));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        if (!remove && time != null && !time.isEmpty()) payload.put("time", time);
        if (reason != null && !reason.isEmpty()) payload.put("reason", reason);
        if (actor  != null && !actor.isEmpty())  payload.put("actor", actor);
        if (remove) payload.put("remove", true);
        payload.put("timestamp", ts);
        long timeoutMs = Math.max(5000L, config.getInt("backend.connect-timeout-ms", 8000) + 5000L);
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create(ConfigManager.DEFAULT_BACKEND_URL + "/api/v1/allowlist"))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licenseKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig)
                .POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(payload), StandardCharsets.UTF_8))
                .build();
        return http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .thenApply(HttpResponse::statusCode)
                .exceptionally(e -> { logger.debug("whitelist {}: {}", username, e.toString()); return 0; });
    }

    private void report(String endpoint, String ipForSig, String userForSig,
                        Map<String, Object> payload, String errorMsg) {
        if (signer == null || !signer.hasSecret()) return;
        long   ts         = clock.now();
        String licKey     = licenseKey;
        String backendUrl = ConfigManager.DEFAULT_BACKEND_URL;
        String sig        = signer.sign(HmacSigner.requestPayload(ts, ipForSig, userForSig));
        payload.put("timestamp", ts);
        sendAsync(backendUrl + endpoint, licKey, ts, sig, null, GSON.toJson(payload),
                () -> logger.debug("{}", errorMsg));
    }

    private void reportConIdentidad(String endpoint, String ipForSig, String userForSig,
                                    String uuid, boolean premium,
                                    Map<String, Object> payload, String errorMsg) {
        if (signer == null || !signer.hasSecret()) return;
        long   ts         = clock.now();
        String licKey     = licenseKey;
        String backendUrl = ConfigManager.DEFAULT_BACKEND_URL;
        String sig        = signer.sign(HmacSigner.requestPayloadWithIdentity(ts, ipForSig, userForSig, uuid, premium));
        payload.put("timestamp", ts);
        sendAsync(backendUrl + endpoint, licKey, ts, sig, HmacSigner.CANON_SEEN_AMPLIADO, GSON.toJson(payload),
                () -> logger.debug("{}", errorMsg));
    }

    private void sendAsync(String url, String licKey, long ts, String sig, String canon, String body, Runnable onError) {

        long timeoutMs = Math.max(5000L, config.getInt("backend.connect-timeout-ms", 8000) + 5000L);
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(timeoutMs))
                .header("Content-Type",  "application/json")
                .header("X-License-Key", licKey)
                .header("X-Timestamp",   String.valueOf(ts))
                .header("X-Signature",   sig);

        if (canon != null) b.header("X-Sig-Canon", canon);
        HttpRequest req = b.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
        http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .exceptionally(e -> { onError.run(); return null; });
    }
}
