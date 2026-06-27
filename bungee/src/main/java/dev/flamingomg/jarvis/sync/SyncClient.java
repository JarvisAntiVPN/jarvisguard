package dev.flamingomg.jarvis.sync;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.security.HmacSigner;
import net.kyori.adventure.text.serializer.bungeecord.BungeeComponentSerializer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.minimessage.tag.resolver.TagResolver;
import net.kyori.adventure.text.minimessage.tag.standard.StandardTags;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.connection.ProxiedPlayer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.stream.Stream;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SyncClient {

    private static final MiniMessage MM = MiniMessage.miniMessage();

    private static final MiniMessage MM_SAFE = MiniMessage.builder()
            .tags(TagResolver.builder()
                    .resolver(StandardTags.color())
                    .resolver(StandardTags.decorations())
                    .resolver(StandardTags.gradient())
                    .resolver(StandardTags.rainbow())
                    .resolver(StandardTags.reset())
                    .resolver(StandardTags.newline())
                    .build())
            .build();

    private final ConfigManager config;
    private final Logger logger;
    private final JarvisClient jarvisClient;
    private final BanCache banCache;
    private final ProxyServer proxy;

    private final java.util.concurrent.ExecutorService httpExecutor =
            java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor();
    private final HttpClient http;
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private static final int RECONNECT_BASE_SEC = 5;
    private static final int RECONNECT_MAX_SEC = 60;
    private static final long RESYNC_PERIOD_MS = 12 * 60_000L;
    private static final long RESYNC_JITTER_MS = 3 * 60_000L;
    private int reconnectDelaySec = RECONNECT_BASE_SEC;

    private static final long SSE_STALE_MS = 60_000L;
    private volatile long lastActivityMs = 0L;
    private volatile Thread streamThread;
    private final ScheduledExecutorService watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "jarvis-sync-watchdog");
        t.setDaemon(true);
        return t;
    });

    private String currentEvent = "";

    public SyncClient(ConfigManager config, Logger logger, JarvisClient jarvisClient,
                      BanCache banCache, ProxyServer proxy) {
        this.config = config;
        this.logger = logger;
        this.jarvisClient = jarvisClient;
        this.banCache = banCache;
        this.proxy = proxy;

        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).executor(httpExecutor).build();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "jarvis-sync");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() {
        running.set(true);
        scheduler.execute(this::connect);

        watchdog.scheduleAtFixedRate(this::checkStale, SSE_STALE_MS, SSE_STALE_MS / 2, TimeUnit.MILLISECONDS);
        scheduleResync();
    }

    private void scheduleResync() {
        long delay = RESYNC_PERIOD_MS + java.util.concurrent.ThreadLocalRandom.current().nextLong(0, RESYNC_JITTER_MS);
        watchdog.schedule(() -> {
            try {
                dev.flamingomg.jarvis.security.HmacSigner s = jarvisClient.signer();
                if (running.get() && s != null && s.hasSecret()) jarvisClient.fetchAndSyncBans(banCache);
            } catch (Throwable t) { logger.fine("[sync] periodic resync failed: " + t.toString()); }
            if (running.get()) scheduleResync();
        }, delay, TimeUnit.MILLISECONDS);
    }

    public void stop() {
        running.set(false);
        scheduler.shutdownNow();
        watchdog.shutdownNow();

        try { http.close(); } catch (Exception ignored) {}
        httpExecutor.shutdownNow();
    }

    private void checkStale() {
        try {
            Thread st = streamThread;
            if (!running.get() || st == null) return;
            long idle = System.currentTimeMillis() - lastActivityMs;
            if (idle > SSE_STALE_MS) {
                logger.warning("[sync] SSE stream idle for " + idle + " ms (possible half-open); forcing reconnect.");
                st.interrupt();
            }
        } catch (Throwable t) {
            logger.fine("[sync] watchdog: " + t.toString());
        }
    }

    private void connect() {
        if (!running.get()) return;
        Thread.interrupted();
        HmacSigner signer = jarvisClient.signer();
        if (signer == null || !signer.hasSecret()) {

            jarvisClient.ensureReady();
            scheduler.schedule(this::connect, 5, TimeUnit.SECONDS);
            return;
        }
        String backendUrl = config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
        String licenseKey = config.getString("backend.license-key", "");
        long ts = System.currentTimeMillis();
        String signature = signer.sign(HmacSigner.requestPayload(ts, "sync", licenseKey));

        HttpRequest request = HttpRequest.newBuilder(URI.create(backendUrl + "/api/v1/sync/events"))
                .header("X-License-Key", licenseKey)
                .header("X-Timestamp", String.valueOf(ts))
                .header("X-Signature", signature)

                .header("X-Connector-Version", dev.flamingomg.jarvis.JarvisBungeePlugin.VERSION)
                .header("X-Connector-Platform", "bungee")
                .header("Accept", "text/event-stream")
                .GET()
                .build();

        try {
            HttpResponse<Stream<String>> resp = http.send(request, HttpResponse.BodyHandlers.ofLines());
            if (resp.statusCode() == 200) {
                reconnectDelaySec = RECONNECT_BASE_SEC;
                lastActivityMs = System.currentTimeMillis();
                streamThread = Thread.currentThread();

                try { jarvisClient.fetchAndSyncBans(banCache); }
                catch (Throwable t) { logger.fine("[sync] resync on connect failed: " + t.toString()); }
                try (java.util.stream.Stream<String> body = resp.body()) {

                    body.forEach(this::processLine);
                } finally {
                    streamThread = null;
                }
            } else if (running.get()) {

                logger.fine("[sync] SSE rejected HTTP " + resp.statusCode());
            }
        } catch (Exception e) {
            if (running.get()) {
                logger.fine("[sync] SSE connection lost, retrying in " + reconnectDelaySec + "s: " + e.getMessage());
            }
        }

        if (running.get()) {
            int delay = reconnectDelaySec;
            reconnectDelaySec = Math.min(reconnectDelaySec * 2, RECONNECT_MAX_SEC);

            int jitter = delay <= 1 ? 0 : java.util.concurrent.ThreadLocalRandom.current().nextInt(0, delay);
            scheduler.schedule(this::connect, delay + jitter, TimeUnit.SECONDS);
        }
    }

    private static final String[] SIGN_FIELDS =
            {"ip", "ips", "username", "reason", "text", "type", "maxAccountsPerIp", "ownerLocale"};
    private static final char SIGN_SEP = '\u001e';
    private static final long EVENT_FRESH_MS = 120_000L;

    private static boolean eventSignatureOk(String event, String data) {
        String sigB64 = extractField(data, "_sig");
        if (sigB64 == null) return false;
        long ts;
        try {
            String t = extractField(data, "_ts");
            ts = (t == null) ? 0L : Long.parseLong(t.trim());
        } catch (NumberFormatException e) { return false; }
        if (Math.abs(System.currentTimeMillis() - ts) > EVENT_FRESH_MS) return false;
        StringBuilder sb = new StringBuilder().append(event).append(SIGN_SEP).append(ts);
        for (String f : SIGN_FIELDS) {
            String v = extractField(data, f);
            sb.append(SIGN_SEP).append(v == null ? "" : v);
        }
        return dev.flamingomg.jarvis.security.VerdictVerifier.verifyEvent(sb.toString(), sigB64);
    }

    private void processLine(String line) {
        lastActivityMs = System.currentTimeMillis();
        if (line.startsWith("event:")) {
            currentEvent = line.substring(6).trim();
            return;
        }
        if (!line.startsWith("data:")) return;
        String data = line.substring(5).trim();

        try {

            if ("connected".equals(currentEvent)) return;
            if (!eventSignatureOk(currentEvent, data)) {
                logger.warning("[sync] discarded event '" + currentEvent + "' (bad/missing signature or stale)");
                return;
            }
            switch (currentEvent) {
                case "kick"        -> handleKick(data);
                case "message"     -> handleMessage(data);
                case "unban"       -> handleUnban(data);
                case "clean-cache" -> handleCleanCache();
                case "config"      -> handleConfig(data);
                default            -> handleBan(data);
            }
        } catch (Exception e) {
            logger.warning("[sync] Error processing event '" + currentEvent + "': " + e.getMessage());
        } finally {

            currentEvent = "";
        }
    }

    private void handleConfig(String data) {
        String v = extractField(data, "maxAccountsPerIp");
        if (v != null) {
            try { jarvisClient.setMaxAccountsPerIp(Integer.parseInt(v.trim())); }
            catch (NumberFormatException ignored) {  }
        }
        String loc = extractField(data, "ownerLocale");
        if (loc != null && !loc.isBlank()) jarvisClient.setLocale(loc);
    }

    private void handleCleanCache() {
        jarvisClient.cache().invalidateAll();
        banCache.clear();
        logger.fine("[sync] Local cache cleared by backend order");
    }

    private void handleBan(String data) {
        String ip = extractField(data, "ip");
        if (ip != null && !ip.isEmpty()) {
            logger.fine("[sync] Global ban received for IP " + ip);
            jarvisClient.invalidateIp(ip);
            banCache.ban(ip);
        }
    }

    private void handleUnban(String data) {
        String list = extractField(data, "ips");
        String single = extractField(data, "ip");
        String all = (list != null && !list.isEmpty()) ? list : single;
        if (all == null || all.isEmpty()) return;
        for (String raw : all.split(",")) {
            String ip = raw.trim();
            if (ip.isEmpty()) continue;
            banCache.unban(ip);
            jarvisClient.invalidateIp(ip);
            logger.fine("[sync] Targeted unban for IP " + ip);
        }
    }

    private void handleKick(String data) {
        String username = extractField(data, "username");
        String reason = extractField(data, "reason");
        if (username == null || username.isEmpty()) return;
        Component msg = render(reason != null ? reason : Messages.get(jarvisClient.locale(), "kick"));
        ProxiedPlayer p = proxy.getPlayer(username);
        if (p != null) {
            logger.fine("[sync] Remote kick of " + username + " from the panel");
            p.disconnect(BungeeComponentSerializer.get().serialize(msg));
        }
    }

    private void handleMessage(String data) {
        String username = extractField(data, "username");
        String text = extractField(data, "text");
        if (text == null || text.isEmpty()) return;
        String type = extractField(data, "type");

        if ("title".equals(type)) {
            String[] parts = text.replace("\\n", "\n").split("\n", 2);
            net.md_5.bungee.api.Title bt = proxy.createTitle();
            bt.title(BungeeComponentSerializer.get().serialize(renderSafe(parts[0])));
            bt.subTitle(BungeeComponentSerializer.get().serialize(parts.length > 1 ? renderSafe(parts[1]) : Component.empty()));
            if (username == null || username.isEmpty()) proxy.getPlayers().forEach(p -> p.sendTitle(bt));
            else { ProxiedPlayer p = proxy.getPlayer(username); if (p != null) p.sendTitle(bt); }
            return;
        }
        Component msg = renderSafe(text);
        if ("actionbar".equals(type)) {
            net.md_5.bungee.api.chat.BaseComponent[] bc = BungeeComponentSerializer.get().serialize(msg);
            if (username == null || username.isEmpty()) proxy.getPlayers().forEach(p -> p.sendMessage(net.md_5.bungee.api.ChatMessageType.ACTION_BAR, bc));
            else { ProxiedPlayer p = proxy.getPlayer(username); if (p != null) p.sendMessage(net.md_5.bungee.api.ChatMessageType.ACTION_BAR, bc); }
            return;
        }
        if (username == null || username.isEmpty()) {
            proxy.getPlayers().forEach(p -> p.sendMessage(BungeeComponentSerializer.get().serialize(msg)));
        } else {
            ProxiedPlayer p = proxy.getPlayer(username);
            if (p != null) p.sendMessage(BungeeComponentSerializer.get().serialize(msg));
        }
    }

    private static final java.util.regex.Pattern MM_TAG = java.util.regex.Pattern.compile(
            "<\\/?(#[0-9a-fA-F]{6}|colou?r|gradient|rainbow|bold|italic|underlined|strikethrough|obfuscated|"
          + "reset|black|dark_blue|dark_green|dark_aqua|dark_red|dark_purple|gold|gr[ae]y|dark_gr[ae]y|blue|"
          + "green|aqua|red|light_purple|yellow|white|b|i|u|st|em)(:[^>]*)?>", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern LEGACY_HEX = java.util.regex.Pattern.compile("[&§]#([0-9a-fA-F]{6})");
    private static final java.util.regex.Pattern LEGACY_AMP = java.util.regex.Pattern.compile("&([0-9a-fk-orA-FK-OR])");
    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.builder().character('§').hexColors().build();

    private static String normalizeLegacy(String msg) {
        String norm = LEGACY_HEX.matcher(msg).replaceAll(mr -> {
            StringBuilder sb = new StringBuilder("§x");
            for (char c : mr.group(1).toCharArray()) sb.append('§').append(c);
            return sb.toString();
        });
        return LEGACY_AMP.matcher(norm).replaceAll("§$1");
    }

    private static Component render(String msg) {
        if (msg == null) return Component.empty();
        msg = msg.replace("\\n", "\n");
        if (MM_TAG.matcher(msg).find()) {
            try { return MM.deserialize(msg); } catch (Exception ignored) { }
        }
        return LEGACY.deserialize(normalizeLegacy(msg));
    }

    private static Component renderSafe(String msg) {
        if (msg == null) return Component.empty();
        msg = msg.replace("\\n", "\n");
        if (MM_TAG.matcher(msg).find()) {
            try { return MM_SAFE.deserialize(msg); } catch (Exception ignored) { }
        }
        return LEGACY.deserialize(normalizeLegacy(msg));
    }

    private static final com.google.gson.Gson GSON = new com.google.gson.Gson();

    static String extractField(String json, String field) {
        try {
            com.google.gson.JsonObject obj = GSON.fromJson(json, com.google.gson.JsonObject.class);
            if (obj == null || !obj.has(field) || obj.get(field).isJsonNull()) return null;
            return obj.get(field).getAsString();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
