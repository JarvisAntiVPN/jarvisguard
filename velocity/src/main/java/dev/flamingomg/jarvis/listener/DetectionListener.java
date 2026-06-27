package dev.flamingomg.jarvis.listener;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.PlayerChannelRegisterEvent;
import com.velocitypowered.api.proxy.messages.ChannelIdentifier;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.model.VerdictResponse;
import dev.flamingomg.jarvis.model.VerdictType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class DetectionListener {

    private static final MiniMessage MM = MiniMessage.miniMessage();

    private final ProxyServer proxy;
    private final Object pluginInstance;
    private final JarvisClient client;
    private final BedrockDetector bedrockDetector;
    private final ConfigManager config;
    private final Logger logger;
    private final FloodGuard floodGuard;
    private final BanCache banCache;

    private final Cache<UUID, long[]> sessionStart =
            Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<UUID, java.util.Set<String>> knownChannels =
            Caffeine.newBuilder().maximumSize(20_000).build();
    private static final int MAX_CHANNELS_PER_PLAYER = 64;

    private final Cache<String, Boolean> bypassNames =
            Caffeine.newBuilder().maximumSize(10_000)

                    .expireAfterAccess(java.time.Duration.ofDays(7)).build();

    public DetectionListener(ProxyServer proxy, Object pluginInstance, JarvisClient client,
                             BedrockDetector bedrockDetector, ConfigManager config,
                             Logger logger, FloodGuard floodGuard, BanCache banCache) {
        this.proxy = proxy;
        this.pluginInstance = pluginInstance;
        this.client = client;
        this.bedrockDetector = bedrockDetector;
        this.config = config;
        this.logger = logger;
        this.floodGuard = floodGuard;
        this.banCache = banCache;
    }

    @Subscribe
    public EventTask onLogin(LoginEvent event) {
        if (!event.getResult().isAllowed()) return null;
        Player player = event.getPlayer();
        InetSocketAddress addr = player.getRemoteAddress();
        if (addr == null || addr.getAddress() == null) return null;

        String ip   = addr.getAddress().getHostAddress();
        String name = player.getUsername();

        boolean bedrock = bedrockDetector.isBedrockPlayer(player.getUniqueId())
                || bedrockDetector.isBedrockUsername(name);

        if (isBypassed(name) || (name != null && bypassNames.getIfPresent(name.toLowerCase(java.util.Locale.ROOT)) != null)) return null;

        boolean bedrockBypass = bedrock && config.getBoolean("floodgate.bypass-bedrock", false);

        if (!bedrockBypass) {
            if (floodGuard.checkAndRecord(ip)) {
                String msg = config.getString("messages.flood",
                        dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "flood"));
                event.setResult(ResultedEvent.ComponentResult.denied(renderBranded(msg)));
                return null;
            }
            if (banCache.isBanned(ip)) {
                String msg = config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
                event.setResult(ResultedEvent.ComponentResult.denied(renderBranded(msg)));
                return null;
            }

            int maxPerIp = client.maxAccountsPerIp();
            if (maxPerIp > 0 && atLeastNFromSameIp(ip, maxPerIp)) {
                String msg = config.getString("messages.maxperip",
                        dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "maxperip"));
                event.setResult(ResultedEvent.ComponentResult.denied(renderBranded(msg)));
                return null;
            }
        }

        boolean premium = player.isOnlineMode();
        final boolean bedrockFinal = bedrock;

        final java.util.concurrent.CompletableFuture<VerdictResponse> verdictFuture;
        try {
            verdictFuture = client.requestVerdictAsync(ip, name, bedrockFinal, premium);
        } catch (Throwable t) {
            logger.warn("[jarvis] Error starting the verdict for {} ({}): {}", name, ip, t.toString());
            applyFallbackPolicy(event, name, ip);
            return null;
        }

        return EventTask.resumeWhenComplete(verdictFuture.handle((verdict, err) -> {
            try {
                if (err != null || verdict == null) {
                    logger.debug("[jarvis] Error getting the verdict for {} ({}): {}", name, ip,
                            err != null ? err.toString() : "null response");
                    applyFallbackPolicy(event, name, ip);
                    return null;
                }
                VerdictType type = verdict.verdictType();

                if (bedrockFinal && type.denies() && config.getBoolean("floodgate.bypass-bedrock", false)) {
                    type = VerdictType.FLAG;
                }

                if (type.isUnknown()) {
                    applyFallbackPolicy(event, name, ip);
                    return null;
                }

                if (type != VerdictType.ALLOW) {
                    logger.debug("[detection] {} ({}) -> {}", name, ip, type);
                }

                if (type.denies()) {
                    banCache.ban(ip);
                    String msg = verdict.message() != null
                            ? verdict.message()
                            : config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
                    event.setResult(ResultedEvent.ComponentResult.denied(renderBranded(msg)));
                    notifyStaff(name, ip);
                }
            } catch (Exception e) {
                logger.warn("[jarvis] Exception applying the verdict for {} ({}): {}", name, ip, e.toString());
                applyFallbackPolicy(event, name, ip);
            }
            return null;
        }));
    }

    private volatile boolean warnedBadFallback = false;

    private void applyFallbackPolicy(LoginEvent event, String name, String ip) {

        String raw = config.getString("fallback.policy",
                config.getString("unknown.policy", "ALLOW"));
        String policy = raw == null ? "ALLOW" : raw.trim().toUpperCase();
        if (!"ALLOW".equals(policy) && !"BLOCK".equals(policy)) {
            if (!warnedBadFallback) {
                warnedBadFallback = true;
                logger.warn("[jarvis] fallback.policy='{}' no reconocido; se asume ALLOW (valores válidos: ALLOW/BLOCK).", raw);
            }
            policy = "ALLOW";
        }
        if ("BLOCK".equals(policy)) {
            String msg = config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
            event.setResult(ResultedEvent.ComponentResult.denied(renderBranded(msg)));
            logger.warn("[jarvis] UNKNOWN (degraded) → BLOCK applied to {} ({})", name, ip);
        }
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();

        sessionStart.put(player.getUniqueId(), new long[]{System.currentTimeMillis()});
        maybeRecordPlayerSeen(player);

        String lname = player.getUsername().toLowerCase(java.util.Locale.ROOT);
        if (player.hasPermission("jarvis.bypass")) bypassNames.put(lname, Boolean.TRUE);

        else bypassNames.invalidate(lname);
    }

    @Subscribe
    public void onChannelRegister(PlayerChannelRegisterEvent event) {
        UUID uuid = event.getPlayer().getUniqueId();

        java.util.Set<String> set = knownChannels.asMap().computeIfAbsent(uuid, k -> ConcurrentHashMap.newKeySet());
        for (ChannelIdentifier id : event.getChannels()) {
            if (set.size() >= MAX_CHANNELS_PER_PLAYER) break;
            if (id != null && id.getId() != null) set.add(id.getId());
        }
    }

    private void maybeRecordPlayerSeen(Player player) {
        java.net.InetSocketAddress addr = player.getRemoteAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        boolean bedrock = bedrockDetector.isBedrockPlayer(player.getUniqueId())
                || bedrockDetector.isBedrockUsername(player.getUsername());

        var protocol = player.getProtocolVersion();
        String mrv = protocol.getMostRecentSupportedVersion();
        String version = (mrv != null && !mrv.isBlank()) ? mrv : protocol.getVersionIntroducedIn();
        String host = player.getVirtualHost()
                .map(java.net.InetSocketAddress::getHostString).orElse(null);

        proxy.getScheduler().buildTask(pluginInstance, () -> {
            String brand = player.isActive() ? player.getClientBrand() : null;

            String locale = null, chatMode = null; Integer viewDistance = null;
            try {
                var s = player.getPlayerSettings();
                if (s != null) {
                    if (s.getLocale() != null) locale = s.getLocale().toLanguageTag();
                    viewDistance = (int) s.getViewDistance();
                    if (s.getChatMode() != null) chatMode = s.getChatMode().name();
                }
            } catch (Exception ignored) {  }

            java.util.Set<String> ch = knownChannels.getIfPresent(player.getUniqueId());
            java.util.List<String> channels = (ch == null || ch.isEmpty())
                    ? null : java.util.List.copyOf(ch);
            client.reportPlayerSeen(player.getUniqueId().toString(), player.getUsername(),
                    ip, bedrock, version, brand, host, locale, viewDistance, chatMode, channels,
                    player.isOnlineMode());
        }).delay(2, TimeUnit.SECONDS).schedule();
    }

    private static final java.util.regex.Pattern MM_TAG = java.util.regex.Pattern.compile(
            "<\\/?(#[0-9a-fA-F]{6}|colou?r|gradient|rainbow|bold|italic|underlined|strikethrough|obfuscated|"
          + "reset|black|dark_blue|dark_green|dark_aqua|dark_red|dark_purple|gold|gr[ae]y|dark_gr[ae]y|blue|"
          + "green|aqua|red|light_purple|yellow|white|b|i|u|st|em)(:[^>]*)?>", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern LEGACY_HEX = java.util.regex.Pattern.compile("[&\u00a7]#([0-9a-fA-F]{6})");
    private static final java.util.regex.Pattern LEGACY_AMP = java.util.regex.Pattern.compile("&([0-9a-fk-orA-FK-OR])");
    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.builder().character('\u00a7').hexColors().build();

    private static Component render(String msg) {
        if (msg == null) return Component.empty();
        if (MM_TAG.matcher(msg).find()) {
            try { return MM.deserialize(msg); } catch (Exception ignored) {  }
        }

        String norm = LEGACY_HEX.matcher(msg).replaceAll(mr -> {
            StringBuilder sb = new StringBuilder("\u00a7x");
            for (char c : mr.group(1).toCharArray()) sb.append('\u00a7').append(c);
            return sb.toString();
        });

        norm = LEGACY_AMP.matcher(norm).replaceAll("\u00a7$1");
        return LEGACY.deserialize(norm);
    }

    private record Branding(String locale, Component component) {}
    private volatile Branding branding;

    private Component brandingFor(String locale) {
        Branding b = branding;
        if (b != null && locale.equals(b.locale())) return b.component();
        String wm = dev.flamingomg.jarvis.i18n.Messages.get(locale, "watermark");
        Component component = Component.newline().append(Component.newline())
                .append(MM.deserialize("<dark_gray>🛡 " + MM.escapeTags(wm) + "</dark_gray> <gradient:#00ff9c:#22e0d8><bold>jarvisguard.com</bold></gradient>"));
        branding = new Branding(locale, component);
        return component;
    }

    private Component renderBranded(String msg) {
        return render(msg).append(brandingFor(client.locale()));
    }

    private boolean atLeastNFromSameIp(String ip, int n) {
        int matches = 0;
        for (Player p : proxy.getAllPlayers()) {
            InetSocketAddress a = p.getRemoteAddress();
            if (a != null && a.getAddress() != null && ip.equals(a.getAddress().getHostAddress())) {
                if (++matches >= n) return true;
            }
        }
        return false;
    }

    private boolean isBypassed(String username) {

        return username != null && config.bypassUsernames().contains(username.toLowerCase(java.util.Locale.ROOT));
    }

    private void notifyStaff(String name, String ip) {
        if (!config.getBoolean("messages.notify-staff", true)) return;

        String safeName = (name != null) ? name : "?";
        String safeIp   = (ip != null) ? ip : "?";
        String template = config.getString("messages.staff-notify",
                dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "staff"));

        net.kyori.adventure.text.Component notification = MM.deserialize(
                template.replace("{name}", MM.escapeTags(safeName))
                        .replace("{ip}", MM.escapeTags(safeIp))
                        .replace("{score}", ""));
        proxy.getAllPlayers().stream()
                .filter(p -> p.hasPermission("jarvis.admin"))
                .forEach(p -> p.sendMessage(notification));
    }

    @Subscribe
    public EventTask onDisconnect(DisconnectEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        knownChannels.invalidate(uuid);

        long[] startArr = sessionStart.asMap().remove(uuid);
        if (startArr == null) return null;

        long durationMs = System.currentTimeMillis() - startArr[0];
        InetSocketAddress addr = player.getRemoteAddress();
        if (addr == null || addr.getAddress() == null) return null;

        String ip   = addr.getAddress().getHostAddress();
        String name = player.getUsername();

        return EventTask.async(() -> client.reportSessionEnd(name, ip, durationMs));
    }
}
