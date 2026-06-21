package dev.flamingomg.jarvis.listener;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.model.VerdictType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.serializer.bungeecord.BungeeComponentSerializer;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.BaseComponent;
import net.md_5.bungee.api.connection.Connection;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PluginMessageEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;

import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public final class DetectionListener implements Listener {

    private static final MiniMessage MM = MiniMessage.miniMessage();
    private static final BungeeComponentSerializer BUNGEE = BungeeComponentSerializer.get();

    private final ProxyServer proxy;
    private final Plugin plugin;
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

    private final Cache<UUID, String> clientBrands =
            Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<String, Boolean> bypassNames =
            Caffeine.newBuilder().maximumSize(10_000).build();

    public DetectionListener(ProxyServer proxy, Plugin plugin, JarvisClient client,
                             BedrockDetector bedrockDetector, ConfigManager config,
                             Logger logger, FloodGuard floodGuard, BanCache banCache) {
        this.proxy = proxy;
        this.plugin = plugin;
        this.client = client;
        this.bedrockDetector = bedrockDetector;
        this.config = config;
        this.logger = logger;
        this.floodGuard = floodGuard;
        this.banCache = banCache;
    }

    @EventHandler
    public void onLogin(LoginEvent event) {
        if (event.isCancelled()) return;
        PendingConnection conn = event.getConnection();
        InetSocketAddress addr = conn.getAddress();
        if (addr == null || addr.getAddress() == null) return;

        String ip   = addr.getAddress().getHostAddress();
        String name = conn.getName();
        UUID uuid   = conn.getUniqueId();

        boolean bedrock = (uuid != null && bedrockDetector.isBedrockPlayer(uuid))
                || bedrockDetector.isBedrockUsername(name);

        if (isBypassed(name) || (name != null && bypassNames.getIfPresent(name.toLowerCase()) != null)) return;

        boolean bedrockBypass = bedrock && config.getBoolean("floodgate.bypass-bedrock", false);

        if (!bedrockBypass) {
            if (floodGuard.checkAndRecord(ip)) {
                String msg = config.getString("messages.flood",
                        dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "flood"));
                event.setCancelled(true);
                event.setCancelReason(serialize(renderBranded(msg)));
                return;
            }
            if (banCache.isBanned(ip)) {
                String msg = config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
                event.setCancelled(true);
                event.setCancelReason(serialize(renderBranded(msg)));
                return;
            }

            int maxPerIp = client.maxAccountsPerIp();
            if (maxPerIp > 0 && countOnlineFromIp(ip) >= maxPerIp) {
                String msg = config.getString("messages.maxperip",
                        dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "maxperip"));
                event.setCancelled(true);
                event.setCancelReason(serialize(renderBranded(msg)));
                return;
            }
        }

        boolean premium = conn.isOnlineMode();
        final boolean bedrockFinal = bedrock;

        event.registerIntent(plugin);

        final java.util.concurrent.CompletableFuture<dev.flamingomg.jarvis.model.VerdictResponse> verdictFuture;
        try {
            verdictFuture = client.requestVerdictAsync(ip, name, bedrockFinal, premium);
        } catch (Throwable t) {
            logger.warning("[jarvis] Error starting the verdict for " + name + " (" + ip + "): " + t.getMessage());
            applyFallbackPolicy(event, name, ip);
            event.completeIntent(plugin);
            return;
        }
        verdictFuture.whenComplete((verdict, err) -> {
            try {
                if (err != null || verdict == null) {

                    logger.fine("[jarvis] Error getting the verdict for " + name + " (" + ip + "): "
                            + (err != null ? err.getMessage() : "respuesta nula"));
                    applyFallbackPolicy(event, name, ip);
                    return;
                }
                VerdictType type = verdict.verdictType();

                if (bedrockFinal && type.denies() && config.getBoolean("floodgate.bypass-bedrock", false)) {
                    type = VerdictType.FLAG;
                }

                if (type.isUnknown()) {
                    applyFallbackPolicy(event, name, ip);
                    return;
                }

                if (type != VerdictType.ALLOW) {
                    logger.fine("[detection] " + name + " (" + ip + ") -> " + type);
                }

                if (type.denies()) {
                    banCache.ban(ip);
                    String msg = verdict.message() != null
                            ? verdict.message()
                            : config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
                    event.setCancelled(true);
                    event.setCancelReason(serialize(renderBranded(msg)));
                    notifyStaff(name, ip);
                }

            } catch (Exception e) {

                logger.warning("[jarvis] Exception applying the verdict for " + name + " (" + ip + "): " + e.getMessage());
            } finally {

                event.completeIntent(plugin);
            }
        });
    }

    private void applyFallbackPolicy(LoginEvent event, String name, String ip) {
        String policy = config.getString("fallback.policy",
                config.getString("unknown.policy", "ALLOW")).toUpperCase();
        if ("BLOCK".equals(policy)) {
            String msg = config.getString("messages.block", dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "block"));
            event.setCancelled(true);
            event.setCancelReason(serialize(renderBranded(msg)));
            logger.warning("[jarvis] UNKNOWN (degraded) → BLOCK applied to " + name + " (" + ip + ")");
        }

    }

    @EventHandler
    public void onPostLogin(PostLoginEvent event) {
        ProxiedPlayer player = event.getPlayer();

        sessionStart.put(player.getUniqueId(), new long[]{System.currentTimeMillis()});
        maybeRecordPlayerSeen(player);

        if (player.hasPermission("jarvis.bypass")) {

            bypassNames.put(player.getName().toLowerCase(), Boolean.TRUE);
        }
    }

    @EventHandler
    public void onPluginMessage(PluginMessageEvent event) {
        String tag = event.getTag();
        if (tag == null) return;

        Connection sender = event.getSender();
        if (!(sender instanceof ProxiedPlayer player)) return;
        UUID uuid = player.getUniqueId();

        if ("minecraft:register".equals(tag) || "REGISTER".equals(tag)) {

            java.util.Set<String> set = knownChannels.asMap().computeIfAbsent(uuid, k -> ConcurrentHashMap.newKeySet());
            try {
                String payload = new String(event.getData(), java.nio.charset.StandardCharsets.UTF_8);
                for (String channel : payload.split("\u0000")) {
                    if (set.size() >= MAX_CHANNELS_PER_PLAYER) break;
                    String c = channel.trim();
                    if (!c.isEmpty()) set.add(c);
                }
            } catch (Exception ignored) {  }
            return;
        }

        if ("minecraft:brand".equals(tag) || "MC|Brand".equals(tag)) {

            try {
                String brand = readBrand(event.getData());
                if (brand != null && !brand.isBlank()) clientBrands.put(uuid, brand.trim());
            } catch (Exception ignored) {  }
        }
    }

    private static String readBrand(byte[] data) {
        if (data == null || data.length == 0) return null;
        int idx = 0;

        int len = 0, shift = 0;
        while (idx < data.length && idx < 5) {
            byte b = data[idx++];
            len |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }

        if (len > 0 && len <= data.length - idx) {
            return new String(data, idx, len, java.nio.charset.StandardCharsets.UTF_8);
        }

        int start = (data.length > 1 && (data[0] & 0x80) == 0 && data[0] < data.length) ? 1 : 0;
        String s = new String(data, start, data.length - start, java.nio.charset.StandardCharsets.UTF_8);

        return s.replace("\u0000", "").trim();
    }

    private void maybeRecordPlayerSeen(ProxiedPlayer player) {
        PendingConnection conn = player.getPendingConnection();
        InetSocketAddress addr = conn.getAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        boolean bedrock = bedrockDetector.isBedrockPlayer(player.getUniqueId())
                || bedrockDetector.isBedrockUsername(player.getName());

        InetSocketAddress vh = conn.getVirtualHost();
        String host = vh != null ? vh.getHostString() : null;
        boolean premium = conn.isOnlineMode();

        proxy.getScheduler().schedule(plugin, () -> {

            String brand = clientBrands.getIfPresent(player.getUniqueId());

            String locale = player.getLocale() != null ? player.getLocale().toLanguageTag() : null;
            Integer viewDistance = null;
            String chatMode = null;

            String version = null;

            java.util.Set<String> ch = knownChannels.getIfPresent(player.getUniqueId());
            java.util.List<String> channels = (ch == null || ch.isEmpty())
                    ? null : java.util.List.copyOf(ch);
            client.reportPlayerSeen(player.getUniqueId().toString(), player.getName(),
                    ip, bedrock, version, brand, host, locale, viewDistance, chatMode, channels,
                    premium);
        }, 2, TimeUnit.SECONDS);
    }

    private static final java.util.regex.Pattern MM_TAG = java.util.regex.Pattern.compile(
            "<\\/?(#[0-9a-fA-F]{6}|colou?r|gradient|rainbow|bold|italic|underlined|strikethrough|obfuscated|"
          + "reset|black|dark_blue|dark_green|dark_aqua|dark_red|dark_purple|gold|gr[ae]y|dark_gr[ae]y|blue|"
          + "green|aqua|red|light_purple|yellow|white|b|i|u|st|em)(:[^>]*)?>", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern LEGACY_HEX = java.util.regex.Pattern.compile("[&§]#([0-9a-fA-F]{6})");
    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.builder().character('§').hexColors().build();

    private static Component render(String msg) {
        if (msg == null) return Component.empty();
        if (MM_TAG.matcher(msg).find()) {
            try { return MM.deserialize(msg); } catch (Exception ignored) {  }
        }

        String norm = LEGACY_HEX.matcher(msg).replaceAll(mr -> {
            StringBuilder sb = new StringBuilder("§x");
            for (char c : mr.group(1).toCharArray()) sb.append('§').append(c);
            return sb.toString();
        });

        norm = norm.replaceAll("&([0-9a-fk-orA-FK-OR])", "§$1");
        return LEGACY.deserialize(norm);
    }

    private Component renderBranded(String msg) {
        String wm = dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "watermark");
        Component branding = Component.newline().append(Component.newline())
                .append(MM.deserialize("<dark_gray>🛡 " + MM.escapeTags(wm) + "</dark_gray> <gradient:#00ff9c:#22e0d8><bold>jarvisguard.com</bold></gradient>"));
        return render(msg).append(branding);
    }

    private static BaseComponent[] serialize(Component component) {
        return BUNGEE.serialize(component);
    }

    private long countOnlineFromIp(String ip) {
        return proxy.getPlayers().stream().filter(p -> {
            InetSocketAddress a = p.getPendingConnection().getAddress();
            return a != null && a.getAddress() != null && ip.equals(a.getAddress().getHostAddress());
        }).count();
    }

    private boolean isBypassed(String username) {
        if (username == null) return false;
        return config.getList("bypass.usernames").stream()
                .filter(java.util.Objects::nonNull)
                .anyMatch(u -> u.toString().equalsIgnoreCase(username));
    }

    private void notifyStaff(String name, String ip) {
        if (!config.getBoolean("messages.notify-staff", true)) return;

        String safeName = (name != null) ? name : "?";
        String safeIp   = (ip != null) ? ip : "?";
        String template = config.getString("messages.staff-notify",
                dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "staff"));

        Component notification = MM.deserialize(
                template.replace("{name}", MM.escapeTags(safeName))
                        .replace("{ip}", MM.escapeTags(safeIp))
                        .replace("{score}", ""));
        BaseComponent[] serialized = serialize(notification);
        proxy.getPlayers().stream()
                .filter(p -> p.hasPermission("jarvis.admin"))
                .forEach(p -> p.sendMessage(serialized));
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        ProxiedPlayer player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        knownChannels.invalidate(uuid);
        clientBrands.invalidate(uuid);

        long[] startArr = sessionStart.asMap().remove(uuid);
        if (startArr == null) return;

        long durationMs = System.currentTimeMillis() - startArr[0];
        InetSocketAddress addr = player.getPendingConnection().getAddress();
        if (addr == null || addr.getAddress() == null) return;

        String ip   = addr.getAddress().getHostAddress();
        String name = player.getName();

        proxy.getScheduler().runAsync(plugin, () -> client.reportSessionEnd(name, ip, durationMs));
    }
}
