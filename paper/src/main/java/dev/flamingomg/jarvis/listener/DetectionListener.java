package dev.flamingomg.jarvis.listener;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.model.VerdictResponse;
import dev.flamingomg.jarvis.model.VerdictType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.messaging.PluginMessageListener;

import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public final class DetectionListener implements Listener, PluginMessageListener {

    private static final MiniMessage MM = MiniMessage.miniMessage();
    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.builder().character('§').hexColors().build();

    private static final java.util.regex.Pattern MM_TAG = java.util.regex.Pattern.compile(
            "<\\/?(#[0-9a-fA-F]{6}|colou?r|gradient|rainbow|bold|italic|underlined|strikethrough|obfuscated|"
          + "reset|black|dark_blue|dark_green|dark_aqua|dark_red|dark_purple|gold|gr[ae]y|dark_gr[ae]y|blue|"
          + "green|aqua|red|light_purple|yellow|white|b|i|u|st|em)(:[^>]*)?>", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern LEGACY_HEX = java.util.regex.Pattern.compile("[&§]#([0-9a-fA-F]{6})");

    private final Plugin plugin;
    private final JarvisClient client;
    private final BedrockDetector bedrockDetector;
    private final ConfigManager config;
    private final Logger logger;
    private final FloodGuard floodGuard;
    private final BanCache banCache;

    private final Cache<UUID, Long> sessionStart = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<String, Boolean> bypassNames = Caffeine.newBuilder().maximumSize(10_000).build();

    private final Cache<UUID, String> clientBrands = Caffeine.newBuilder().maximumSize(20_000).build();

    public DetectionListener(Plugin plugin, JarvisClient client, BedrockDetector bedrockDetector,
                             ConfigManager config, Logger logger, FloodGuard floodGuard, BanCache banCache) {
        this.plugin = plugin;
        this.client = client;
        this.bedrockDetector = bedrockDetector;
        this.config = config;
        this.logger = logger;
        this.floodGuard = floodGuard;
        this.banCache = banCache;
    }

    @EventHandler(priority = EventPriority.HIGH)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        if (config.getBoolean("server.behind-proxy", false)) return;
        if (event.getAddress() == null) return;

        String ip   = event.getAddress().getHostAddress();
        String name = event.getName();
        UUID uuid   = event.getUniqueId();

        boolean bedrock = (uuid != null && bedrockDetector.isBedrockPlayer(uuid))
                || bedrockDetector.isBedrockUsername(name);

        if (isBypassed(name) || (name != null && bypassNames.getIfPresent(name.toLowerCase()) != null)) return;

        boolean bedrockBypass = bedrock && config.getBoolean("floodgate.bypass-bedrock", false);

        if (!bedrockBypass) {
            if (floodGuard.checkAndRecord(ip)) {
                deny(event, config.getString("messages.flood", Messages.get(client.locale(), "flood")));
                return;
            }
            if (banCache.isBanned(ip)) {
                deny(event, config.getString("messages.block", Messages.get(client.locale(), "block")));
                return;
            }
            int maxPerIp = client.maxAccountsPerIp();
            if (maxPerIp > 0 && countOnlineFromIp(ip) >= maxPerIp) {
                deny(event, config.getString("messages.maxperip", Messages.get(client.locale(), "maxperip")));
                return;
            }
        }

        boolean premium = Bukkit.getOnlineMode();

        VerdictResponse verdict;
        try {
            long timeoutMs = config.getInt("backend.timeout-ms", 500) + 4500L;
            verdict = client.requestVerdictAsync(ip, name, bedrock, premium).get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (Throwable t) {
            logger.fine("[jarvis] Error getting the verdict for " + name + " (" + ip + "): " + t.getMessage());
            applyFallbackPolicy(event, name, ip);
            return;
        }

        if (verdict == null) { applyFallbackPolicy(event, name, ip); return; }
        VerdictType type = verdict.verdictType();

        if (bedrock && type.denies() && config.getBoolean("floodgate.bypass-bedrock", false)) {
            type = VerdictType.FLAG;
        }
        if (type.isUnknown()) { applyFallbackPolicy(event, name, ip); return; }
        if (type != VerdictType.ALLOW) logger.fine("[detection] " + name + " (" + ip + ") -> " + type);

        if (type.denies()) {
            banCache.ban(ip);
            String msg = verdict.message() != null
                    ? verdict.message()
                    : config.getString("messages.block", Messages.get(client.locale(), "block"));
            deny(event, msg);
            notifyStaff(name, ip);
        }
    }

    private void deny(AsyncPlayerPreLoginEvent event, String msg) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, renderBranded(msg));
    }

    private void applyFallbackPolicy(AsyncPlayerPreLoginEvent event, String name, String ip) {
        String policy = config.getString("fallback.policy", config.getString("unknown.policy", "ALLOW")).toUpperCase();
        if ("BLOCK".equals(policy)) {
            deny(event, config.getString("messages.block", Messages.get(client.locale(), "block")));
            logger.warning("[jarvis] UNKNOWN (degraded) -> BLOCK applied to " + name + " (" + ip + ")");
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        sessionStart.put(player.getUniqueId(), System.currentTimeMillis());
        if (player.hasPermission("jarvis.bypass")) bypassNames.put(player.getName().toLowerCase(), Boolean.TRUE);
        maybeRecordPlayerSeen(player);
    }

    private void maybeRecordPlayerSeen(Player player) {
        InetSocketAddress addr = player.getAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        UUID uuid = player.getUniqueId();
        boolean bedrock = bedrockDetector.isBedrockPlayer(uuid) || bedrockDetector.isBedrockUsername(player.getName());
        boolean premium = Bukkit.getOnlineMode();
        String locale = null;
        try { locale = player.getLocale(); } catch (Throwable ignored) {}
        String host = virtualHost(player);
        java.util.Set<String> ch = player.getListeningPluginChannels();
        java.util.List<String> channels = (ch == null || ch.isEmpty()) ? null : java.util.List.copyOf(ch);
        final String localeF = locale, hostF = host, nameF = player.getName();

        Bukkit.getScheduler().runTaskLaterAsynchronously(plugin, () -> {
            String brand = clientBrands.getIfPresent(uuid);
            client.reportPlayerSeen(uuid.toString(), nameF, ip, bedrock,
                    null, brand, hostF, localeF, null, null, channels, premium);
        }, 40L);
    }

    @Override
    public void onPluginMessageReceived(String channel, Player player, byte[] message) {
        if (!"minecraft:brand".equals(channel)) return;
        String brand = readBrand(message);
        if (brand != null && !brand.isBlank()) clientBrands.put(player.getUniqueId(), brand.trim());
    }

    private static String readBrand(byte[] data) {
        if (data == null || data.length == 0) return null;
        int idx = 0, len = 0, shift = 0;
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
        return new String(data, start, data.length - start, java.nio.charset.StandardCharsets.UTF_8)
                .replace("\u0000", "").trim();
    }

    private static String virtualHost(Player player) {
        try {
            Object vh = Player.class.getMethod("getVirtualHost").invoke(player);
            if (vh instanceof InetSocketAddress isa) return isa.getHostString();
        } catch (Throwable ignored) {}
        return null;
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        clientBrands.invalidate(player.getUniqueId());
        Long start = sessionStart.asMap().remove(player.getUniqueId());
        if (start == null) return;
        long durationMs = System.currentTimeMillis() - start;
        InetSocketAddress addr = player.getAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        String name = player.getName();
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> client.reportSessionEnd(name, ip, durationMs));
    }

    private static Component renderComponent(String msg) {
        if (msg == null) return Component.empty();
        if (MM_TAG.matcher(msg).find()) {
            try { return MM.deserialize(msg); } catch (Exception ignored) {}
        }
        String norm = LEGACY_HEX.matcher(msg).replaceAll(mr -> {
            StringBuilder sb = new StringBuilder("§x");
            for (char c : mr.group(1).toCharArray()) sb.append('§').append(c);
            return sb.toString();
        });
        norm = norm.replaceAll("&([0-9a-fk-orA-FK-OR])", "§$1");
        return LegacyComponentSerializer.builder().character('§').hexColors().build().deserialize(norm);
    }

    private String renderBranded(String msg) {
        String wm = Messages.get(client.locale(), "watermark");
        Component branding = Component.newline().append(Component.newline())
                .append(MM.deserialize("<dark_gray>🛡 " + MM.escapeTags(wm)
                        + "</dark_gray> <gradient:#00ff9c:#22e0d8><bold>jarvisguard.com</bold></gradient>"));
        return LEGACY.serialize(renderComponent(msg).append(branding));
    }

    private long countOnlineFromIp(String ip) {
        long n = 0;
        for (Player p : Bukkit.getOnlinePlayers()) {
            InetSocketAddress a = p.getAddress();
            if (a != null && a.getAddress() != null && ip.equals(a.getAddress().getHostAddress())) n++;
        }
        return n;
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
        String template = config.getString("messages.staff-notify", Messages.get(client.locale(), "staff"));
        String text = LEGACY.serialize(MM.deserialize(template
                .replace("{name}", MM.escapeTags(safeName)).replace("{ip}", MM.escapeTags(safeIp)).replace("{score}", "")));
        Bukkit.getScheduler().runTask(plugin, () -> {
            for (Player p : Bukkit.getOnlinePlayers()) if (p.hasPermission("jarvis.admin")) p.sendMessage(text);
        });
    }
}
