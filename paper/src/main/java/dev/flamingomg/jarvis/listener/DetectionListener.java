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
import dev.flamingomg.jarvis.util.Log;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class DetectionListener implements Listener, PluginMessageListener {

    private static final MiniMessage MM = MiniMessage.miniMessage();

    private static final LegacyComponentSerializer LEGACY =
            LegacyComponentSerializer.builder().character('§').hexColors()
                    .useUnusualXRepeatedCharacterHexFormat().build();

    private static final java.util.regex.Pattern MM_TAG = java.util.regex.Pattern.compile(
            "<\\/?(#[0-9a-fA-F]{6}|colou?r|gradient|rainbow|bold|italic|underlined|strikethrough|obfuscated|"
          + "reset|black|dark_blue|dark_green|dark_aqua|dark_red|dark_purple|gold|gr[ae]y|dark_gr[ae]y|blue|"
          + "green|aqua|red|light_purple|yellow|white|b|i|u|st|em)(:[^>]*)?>", java.util.regex.Pattern.CASE_INSENSITIVE);
    private static final java.util.regex.Pattern LEGACY_HEX = java.util.regex.Pattern.compile("[&§]#([0-9a-fA-F]{6})");
    private static final java.util.regex.Pattern LEGACY_AMP = java.util.regex.Pattern.compile("&([0-9a-fk-orA-FK-OR])");

    private final Plugin plugin;
    private final JarvisClient client;
    private final BedrockDetector bedrockDetector;
    private final ConfigManager config;
    private final Log logger;
    private final FloodGuard floodGuard;
    private final BanCache banCache;

    private final ConcurrentHashMap<String, Integer> connectingByIp = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Integer> connectedByIp = new ConcurrentHashMap<>();

    private final Cache<UUID, Long> sessionStart = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<UUID, String> sessionIp = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<String, Boolean> bypassNames = Caffeine.newBuilder().maximumSize(10_000)

            .expireAfterAccess(java.time.Duration.ofDays(7)).build();

    private final Cache<UUID, String> clientBrands = Caffeine.newBuilder().maximumSize(20_000).build();

    public DetectionListener(Plugin plugin, JarvisClient client, BedrockDetector bedrockDetector,
                             ConfigManager config, Log logger, FloodGuard floodGuard, BanCache banCache) {
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

        if (isBypassed(name) || (name != null && bypassNames.getIfPresent(name.toLowerCase(java.util.Locale.ROOT)) != null)) return;

        boolean bedrockBypass = bedrock && config.getBoolean("floodgate.bypass-bedrock", false);

        boolean reservedIp = false;
        if (!bedrockBypass) {
            if (floodGuard.checkAndRecord(ip)) {
                client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.FLOOD, ip, name);
                denyLocal(event, config.getString("messages.flood", Messages.get(client.locale(), "flood")));
                return;
            }
            if (banCache.isBanned(ip)) {
                client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.LOCAL_BAN, ip, name);
                denyLocal(event, config.getString("messages.block", Messages.get(client.locale(), "block")));
                return;
            }
            int maxPerIp = client.maxAccountsPerIp();
            if (maxPerIp > 0) {

                int connecting = connectingByIp.merge(ip, 1, Integer::sum);
                reservedIp = true;
                if (connecting + connectedByIp.getOrDefault(ip, 0) > maxPerIp) {
                    releaseConnecting(ip);
                    reservedIp = false;
                    client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.MAX_PER_IP, ip, name);
                    denyLocal(event, config.getString("messages.maxperip", Messages.get(client.locale(), "maxperip")));
                    return;
                }
            }
        }

        boolean premium = Bukkit.getOnlineMode();

        try {
            VerdictResponse verdict;

            java.util.concurrent.CompletableFuture<VerdictResponse> verdictFuture;
            try {
                verdictFuture = client.requestVerdictAsync(ip, name, bedrock, premium);
            } catch (Throwable t) {
                logger.warn("Error starting the verdict for {} ({}): {}", name, ip, t.toString());
                applyFallbackPolicy(event, name, ip);
                return;
            }
            try {
                long timeoutMs = config.getInt("backend.timeout-ms", 500) + 4500L;
                verdict = verdictFuture.get(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (Throwable t) {
                logger.debug("Error getting the verdict for {} ({}): {}", name, ip, t.getMessage());
                applyFallbackPolicy(event, name, ip);
                return;
            }

            if (verdict == null) { applyFallbackPolicy(event, name, ip); return; }
            VerdictType type = verdict.verdictType();

            if (bedrock && type.denies() && config.getBoolean("floodgate.bypass-bedrock", false)) {
                type = VerdictType.FLAG;
            }
            if (type.isUnknown()) { applyFallbackPolicy(event, name, ip); return; }
            if (type != VerdictType.ALLOW) logger.debug("[detection] {} ({}) -> {}", name, ip, type);

            if (type.denies()) {
                banCache.ban(ip);
                String msg = verdict.message() != null
                        ? verdict.message()
                        : config.getString("messages.block", Messages.get(client.locale(), "block"));
                deny(event, msg);
                notifyStaff(name, ip);
            }
        } finally {
            if (reservedIp) releaseConnecting(ip);
        }
    }

    private void deny(AsyncPlayerPreLoginEvent event, String msg) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, renderBranded(msg));
    }

    private void denyLocal(AsyncPlayerPreLoginEvent event, String rawMsg) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, renderBrandedLocal(rawMsg));
    }

    private void applyFallbackPolicy(AsyncPlayerPreLoginEvent event, String name, String ip) {

    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        sessionStart.put(player.getUniqueId(), System.currentTimeMillis());
        recordConnected(player);
        String lname = player.getName().toLowerCase(java.util.Locale.ROOT);

        if (player.hasPermission("jarvis.bypass")) bypassNames.put(lname, Boolean.TRUE);
        else bypassNames.invalidate(lname);
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
        Integer vd = null;
        try { vd = player.getClientViewDistance(); } catch (Throwable ignored) {}
        java.util.Set<String> ch = player.getListeningPluginChannels();
        java.util.List<String> channels = (ch == null || ch.isEmpty()) ? null : java.util.List.copyOf(ch);
        final String localeF = locale, hostF = host, nameF = player.getName();
        final Integer vdF = vd;

        Bukkit.getScheduler().runTaskLaterAsynchronously(plugin, () -> {
            String brand = clientBrands.getIfPresent(uuid);
            client.reportPlayerSeen(uuid.toString(), nameF, ip, bedrock,
                    null, brand, hostF, localeF, vdF, null, channels, premium, null);
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

    private static final java.lang.reflect.Method GET_VIRTUAL_HOST = resolveVirtualHost();

    private static java.lang.reflect.Method resolveVirtualHost() {
        try { return Player.class.getMethod("getVirtualHost"); }
        catch (Throwable ignored) { return null; }
    }

    private static String virtualHost(Player player) {
        if (GET_VIRTUAL_HOST == null) return null;
        try {
            Object vh = GET_VIRTUAL_HOST.invoke(player);
            if (vh instanceof InetSocketAddress isa) return isa.getHostString();
        } catch (Throwable ignored) {}
        return null;
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        clientBrands.invalidate(player.getUniqueId());

        String estIp = sessionIp.asMap().remove(player.getUniqueId());
        if (estIp != null) connectedByIp.computeIfPresent(estIp, (k, v) -> v <= 1 ? null : v - 1);
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
        norm = LEGACY_AMP.matcher(norm).replaceAll("§$1");
        return LEGACY.deserialize(norm);
    }

    private record Branding(String locale, Component component) {}
    private volatile Branding branding;

    private Component brandingFor(String locale) {
        Branding b = branding;
        if (b != null && locale.equals(b.locale())) return b.component();
        String wm = Messages.get(locale, "watermark");
        Component component = Component.newline().append(Component.newline())
                .append(MM.deserialize("<dark_gray>🛡 " + MM.escapeTags(wm)
                        + "</dark_gray> <gradient:#00ff9c:#22e0d8><bold>jarvisguard.com</bold></gradient>"));
        branding = new Branding(locale, component);
        return component;
    }

    private String renderBranded(String msg) {

        return LEGACY.serialize(renderComponent(msg).append(brandingFor(client.locale())));
    }

    private record LocalMsg(String locale, String rawText, String rendered) {}
    private volatile LocalMsg localMsg;

    private String renderBrandedLocal(String rawText) {
        String locale = client.locale();
        LocalMsg m = localMsg;
        if (m != null && locale.equals(m.locale()) && java.util.Objects.equals(rawText, m.rawText())) return m.rendered();
        String rendered = LEGACY.serialize(renderComponent(rawText).append(brandingFor(locale)));
        localMsg = new LocalMsg(locale, rawText, rendered);
        return rendered;
    }

    private void recordConnected(Player player) {
        InetSocketAddress addr = player.getAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        sessionIp.put(player.getUniqueId(), ip);
        connectedByIp.merge(ip, 1, Integer::sum);
    }

    public void init() {

        Bukkit.getScheduler().runTaskTimer(plugin, this::reconcile, 0L, 300L);
    }

    private void reconcile() {
        java.util.HashMap<String, Integer> truth = new java.util.HashMap<>();
        for (Player p : Bukkit.getOnlinePlayers()) {
            InetSocketAddress a = p.getAddress();
            if (a != null && a.getAddress() != null) {
                truth.merge(a.getAddress().getHostAddress(), 1, Integer::sum);
            }
        }
        connectedByIp.keySet().removeIf(k -> !truth.containsKey(k));
        connectedByIp.putAll(truth);
    }

    private void releaseConnecting(String ip) {
        connectingByIp.computeIfPresent(ip, (k, v) -> v <= 1 ? null : v - 1);
    }

    private boolean isBypassed(String username) {

        return username != null && config.bypassUsernames().contains(username.toLowerCase(java.util.Locale.ROOT));
    }

    private void notifyStaff(String name, String ip) {
        if (!client.notifyStaffEnabled()) return;

        String safeName = (name != null) ? name : "?";
        String safeIp   = (ip != null) ? ip : "?";
        String template = config.getString("messages.staff-notify", Messages.get(client.locale(), "staff"));
        String text = LEGACY.serialize(MM.deserialize(template
                .replace("{name}", MM.escapeTags(safeName)).replace("{ip}", MM.escapeTags(safeIp)).replace("{score}", "")));
        Bukkit.getScheduler().runTask(plugin, () -> {

            for (Player p : Bukkit.getOnlinePlayers())
                if (p.hasPermission(client.notifyPermission()) || p.hasPermission("jarvis.admin")) p.sendMessage(text);
        });
    }
}
