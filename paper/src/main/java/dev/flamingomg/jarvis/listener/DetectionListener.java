package dev.flamingomg.jarvis.listener;

import dev.flamingomg.jarvis.util.Schedulers;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.MarcaDeCliente;
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

    private final dev.flamingomg.jarvis.detection.PrivateIpWatch privateIpWatch =
            new dev.flamingomg.jarvis.detection.PrivateIpWatch(
                    "This connector is for DIRECT servers. If yours is behind a BungeeCord/Velocity proxy, install the proxy connector THERE and remove this one; if not, fix IP forwarding in your container.");

    public dev.flamingomg.jarvis.detection.PrivateIpWatch privateIpWatch() { return privateIpWatch; }

    private final FloodGuard floodGuard;
    private final BanCache banCache;

    private final ConcurrentHashMap<String, Integer> connectingByIp = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Integer> connectedByIp = new ConcurrentHashMap<>();

    private final Cache<UUID, Long> sessionStart = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<UUID, String> sessionIp = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<String, Boolean> bypassNames = Caffeine.newBuilder().maximumSize(10_000)

            .expireAfterAccess(java.time.Duration.ofDays(7)).build();

    private final Cache<UUID, String> clientBrands = Caffeine.newBuilder().maximumSize(20_000).build();

    private final Cache<UUID, java.util.Set<String>> knownChannels = Caffeine.newBuilder().maximumSize(20_000).build();
    private static final int MAX_CHANNELS_PER_PLAYER = 64;

    private final Cache<String, String> ultimoBloqueo;

    public DetectionListener(Plugin plugin, JarvisClient client, BedrockDetector bedrockDetector,
                             ConfigManager config, Log logger, FloodGuard floodGuard, BanCache banCache) {
        this.plugin = plugin;
        this.client = client;
        this.bedrockDetector = bedrockDetector;
        this.config = config;
        this.logger = logger;
        this.floodGuard = floodGuard;
        this.banCache = banCache;

        long recuerdoMin = Math.min(Math.max(0, config.getInt("bans.remember-kick-minutes", 1440)), 43_200);
        this.ultimoBloqueo = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(java.time.Duration.ofMinutes(recuerdoMin))
                .build();
    }

    @EventHandler(priority = EventPriority.HIGH)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;
        if (config.getBoolean("server.behind-proxy", false)) return;
        if (event.getAddress() == null) return;

        String ip   = event.getAddress().getHostAddress();
        String name = event.getName();

        for (String l : privateIpWatch.lineas(ip, System.currentTimeMillis())) logger.warn(l);
        UUID uuid   = event.getUniqueId();

        boolean bedrock = (uuid != null && bedrockDetector.isBedrockPlayer(uuid))
                || bedrockDetector.isBedrockUsername(name);

        if (isBypassed(name) || (name != null && bypassNames.getIfPresent(name.toLowerCase(java.util.Locale.ROOT)) != null)) return;

        boolean bedrockBypass = bedrock && config.getBoolean("floodgate.bypass-bedrock", false);

        boolean reservedIp = false;
        if (!bedrockBypass) {
            if (floodGuard.checkAndRecord(ip)) {
                client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.FLOOD, ip, name);
                denyLocal(event, config.getString("messages.flood", Messages.get(client.locale(), "flood")), name);
                return;
            }

            if (banCache.isBannedFor(ip, name)) {
                client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.LOCAL_BAN, ip, name);

                String recordado = ultimoBloqueo.getIfPresent(claveBloqueo(ip, name));
                if (recordado != null) deny(event, recordado);
                else denyLocal(event, textoBloqueoLocal(ip), name);
                return;
            }
            int maxPerIp = client.maxAccountsPerIp();
            if (maxPerIp > 0) {

                int connecting = connectingByIp.merge(ip, 1, Integer::sum);
                reservedIp = true;
                if (superaAforo(connecting, connectedByIp.getOrDefault(ip, 0), maxPerIp)) {
                    releaseConnecting(ip);
                    reservedIp = false;
                    client.denials().record(dev.flamingomg.jarvis.client.LocalDenialReporter.MAX_PER_IP, ip, name);
                    denyLocal(event, config.getString("messages.maxperip", Messages.get(client.locale(), "maxperip")), name);
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

                if (!Boolean.FALSE.equals(verdict.cacheIp())) {

                    banCache.ban(ip, motivoParaRecordar(verdict.msgKey()));
                }
                if (verdict.message() != null) {

                    ultimoBloqueo.put(claveBloqueo(ip, name), verdict.message());
                    deny(event, verdict.message());
                } else {
                    denyLocal(event, textoBloqueoLocal(ip), name);
                }
                notifyStaff(name, ip, verdict.msgKey());
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

    private void denyLocal(AsyncPlayerPreLoginEvent event, String rawMsg, String name) {
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, renderBrandedLocal(rawMsg, name));
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
        final String localeF = locale, hostF = host, nameF = player.getName();
        final Integer vdF = vd;
        programarInforme(player, uuid, ip, bedrock, premium, localeF, hostF, vdF, nameF, 1);
    }

    private boolean reprogramar(Player player, UUID uuid, String ip, boolean bedrock, boolean premium,
                                String localeF, String hostF, Integer vdF, String nameF, int intento) {
        try {
            programarInforme(player, uuid, ip, bedrock, premium, localeF, hostF, vdF, nameF, intento);
            return true;
        } catch (Throwable apagando) {
            return false;
        }
    }

    private void programarInforme(Player player, UUID uuid, String ip, boolean bedrock, boolean premium,
                                  String localeF, String hostF, Integer vdF, String nameF, int intento) {
        Schedulers.asyncRetrasada(plugin, () -> {
            String brand = clientBrands.getIfPresent(uuid);
            boolean conectado = player.isOnline();
            int tope = MarcaDeCliente.intentos(
                    config.getInt("seen.brand-wait-attempts", MarcaDeCliente.INTENTOS_POR_DEFECTO));
            if (MarcaDeCliente.paso(brand, conectado, intento, tope) == MarcaDeCliente.Paso.ESPERAR
                    && reprogramar(player, uuid, ip, bedrock, premium, localeF, hostF, vdF, nameF, intento + 1)) {
                return;
            }

            java.util.Set<String> ch = knownChannels.getIfPresent(uuid);
            java.util.List<String> channels = (ch == null || ch.isEmpty()) ? null : java.util.List.copyOf(ch);
            client.reportPlayerSeen(uuid.toString(), nameF, ip, bedrock,
                    null, brand, hostF, localeF, vdF, null, channels, premium, protocoloDelCliente());
        }, 40L);
    }

    private volatile int protocoloCache = -1;

    private Integer protocoloDelCliente() {
        int cache = protocoloCache;
        if (cache == -1) {
            cache = calcularProtocolo();
            protocoloCache = cache;
        }
        return cache > 0 ? cache : null;
    }

    private int calcularProtocolo() {
        try {
            var pm = plugin.getServer().getPluginManager();
            for (String traductor : new String[]{"ViaVersion", "ProtocolSupport"}) {
                if (pm.getPlugin(traductor) != null) return 0;
            }
            Object unsafe = org.bukkit.Bukkit.class.getMethod("getUnsafe").invoke(null);
            Object v = unsafe.getClass().getMethod("getProtocolVersion").invoke(unsafe);
            return (v instanceof Integer i && i > 0) ? i : 0;
        } catch (Throwable t) {
            return 0;
        }
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
    public void onChannelRegister(org.bukkit.event.player.PlayerRegisterChannelEvent event) {
        java.util.Set<String> set = knownChannels.asMap()
                .computeIfAbsent(event.getPlayer().getUniqueId(),
                                 k -> java.util.concurrent.ConcurrentHashMap.newKeySet());
        if (set.size() >= MAX_CHANNELS_PER_PLAYER) return;
        String id = event.getChannel();
        if (id != null && !id.isBlank()) set.add(id.trim());
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        clientBrands.invalidate(player.getUniqueId());
        knownChannels.invalidate(player.getUniqueId());

        String estIp = sessionIp.asMap().remove(player.getUniqueId());
        descontar(connectedByIp, estIp);
        Long start = sessionStart.asMap().remove(player.getUniqueId());
        if (start == null) return;
        long durationMs = System.currentTimeMillis() - start;
        InetSocketAddress addr = player.getAddress();
        if (addr == null || addr.getAddress() == null) return;
        String ip = addr.getAddress().getHostAddress();
        String name = player.getName();
        Schedulers.async(plugin, () -> client.reportSessionEnd(name, ip, durationMs));
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

        if (msg != null && msg.contains("jarvisguard.com")) return LEGACY.serialize(renderComponent(msg));
        return LEGACY.serialize(renderComponent(msg).append(brandingFor(client.locale())));
    }

    private String textoBloqueoLocal(String ip) {
        String motivo = banCache.msgKeyDe(ip);
        String delPanel = client.offlineMessage(motivo);

        String propio = dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), claveTextoLocal(motivo));
        return config.getString("messages.block", delPanel != null ? delPanel : propio);
    }

    static String claveBloqueo(String ip, String name) {
        return ip + " " + (name == null ? "" : name.toLowerCase(java.util.Locale.ROOT));
    }

    private String renderBrandedLocal(String rawText, String name) {
        if (rawText != null && rawText.indexOf('{') >= 0) {
            return renderBranded(rellenarNombre(rawText, name));
        }
        return renderBrandedLocal(rawText);
    }

    static String nombreSeguro(String name) {
        if (name == null || name.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(Math.min(name.length(), 32));
        for (int i = 0; i < name.length() && sb.length() < 32; i++) {
            char c = name.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == ' ') sb.append(c);
        }
        return sb.toString();
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

        Schedulers.globalRepetida(plugin, this::reconcile, 0L, 300L);
    }

    private void reconcile() {
        java.util.HashMap<String, Integer> truth = new java.util.HashMap<>();
        for (Player p : Bukkit.getOnlinePlayers()) {
            InetSocketAddress a = p.getAddress();
            if (a != null && a.getAddress() != null) {
                truth.merge(a.getAddress().getHostAddress(), 1, Integer::sum);
            }
        }
        reconciliar(connectedByIp, truth);
    }

    private void releaseConnecting(String ip) {
        connectingByIp.computeIfPresent(ip, (k, v) -> v <= 1 ? null : v - 1);
    }

    private boolean isBypassed(String username) {

        return username != null && config.bypassUsernames().contains(username.toLowerCase(java.util.Locale.ROOT));
    }

    private static final java.util.Set<String> MOTIVOS = java.util.Set.of(
            "vpn_proxy", "mobile_hotspot", "lockdown", "invalid_username", "block", "game_relay",

            "home_country");

    static String claveTextoLocal(String motivo) {
        if ("vpn_proxy".equals(motivo)) return "block.vpn";
        if ("game_relay".equals(motivo)) return "block.game_relay";
        return "block";
    }

    static boolean superaAforo(int enCurso, int yaConectados, int maxPorIp) {
        return maxPorIp > 0 && enCurso + yaConectados > maxPorIp;
    }

    static void descontar(java.util.Map<String, Integer> contador, String ip) {
        if (contador == null || ip == null) return;
        contador.computeIfPresent(ip, (k, v) -> v <= 1 ? null : v - 1);
    }

    static void reconciliar(java.util.Map<String, Integer> contador, java.util.Map<String, Integer> verdad) {
        if (contador == null || verdad == null) return;
        contador.keySet().removeIf(k -> !verdad.containsKey(k));
        contador.putAll(verdad);
    }

    static String rellenarNombre(String rawText, String name) {
        return rawText == null ? null : rawText.replace("{username}", nombreSeguro(name));
    }

    static String textoStaff(String plantilla, String nombre, String ip, String motivo) {
        if (plantilla == null) return "";
        String n = (nombre != null) ? nombre : "?";
        String i = (ip != null) ? ip : "?";
        String r = (motivo != null) ? motivo : "";
        return plantilla.replace("{name}", MM.escapeTags(n))
                        .replace("{ip}", MM.escapeTags(i))
                        .replace("{score}", "")
                        .replace("{reason}", MM.escapeTags(r));
    }

    static String motivoParaRecordar(String msgKey) {
        if (msgKey == null || msgKey.isBlank()) return "vpn_proxy";
        return esMotivo(msgKey) ? msgKey : "block";
    }

    private static boolean esMotivo(String msgKey) {
        return msgKey != null && MOTIVOS.contains(msgKey);
    }

    private String motivoLegible(String msgKey) {
        if (!esMotivo(msgKey)) return "";
        return dev.flamingomg.jarvis.i18n.Messages.get(client.locale(), "motivo." + msgKey);
    }

    private void notifyStaff(String name, String ip, String msgKey) {
        if (!client.notifyStaffEnabled()) return;

        String safeName = (name != null) ? name : "?";
        String safeIp   = (ip != null) ? ip : "?";
        String template = config.getString("messages.staff-notify", Messages.get(client.locale(), "staff"));
        String text = LEGACY.serialize(MM.deserialize(textoStaff(template, safeName, safeIp, motivoLegible(msgKey))));

        Schedulers.global(plugin, () -> {

            for (Player p : Bukkit.getOnlinePlayers())

                Schedulers.deEntidad(plugin, p, () -> {
                    if (p.hasPermission(client.notifyPermission()) || p.hasPermission("jarvis.admin"))
                        p.sendMessage(text);
                });
        });
    }
}
