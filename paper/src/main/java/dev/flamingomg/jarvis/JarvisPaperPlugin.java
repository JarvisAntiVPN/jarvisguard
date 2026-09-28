package dev.flamingomg.jarvis;

import dev.flamingomg.jarvis.util.Schedulers;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.client.PairingClient;
import dev.flamingomg.jarvis.command.AntiVpnCommand;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.detection.ProxyDetector;
import dev.flamingomg.jarvis.listener.DetectionListener;
import dev.flamingomg.jarvis.sync.SyncClient;
import dev.flamingomg.jarvis.util.Log;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JarvisPaperPlugin extends JavaPlugin {

    public static final String VERSION = "0.5.26";
    private static final int BSTATS_PLUGIN_ID = 31883;

    private Log logger;
    private ConfigManager config;
    private JarvisClient jarvisClient;
    private BanCache banCache;
    private SyncClient syncClient;

    private dev.flamingomg.jarvis.util.BStats metrics;
    private PairingClient pairing;
    private Runnable pairTask;
    private volatile String pairDeviceCode;
    private volatile long pairExpiresAt;
    private String pairVerificationUri;
    private long pairBannerNextAt = 0L;
    private static final long PAIR_BANNER_REPEAT_MS = 600_000L;
    private String pairLocale;
    private final dev.flamingomg.jarvis.client.AvisoSinVincular avisoSinVincular =
            new dev.flamingomg.jarvis.client.AvisoSinVincular();
    private volatile boolean proxyDetectado;
    private long pairNextStartAt = 0L;
    private long pairNextPollAt = System.nanoTime();
    private long pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(0);
    private int  pairStartFails = 0;
    private boolean pairWarned = false;

    @Override
    public void onEnable() {
        this.logger = new Log(getLogger());
        this.config = new ConfigManager(getDataFolder().toPath(), logger);
        this.configCargada = config.load();

        if (Schedulers.folia()) {
            if (Schedulers.disponible()) {
                logger.info("Folia detected: using the regionised schedulers.");
            } else {
                logger.warn("");
                logger.warn("=================== JARVIS · FOLIA API MISMATCH ===================");
                logger.warn("  Folia was detected but its scheduler API could not be resolved.");
                logger.warn("  This build of Jarvis cannot schedule tasks on this Folia version,");
                logger.warn("  so protection will NOT work. Please report the Folia version.");
                logger.warn("==================================================================");
                logger.warn("");
            }
        }

        boolean proxyForced = config.getBoolean("server.behind-proxy", false);
        boolean proxyDetected = ProxyDetector.behindProxy(logger);
        proxyDetectado = proxyDetected;
        if (avisarDeProxy(config.isSet("server.behind-proxy"), proxyForced, proxyDetected)) {
            logger.warn("");
            logger.warn("==================== JARVIS · PROXY WARNING ====================");
            logger.warn("  This server appears to be BEHIND A PROXY{}.",
                    proxyDetected ? " (forwarding enabled in the server config)" : "");
            logger.warn("  This connector is for DIRECT servers: the anti-VPN must run on the");
            logger.warn("  PROXY -> install the Velocity/Bungee connector there, not this one.");
            if (proxyForced) {
                logger.warn("  server.behind-proxy=true -> IP-based detection is DISABLED here.");
            } else {
                logger.warn("  If forwarding does NOT yield the real IP, set server.behind-proxy: true so this");
                logger.warn("  node stops checking by IP. If it DOES, set it to false to hide this notice.");
            }
            logger.warn("===============================================================");
        }

        this.jarvisClient = new JarvisClient(config, logger);

        jarvisClient.setIpCheckDisabled(proxyForced);
        BedrockDetector bedrockDetector = new BedrockDetector(config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config, logger);
        jarvisClient.setBanCacheParaExentos(this.banCache);
        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, this);

        DetectionListener listener = new DetectionListener(this, jarvisClient, bedrockDetector, config,
                logger, floodGuard, banCache);
        getServer().getPluginManager().registerEvents(listener, this);
        getServer().getPluginManager().registerEvents(new AvisoAlEntrar(this), this);
        getServer().getMessenger().registerIncomingPluginChannel(this, "minecraft:brand", listener);
        listener.init();

        AntiVpnCommand cmd = new AntiVpnCommand(jarvisClient, banCache, config, this, floodGuard, syncClient, listener);
        if (getCommand("antivpn") != null) getCommand("antivpn").setExecutor(cmd);

        jarvisClient.fetchAndSyncBans(banCache);

        syncClient.start();

        if (BSTATS_PLUGIN_ID > 0) {
            try { this.metrics = new dev.flamingomg.jarvis.util.BStats(this, BSTATS_PLUGIN_ID); logger.debug("bStats metrics enabled."); }
            catch (Throwable t) { logger.warn("Couldn't start bStats metrics: {}", t.toString()); }
        }

        Schedulers.globalRepetida(this, this::reportPresence, 200L, 200L);

        this.pairing = new PairingClient(config, logger);
        switch (ConfigManager.arranque(configCargada, isBlank(config.getString("backend.license-key", "")))) {
            case VINCULAR -> startPairingFlow();
            case CONFIG_ILEGIBLE -> avisoConfigIlegible();
            case PROTEGER -> { }
        }

        logger.info("Jarvis v{} client active.", VERSION);
    }

    @Override
    public void onDisable() {
        if (jarvisClient != null) jarvisClient.marcarApagando();
        stopPairing();
        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        if (metrics != null) metrics.shutdown();
        logger.info("Jarvis stopped.");
    }

    static boolean pingMedido(long ping) {
        return ping > 0;
    }

    private void reportPresence() {
        try {
            List<Map<String, Object>> players = new ArrayList<>();
            for (Player p : Bukkit.getOnlinePlayers()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", p.getName());
                entry.put("uuid", p.getUniqueId().toString());
                entry.put("server", "");
                int ping = p.getPing();
                if (pingMedido(ping)) entry.put("ping", ping);
                players.add(entry);
            }
            Schedulers.async(this, () -> jarvisClient.reportPresence(players.size(), players));
        } catch (Exception e) {
            logger.debug("reportPresence failed: {}", e.getMessage());
        }
    }

    private boolean configCargada;

    private void avisoConfigIlegible() {
        String motivo = config.motivoCargaFallida();
        logger.warn("");
        logger.warn("=================== JARVIS · CHECK YOUR CONFIG ===================");
        logger.warn("  Jarvis is NOT protecting this server.");
        logger.warn("  {}", motivo != null ? motivo : "config.yml couldn't be loaded.");
        logger.warn("  Fix the file and restart the server.");
        logger.warn("  The linking link is NOT shown on purpose: your license key may");
        logger.warn("  already be in that file, and linking would overwrite it.");
        logger.warn("==================================================================");
    }

    private void startPairingFlow() {
        pairTask = Schedulers.asyncRepetida(this, this::pairTick, 1L, 100L);
    }

    private void requestAndPrintPairing() {
        String server = "Paper/Spigot " + getServer().getVersion();
        PairingClient.Start s = pairing.start(null, server, VERSION);
        if (s == null || s.verificationUri() == null) {
            pairDeviceCode = null;
            pairStartFails = Math.min(pairStartFails + 1, 6);
            pairNextStartAt = System.currentTimeMillis() + Math.min(300_000L, 5_000L * (1L << pairStartFails));
            if (!pairWarned) {
                pairWarned = true;
                logger.warn("Couldn't generate the linking link; retrying in the background. "
                        + "Alternative: /antivpn key <license>");
            }
            return;
        }
        pairStartFails = 0;
        pairNextStartAt = 0L;
        pairWarned = false;
        pairDeviceCode = s.deviceCode();
        long ahoraPar = System.currentTimeMillis();
        pairExpiresAt = dev.flamingomg.jarvis.client.PairingClient.caducidadMs(ahoraPar, s.expiresIn());
        pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(s.interval());
        pairNextPollAt = System.nanoTime();
        pairVerificationUri = s.verificationUri();
        printPairingBanner();
        avisarSinVincularATodos();
    }

    private void avisarSinVincular(Player p) {
        String enlace = pairVerificationUri;
        long ahora = System.currentTimeMillis();
        if (pairDeviceCode == null
                || !dev.flamingomg.jarvis.client.AvisoSinVincular.enlaceUtil(enlace, pairExpiresAt, ahora)) return;
        if (!p.hasPermission("jarvis.admin")) return;
        dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido que = dev.flamingomg.jarvis.client.AvisoSinVincular
                .queEnsenar(getServer().getOnlineMode(), detrasDeProxy(config, proxyDetectado));
        if (que == dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.NADA) return;
        if (!avisoSinVincular.tocaAvisar(p.getUniqueId(), ahora)) return;
        String idioma = null;
        try { idioma = p.getLocale(); } catch (Throwable ignored) {}
        List<String> l = dev.flamingomg.jarvis.client.AvisoSinVincular.lineas(idioma);
        String pre = "\u00a7b\u00a7l[Jarvis]\u00a7r ";
        p.sendMessage(pre + "\u00a7c" + l.get(0));
        if (que == dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.CON_ENLACE) {
            net.md_5.bungee.api.chat.TextComponent clic = new net.md_5.bungee.api.chat.TextComponent(enlace);
            clic.setColor(net.md_5.bungee.api.ChatColor.AQUA);
            clic.setUnderlined(true);
            clic.setClickEvent(new net.md_5.bungee.api.chat.ClickEvent(
                    net.md_5.bungee.api.chat.ClickEvent.Action.OPEN_URL, enlace));
            List<net.md_5.bungee.api.chat.BaseComponent> linea = new ArrayList<>(List.of(
                    net.md_5.bungee.api.chat.TextComponent.fromLegacyText(pre + "\u00a7e" + l.get(1) + " ")));
            linea.add(clic);
            p.spigot().sendMessage(linea.toArray(new net.md_5.bungee.api.chat.BaseComponent[0]));
        }
        p.sendMessage(pre + "\u00a77" + l.get(2));
    }

    public static final class AvisoAlEntrar implements org.bukkit.event.Listener {
        private final JarvisPaperPlugin plugin;
        AvisoAlEntrar(JarvisPaperPlugin plugin) { this.plugin = plugin; }
        @org.bukkit.event.EventHandler(priority = org.bukkit.event.EventPriority.MONITOR)
        public void alEntrar(org.bukkit.event.player.PlayerJoinEvent e) { plugin.avisarSinVincular(e.getPlayer()); }
    }

    private void avisarSinVincularATodos() {
        Schedulers.global(this, () -> {
            for (Player p : Bukkit.getOnlinePlayers()) Schedulers.deEntidad(this, p, () -> avisarSinVincular(p));
        });
    }

    private void printPairingBanner() {
        pairBannerNextAt = System.currentTimeMillis() + PAIR_BANNER_REPEAT_MS;
        String loc = pairLocale != null ? pairLocale : dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina();
        logger.warn("");
        logger.warn("==================== JARVIS · LINK SERVER ====================");
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.notLinked"));
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.open"));
        logger.warn("");
        logger.warn("    {}", pairVerificationUri);
        logger.warn("");
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.manual"));
        logger.warn("=============================================================");
    }

    private void recordarVinculacionSiToca() {
        if (pairVerificationUri == null) return;
        if (System.currentTimeMillis() < pairBannerNextAt) return;
        printPairingBanner();
    }

    private void anotarLocaleDelDueno(String loc) {
        if (loc == null || loc.isBlank()) return;
        if (loc.equals(pairLocale)) return;
        pairLocale = loc;
        pairBannerNextAt = 0L;
    }

    private final java.util.concurrent.atomic.AtomicBoolean pairTickEnCurso =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private void pairTick() {
        if (!pairTickEnCurso.compareAndSet(false, true)) return;
        try {
            pairTickBody();
        } finally {
            pairTickEnCurso.set(false);
        }
    }

    private void pairTickBody() {
        if (!isBlank(config.getString("backend.license-key", ""))) { stopPairing(); return; }
        if (pairDeviceCode == null || System.currentTimeMillis() > pairExpiresAt) {
            if (System.currentTimeMillis() < pairNextStartAt) return;
            requestAndPrintPairing();
            return;
        }
        recordarVinculacionSiToca();

        long ahoraPoll = System.nanoTime();
        if (!dev.flamingomg.jarvis.client.PairingClient.tocaSondear(ahoraPoll, pairNextPollAt)) return;
        pairNextPollAt = ahoraPoll + pairPollIntervalNanos;
        String[] res = pairing.poll(pairDeviceCode);
        if (res.length > 2) anotarLocaleDelDueno(res[2]);
        switch (res[0] == null ? "error" : res[0]) {
            case "approved" -> { if (res[1] != null && !res[1].isBlank() && applyPairedKey(res[1])) stopPairing(); }
            case "denied", "expired" -> pairDeviceCode = null;
            default -> { }
        }
    }

    private boolean applyPairedKey(String key) {
        if (!config.setKey(key)) { logger.warn("Couldn't save the linked key."); return false; }
        Schedulers.async(this, () -> {
            boolean ok = jarvisClient.ensureReady();
            if (ok) {
                jarvisClient.fetchAndSyncBans(banCache);
                logger.info("================================================================");
                logger.info("  {}", dev.flamingomg.jarvis.i18n.Messages.get(jarvisClient.locale(), "log.pairedProtected"));
                logger.info("================================================================");
            } else {
                logger.warn(dev.flamingomg.jarvis.i18n.Messages.get(jarvisClient.locale(), "log.pairedUnprotected"));
            }
        });
        return true;
    }

    private void stopPairing() {
        if (pairTask != null) { pairTask.run(); pairTask = null; }
        pairDeviceCode = null;
        pairVerificationUri = null;
        pairLocale = null;
        avisoSinVincular.olvidarTodo();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }

    static boolean avisarDeProxy(boolean puesto, boolean forzado, boolean detectado) {
        if (forzado) return true;
        if (puesto)  return false;
        return detectado;
    }

    static boolean detrasDeProxy(ConfigManager config, boolean detectado) {
        return avisarDeProxy(config.isSet("server.behind-proxy"),
                config.getBoolean("server.behind-proxy", false), detectado);
    }
}
