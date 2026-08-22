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

    public static final String VERSION = "0.5.24";

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
    private boolean pairBannerShown = false;

    private long pairNextStartAt = 0L;

    private long pairNextPollAt = System.nanoTime();
    private long pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(0);
    private int  pairStartFails = 0;
    private boolean pairWarned = false;

    @Override
    public void onEnable() {
        this.logger = new Log(getLogger());
        this.config = new ConfigManager(getDataFolder().toPath(), logger);
        config.load();

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

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, this);

        DetectionListener listener = new DetectionListener(this, jarvisClient, bedrockDetector, config,
                logger, floodGuard, banCache);
        getServer().getPluginManager().registerEvents(listener, this);

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
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        logger.info("Jarvis v{} client active.", VERSION);
    }

    @Override
    public void onDisable() {

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

    private void startPairingFlow() {
        requestAndPrintPairing();
        pairTask = Schedulers.asyncRepetida(this, this::pairTick, 100L, 100L);
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
        if (!pairBannerShown) {
            pairBannerShown = true;
            logger.warn("");
            logger.warn("==================== JARVIS · LINK SERVER ====================");
            logger.warn("  This server isn't linked yet. Open this link and sign in");
            logger.warn("  to bind it to your account (one click, no key to paste):");
            logger.warn("");
            logger.warn("    {}", s.verificationUri());
            logger.warn("");
            logger.warn("  (manual alternative:  /antivpn key <license> )");
            logger.warn("=============================================================");
        } else {
            logger.warn("Linking link renewed (the previous one expired): {}", s.verificationUri());
        }
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

        long ahoraPoll = System.nanoTime();
        if (!dev.flamingomg.jarvis.client.PairingClient.tocaSondear(ahoraPoll, pairNextPollAt)) return;
        pairNextPollAt = ahoraPoll + pairPollIntervalNanos;
        String[] res = pairing.poll(pairDeviceCode);
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
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }

    static boolean avisarDeProxy(boolean puesto, boolean forzado, boolean detectado) {
        if (forzado) return true;
        if (puesto)  return false;
        return detectado;
    }
}
