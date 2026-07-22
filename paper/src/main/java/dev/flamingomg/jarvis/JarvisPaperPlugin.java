package dev.flamingomg.jarvis;

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
import org.bukkit.scheduler.BukkitTask;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JarvisPaperPlugin extends JavaPlugin {

    public static final String VERSION = "0.5.20";

    private static final int BSTATS_PLUGIN_ID = 31883;

    private Log logger;
    private ConfigManager config;
    private JarvisClient jarvisClient;
    private BanCache banCache;
    private SyncClient syncClient;

    private PairingClient pairing;
    private BukkitTask pairTask;
    private volatile String pairDeviceCode;
    private volatile long pairExpiresAt;
    private boolean pairBannerShown = false;

    @Override
    public void onEnable() {
        this.logger = new Log(getLogger());
        this.config = new ConfigManager(getDataFolder().toPath(), logger);
        config.load();

        boolean proxyForced = config.getBoolean("server.behind-proxy", false);
        boolean proxyDetected = ProxyDetector.behindProxy(logger);
        if (proxyForced || proxyDetected) {
            logger.warn("");
            logger.warn("==================== JARVIS · PROXY WARNING ====================");
            logger.warn("  This server appears to be BEHIND A PROXY{}.",
                    proxyDetected ? " (forwarding enabled in the server config)" : "");
            logger.warn("  This connector is for DIRECT servers: the anti-VPN must run on the");
            logger.warn("  PROXY -> install the Velocity/Bungee connector there, not this one.");
            if (proxyForced) logger.warn("  server.behind-proxy=true -> IP-based detection is DISABLED here.");
            else logger.warn("  If forwarding yields the REAL IP you can ignore this; otherwise set server.behind-proxy: true.");
            logger.warn("===============================================================");
        }

        this.jarvisClient = new JarvisClient(config, logger);
        BedrockDetector bedrockDetector = new BedrockDetector(config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config);

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, this);

        DetectionListener listener = new DetectionListener(this, jarvisClient, bedrockDetector, config,
                logger, floodGuard, banCache);
        getServer().getPluginManager().registerEvents(listener, this);

        getServer().getMessenger().registerIncomingPluginChannel(this, "minecraft:brand", listener);
        listener.init();

        AntiVpnCommand cmd = new AntiVpnCommand(jarvisClient, banCache, config, this, floodGuard, syncClient);
        if (getCommand("antivpn") != null) getCommand("antivpn").setExecutor(cmd);

        jarvisClient.fetchAndSyncBans(banCache);

        syncClient.start();

        if (BSTATS_PLUGIN_ID > 0) {
            try { new org.bstats.bukkit.Metrics(this, BSTATS_PLUGIN_ID); logger.debug("bStats metrics enabled."); }
            catch (Exception e) { logger.warn("Couldn't start bStats metrics: {}", e.getMessage()); }
        }

        getServer().getScheduler().runTaskTimer(this, this::reportPresence, 200L, 200L);

        this.pairing = new PairingClient(config, logger);
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        logger.info("Jarvis v{} client active.", VERSION);
    }

    @Override
    public void onDisable() {

        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        logger.info("Jarvis stopped.");
    }

    private void reportPresence() {
        try {

            List<Map<String, Object>> players = new ArrayList<>();
            for (Player p : Bukkit.getOnlinePlayers()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", p.getName());
                entry.put("uuid", p.getUniqueId().toString());
                entry.put("server", "");
                players.add(entry);
            }

            getServer().getScheduler().runTaskAsynchronously(this, () -> jarvisClient.reportPresence(players.size(), players));
        } catch (Exception e) {

            logger.debug("reportPresence failed: {}", e.getMessage());
        }
    }

    private void startPairingFlow() {
        requestAndPrintPairing();
        this.pairTask = getServer().getScheduler().runTaskTimerAsynchronously(this, this::pairTick, 100L, 100L);
    }

    private void requestAndPrintPairing() {
        String server = "Paper/Spigot " + getServer().getVersion();
        PairingClient.Start s = pairing.start(null, server, VERSION);
        if (s == null || s.verificationUri() == null) {
            pairDeviceCode = null;
            logger.warn("Couldn't generate the linking link; retrying shortly. "
                    + "Alternative: /antivpn key <license>");
            return;
        }
        pairDeviceCode = s.deviceCode();
        pairExpiresAt = System.currentTimeMillis() + s.expiresIn() * 1000L;
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

    private void pairTick() {
        if (!isBlank(config.getString("backend.license-key", ""))) { stopPairing(); return; }
        if (pairDeviceCode == null || System.currentTimeMillis() > pairExpiresAt) { requestAndPrintPairing(); return; }
        String[] res = pairing.poll(pairDeviceCode);
        switch (res[0] == null ? "error" : res[0]) {
            case "approved" -> { if (res[1] != null && !res[1].isBlank()) { applyPairedKey(res[1]); stopPairing(); } }
            case "denied", "expired" -> pairDeviceCode = null;
            default -> { }
        }
    }

    private void applyPairedKey(String key) {
        if (!config.setKey(key)) { logger.warn("Couldn't save the linked key."); return; }
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
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
    }

    private void stopPairing() {
        if (pairTask != null) { pairTask.cancel(); pairTask = null; }
        pairDeviceCode = null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }
}
