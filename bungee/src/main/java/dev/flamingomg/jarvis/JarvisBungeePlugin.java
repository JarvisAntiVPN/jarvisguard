package dev.flamingomg.jarvis;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.command.AntiVpnCommand;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.listener.DetectionListener;
import dev.flamingomg.jarvis.sync.SyncClient;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.scheduler.ScheduledTask;

import java.util.concurrent.TimeUnit;

public final class JarvisBungeePlugin extends Plugin {

    private static final int BSTATS_PLUGIN_ID = 31796;

    public static final String VERSION = "0.5.20";

    private dev.flamingomg.jarvis.util.Log logger;

    private ConfigManager config;
    private JarvisClient jarvisClient;
    private SyncClient syncClient;
    private BanCache banCache;

    private dev.flamingomg.jarvis.client.PairingClient pairing;
    private ScheduledTask pairTask;
    private volatile String pairDeviceCode;
    private volatile long pairExpiresAt;
    private boolean pairBannerShown = false;

    @Override
    public void onEnable() {
        this.logger = new dev.flamingomg.jarvis.util.Log(getLogger());
        this.config = new ConfigManager(getDataFolder().toPath(), logger);
        config.load();

        this.jarvisClient = new JarvisClient(config, logger);

        BedrockDetector bedrockDetector = new BedrockDetector(getProxy(), config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config);

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, getProxy());

        DetectionListener detectionListener = new DetectionListener(getProxy(), this, jarvisClient, bedrockDetector,
                config, logger, floodGuard, banCache);
        getProxy().getPluginManager().registerListener(this, detectionListener);
        detectionListener.init();

        getProxy().getPluginManager().registerCommand(this,
                new AntiVpnCommand(jarvisClient, getProxy(), banCache, config, this, floodGuard, syncClient));

        syncClient.start();
        jarvisClient.fetchAndSyncBans(banCache);

        if (BSTATS_PLUGIN_ID > 0) {
            try {
                new org.bstats.bungeecord.Metrics(this, BSTATS_PLUGIN_ID);
                logger.debug("bStats metrics enabled.");
            } catch (Exception e) {
                logger.warn("Couldn't start bStats metrics: {}", e.getMessage());
            }
        }

        getProxy().getScheduler().schedule(this, this::reportPresence, 10, 10, TimeUnit.SECONDS);

        this.pairing = new dev.flamingomg.jarvis.client.PairingClient(config, logger);
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        logger.info("Jarvis v{} client active.", VERSION);
    }

    private void startPairingFlow() {
        requestAndPrintPairing();

        this.pairTask = getProxy().getScheduler().schedule(this, this::pairTick, 5, 5, TimeUnit.SECONDS);
    }

    private void requestAndPrintPairing() {
        String server = "BungeeCord " + getProxy().getVersion();
        dev.flamingomg.jarvis.client.PairingClient.Start s = pairing.start(null, server, VERSION);
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
            logger.warn("==================== JARVIS · LINK PROXY ====================");
            logger.warn("  This proxy isn't linked yet. Open this link and sign in");
            logger.warn("  to bind it to your server (one click, no key to paste):");
            logger.warn("");
            logger.warn("    {}", s.verificationUri());
            logger.warn("");
            logger.warn("  (manual alternative:  /antivpn key <license> )");
            logger.warn("============================================================");
        } else {
            logger.warn("Linking link renewed (the previous one expired): {}", s.verificationUri());
        }
    }

    private void pairTick() {

        if (!isBlank(config.getString("backend.license-key", ""))) { stopPairing(); return; }

        if (pairDeviceCode == null || System.currentTimeMillis() > pairExpiresAt) { requestAndPrintPairing(); return; }
        String[] res = pairing.poll(pairDeviceCode);
        switch (res[0] == null ? "error" : res[0]) {
            case "approved" -> {
                if (res[1] != null && !res[1].isBlank()) { applyPairedKey(res[1]); stopPairing(); }
            }
            case "denied", "expired" -> pairDeviceCode = null;
            default -> {  }
        }
    }

    private void applyPairedKey(String key) {
        if (!config.setKey(key)) { logger.warn("Couldn't save the linked key."); return; }
        getProxy().getScheduler().runAsync(this, () -> {
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

    private void reportPresence() {
        try {
            java.util.List<java.util.Map<String, Object>> players = new java.util.ArrayList<>();
            for (ProxiedPlayer p : getProxy().getPlayers()) {
                java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
                entry.put("name", p.getName());
                entry.put("uuid", p.getUniqueId().toString());
                entry.put("server", p.getServer() != null ? p.getServer().getInfo().getName() : "");
                players.add(entry);
            }
            jarvisClient.reportPresence(players.size(), players);
        } catch (Exception e) {

            logger.debug("reportPresence failed: {}", e.getMessage());
        }
    }

    @Override
    public void onDisable() {

        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        logger.info("Jarvis stopped.");
    }
}
