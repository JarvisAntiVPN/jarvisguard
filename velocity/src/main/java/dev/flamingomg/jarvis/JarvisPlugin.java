package dev.flamingomg.jarvis;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.command.AntiVpnCommand;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.BedrockDetector;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.listener.DetectionListener;
import dev.flamingomg.jarvis.sync.SyncClient;
import org.bstats.velocity.Metrics;
import org.slf4j.Logger;

import java.nio.file.Path;

@Plugin(
        id = "jarvis",
        name = "Jarvis",
        version = "0.5.14",
        description = "Cliente anti-VPN/proxy SaaS para Velocity",
        authors = {"TheFlamingOMG"},
        dependencies = {@Dependency(id = "floodgate", optional = true)}
)
public final class JarvisPlugin {

    private static final int BSTATS_PLUGIN_ID = 31671;

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;
    private final Metrics.Factory metricsFactory;

    private ConfigManager config;
    private JarvisClient jarvisClient;
    private SyncClient syncClient;
    private BanCache banCache;

    private dev.flamingomg.jarvis.client.PairingClient pairing;
    private com.velocitypowered.api.scheduler.ScheduledTask pairTask;
    private volatile String pairDeviceCode;
    private volatile long pairExpiresAt;
    private boolean pairBannerShown = false;

    @Inject
    public JarvisPlugin(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory,
                        Metrics.Factory metricsFactory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.metricsFactory = metricsFactory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        this.config = new ConfigManager(dataDirectory, logger);
        config.load();

        this.jarvisClient = new JarvisClient(config, logger);

        BedrockDetector bedrockDetector = new BedrockDetector(proxy, config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config);

        proxy.getEventManager().register(this,
                new DetectionListener(proxy, this, jarvisClient, bedrockDetector,
                        config, logger, floodGuard, banCache));

        CommandManager cm = proxy.getCommandManager();

        CommandMeta antivpnMeta = cm.metaBuilder("antivpn").aliases("jarvis", "avpn").plugin(this).build();
        cm.register(antivpnMeta, new AntiVpnCommand(jarvisClient, proxy, banCache, config, this));

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, proxy);
        syncClient.start();
        jarvisClient.fetchAndSyncBans(banCache);

        if (BSTATS_PLUGIN_ID > 0) {
            try {
                metricsFactory.make(this, BSTATS_PLUGIN_ID);
                logger.debug("bStats metrics enabled.");
            } catch (Exception e) {
                logger.warn("Couldn't start bStats metrics: {}", e.getMessage());
            }
        }

        proxy.getScheduler().buildTask(this, this::reportPresence)
                .repeat(10, java.util.concurrent.TimeUnit.SECONDS)
                .delay(10, java.util.concurrent.TimeUnit.SECONDS)
                .schedule();

        this.pairing = new dev.flamingomg.jarvis.client.PairingClient(config, logger);
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        logger.info("Jarvis v0.5.14 client (SaaS) active.");
    }

    private void startPairingFlow() {
        requestAndPrintPairing();

        this.pairTask = proxy.getScheduler().buildTask(this, this::pairTick)
                .repeat(5, java.util.concurrent.TimeUnit.SECONDS)
                .delay(5, java.util.concurrent.TimeUnit.SECONDS)
                .schedule();
    }

    private void requestAndPrintPairing() {
        String server = "Velocity " + proxy.getVersion().getVersion();
        dev.flamingomg.jarvis.client.PairingClient.Start s = pairing.start(null, server, "0.5.14");
        if (s == null || s.verificationUri() == null) {
            pairDeviceCode = null;
            logger.warn("[Jarvis] Couldn't generate the linking link; retrying shortly. "
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
            logger.warn("[Jarvis] Linking link renewed (the previous one expired): {}", s.verificationUri());
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
        if (!config.setKey(key)) { logger.warn("[Jarvis] Couldn't save the linked key."); return; }
        proxy.getScheduler().buildTask(this, () -> {
            boolean ok = jarvisClient.ensureReady();
            if (ok) jarvisClient.fetchAndSyncBans(banCache);
            logger.info("================================================================");
            logger.info("  Jarvis linked successfully. Protection active.");
            logger.info("================================================================");
        }).schedule();
    }

    private void stopPairing() {
        if (pairTask != null) { pairTask.cancel(); pairTask = null; }
        pairDeviceCode = null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }

    private void reportPresence() {
        java.util.List<java.util.Map<String, Object>> players = new java.util.ArrayList<>();
        for (com.velocitypowered.api.proxy.Player p : proxy.getAllPlayers()) {
            java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
            entry.put("name", p.getUsername());
            entry.put("uuid", p.getUniqueId().toString());
            entry.put("server", p.getCurrentServer()
                    .map(s -> s.getServerInfo().getName()).orElse(""));
            players.add(entry);
        }
        jarvisClient.reportPresence(players.size(), players);
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (syncClient != null) syncClient.stop();
        logger.info("Jarvis stopped.");
    }
}
