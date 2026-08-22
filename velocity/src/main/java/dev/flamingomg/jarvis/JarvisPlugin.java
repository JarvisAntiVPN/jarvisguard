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
import dev.flamingomg.jarvis.util.Log;
import org.bstats.velocity.Metrics;
import org.slf4j.Logger;

import java.nio.file.Path;

@Plugin(
        id = "jarvis",
        name = "Jarvis",
        version = JarvisPlugin.VERSION,
        description = "Anti-VPN/proxy client for Velocity",
        authors = {"TheFlamingOMG"},
        dependencies = {@Dependency(id = "floodgate", optional = true)}
)
public final class JarvisPlugin {

    public static final String VERSION = "0.5.24";

    private static final int BSTATS_PLUGIN_ID = 31671;

    private final ProxyServer proxy;
    private final Log logger;
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

    private long pairNextStartAt = 0L;

    private long pairNextPollAt = System.nanoTime();
    private long pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(0);
    private int  pairStartFails = 0;
    private boolean pairWarned = false;

    @Inject
    public JarvisPlugin(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory,
                        Metrics.Factory metricsFactory) {
        this.proxy = proxy;
        this.logger = new Log(logger);
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
        this.banCache = new BanCache(config, logger);

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, proxy);

        DetectionListener detectionListener = new DetectionListener(proxy, this, jarvisClient, bedrockDetector,
                config, logger, floodGuard, banCache);
        proxy.getEventManager().register(this, detectionListener);
        detectionListener.init();

        CommandManager cm = proxy.getCommandManager();

        CommandMeta antivpnMeta = cm.metaBuilder("antivpn").aliases("jarvis", "avpn").plugin(this).build();
        cm.register(antivpnMeta, new AntiVpnCommand(jarvisClient, proxy, banCache, config, this, floodGuard, syncClient,
                detectionListener));

        syncClient.start();
        jarvisClient.fetchAndSyncBans(banCache);

        if (BSTATS_PLUGIN_ID > 0) {
            try {
                metricsFactory.make(this, BSTATS_PLUGIN_ID);
                logger.debug("bStats metrics enabled.");

            } catch (Throwable t) {
                logger.warn("Couldn't start bStats metrics: {}", t.toString());
            }
        }

        proxy.getScheduler().buildTask(this, this::reportPresence)
                .repeat(10, java.util.concurrent.TimeUnit.SECONDS)
                .delay(10, java.util.concurrent.TimeUnit.SECONDS)
                .schedule();

        this.pairing = new dev.flamingomg.jarvis.client.PairingClient(config, logger);
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        logger.info("Jarvis v{} client active.", VERSION);
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
        dev.flamingomg.jarvis.client.PairingClient.Start s = pairing.start(null, server, VERSION);
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
            case "approved" -> {

                if (res[1] != null && !res[1].isBlank() && applyPairedKey(res[1])) stopPairing();
            }
            case "denied", "expired" -> pairDeviceCode = null;
            default -> {  }
        }
    }

    private boolean applyPairedKey(String key) {
        if (!config.setKey(key)) { logger.warn("Couldn't save the linked key."); return false; }
        proxy.getScheduler().buildTask(this, () -> {
            boolean ok = jarvisClient.ensureReady();

            if (ok) {
                jarvisClient.fetchAndSyncBans(banCache);
                logger.info("================================================================");
                logger.info("  " + dev.flamingomg.jarvis.i18n.Messages.get(jarvisClient.locale(), "log.pairedProtected"));
                logger.info("================================================================");
            } else {
                logger.warn(dev.flamingomg.jarvis.i18n.Messages.get(jarvisClient.locale(), "log.pairedUnprotected"));
            }
        }).schedule();
        return true;
    }

    private void stopPairing() {
        if (pairTask != null) { pairTask.cancel(); pairTask = null; }
        pairDeviceCode = null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }

    static boolean pingMedido(long ping) {
        return ping > 0;
    }

    private void reportPresence() {
        try {
            java.util.List<java.util.Map<String, Object>> players = new java.util.ArrayList<>();
            for (com.velocitypowered.api.proxy.Player p : proxy.getAllPlayers()) {
                java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
                entry.put("name", p.getUsername());
                entry.put("uuid", p.getUniqueId().toString());
                entry.put("server", p.getCurrentServer()
                        .map(s -> s.getServerInfo().getName()).orElse(""));

                long ping = p.getPing();
                if (pingMedido(ping)) entry.put("ping", ping);
                players.add(entry);
            }
            jarvisClient.reportPresence(players.size(), players);
        } catch (Exception e) {

            logger.debug("reportPresence failed: {}", e.getMessage());
        }
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {

        stopPairing();
        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        logger.info("Jarvis stopped.");
    }
}
