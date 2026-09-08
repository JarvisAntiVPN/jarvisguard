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

    public static final String VERSION = "0.5.25";

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

    private long pairNextStartAt = 0L;

    private long pairNextPollAt = System.nanoTime();
    private long pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(0);
    private int  pairStartFails = 0;
    private boolean pairWarned = false;

    @Override
    public void onEnable() {
        this.logger = new dev.flamingomg.jarvis.util.Log(getLogger());
        this.config = new ConfigManager(getDataFolder().toPath(), logger);
        this.configCargada = config.load();

        this.jarvisClient = new JarvisClient(config, logger);

        BedrockDetector bedrockDetector = new BedrockDetector(getProxy(), config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config, logger);

        jarvisClient.setBanCacheParaExentos(this.banCache);

        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, getProxy());

        DetectionListener detectionListener = new DetectionListener(getProxy(), this, jarvisClient, bedrockDetector,
                config, logger, floodGuard, banCache);
        getProxy().getPluginManager().registerListener(this, detectionListener);
        detectionListener.init();

        getProxy().getPluginManager().registerCommand(this,
                new AntiVpnCommand(jarvisClient, getProxy(), banCache, config, this, floodGuard, syncClient,
                        detectionListener));

        syncClient.start();
        jarvisClient.fetchAndSyncBans(banCache);

        if (BSTATS_PLUGIN_ID > 0) {
            try {
                new org.bstats.bungeecord.Metrics(this, BSTATS_PLUGIN_ID);
                logger.debug("bStats metrics enabled.");

            } catch (Throwable t) {
                logger.warn("Couldn't start bStats metrics: {}", t.toString());
            }
        }

        getProxy().getScheduler().schedule(this, this::reportPresence, 10, 10, TimeUnit.SECONDS);

        this.pairing = new dev.flamingomg.jarvis.client.PairingClient(config, logger);
        switch (ConfigManager.arranque(configCargada, isBlank(config.getString("backend.license-key", "")))) {
            case VINCULAR -> startPairingFlow();
            case CONFIG_ILEGIBLE -> avisoConfigIlegible();
            case PROTEGER -> { }
        }

        logger.info("Jarvis v{} client active.", VERSION);
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
        requestAndPrintPairing();

        this.pairTask = getProxy().getScheduler().schedule(this, this::pairTick, 5, 5, TimeUnit.SECONDS);
    }

    private void requestAndPrintPairing() {
        String server = "BungeeCord " + getProxy().getVersion();
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
            for (ProxiedPlayer p : getProxy().getPlayers()) {
                java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
                entry.put("name", p.getName());
                entry.put("uuid", p.getUniqueId().toString());
                entry.put("server", p.getServer() != null ? p.getServer().getInfo().getName() : "");

                int ping = p.getPing();
                if (pingMedido(ping)) entry.put("ping", ping);
                players.add(entry);
            }
            jarvisClient.reportPresence(players.size(), players);
        } catch (Exception e) {

            logger.debug("reportPresence failed: {}", e.getMessage());
        }
    }

    @Override
    public void onDisable() {

        if (jarvisClient != null) jarvisClient.marcarApagando();

        stopPairing();
        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        logger.info("Jarvis stopped.");
    }
}
