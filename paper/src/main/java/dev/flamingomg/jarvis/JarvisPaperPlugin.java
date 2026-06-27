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
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JarvisPaperPlugin extends JavaPlugin {

    public static final String VERSION = "0.5.15";

    private static final int BSTATS_PLUGIN_ID = 31883;

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
        this.config = new ConfigManager(getDataFolder().toPath(), getLogger());
        config.load();

        boolean proxyForced = config.getBoolean("server.behind-proxy", false);
        boolean proxyDetected = ProxyDetector.behindProxy(getLogger());
        if (proxyForced || proxyDetected) {
            getLogger().warning("");
            getLogger().warning("==================== JARVIS · PROXY WARNING ====================");
            getLogger().warning("  This server appears to be BEHIND A PROXY"
                    + (proxyDetected ? " (forwarding enabled in the server config)" : "") + ".");
            getLogger().warning("  This connector is for DIRECT servers: the anti-VPN must run on the");
            getLogger().warning("  PROXY -> install the Velocity/Bungee connector there, not this one.");
            if (proxyForced) getLogger().warning("  server.behind-proxy=true -> IP-based detection is DISABLED here.");
            else getLogger().warning("  If forwarding yields the REAL IP you can ignore this; otherwise set server.behind-proxy: true.");
            getLogger().warning("===============================================================");
        }

        this.jarvisClient = new JarvisClient(config, getLogger());
        BedrockDetector bedrockDetector = new BedrockDetector(config, getLogger());
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config);

        DetectionListener listener = new DetectionListener(this, jarvisClient, bedrockDetector, config,
                getLogger(), floodGuard, banCache);
        getServer().getPluginManager().registerEvents(listener, this);

        getServer().getMessenger().registerIncomingPluginChannel(this, "minecraft:brand", listener);

        AntiVpnCommand cmd = new AntiVpnCommand(jarvisClient, banCache, config, this);
        if (getCommand("antivpn") != null) getCommand("antivpn").setExecutor(cmd);

        jarvisClient.fetchAndSyncBans(banCache);

        this.syncClient = new SyncClient(config, getLogger(), jarvisClient, banCache, this);
        syncClient.start();

        if (BSTATS_PLUGIN_ID > 0) {
            try { new org.bstats.bukkit.Metrics(this, BSTATS_PLUGIN_ID); }
            catch (Exception e) { getLogger().warning("Couldn't start bStats metrics: " + e.getMessage()); }
        }

        getServer().getScheduler().runTaskTimer(this, this::reportPresence, 200L, 200L);

        this.pairing = new PairingClient(config, getLogger());
        if (isBlank(config.getString("backend.license-key", ""))) startPairingFlow();

        getLogger().info("Jarvis v" + VERSION + " client (SaaS) active.");
    }

    @Override
    public void onDisable() {

        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        getLogger().info("Jarvis stopped.");
    }

    private void reportPresence() {

        List<Map<String, Object>> players = new ArrayList<>();
        for (Player p : Bukkit.getOnlinePlayers()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", p.getName());
            entry.put("uuid", p.getUniqueId().toString());
            entry.put("server", "");
            players.add(entry);
        }

        getServer().getScheduler().runTaskAsynchronously(this, () -> jarvisClient.reportPresence(players.size(), players));
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
            getLogger().warning("[Jarvis] Couldn't generate the linking link; retrying shortly. "
                    + "Alternative: /antivpn key <license>");
            return;
        }
        pairDeviceCode = s.deviceCode();
        pairExpiresAt = System.currentTimeMillis() + s.expiresIn() * 1000L;
        if (!pairBannerShown) {
            pairBannerShown = true;
            getLogger().warning("");
            getLogger().warning("==================== JARVIS · LINK SERVER ====================");
            getLogger().warning("  This server isn't linked yet. Open this link and sign in");
            getLogger().warning("  to bind it to your account (one click, no key to paste):");
            getLogger().warning("");
            getLogger().warning("    " + s.verificationUri());
            getLogger().warning("");
            getLogger().warning("  (manual alternative:  /antivpn key <license> )");
            getLogger().warning("=============================================================");
        } else {
            getLogger().warning("[Jarvis] Linking link renewed (the previous one expired): " + s.verificationUri());
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
        if (!config.setKey(key)) { getLogger().warning("[Jarvis] Couldn't save the linked key."); return; }
        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            if (jarvisClient.ensureReady()) jarvisClient.fetchAndSyncBans(banCache);
            getLogger().info("================================================================");
            getLogger().info("  Jarvis linked successfully. Protection active.");
            getLogger().info("================================================================");
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
