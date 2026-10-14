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

    public static final String VERSION = "0.5.27";
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
    private final dev.flamingomg.jarvis.client.PairingClient.Anteriores pairAnteriores =
            new dev.flamingomg.jarvis.client.PairingClient.Anteriores();
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
        this.quitarFiltroClave = taparClaveEnElLog(
                () -> dev.flamingomg.jarvis.util.ClaveFueraDelLog.instalar(getServer().getClass().getClassLoader()),
                logger);
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
        ConfigManager.Arranque arranque = ConfigManager.arranque(configCargada,
                isBlank(config.getString("backend.license-key", "")));
        if (arranque != ConfigManager.Arranque.VINCULAR
                && avisarDeProxy(config.isSet("server.behind-proxy"), proxyForced, proxyDetected)) {
            logger.warn("");
            logger.warn("==================== JARVIS · PROXY WARNING ====================");
            logger.warn("  This server appears to be BEHIND A PROXY{}.",
                    proxyDetected ? " (forwarding enabled in the server config)" : "");
            logger.warn("  This connector is for DIRECT servers: the anti-VPN must run on the");
            logger.warn("  PROXY -> install the Velocity/Bungee connector there, not this one.");
            if (proxyForced) {
                logger.warn("  server.behind-proxy=true -> IP-based detection is DISABLED here.");
            } else {
                logger.warn("  If forwarding does NOT yield the real IP, add this to config.yml so this node");
                logger.warn("  stops checking by IP:");
                logger.warn("      server:");
                logger.warn("        behind-proxy: true");
                logger.warn("  If it DOES, put false there instead of true to hide this notice.");
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
        this.detectionListener = listener;
        getServer().getPluginManager().registerEvents(listener, this);
        getServer().getPluginManager().registerEvents(new AvisoAlEntrar(this), this);
        getServer().getMessenger().registerIncomingPluginChannel(this, "minecraft:brand", listener);
        listener.init();

        AntiVpnCommand cmd = new AntiVpnCommand(jarvisClient, banCache, config, this, floodGuard, syncClient, listener,
                this::vincularTrasRecargar, this::vinculacionAhora, this::lineasDeLink, this::lineasDeLinkParaRcon);
        if (getCommand("antivpn") != null) getCommand("antivpn").setExecutor(cmd);

        jarvisClient.fetchAndSyncBans(banCache);

        syncClient.start();

        if (BSTATS_PLUGIN_ID > 0) {
            try { this.metrics = new dev.flamingomg.jarvis.util.BStats(this, BSTATS_PLUGIN_ID); logger.debug("bStats metrics enabled."); }
            catch (Throwable t) { logger.warn("Couldn't start bStats metrics: {}", t.toString()); }
        }

        Schedulers.globalRepetida(this, this::reportPresence, 200L, 200L);

        this.pairing = new PairingClient(config, logger);
        logger.info("Jarvis v{} loaded.", VERSION);
        switch (arranque) {
            case VINCULAR -> { avisoClaveMalFormada(); startPairingFlow(); }
            case CONFIG_ILEGIBLE -> avisoConfigIlegible();
            case PROTEGER -> { }
        }
    }

    private void avisoClaveMalFormada() {
        if (config.estadoClave() != ConfigManager.EstadoClave.MAL_FORMADA) return;
        logger.warn("config.yml: {}", dev.flamingomg.jarvis.i18n.Messages.get(
                dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina(), "cmd.invalidkey"));
    }

    @Override
    public void onDisable() {
        if (jarvisClient != null) jarvisClient.marcarApagando();
        stopPairing();
        cerrarSesionesAlApagar();
        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        if (detectionListener != null) detectionListener.guardarBypass();
        if (metrics != null) metrics.shutdown();
        if (quitarFiltroClave != null) {
            try { quitarFiltroClave.run(); } catch (Throwable ignorado) { }
            quitarFiltroClave = null;
        }
        logger.info("Jarvis stopped.");
    }

    private DetectionListener detectionListener;

    static final long TECHO_FINES_AL_APAGAR_MS = 2_500L;

    private void cerrarSesionesAlApagar() {
        if (jarvisClient == null || detectionListener == null || !jarvisClient.sesionesAlApagar()) return;
        try {
            List<JarvisClient.FinPendiente> fines = detectionListener.finesAlApagar(System.currentTimeMillis());
            if (fines.isEmpty()) return;
            int hechos = jarvisClient.reportSessionEndsAlApagar(fines, TECHO_FINES_AL_APAGAR_MS);
            logger.debug("session ends on shutdown: {} of {} answered in time", hechos, fines.size());
        } catch (Throwable t) {
            logger.debug("session ends on shutdown failed: {}", t.toString());
        }
    }

    private Runnable quitarFiltroClave;

    static Runnable taparClaveEnElLog(java.util.function.Supplier<Runnable> instalar, Log logger) {
        try {
            return instalar.get();
        } catch (Throwable t) {
            logger.warn("Couldn't hide the license key in the server log ({}). Avoid typing /antivpn key in game; "
                    + "use the console instead.", t.toString());
            return null;
        }
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
                int ping = dev.flamingomg.jarvis.util.PingJugador.de(p);
                if (pingMedido(ping)) entry.put("ping", ping);
                players.add(entry);
            }
            Schedulers.async(this, () -> jarvisClient.reportPresence(players.size(), players));
        } catch (Exception | LinkageError e) {
            logger.debug("reportPresence failed: {}", e.toString());
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
        if (detrasDeProxy(config, proxyDetectado)) { Schedulers.global(this, this::cartelDetrasDeProxy); return; }
        pairTask = Schedulers.asyncRepetida(this, this::pairTick, 1L, 100L);
    }

    private void cartelDetrasDeProxy() {
        logger.warn("");
        logger.warn("==================== JARVIS · BEHIND A PROXY ====================");
        for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea l : dev.flamingomg.jarvis.client.AvisoSinVincular
                .lineasDetrasDeProxy(dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina())) {
            logger.warn("  {}", l.texto());
        }
        logger.warn("=================================================================");
    }

    private synchronized void vincularTrasRecargar() {
        if (pairing == null) return;
        if (pairTask == null) startPairingFlow();
        else pairBannerNextAt = 0L;
        pairCartelProxyDado = false;
    }

    private void requestAndPrintPairing() {
        if (!pedirCodigo()) return;
        printPairingBanner();
        avisarSinVincularATodos();
    }

    private boolean pedirCodigo() {
        String server = "Paper/Spigot " + getServer().getVersion();
        PairingClient.Start s = pairing.start(null, server, VERSION);
        if (s == null || s.verificationUri() == null) {
            if (System.currentTimeMillis() > pairExpiresAt) {
                pairAnteriores.guardar(pairDeviceCode, pairExpiresAt, System.currentTimeMillis());
                pairDeviceCode = null;
            }
            pairStartFails = Math.min(pairStartFails + 1, 6);
            pairNextStartAt = System.currentTimeMillis() + Math.min(300_000L, 5_000L * (1L << pairStartFails));
            if (!pairWarned) {
                pairWarned = true;
                logger.warn("Couldn't generate the linking link; retrying in the background. "
                        + "Alternative: /antivpn key <license>");
            }
            return false;
        }
        pairStartFails = 0;
        pairNextStartAt = 0L;
        pairWarned = false;
        pairAnteriores.guardar(pairDeviceCode, pairExpiresAt, System.currentTimeMillis());
        pairDeviceCode = s.deviceCode();
        long ahoraPar = System.currentTimeMillis();
        pairExpiresAt = dev.flamingomg.jarvis.client.PairingClient.caducidadMs(ahoraPar, s.expiresIn());
        pairPollIntervalNanos = dev.flamingomg.jarvis.client.PairingClient.intervaloPollNanos(s.interval());
        pairNextPollAt = System.nanoTime();
        pairVerificationUri = s.verificationUri();
        return true;
    }

    private dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion vinculacionAhora() {
        return dev.flamingomg.jarvis.client.AvisoSinVincular.vinculacion(
                !isBlank(config.getString("backend.license-key", "")), detrasDeProxyLeido(),
                pairTask != null,
                pairStartFails == 0 || (pairDeviceCode != null && pairExpiresAt - System.currentTimeMillis()
                        >= dev.flamingomg.jarvis.client.AvisoSinVincular.MARGEN_MIN_MS));
    }

    private List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> lineasDeLink(Player quien, String idiomaDelCliente,
                                                                                  boolean consola) {
        boolean turno = dev.flamingomg.jarvis.client.AvisoSinVincular.esperarTurno(
                pairTickEnCurso, dev.flamingomg.jarvis.client.AvisoSinVincular.ESPERA_TURNO_MS);
        try {
            boolean clave = !isBlank(config.getString("backend.license-key", ""));
            dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido que = quien != null
                    ? dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(getServer().getOnlineMode(),
                            detrasDeProxyLeido())
                    : consola ? dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.CON_ENLACE
                    : dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(false, detrasDeProxyLeido());
            long ahora = System.currentTimeMillis();
            boolean nuevo = false;
            if (turno && !clave && pairTask != null
                    && que != dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.NADA
                    && !detrasDeProxyLeido()
                    && dev.flamingomg.jarvis.client.AvisoSinVincular.tocaCodigoNuevo(pairDeviceCode, pairExpiresAt, ahora)
                    && ahora >= pairNextStartAt && pedirCodigo()) {
                nuevo = true;
                if (!consola) printPairingBanner();
                else pairBannerNextAt = System.currentTimeMillis() + PAIR_BANNER_REPEAT_MS;
            }
            String enlace = pairVerificationUri;
            boolean hay = pairDeviceCode != null && dev.flamingomg.jarvis.client.AvisoSinVincular.enlaceParaElComando(
                    enlace, pairExpiresAt, System.currentTimeMillis(), nuevo);
            dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion v = dev.flamingomg.jarvis.client.AvisoSinVincular
                    .vinculacion(clave, detrasDeProxyLeido(), pairTask != null, hay);
            if (quien != null && v == dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion.CON_ENLACE) {
                avisoSinVincular.tocaAvisar(quien.getUniqueId(), ahora);
            }
            if (nuevo) avisarSinVincularATodos();
            String loc = quien == null
                    ? (clave && jarvisClient != null ? jarvisClient.locale()
                            : pairLocale != null ? pairLocale : dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina())
                    : (idiomaDelCliente != null ? idiomaDelCliente : pairLocale);
            return dev.flamingomg.jarvis.client.AvisoSinVincular.respuestaDeLink(loc, v, que, hay ? enlace : null,
                    config.motivoCargaFallida() != null);
        } finally {
            if (turno) pairTickEnCurso.set(false);
        }
    }

    private List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> lineasDeLinkParaRcon() {
        boolean clave = !isBlank(config.getString("backend.license-key", ""));
        String loc = clave && jarvisClient != null ? jarvisClient.locale()
                : pairLocale != null ? pairLocale : dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina();
        List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> l = dev.flamingomg.jarvis.client.AvisoSinVincular
                .respuestaDeLink(loc, vinculacionAhora(), dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(
                        false, detrasDeProxyLeido()), null, config.motivoCargaFallida() != null);
        Schedulers.async(this, () -> lineasDeLink(null, null, false));
        return l;
    }

    private void avisarSinVincular(Player p) {
        String enlace = pairVerificationUri;
        long ahora = System.currentTimeMillis();
        if (pairDeviceCode == null
                || !dev.flamingomg.jarvis.client.AvisoSinVincular.enlaceUtil(enlace, pairExpiresAt, ahora)) return;
        if (!p.hasPermission("jarvis.admin")) return;
        dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido que = dev.flamingomg.jarvis.client.AvisoSinVincular
                .queEnsenar(getServer().getOnlineMode(), detrasDeProxyLeido());
        if (que == dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.NADA) return;
        if (!avisoSinVincular.tocaAvisar(p.getUniqueId(), ahora)) return;
        String idioma = dev.flamingomg.jarvis.util.IdiomaJugador.de(p);
        List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> l =
                dev.flamingomg.jarvis.client.AvisoSinVincular.lineas(idioma, que, enlace);
        String pre = "\u00a7b\u00a7l[Jarvis]\u00a7r ";
        for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea x : l) {
            String color = switch (x.tono()) {
                case ROJO  -> "\u00a7c";
                case AMBAR -> "\u00a7e";
                case GRIS  -> "\u00a77";
            };
            if (x.enlace() == null) {
                p.sendMessage(pre + color + x.texto());
                continue;
            }
            net.md_5.bungee.api.chat.TextComponent clic = new net.md_5.bungee.api.chat.TextComponent(x.enlace());
            clic.setColor(net.md_5.bungee.api.ChatColor.AQUA);
            clic.setUnderlined(true);
            clic.setClickEvent(new net.md_5.bungee.api.chat.ClickEvent(
                    net.md_5.bungee.api.chat.ClickEvent.Action.OPEN_URL, x.enlace()));
            List<net.md_5.bungee.api.chat.BaseComponent> linea = new ArrayList<>(List.of(
                    net.md_5.bungee.api.chat.TextComponent.fromLegacyText(pre + color + x.texto() + " ")));
            linea.add(clic);
            p.spigot().sendMessage(linea.toArray(new net.md_5.bungee.api.chat.BaseComponent[0]));
        }
    }

    public static final class AvisoAlEntrar implements org.bukkit.event.Listener {
        private final JarvisPaperPlugin plugin;
        AvisoAlEntrar(JarvisPaperPlugin plugin) { this.plugin = plugin; }
        @org.bukkit.event.EventHandler(priority = org.bukkit.event.EventPriority.MONITOR)
        public void alEntrar(org.bukkit.event.player.PlayerJoinEvent e) {
            Player p = e.getPlayer();
            Schedulers.asyncRetrasada(plugin, () -> {
                try {
                    Schedulers.deEntidad(plugin, p, () -> { if (Bukkit.getPlayer(p.getUniqueId()) == p) plugin.avisarSinVincular(p); });
                } catch (Throwable apagando) {
                }
            }, 100L);
        }
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
        boolean proxy = detrasDeProxy(config, proxyDetectado);
        if (proxy && !pairCartelProxyDado) {
            pairCartelProxyDado = true;
            pairAnteriores.guardar(pairDeviceCode, pairExpiresAt, System.currentTimeMillis());
            pairDeviceCode = null;
            pairVerificationUri = null;
            cartelDetrasDeProxy();
        }

        String aprobada = pairAnteriores.sondear(pairing::poll, System.currentTimeMillis(), System.nanoTime(),
                pairPollIntervalNanos);
        if (aprobada != null && applyPairedKey(aprobada)) { stopPairing(); return; }
        if (proxy) {
            if (pairAnteriores.sondeados().isEmpty()) stopPairing();
            return;
        }
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
        pairAnteriores.olvidar();
        avisoSinVincular.olvidarTodo();
    }

    private volatile boolean pairCartelProxyDado = false;

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

    private boolean detrasDeProxyLeido() {
        return (configCargada || config.motivoCargaFallida() == null) && detrasDeProxy(config, proxyDetectado);
    }
}
