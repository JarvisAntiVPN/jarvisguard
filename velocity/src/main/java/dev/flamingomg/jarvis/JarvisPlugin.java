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

    public static final String VERSION = "0.5.28";

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
    private final dev.flamingomg.jarvis.client.PairingClient.Anteriores pairAnteriores =
            new dev.flamingomg.jarvis.client.PairingClient.Anteriores();
    private String pairVerificationUri;
    private long pairBannerNextAt = 0L;
    private String pairLocale;
    private final dev.flamingomg.jarvis.client.AvisoSinVincular avisoSinVincular =
            new dev.flamingomg.jarvis.client.AvisoSinVincular();
    private static final long PAIR_BANNER_REPEAT_MS = 600_000L;
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
        this.configCargada = config.load();

        this.jarvisClient = new JarvisClient(config, logger);
        jarvisClient.setVersionPropia(VERSION);

        BedrockDetector bedrockDetector = new BedrockDetector(proxy, config, logger);
        FloodGuard floodGuard = new FloodGuard(config);
        this.banCache = new BanCache(config, logger);
        jarvisClient.setBanCacheParaExentos(this.banCache);
        this.syncClient = new SyncClient(config, logger, jarvisClient, banCache, proxy);

        DetectionListener detectionListener = new DetectionListener(proxy, this, jarvisClient, bedrockDetector,
                config, logger, floodGuard, banCache);
        proxy.getEventManager().register(this, detectionListener);
        detectionListener.init();

        CommandManager cm = proxy.getCommandManager();

        CommandMeta antivpnMeta = cm.metaBuilder("antivpn").aliases("jarvis", "avpn").plugin(this).build();
        cm.register(antivpnMeta, new AntiVpnCommand(jarvisClient, proxy, banCache, config, this, floodGuard, syncClient,
                detectionListener, this::vincularTrasRecargar, this::vinculacionAhora, this::lineasDeLink));

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
        logger.info("Jarvis v{} loaded.", VERSION);
        switch (ConfigManager.arranque(configCargada, isBlank(config.getString("backend.license-key", "")))) {
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

    private boolean configCargada;

    private void avisoConfigIlegible() {
        String motivo = config.motivoCargaFallida();
        logger.warn("");
        logger.warn("=================== JARVIS · CHECK YOUR CONFIG ===================");
        logger.warn("  Jarvis is NOT protecting this server.");
        logger.warn("  {}", motivo != null ? motivo : "config.yml couldn't be loaded.");
        logger.warn("  Fix the file and restart the proxy.");
        logger.warn("  The linking link is NOT shown on purpose: your license key may");
        logger.warn("  already be in that file, and linking would overwrite it.");
        logger.warn("==================================================================");
    }

    private void startPairingFlow() {
        this.pairTask = proxy.getScheduler().buildTask(this, this::pairTick)
                .repeat(5, java.util.concurrent.TimeUnit.SECONDS)
                .schedule();
    }

    private synchronized void vincularTrasRecargar() {
        if (pairing == null) return;
        if (pairTask == null) startPairingFlow();
        else pairBannerNextAt = 0L;
    }

    private void requestAndPrintPairing() {
        if (!pedirCodigo()) return;
        printPairingBanner();
        avisarSinVincularATodos();
    }

    private boolean pedirCodigo() {
        String server = "Velocity " + proxy.getVersion().getVersion();
        dev.flamingomg.jarvis.client.PairingClient.Start s = pairing.start(null, server, VERSION);
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
                !isBlank(config.getString("backend.license-key", "")), pairTask != null,
                pairStartFails == 0 || (pairDeviceCode != null && pairExpiresAt - System.currentTimeMillis()
                        >= dev.flamingomg.jarvis.client.AvisoSinVincular.MARGEN_MIN_MS));
    }

    private java.util.List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> lineasDeLink(
            com.velocitypowered.api.proxy.Player quien, String idiomaDelCliente, boolean consola) {
        boolean turno = dev.flamingomg.jarvis.client.AvisoSinVincular.esperarTurno(
                pairTickEnCurso, dev.flamingomg.jarvis.client.AvisoSinVincular.ESPERA_TURNO_MS);
        try {
            boolean clave = !isBlank(config.getString("backend.license-key", ""));
            dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido que = quien != null
                    ? dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(quien.isOnlineMode(), false)
                    : consola ? dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.CON_ENLACE
                    : dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(false, false);
            long ahora = System.currentTimeMillis();
            boolean nuevo = false;
            if (turno && !clave && pairTask != null
                    && que != dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.NADA
                    && dev.flamingomg.jarvis.client.AvisoSinVincular.tocaCodigoNuevo(pairDeviceCode, pairExpiresAt, ahora)
                    && ahora >= pairNextStartAt && pedirCodigo()) {
                nuevo = true;
                if (!consola) printPairingBanner();
                else pairBannerNextAt = System.currentTimeMillis() + PAIR_BANNER_REPEAT_MS;
            }
            String enlace = pairVerificationUri;
            boolean hay = pairDeviceCode != null && dev.flamingomg.jarvis.client.AvisoSinVincular.enlaceParaElComando(
                    enlace, pairExpiresAt, System.currentTimeMillis(), nuevo);
            dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion v =
                    dev.flamingomg.jarvis.client.AvisoSinVincular.vinculacion(clave, pairTask != null, hay);
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

    @Subscribe
    public void onPostLogin(com.velocitypowered.api.event.connection.PostLoginEvent event) {
        com.velocitypowered.api.proxy.Player p = event.getPlayer();
        if (pairDeviceCode == null && (jarvisClient == null || jarvisClient.versionNueva() == null)) return;
        proxy.getScheduler().buildTask(this, () -> { if (p.isActive()) { avisarSinVincular(p); avisarVersion(p); } })
                .delay(5, java.util.concurrent.TimeUnit.SECONDS).schedule();
    }

    private void avisarVersion(com.velocitypowered.api.proxy.Player p) {
        String nueva = jarvisClient == null ? null : jarvisClient.versionNueva();
        if (nueva == null || !p.hasPermission("jarvis.admin")) return;
        if (!jarvisClient.avisoVersion().tocaAvisar(p.getUniqueId(), nueva)) return;
        java.util.Locale idioma = p.getEffectiveLocale();
        java.util.List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> l = dev.flamingomg.jarvis.client.AvisoVersion
                .lineas(idioma != null ? idioma.toLanguageTag() : jarvisClient.locale(), VERSION, nueva);
        net.kyori.adventure.text.Component pre = net.kyori.adventure.text.Component.text("[Jarvis] ",
                net.kyori.adventure.text.format.NamedTextColor.AQUA, net.kyori.adventure.text.format.TextDecoration.BOLD);
        for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea x : l) {
            net.kyori.adventure.text.format.NamedTextColor color = switch (x.tono()) {
                case ROJO  -> net.kyori.adventure.text.format.NamedTextColor.RED;
                case AMBAR -> net.kyori.adventure.text.format.NamedTextColor.YELLOW;
                case GRIS  -> net.kyori.adventure.text.format.NamedTextColor.GRAY;
            };
            net.kyori.adventure.text.Component linea = net.kyori.adventure.text.Component.empty().append(pre)
                    .append(net.kyori.adventure.text.Component.text(x.texto(), color));
            if (x.enlace() != null) {
                linea = linea.append(net.kyori.adventure.text.Component.text(" "))
                        .append(net.kyori.adventure.text.Component.text(x.enlace(),
                                        net.kyori.adventure.text.format.NamedTextColor.AQUA)
                                .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED)
                                .clickEvent(net.kyori.adventure.text.event.ClickEvent.openUrl(x.enlace())));
            }
            p.sendMessage(linea);
        }
    }

    private void avisarSinVincular(com.velocitypowered.api.proxy.Player p) {
        String enlace = pairVerificationUri;
        long ahora = System.currentTimeMillis();
        if (pairDeviceCode == null
                || !dev.flamingomg.jarvis.client.AvisoSinVincular.enlaceUtil(enlace, pairExpiresAt, ahora)) return;
        if (!p.hasPermission("jarvis.admin")) return;
        dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido que =
                dev.flamingomg.jarvis.client.AvisoSinVincular.queEnsenar(p.isOnlineMode(), false);
        if (que == dev.flamingomg.jarvis.client.AvisoSinVincular.Contenido.NADA) return;
        if (!avisoSinVincular.tocaAvisar(p.getUniqueId(), ahora)) return;
        java.util.Locale idioma = p.getEffectiveLocale();
        java.util.List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> l =
                dev.flamingomg.jarvis.client.AvisoSinVincular.lineas(
                        idioma != null ? idioma.toLanguageTag() : pairLocale, que, enlace);
        net.kyori.adventure.text.Component pre = net.kyori.adventure.text.Component.text("[Jarvis] ",
                net.kyori.adventure.text.format.NamedTextColor.AQUA, net.kyori.adventure.text.format.TextDecoration.BOLD);
        for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea x : l) {
            net.kyori.adventure.text.format.NamedTextColor color = switch (x.tono()) {
                case ROJO  -> net.kyori.adventure.text.format.NamedTextColor.RED;
                case AMBAR -> net.kyori.adventure.text.format.NamedTextColor.YELLOW;
                case GRIS  -> net.kyori.adventure.text.format.NamedTextColor.GRAY;
            };
            net.kyori.adventure.text.Component linea = net.kyori.adventure.text.Component.empty().append(pre)
                    .append(net.kyori.adventure.text.Component.text(x.texto(), color));
            if (x.enlace() != null) {
                linea = linea.append(net.kyori.adventure.text.Component.text(" "))
                        .append(net.kyori.adventure.text.Component.text(x.enlace(),
                                        net.kyori.adventure.text.format.NamedTextColor.AQUA)
                                .decorate(net.kyori.adventure.text.format.TextDecoration.UNDERLINED)
                                .clickEvent(net.kyori.adventure.text.event.ClickEvent.openUrl(x.enlace())));
            }
            p.sendMessage(linea);
        }
    }

    private void avisarSinVincularATodos() {
        for (com.velocitypowered.api.proxy.Player p : proxy.getAllPlayers()) avisarSinVincular(p);
    }

    private void printPairingBanner() {
        pairBannerNextAt = System.currentTimeMillis() + PAIR_BANNER_REPEAT_MS;
        String loc = pairLocale != null ? pairLocale : dev.flamingomg.jarvis.i18n.Messages.localeDeLaMaquina();
        logger.warn("");
        logger.warn("==================== JARVIS · LINK PROXY ====================");
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.notLinked"));
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.open"));
        logger.warn("");
        logger.warn("    {}", pairVerificationUri);
        logger.warn("");
        logger.warn("  {}", dev.flamingomg.jarvis.i18n.Messages.get(loc, "log.link.manual"));
        logger.warn("============================================================");
    }

    private void anotarLocaleDelDueno(String loc) {
        if (loc == null || loc.isBlank()) return;
        if (loc.equals(pairLocale)) return;
        pairLocale = loc;
        pairBannerNextAt = 0L;
    }

    private void recordarVinculacionSiToca() {
        if (pairVerificationUri == null) return;
        if (System.currentTimeMillis() < pairBannerNextAt) return;
        printPairingBanner();
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

        String aprobada = pairAnteriores.sondear(pairing::poll, System.currentTimeMillis(), System.nanoTime(),
                pairPollIntervalNanos);
        if (aprobada != null && applyPairedKey(aprobada)) { stopPairing(); return; }

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
        pairVerificationUri = null;
        pairLocale = null;
        pairAnteriores.olvidar();
        avisoSinVincular.olvidarTodo();
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
        if (jarvisClient != null) jarvisClient.marcarApagando();
        stopPairing();
        if (syncClient != null) syncClient.stop();
        if (jarvisClient != null) jarvisClient.shutdown();
        if (pairing != null) pairing.shutdown();
        logger.info("Jarvis stopped.");
    }
}
