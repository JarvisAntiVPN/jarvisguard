package dev.flamingomg.jarvis.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.diag.Diagnostico;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.sync.SyncClient;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand implements SimpleCommand {

    private static final List<String> SUB = List.of("key", "stats", "doctor", "reload", "blacklist", "unblacklist",
            "whitelist", "unwhitelist");

    private final JarvisClient client;
    private final ProxyServer proxy;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Object plugin;
    private final FloodGuard floodGuard;
    private final SyncClient syncClient;
    private final dev.flamingomg.jarvis.listener.DetectionListener listener;

    public AntiVpnCommand(JarvisClient client, ProxyServer proxy,
                          BanCache banCache, ConfigManager config,
                          Object plugin, FloodGuard floodGuard, SyncClient syncClient,
                          dev.flamingomg.jarvis.listener.DetectionListener listener) {
        this.client = client;
        this.proxy = proxy;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
        this.floodGuard = floodGuard;
        this.syncClient = syncClient;
        this.listener = listener;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }

    @Override
    public void execute(Invocation inv) {
        CommandSource src = inv.source();
        String[] args = inv.arguments();
        if (args.length == 0) { sendHelp(src); return; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"       -> setKey(src, args);
            case "stats"     -> stats(src);
            case "doctor"    -> doctor(src);
            case "blacklist"   -> blacklist(src, args, false);
            case "unblacklist" -> blacklist(src, args, true);
            case "whitelist"   -> whitelist(src, args, false);
            case "unwhitelist" -> whitelist(src, args, true);
            case "reload"    -> {

                if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }

                if (!config.reload()) {
                    src.sendMessage(pre().append(Component.text(m("cmd.reloadFail"), NamedTextColor.RED)));
                    return;
                }

                floodGuard.reconfigure();
                banCache.reconfigure();
                client.cache().invalidateAll();

                proxy.getScheduler().buildTask(plugin, () -> {
                    client.ensureReady();
                    client.fetchAndSyncBans(banCache);
                    client.refreshConfig();

                    syncClient.reconnectIfKeyChanged();
                }).schedule();
                src.sendMessage(pre().append(Component.text(m("cmd.reloaded"), NamedTextColor.GREEN)));
            }
            default -> sendHelp(src);
        }
    }

    private void setKey(CommandSource src, String[] args) {
        if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
        if (args.length < 2) {
            src.sendMessage(pre().append(Component.text(m("cmd.usage"), NamedTextColor.RED)));
            return;
        }
        String newKey = args[1].trim();
        if (newKey.isEmpty() || "CHANGE_ME".equalsIgnoreCase(newKey)) {
            src.sendMessage(pre().append(Component.text(m("cmd.invalidkey"), NamedTextColor.RED)));
            return;
        }
        if (!config.setKey(newKey)) {
            src.sendMessage(pre().append(Component.text(m("cmd.savefail"), NamedTextColor.RED)));
            return;
        }
        src.sendMessage(pre().append(Component.text(m("cmd.keysaved"), NamedTextColor.YELLOW)));

        proxy.getScheduler().buildTask(plugin, () -> {
            boolean ok = client.ensureReady();
            if (ok) {
                client.fetchAndSyncBans(banCache);
                src.sendMessage(pre().append(Component.text(m("cmd.active"), NamedTextColor.GREEN)));
            } else if (client.keyRejected()) {

                src.sendMessage(pre().append(Component.text(m("cmd.keyrejected"), NamedTextColor.RED)));
            } else {
                src.sendMessage(pre().append(Component.text(m("cmd.validatefail"), NamedTextColor.YELLOW)));
            }

            syncClient.reconnectIfKeyChanged();
        }).schedule();
    }

    private void stats(CommandSource src) {
        if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
        src.sendMessage(pre().append(Component.text(m("cmd.statsTitle"), NamedTextColor.AQUA)));

        var estado = client.protectionState();

        if (estado.isProtecting()) {
            src.sendMessage(pre().append(Component.text(m("cmd.protected"), NamedTextColor.GREEN)));
        } else {
            switch (estado) {
                case DEGRADED -> {

                    src.sendMessage(pre().append(Component.text(m("cmd.degraded"), NamedTextColor.YELLOW)));
                    src.sendMessage(pre().append(Component.text(m("cmd.degradedWhy"), NamedTextColor.GRAY)));
                }
                case BEHIND_PROXY -> src.sendMessage(pre().append(Component.text(m("cmd.behindProxy"), NamedTextColor.YELLOW)));
                default -> {
                    src.sendMessage(pre().append(Component.text(m("cmd.unprotected"), NamedTextColor.RED)));
                    if (client.keyRejected()) {
                        src.sendMessage(pre().append(Component.text(m("cmd.keyrejected"), NamedTextColor.RED)));
                    }
                }
            }
        }

        src.sendMessage(kv(m("cmd.version"), dev.flamingomg.jarvis.JarvisPlugin.VERSION));

        src.sendMessage(kv(m("cmd.ipcache"), String.valueOf(client.cache().estimatedSize())));
        src.sendMessage(kv(m("cmd.blockedips"), String.valueOf(banCache.size())));
        src.sendMessage(kv(m("cmd.online"), String.valueOf(proxy.getPlayerCount())));

    }

    private void doctor(CommandSource src) {
        if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
        long ahora = System.currentTimeMillis();
        var datos = new Diagnostico.Datos(
                client.protectionState(),
                client.keyRejected(),
                client.signer() != null && client.signer().hasSecret(),
                !isBlank(config.getString("backend.license-key", "")),
                client.clock().offsetMs(),
                syncClient.streamVivo(),
                syncClient.ultimoRechazo(),
                listener.privateIpWatch().privadaReciente(ahora, VENTANA_IP_PRIVADA_MS),
                banCache.size(),
                config.motivoCargaFallida());

        src.sendMessage(pre().append(Component.text(m("cmd.doctorTitle"), NamedTextColor.AQUA)));
        var lineas = Diagnostico.revisar(datos);
        for (var l : lineas) src.sendMessage(pintar(l));
        if (Diagnostico.peor(lineas) == Diagnostico.Nivel.OK) {
            src.sendMessage(pre().append(Component.text(m("cmd.diagAllOk"), NamedTextColor.GREEN)));
        }
    }

    private static final long VENTANA_IP_PRIVADA_MS = 30 * 60 * 1000L;

    private Component pintar(Diagnostico.Linea l) {
        NamedTextColor color = switch (l.nivel()) {
            case OK     -> NamedTextColor.GREEN;
            case NEUTRO -> NamedTextColor.GRAY;
            case AVISO  -> NamedTextColor.YELLOW;
            case FALLO  -> NamedTextColor.RED;
        };

        String marca = switch (l.nivel()) {
            case OK     -> "✔";
            case NEUTRO -> "–";
            default     -> "✖";
        };
        String texto = l.detalle() == null ? "" : m(l.detalle());
        if (l.dato() != null) {
            texto = texto.isEmpty() ? l.dato() : texto.replace("{ms}", l.dato()).replace("{ip}", l.dato());
        }
        Component base = Component.text("  " + marca + " ", color)
                .append(Component.text(m(l.etiqueta()), NamedTextColor.GRAY));
        return texto.isEmpty() ? base : base.append(Component.text(": ", NamedTextColor.GRAY))
                .append(Component.text(texto, color));
    }

    private void sendHelp(CommandSource src) {
        src.sendMessage(pre().append(Component.text(m("cmd.helpTitle"), NamedTextColor.AQUA)));
        src.sendMessage(help("key <license>", m("cmd.descKey")));
        src.sendMessage(help("stats",         m("cmd.descStats")));
        src.sendMessage(help("doctor",        m("cmd.descDoctor")));
        src.sendMessage(help("reload",        m("cmd.descReload")));
        src.sendMessage(help("blacklist <player> [reason]", m("cmd.descBlacklist")));
        src.sendMessage(help("unblacklist <player>",        m("cmd.descUnblacklist")));
        src.sendMessage(help("whitelist <player> [time] [reason]", m("cmd.descWhitelist")));
        src.sendMessage(help("unwhitelist <player>",               m("cmd.descUnwhitelist")));
    }

    static boolean pareceTiempo(String arg) {
        if (arg == null || arg.isEmpty()) return false;
        char c = arg.charAt(0);
        if (c >= '0' && c <= '9') return true;
        String s = arg.toLowerCase(Locale.ROOT);
        return s.equals("perma") || s.equals("permanent") || s.equals("permanente");
    }

    enum Tono { HECHO, AVISO, FALLO }

    record ResumenLista(Tono tono, String titular, List<String> detalles) {}

    static ResumenLista resumirLista(dev.flamingomg.jarvis.client.JarvisClient.RespuestaLista r, boolean remove,
                                     String claveOk, String objetivo, String ecoTiempo,
                                     java.util.function.UnaryOperator<String> tr, long ahoraMs) {

        List<String> detalles = new java.util.ArrayList<>(2);
        if (Boolean.FALSE.equals(r.saved())) {

            return new ResumenLista(Tono.FALLO, tr.apply("cmd.notSaved") + " " + objetivo, detalles);
        }
        boolean nadaQueQuitar = remove && Boolean.FALSE.equals(r.found());
        boolean yaEstaba      = !remove && Boolean.TRUE.equals(r.already());
        String titular;
        if (nadaQueQuitar) {
            titular = tr.apply("cmd.notInList") + " " + objetivo;
        } else if (yaEstaba) {
            titular = tr.apply("cmd.alreadyInList") + " " + objetivo;
        } else {
            String eco = (r.expiresAt() == null && ecoTiempo != null && !ecoTiempo.isEmpty())
                    ? " (" + ecoTiempo + ")" : "";
            titular = tr.apply(claveOk) + " " + objetivo + eco;
        }
        Long caduca = r.expiresAt();
        if (!remove && caduca != null && caduca > 0) {
            detalles.add(tr.apply("cmd.expiresIn").replace("{t}", tiempoRelativo(caduca - ahoraMs)));
        }
        Integer ips = r.ipUnbanned();
        if (ips != null && ips > 0) {
            detalles.add(tr.apply("cmd.ipsLifted").replace("{n}", String.valueOf(ips)));
        }
        return new ResumenLista(nadaQueQuitar || yaEstaba ? Tono.AVISO : Tono.HECHO, titular, detalles);
    }

    static String tiempoRelativo(long ms) {
        if (ms < 60_000L) return "<1m";
        long dias = ms / 86_400_000L;
        if (dias >= 1) return dias + "d";
        long horas = ms / 3_600_000L;
        if (horas >= 1) return horas + "h";
        return (ms / 60_000L) + "m";
    }

    private static final java.util.Set<String> SUB_JUGADOR =
            java.util.Set.of("blacklist", "unblacklist", "whitelist", "unwhitelist");

    private static final int TOPE_SUGERENCIAS = 50;

    static List<String> filtrarNombres(java.util.Collection<String> conectados, String prefijo) {
        if (conectados == null || conectados.isEmpty()) return List.of();
        String q = prefijo == null ? "" : prefijo.toLowerCase(Locale.ROOT);
        return conectados.stream()
                .filter(n -> n != null && !n.isEmpty())
                .filter(n -> n.toLowerCase(Locale.ROOT).startsWith(q))
                .distinct()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .limit(TOPE_SUGERENCIAS)
                .collect(Collectors.toList());
    }

    static boolean autocompletaJugador(String sub) {
        return sub != null && SUB_JUGADOR.contains(sub.toLowerCase(Locale.ROOT));
    }

    private void whitelist(CommandSource src, String[] args, boolean remove) {
        if (!puedeModerar(src)) { noPermission(src); return; }
        if (args.length < 2 || args[1].isBlank()) {
            src.sendMessage(pre().append(Component.text(
                    m(remove ? "cmd.usageUnwhitelist" : "cmd.usageWhitelist"), NamedTextColor.YELLOW)));
            return;
        }
        String target = args[1];

        if (target.length() > 32) {
            src.sendMessage(pre().append(Component.text(m("cmd.blacklistTooLong"), NamedTextColor.RED)));
            return;
        }
        String time = null;
        int iMotivo = 2;
        if (!remove && args.length > 2 && pareceTiempo(args[2])) { time = args[2]; iMotivo = 3; }
        String reason = (remove || args.length <= iMotivo) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, iMotivo, args.length));
        String actor = (src instanceof Player p) ? p.getUsername() : "consola";
        if (sinFirma(src)) return;
        src.sendMessage(pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        final String eco = time;
        client.whitelistAsync(target, time, reason, actor, remove).thenAccept(r -> {
            if (r.ok()) {
                pintar(src, resumirLista(r, remove, remove ? "cmd.unwhitelistOk" : "cmd.whitelistOk",
                        target, eco, this::m, System.currentTimeMillis()));
            } else if (r.code() == 400) {
                src.sendMessage(pre().append(Component.text(m("cmd.whitelistBadTime"), NamedTextColor.RED)));
            } else {
                src.sendMessage(pre().append(Component.text(m("cmd.blacklistFail"), NamedTextColor.RED)));
            }
        });
    }

    private void blacklist(CommandSource src, String[] args, boolean remove) {
        if (!puedeModerar(src)) { noPermission(src); return; }
        if (args.length < 2 || args[1].isBlank()) {
            src.sendMessage(pre().append(Component.text(
                    m(remove ? "cmd.usageUnblacklist" : "cmd.usageBlacklist"), NamedTextColor.YELLOW)));
            return;
        }
        String target = args[1];

        if (target.length() > 32) {
            src.sendMessage(pre().append(Component.text(m("cmd.blacklistTooLong"), NamedTextColor.RED)));
            return;
        }
        String reason = (remove || args.length < 3) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length));
        String actor = (src instanceof Player p) ? p.getUsername() : "consola";
        if (sinFirma(src)) return;
        src.sendMessage(pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        client.blacklistAsync(target, reason, actor, remove).thenAccept(r -> {
            if (r.ok()) {
                pintar(src, resumirLista(r, remove, remove ? "cmd.unblacklistOk" : "cmd.blacklistOk",
                        target, null, this::m, System.currentTimeMillis()));
            } else {
                src.sendMessage(pre().append(Component.text(m("cmd.blacklistFail"), NamedTextColor.RED)));
            }
        });
    }

    private void pintar(CommandSource src, ResumenLista res) {
        NamedTextColor color = switch (res.tono()) {
            case HECHO -> NamedTextColor.GREEN;
            case AVISO -> NamedTextColor.YELLOW;
            case FALLO -> NamedTextColor.RED;
        };
        src.sendMessage(pre().append(Component.text(res.titular(), color)));
        for (String d : res.detalles()) {
            src.sendMessage(pre().append(Component.text(d, NamedTextColor.GRAY)));
        }
    }

    @Override
    public List<String> suggest(Invocation inv) {
        String[] args = inv.arguments();
        if (args.length <= 1) {
            String q = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
            return SUB.stream().filter(s -> s.startsWith(q)).collect(Collectors.toList());
        }

        if (args.length == 2 && autocompletaJugador(args[0]) && puedeModerar(inv.source())) {
            return filtrarNombres(proxy.getAllPlayers().stream()
                    .map(Player::getUsername).collect(Collectors.toList()), args[1]);
        }
        return List.of();
    }

    @Override
    public boolean hasPermission(Invocation inv) {
        return inv.source().hasPermission("jarvis.command");
    }

    private static Component pre() {
        return Component.text("", NamedTextColor.AQUA, TextDecoration.BOLD);
    }

    private static Component kv(String label, String value) {
        return Component.text("  " + label + ": ", NamedTextColor.GRAY)
                .append(Component.text(value, NamedTextColor.WHITE));
    }

    private static Component help(String usage, String desc) {
        return Component.text("  /antivpn " + usage, NamedTextColor.WHITE)
                .append(Component.text(" - " + desc, NamedTextColor.DARK_GRAY));
    }

    private boolean puedeModerar(CommandSource src) {
        return src.hasPermission("jarvis.staff") || src.hasPermission("jarvis.admin");
    }

    private void noPermission(CommandSource src) {
        src.sendMessage(pre().append(Component.text(m("cmd.noperm"), NamedTextColor.RED)));
    }

    private boolean sinFirma(CommandSource src) {
        if (client.keyRejected()) {
            src.sendMessage(pre().append(Component.text(m("cmd.keyrejected"), NamedTextColor.RED)));
            return true;
        }
        if (client.signer() == null || !client.signer().hasSecret()) {
            src.sendMessage(pre().append(Component.text(m("cmd.notLinked"), NamedTextColor.RED)));
            return true;
        }
        return false;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }
}
