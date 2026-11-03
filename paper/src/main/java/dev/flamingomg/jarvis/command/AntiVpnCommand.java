package dev.flamingomg.jarvis.command;

import dev.flamingomg.jarvis.util.Schedulers;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.diag.Diagnostico;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.sync.SyncClient;
import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.plugin.Plugin;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand implements CommandExecutor, TabCompleter {

    private static final List<String> SUB = List.of("key", "link", "stats", "doctor", "reload", "blacklist",
            "unblacklist", "whitelist", "unwhitelist", "alts");
    private static final String PRE = "§b§l[Jarvis]§r ";

    private final JarvisClient client;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Plugin plugin;
    private final FloodGuard floodGuard;
    private final SyncClient syncClient;
    private final dev.flamingomg.jarvis.listener.DetectionListener listener;
    private final Runnable vincularSinClave;
    private final java.util.function.Supplier<dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion> vinculacion;
    private final dev.flamingomg.jarvis.client.AvisoSinVincular.LineasDeLink<org.bukkit.entity.Player> enlace;
    private final java.util.function.Supplier<List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea>> enlaceRcon;

    public AntiVpnCommand(JarvisClient client, BanCache banCache, ConfigManager config, Plugin plugin,
                          FloodGuard floodGuard, SyncClient syncClient,
                          dev.flamingomg.jarvis.listener.DetectionListener listener, Runnable vincularSinClave,
                          java.util.function.Supplier<dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion> vinculacion,
                          dev.flamingomg.jarvis.client.AvisoSinVincular.LineasDeLink<org.bukkit.entity.Player> enlace,
                          java.util.function.Supplier<List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea>> enlaceRcon) {
        this.vincularSinClave = vincularSinClave;
        this.vinculacion = vinculacion;
        this.enlace = enlace;
        this.enlaceRcon = enlaceRcon;
        this.client = client;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
        this.floodGuard = floodGuard;
        this.syncClient = syncClient;
        this.listener = listener;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) { sendHelp(sender); return true; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"    -> setKey(sender, args);
            case "link"   -> link(sender);
            case "blacklist"   -> blacklist(sender, args, false);
            case "unblacklist" -> blacklist(sender, args, true);
            case "whitelist"   -> whitelist(sender, args, false);
            case "unwhitelist" -> whitelist(sender, args, true);
            case "alts"        -> alts(sender, args);
            case "stats"  -> stats(sender);
            case "doctor" -> doctor(sender);
            case "reload" -> {
                if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return true; }
                String claveAntes = config.getString("backend.license-key", "");
                if (!config.reload()) { sender.sendMessage(PRE + "§c" + m("cmd.reloadFail")); return true; }
                client.claveRecargada(claveAntes);
                floodGuard.reconfigure();
                banCache.reconfigure();
                client.setIpCheckDisabled(config.getBoolean("server.behind-proxy", false));
                client.cache().invalidateAll();
                Schedulers.async(plugin, () -> {
                    client.ensureReady();
                    client.fetchAndSyncBans(banCache);
                    client.refreshConfig();
                    syncClient.reconnectIfKeyChanged();
                });
                if (isBlank(config.getString("backend.license-key", ""))) vincularSinClave.run();
                if (config.estadoClave() == ConfigManager.EstadoClave.MAL_FORMADA) {
                    sender.sendMessage(PRE + "§cconfig.yml: " + m("cmd.invalidkey"));
                    return true;
                }
                sender.sendMessage(PRE + "§a" + m("cmd.reloaded"));
            }
            default -> sendHelp(sender);
        }
        return true;
    }

    private void link(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        org.bukkit.entity.Player p = sender instanceof org.bukkit.entity.Player x ? x : null;
        boolean consola = sender == plugin.getServer().getConsoleSender();
        if (p == null && !consola) {
            if (sender instanceof org.bukkit.command.BlockCommandSender || sender instanceof org.bukkit.entity.Entity
                    || sender instanceof org.bukkit.command.ProxiedCommandSender) {
                sender.sendMessage(PRE + "§c" + m("cmd.noperm"));
            } else {
                for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea l : enlaceRcon.get()) pintar(sender, l);
            }
            return;
        }
        String idioma = p == null ? null : dev.flamingomg.jarvis.util.IdiomaJugador.de(p);
        Schedulers.async(plugin, () -> {
            List<dev.flamingomg.jarvis.client.AvisoSinVincular.Linea> lineas = enlace.de(p, idioma, consola);
            Schedulers.aRemitente(plugin, sender, () -> {
                for (dev.flamingomg.jarvis.client.AvisoSinVincular.Linea l : lineas) pintar(sender, l);
            });
        });
    }

    private static void pintar(CommandSender sender, dev.flamingomg.jarvis.client.AvisoSinVincular.Linea l) {
        String color = switch (l.tono()) {
            case ROJO  -> "§c";
            case AMBAR -> "§e";
            case GRIS  -> "§7";
        };
        if (!(sender instanceof org.bukkit.entity.Player p)) {
            sender.sendMessage(PRE + color + l.texto() + (l.enlace() == null ? "" : " §b" + l.enlace()));
            return;
        }
        List<net.md_5.bungee.api.chat.BaseComponent> linea = new java.util.ArrayList<>(List.of(
                net.md_5.bungee.api.chat.TextComponent.fromLegacyText(PRE)));
        net.md_5.bungee.api.chat.TextComponent texto = new net.md_5.bungee.api.chat.TextComponent(
                l.texto() + (l.enlace() == null ? "" : " "));
        texto.setColor(switch (l.tono()) {
            case ROJO  -> net.md_5.bungee.api.ChatColor.RED;
            case AMBAR -> net.md_5.bungee.api.ChatColor.YELLOW;
            case GRIS  -> net.md_5.bungee.api.ChatColor.GRAY;
        });
        linea.add(texto);
        if (l.enlace() != null) {
            net.md_5.bungee.api.chat.TextComponent clic = new net.md_5.bungee.api.chat.TextComponent(l.enlace());
            clic.setColor(net.md_5.bungee.api.ChatColor.AQUA);
            clic.setUnderlined(true);
            clic.setClickEvent(new net.md_5.bungee.api.chat.ClickEvent(
                    net.md_5.bungee.api.chat.ClickEvent.Action.OPEN_URL, l.enlace()));
            linea.add(clic);
        }
        p.spigot().sendMessage(linea.toArray(new net.md_5.bungee.api.chat.BaseComponent[0]));
    }

    private void setKey(CommandSender sender, String[] args) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        if (args.length < 2) { sender.sendMessage(PRE + "§c" + m("cmd.usage")); return; }
        String newKey = ConfigManager.claveDeLosArgumentos(args);
        if (newKey == null) {
            sender.sendMessage(PRE + "§c" + m("cmd.invalidkey")); return;
        }
        if (!config.setKey(newKey)) { sender.sendMessage(PRE + "§c" + m("cmd.savefail")); return; }
        sender.sendMessage(PRE + "§e" + m("cmd.keysaved"));
        Schedulers.async(plugin, () -> {
            if (client.ensureReady()) {
                client.fetchAndSyncBans(banCache);
                sender.sendMessage(PRE + "§a" + m("cmd.active"));
            } else if (client.keyRejected()) {
                sender.sendMessage(PRE + "§c" + m("cmd.keyrejected"));
            } else {
                sender.sendMessage(PRE + "§e" + m("cmd.validatefail"));
            }
            syncClient.reconnectIfKeyChanged();
        });
    }

    private void stats(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        sender.sendMessage(PRE + "§b" + m("cmd.statsTitle"));

        var estado = client.protectionState();
        if (estado.isProtecting()) {
            sender.sendMessage(PRE + "§a" + m("cmd.protected"));
        } else {
            switch (estado) {
                case DEGRADED -> {
                    sender.sendMessage(PRE + "§e" + m("cmd.degraded"));
                    sender.sendMessage(PRE + "§7" + m(client.causaDegradado().clave()));
                }
                case BEHIND_PROXY -> sender.sendMessage(PRE + "§e" + m("cmd.behindProxy"));
                default -> {
                    boolean proxy = estado == dev.flamingomg.jarvis.model.ProtectionState.NO_KEY
                            && vinculacion.get() == dev.flamingomg.jarvis.client.AvisoSinVincular.Vinculacion.PROXY;
                    sender.sendMessage(PRE + (proxy ? "§e" : "§c") + m("cmd.unprotected"));
                    if (proxy) sender.sendMessage(PRE + "§7" + m("log.link.proxy"));
                    if (client.keyRejected()) {
                        sender.sendMessage(PRE + "§c" + m("cmd.keyrejected"));
                    }
                }
            }
        }

        sender.sendMessage(kv(m("cmd.version"), dev.flamingomg.jarvis.JarvisPaperPlugin.VERSION));

        sender.sendMessage(kv(m("cmd.ipcache"),       String.valueOf(client.cache().estimatedSize())));
        sender.sendMessage(kv(m("cmd.blockedips"),    String.valueOf(banCache.size())));
        sender.sendMessage(kv(m("cmd.online"),        String.valueOf(Bukkit.getOnlinePlayers().size())));
    }

    private void doctor(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "\u00a7c" + m("cmd.noperm")); return; }
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
                listener.privateIpWatch().algunaVista(),
                banCache.size(),
                config.motivoCargaFallida(),
                vinculacion.get(),
                client.causaDegradado());

        sender.sendMessage(PRE + "\u00a7b" + m("cmd.doctorTitle"));
        var lineas = Diagnostico.revisar(datos);
        for (var l : lineas) sender.sendMessage(pintar(l));
        if (Diagnostico.peor(lineas) == Diagnostico.Nivel.OK) {
            sender.sendMessage(PRE + "\u00a7a" + m("cmd.diagAllOk"));
        }
    }

    private static final long VENTANA_IP_PRIVADA_MS = 30 * 60 * 1000L;

    private String pintar(Diagnostico.Linea l) {
        String color = switch (l.nivel()) {
            case OK     -> "\u00a7a";
            case NEUTRO -> "\u00a77";
            case AVISO  -> "\u00a7e";
            case FALLO  -> "\u00a7c";
        };
        String marca = switch (l.nivel()) {
            case OK     -> "\u2714";
            case NEUTRO -> "\u2013";
            default     -> "\u2716";
        };
        String texto = l.detalle() == null ? "" : m(l.detalle());
        if (l.dato() != null) {
            texto = texto.isEmpty() ? l.dato() : texto.replace("{ms}", l.dato()).replace("{ip}", l.dato());
        }
        String base = "  " + color + marca + " \u00a77" + m(l.etiqueta());
        return texto.isEmpty() ? base : base + "\u00a77: " + color + texto;
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(PRE + "§b" + m("cmd.helpTitle"));
        sender.sendMessage(help("key <license>", m("cmd.descKey")));
        sender.sendMessage(help("link",          m("cmd.descLink")));
        sender.sendMessage(help("stats",         m("cmd.descStats")));
        sender.sendMessage(help("doctor",        m("cmd.descDoctor")));
        sender.sendMessage(help("reload",        m("cmd.descReload")));
        sender.sendMessage(help("blacklist <player> [reason]", m("cmd.descBlacklist")));
        sender.sendMessage(help("unblacklist <player>",        m("cmd.descUnblacklist")));
        sender.sendMessage(help("whitelist <player> [time] [reason]", m("cmd.descWhitelist")));
        sender.sendMessage(help("unwhitelist <player>",               m("cmd.descUnwhitelist")));
        sender.sendMessage(help("alts <player>",                      m("cmd.descAlts")));
    }

    private void blacklist(CommandSender sender, String[] args, boolean remove) {
        if (!puedeModerar(sender)) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        if (args.length < 2 || args[1].isBlank()) {
            sender.sendMessage(PRE + "§e" + m(remove ? "cmd.usageUnblacklist" : "cmd.usageBlacklist"));
            return;
        }
        String target = args[1];
        if (target.length() > 32) { sender.sendMessage(PRE + "§c" + m("cmd.blacklistTooLong")); return; }
        String reason = (remove || args.length < 3) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length));
        String actor = (sender instanceof org.bukkit.entity.Player p) ? p.getName() : "consola";
        if (sinFirma(sender)) return;
        sender.sendMessage(PRE + "§7" + m("cmd.blacklistSending"));
        client.blacklistAsync(target, reason, actor, remove).thenAccept(r -> {
            Schedulers.aRemitente(plugin, sender, () -> {
                if (r.ok() || (remove && r.code() == 409 && Boolean.TRUE.equals(r.global())))
                    pintar(sender, resumirLista(r, remove, remove ? "cmd.unblacklistOk" : "cmd.blacklistOk",
                            target, null, this::m, System.currentTimeMillis()));
                else sender.sendMessage(PRE + "§c" + m("cmd.blacklistFail"));
            });
        });
    }

    private void alts(CommandSender sender, String[] args) {
        if (!puedeModerar(sender)) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        if (args.length < 2 || args[1].isBlank()) {
            sender.sendMessage(PRE + "§e" + m("cmd.usageAlts"));
            return;
        }
        String target = args[1];
        if (target.length() > 32) { sender.sendMessage(PRE + "§c" + m("cmd.blacklistTooLong")); return; }
        if (sinFirma(sender)) return;
        sender.sendMessage(PRE + "§7" + m("cmd.blacklistSending"));
        client.altsAsync(target).thenAccept(r -> Schedulers.aRemitente(plugin, sender,
                () -> pintar(sender, resumirAlts(r, target, this::m, System.currentTimeMillis()))));
    }

    private void pintar(CommandSender sender, ResumenLista res) {
        String color = switch (res.tono()) {
            case HECHO -> "§a";
            case AVISO -> "§e";
            case FALLO -> "§c";
        };
        sender.sendMessage(PRE + color + res.titular());
        for (String d : res.detalles()) {
            sender.sendMessage(PRE + "§7" + d);
        }
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
        if (remove && r.code() == 409 && Boolean.TRUE.equals(r.global())) {
            return new ResumenLista(Tono.AVISO, tr.apply("cmd.networkBlock") + " " + objetivo, detalles);
        }
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

    static ResumenLista resumirAlts(dev.flamingomg.jarvis.client.JarvisClient.RespuestaAlts r, String objetivo,
                                    java.util.function.UnaryOperator<String> tr, long ahoraMs) {
        List<String> detalles = new java.util.ArrayList<>();
        if (!r.ok() || r.found() == null) {
            return new ResumenLista(Tono.FALLO, tr.apply("cmd.blacklistFail"), detalles);
        }
        String nombre = sinColor((r.name() == null || r.name().isBlank()) ? objetivo : r.name());
        if (!r.found()) {
            return new ResumenLista(Tono.AVISO, tr.apply("cmd.altsNotFound").replace("{player}", nombre), detalles);
        }
        if (Boolean.TRUE.equals(r.protegido())) {
            return new ResumenLista(Tono.AVISO, tr.apply("cmd.altsProtected").replace("{player}", nombre), detalles);
        }
        if (r.accounts().isEmpty()) {
            return new ResumenLista(Tono.HECHO, tr.apply("cmd.altsNone").replace("{player}", nombre), detalles);
        }
        for (dev.flamingomg.jarvis.client.JarvisClient.CuentaVinculada c : r.accounts()) {
            StringBuilder l = new StringBuilder(sinColor(c.name()));
            l.append(" · ").append(tr.apply("cmd.altsShared").replace("{n}", String.valueOf(c.shared())));
            if (c.together()) l.append(" · ").append(tr.apply("cmd.altsTogether"));
            if (c.lastSeen() != null && c.lastSeen() > 0) {
                l.append(" · ").append(tr.apply("cmd.altsSeen").replace("{t}", tiempoRelativo(ahoraMs - c.lastSeen())));
            }
            if (c.family()) l.append(" · ").append(tr.apply("cmd.altsFamily"));
            if (c.banned()) l.append(" · ").append(tr.apply("cmd.altsBanned"));
            detalles.add(l.toString());
        }
        return new ResumenLista(Tono.HECHO, tr.apply("cmd.altsTitle").replace("{player}", nombre), detalles);
    }

    static String sinColor(String s) { return s == null ? "" : s.replace("§", ""); }

    static String tiempoRelativo(long ms) {
        if (ms < 60_000L) return "<1m";
        long dias = ms / 86_400_000L;
        if (dias >= 1) return dias + "d";
        long horas = ms / 3_600_000L;
        if (horas >= 1) return horas + "h";
        return (ms / 60_000L) + "m";
    }

    private static final java.util.Set<String> SUB_JUGADOR =
            java.util.Set.of("blacklist", "unblacklist", "whitelist", "unwhitelist", "alts");

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

    private void whitelist(CommandSender sender, String[] args, boolean remove) {
        if (!puedeModerar(sender)) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        if (args.length < 2 || args[1].isBlank()) {
            sender.sendMessage(PRE + "§e" + m(remove ? "cmd.usageUnwhitelist" : "cmd.usageWhitelist"));
            return;
        }
        String target = args[1];
        if (target.length() > 32) { sender.sendMessage(PRE + "§c" + m("cmd.blacklistTooLong")); return; }
        String time = null;
        int iMotivo = 2;
        if (!remove && args.length > 2 && pareceTiempo(args[2])) { time = args[2]; iMotivo = 3; }
        String reason = (remove || args.length <= iMotivo) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, iMotivo, args.length));
        String actor = (sender instanceof org.bukkit.entity.Player p) ? p.getName() : "consola";
        if (sinFirma(sender)) return;
        sender.sendMessage(PRE + "§7" + m("cmd.blacklistSending"));
        final String eco = time;
        client.whitelistAsync(target, time, reason, actor, remove).thenAccept(r -> {
            Schedulers.aRemitente(plugin, sender, () -> {
                if (r.ok())
                    pintar(sender, resumirLista(r, remove, remove ? "cmd.unwhitelistOk" : "cmd.whitelistOk",
                            target, eco, this::m, System.currentTimeMillis()));
                else if (r.code() == 400) sender.sendMessage(PRE + "§c" + m("cmd.whitelistBadTime"));
                else                      sender.sendMessage(PRE + "§c" + m("cmd.blacklistFail"));
            });
        });
    }

    private boolean puedeModerar(CommandSender sender) {
        return sender.hasPermission("jarvis.staff") || sender.hasPermission("jarvis.admin");
    }

    private boolean sinFirma(CommandSender sender) {
        if (client.keyRejected()) {
            sender.sendMessage(PRE + "§c" + m("cmd.keyrejected"));
            return true;
        }
        if (client.signer() == null || !client.signer().hasSecret()) {
            sender.sendMessage(PRE + "§c" + m("cmd.notLinked"));
            return true;
        }
        return false;
    }

    private static String kv(String label, String value)  { return "  §7" + label + ": §f" + value; }
    private static String help(String usage, String desc) { return "  §f/antivpn " + usage + " §8- " + desc; }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            String q = args[0].toLowerCase(Locale.ROOT);
            return SUB.stream().filter(s -> s.startsWith(q)).collect(Collectors.toList());
        }
        if (args.length == 2 && autocompletaJugador(args[0]) && puedeModerar(sender)) {
            return filtrarNombres(nombresConectados(), args[1]);
        }
        return List.of();
    }

    private static List<String> nombresConectados() {
        try {
            return Bukkit.getOnlinePlayers().stream()
                    .map(org.bukkit.entity.Player::getName).collect(Collectors.toList());
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty() || s.trim().equalsIgnoreCase("CHANGE_ME");
    }
}
