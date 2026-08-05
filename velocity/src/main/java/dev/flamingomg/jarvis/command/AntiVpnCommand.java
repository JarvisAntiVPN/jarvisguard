package dev.flamingomg.jarvis.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.sync.SyncClient;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand implements SimpleCommand {

    private static final List<String> SUB = List.of("key", "stats", "reload", "blacklist", "unblacklist",
            "whitelist", "unwhitelist");

    private final JarvisClient client;
    private final ProxyServer proxy;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Object plugin;
    private final FloodGuard floodGuard;
    private final SyncClient syncClient;

    public AntiVpnCommand(JarvisClient client, ProxyServer proxy,
                          BanCache banCache, ConfigManager config,
                          Object plugin, FloodGuard floodGuard, SyncClient syncClient) {
        this.client = client;
        this.proxy = proxy;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
        this.floodGuard = floodGuard;
        this.syncClient = syncClient;
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
            case "blacklist"   -> blacklist(src, args, false);
            case "unblacklist" -> blacklist(src, args, true);
            case "whitelist"   -> whitelist(src, args, false);
            case "unwhitelist" -> whitelist(src, args, true);
            case "reload"    -> {

                if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
                config.reload();

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

        boolean canSign = client.signer() != null && client.signer().hasSecret() && !client.keyRejected();

        var estado = dev.flamingomg.jarvis.model.ProtectionState.of(canSign, client.backendHealthy(), false);

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
        src.sendMessage(kv(m("cmd.backendstatus"), client.circuitBreakerStatus()));
    }

    private void sendHelp(CommandSource src) {
        src.sendMessage(pre().append(Component.text(m("cmd.helpTitle"), NamedTextColor.AQUA)));
        src.sendMessage(help("key <license>", m("cmd.descKey")));
        src.sendMessage(help("stats",         m("cmd.descStats")));
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
        String sufijo = time == null ? "" : " (" + time + ")";
        src.sendMessage(pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        client.whitelistAsync(target, time, reason, actor, remove).thenAccept(code -> {
            if (code >= 200 && code < 300) {
                src.sendMessage(pre().append(Component.text(
                        m(remove ? "cmd.unwhitelistOk" : "cmd.whitelistOk") + " " + target + sufijo, NamedTextColor.GREEN)));
            } else if (code == 400) {
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
        src.sendMessage(pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        client.blacklistAsync(target, reason, actor, remove).thenAccept(ok -> {
            if (ok) {
                src.sendMessage(pre().append(Component.text(
                        m(remove ? "cmd.unblacklistOk" : "cmd.blacklistOk") + " " + target, NamedTextColor.GREEN)));
            } else {
                src.sendMessage(pre().append(Component.text(m("cmd.blacklistFail"), NamedTextColor.RED)));
            }
        });
    }

    @Override
    public List<String> suggest(Invocation inv) {
        String[] args = inv.arguments();
        if (args.length <= 1) {
            String q = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
            return SUB.stream().filter(s -> s.startsWith(q)).collect(Collectors.toList());
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
}
