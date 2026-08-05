package dev.flamingomg.jarvis.command;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.plugin.TabExecutor;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.FloodGuard;
import dev.flamingomg.jarvis.i18n.Messages;
import dev.flamingomg.jarvis.sync.SyncClient;

import net.kyori.adventure.text.serializer.bungeecord.BungeeComponentSerializer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand extends Command implements TabExecutor {

    private static final List<String> SUB = List.of("key", "stats", "reload", "blacklist", "unblacklist",
            "whitelist", "unwhitelist");

    private final JarvisClient client;
    private final ProxyServer proxy;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Plugin plugin;
    private final FloodGuard floodGuard;
    private final SyncClient syncClient;

    public AntiVpnCommand(JarvisClient client, ProxyServer proxy,
                          BanCache banCache, ConfigManager config,
                          Plugin plugin, FloodGuard floodGuard, SyncClient syncClient) {
        super("antivpn", "jarvis.command", "jarvis", "avpn");
        this.client = client;
        this.proxy = proxy;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
        this.floodGuard = floodGuard;
        this.syncClient = syncClient;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }
    private void send(CommandSender s, Component c) { s.sendMessage(BungeeComponentSerializer.get().serialize(c)); }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (args.length == 0) { sendHelp(sender); return; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"       -> setKey(sender, args);
            case "blacklist"   -> blacklist(sender, args, false);
            case "unblacklist" -> blacklist(sender, args, true);
            case "whitelist"   -> whitelist(sender, args, false);
            case "unwhitelist" -> whitelist(sender, args, true);
            case "stats"     -> stats(sender);
            case "reload"    -> {

                if (!sender.hasPermission("jarvis.admin")) { noPermission(sender); return; }
                config.reload();

                floodGuard.reconfigure();
                banCache.reconfigure();
                client.cache().invalidateAll();

                proxy.getScheduler().runAsync(plugin, () -> {
                    client.ensureReady();
                    client.fetchAndSyncBans(banCache);
                    client.refreshConfig();

                    syncClient.reconnectIfKeyChanged();
                });
                send(sender, pre().append(Component.text(m("cmd.reloaded"), NamedTextColor.GREEN)));
            }
            default -> sendHelp(sender);
        }
    }

    private void setKey(CommandSender sender, String[] args) {
        if (!sender.hasPermission("jarvis.admin")) { noPermission(sender); return; }
        if (args.length < 2) {
            send(sender, pre().append(Component.text(m("cmd.usage"), NamedTextColor.RED)));
            return;
        }
        String newKey = args[1].trim();
        if (newKey.isEmpty() || "CHANGE_ME".equalsIgnoreCase(newKey)) {
            send(sender, pre().append(Component.text(m("cmd.invalidkey"), NamedTextColor.RED)));
            return;
        }
        if (!config.setKey(newKey)) {
            send(sender, pre().append(Component.text(m("cmd.savefail"), NamedTextColor.RED)));
            return;
        }
        send(sender, pre().append(Component.text(m("cmd.keysaved"), NamedTextColor.YELLOW)));

        proxy.getScheduler().runAsync(plugin, () -> {
            boolean ok = client.ensureReady();
            if (ok) {
                client.fetchAndSyncBans(banCache);
                send(sender, pre().append(Component.text(m("cmd.active"), NamedTextColor.GREEN)));
            } else if (client.keyRejected()) {

                send(sender, pre().append(Component.text(m("cmd.keyrejected"), NamedTextColor.RED)));
            } else {
                send(sender, pre().append(Component.text(m("cmd.validatefail"), NamedTextColor.YELLOW)));
            }

            syncClient.reconnectIfKeyChanged();
        });
    }

    private void stats(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { noPermission(sender); return; }
        send(sender, pre().append(Component.text(m("cmd.statsTitle"), NamedTextColor.AQUA)));

        boolean canSign = client.signer() != null && client.signer().hasSecret() && !client.keyRejected();

        var estado = dev.flamingomg.jarvis.model.ProtectionState.of(canSign, client.backendHealthy(), false);

        if (estado.isProtecting()) {
            send(sender, pre().append(Component.text(m("cmd.protected"), NamedTextColor.GREEN)));
        } else {
            switch (estado) {
                case DEGRADED -> {

                    send(sender, pre().append(Component.text(m("cmd.degraded"), NamedTextColor.YELLOW)));
                    send(sender, pre().append(Component.text(m("cmd.degradedWhy"), NamedTextColor.GRAY)));
                }
                case BEHIND_PROXY -> send(sender, pre().append(Component.text(m("cmd.behindProxy"), NamedTextColor.YELLOW)));
                default -> {
                    send(sender, pre().append(Component.text(m("cmd.unprotected"), NamedTextColor.RED)));
                    if (client.keyRejected()) {
                        send(sender, pre().append(Component.text(m("cmd.keyrejected"), NamedTextColor.RED)));
                    }
                }
            }
        }

        send(sender, kv(m("cmd.version"), dev.flamingomg.jarvis.JarvisBungeePlugin.VERSION));

        send(sender, kv(m("cmd.ipcache"), String.valueOf(client.cache().estimatedSize())));
        send(sender, kv(m("cmd.blockedips"), String.valueOf(banCache.size())));
        send(sender, kv(m("cmd.online"), String.valueOf(proxy.getOnlineCount())));
        send(sender, kv(m("cmd.backendstatus"), client.circuitBreakerStatus()));
    }

    private void sendHelp(CommandSender sender) {
        send(sender, pre().append(Component.text(m("cmd.helpTitle"), NamedTextColor.AQUA)));
        send(sender, help("key <license>", m("cmd.descKey")));
        send(sender, help("stats",         m("cmd.descStats")));
        send(sender, help("reload",        m("cmd.descReload")));
        send(sender, help("blacklist <player> [reason]", m("cmd.descBlacklist")));
        send(sender, help("unblacklist <player>",        m("cmd.descUnblacklist")));
        send(sender, help("whitelist <player> [time] [reason]", m("cmd.descWhitelist")));
        send(sender, help("unwhitelist <player>",               m("cmd.descUnwhitelist")));
    }

    private void blacklist(CommandSender sender, String[] args, boolean remove) {
        if (!puedeModerar(sender)) { noPermission(sender); return; }
        if (args.length < 2 || args[1].isBlank()) {
            send(sender, pre().append(Component.text(
                    m(remove ? "cmd.usageUnblacklist" : "cmd.usageBlacklist"), NamedTextColor.YELLOW)));
            return;
        }
        String target = args[1];
        if (target.length() > 32) {
            send(sender, pre().append(Component.text(m("cmd.blacklistTooLong"), NamedTextColor.RED)));
            return;
        }
        String reason = (remove || args.length < 3) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, 2, args.length));
        String actor = (sender instanceof net.md_5.bungee.api.connection.ProxiedPlayer pp) ? pp.getName() : "consola";
        send(sender, pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        client.blacklistAsync(target, reason, actor, remove).thenAccept(ok -> {
            if (ok) {
                send(sender, pre().append(Component.text(
                        m(remove ? "cmd.unblacklistOk" : "cmd.blacklistOk") + " " + target, NamedTextColor.GREEN)));
            } else {
                send(sender, pre().append(Component.text(m("cmd.blacklistFail"), NamedTextColor.RED)));
            }
        });
    }

    static boolean pareceTiempo(String arg) {
        if (arg == null || arg.isEmpty()) return false;
        char c = arg.charAt(0);
        if (c >= '0' && c <= '9') return true;
        String s = arg.toLowerCase(Locale.ROOT);
        return s.equals("perma") || s.equals("permanent") || s.equals("permanente");
    }

    private void whitelist(CommandSender sender, String[] args, boolean remove) {
        if (!puedeModerar(sender)) { noPermission(sender); return; }
        if (args.length < 2 || args[1].isBlank()) {
            send(sender, pre().append(Component.text(
                    m(remove ? "cmd.usageUnwhitelist" : "cmd.usageWhitelist"), NamedTextColor.YELLOW)));
            return;
        }
        String target = args[1];

        if (target.length() > 32) {
            send(sender, pre().append(Component.text(m("cmd.blacklistTooLong"), NamedTextColor.RED)));
            return;
        }
        String time = null;
        int iMotivo = 2;
        if (!remove && args.length > 2 && pareceTiempo(args[2])) { time = args[2]; iMotivo = 3; }
        String reason = (remove || args.length <= iMotivo) ? null
                : String.join(" ", java.util.Arrays.copyOfRange(args, iMotivo, args.length));
        String actor = (sender instanceof net.md_5.bungee.api.connection.ProxiedPlayer pp) ? pp.getName() : "consola";
        String sufijo = time == null ? "" : " (" + time + ")";
        send(sender, pre().append(Component.text(m("cmd.blacklistSending"), NamedTextColor.GRAY)));
        client.whitelistAsync(target, time, reason, actor, remove).thenAccept(code -> {
            if (code >= 200 && code < 300) {
                send(sender, pre().append(Component.text(
                        m(remove ? "cmd.unwhitelistOk" : "cmd.whitelistOk") + " " + target + sufijo, NamedTextColor.GREEN)));
            } else if (code == 400) {
                send(sender, pre().append(Component.text(m("cmd.whitelistBadTime"), NamedTextColor.RED)));
            } else {
                send(sender, pre().append(Component.text(m("cmd.blacklistFail"), NamedTextColor.RED)));
            }
        });
    }

    @Override
    public Iterable<String> onTabComplete(CommandSender sender, String[] args) {
        if (args.length <= 1) {
            String q = args.length == 0 ? "" : args[0].toLowerCase(Locale.ROOT);
            return SUB.stream().filter(s -> s.startsWith(q)).collect(Collectors.toList());
        }
        return List.of();
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

    private boolean puedeModerar(CommandSender sender) {
        return sender.hasPermission("jarvis.staff") || sender.hasPermission("jarvis.admin");
    }

    private void noPermission(CommandSender sender) {
        send(sender, pre().append(Component.text(m("cmd.noperm"), NamedTextColor.RED)));
    }
}
