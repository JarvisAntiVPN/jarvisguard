package dev.flamingomg.jarvis.command;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.detection.FloodGuard;
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

    private static final List<String> SUB = List.of("key", "stats", "reload", "blacklist", "unblacklist",
            "whitelist", "unwhitelist");
    private static final String PRE = "§b§l[Jarvis]§r ";

    private final JarvisClient client;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Plugin plugin;
    private final FloodGuard floodGuard;
    private final SyncClient syncClient;

    public AntiVpnCommand(JarvisClient client, BanCache banCache, ConfigManager config, Plugin plugin,
                          FloodGuard floodGuard, SyncClient syncClient) {
        this.client = client;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
        this.floodGuard = floodGuard;
        this.syncClient = syncClient;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) { sendHelp(sender); return true; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"    -> setKey(sender, args);
            case "blacklist"   -> blacklist(sender, args, false);
            case "unblacklist" -> blacklist(sender, args, true);
            case "whitelist"   -> whitelist(sender, args, false);
            case "unwhitelist" -> whitelist(sender, args, true);
            case "stats"  -> stats(sender);
            case "reload" -> {
                if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return true; }
                config.reload();

                floodGuard.reconfigure();
                banCache.reconfigure();
                client.cache().invalidateAll();

                Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
                    client.ensureReady();
                    client.fetchAndSyncBans(banCache);
                    client.refreshConfig();

                    syncClient.reconnectIfKeyChanged();
                });
                sender.sendMessage(PRE + "§a" + m("cmd.reloaded"));
            }
            default -> sendHelp(sender);
        }
        return true;
    }

    private void setKey(CommandSender sender, String[] args) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        if (args.length < 2) { sender.sendMessage(PRE + "§c" + m("cmd.usage")); return; }
        String newKey = args[1].trim();
        if (newKey.isEmpty() || "CHANGE_ME".equalsIgnoreCase(newKey)) {
            sender.sendMessage(PRE + "§c" + m("cmd.invalidkey")); return;
        }
        if (!config.setKey(newKey)) { sender.sendMessage(PRE + "§c" + m("cmd.savefail")); return; }
        sender.sendMessage(PRE + "§e" + m("cmd.keysaved"));
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
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

        boolean canSign = client.signer() != null && client.signer().hasSecret() && !client.keyRejected();
        boolean ipCheckDisabled = config.getBoolean("server.behind-proxy", false);
        var estado = dev.flamingomg.jarvis.model.ProtectionState.of(canSign, client.backendHealthy(), ipCheckDisabled);

        if (estado.isProtecting()) {
            sender.sendMessage(PRE + "§a" + m("cmd.protected"));
        } else {
            switch (estado) {
                case DEGRADED -> {

                    sender.sendMessage(PRE + "§e" + m("cmd.degraded"));
                    sender.sendMessage(PRE + "§7" + m("cmd.degradedWhy"));
                }
                case BEHIND_PROXY -> sender.sendMessage(PRE + "§e" + m("cmd.behindProxy"));
                default -> {
                    sender.sendMessage(PRE + "§c" + m("cmd.unprotected"));
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
        sender.sendMessage(kv(m("cmd.backendstatus"), client.circuitBreakerStatus()));
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(PRE + "§b" + m("cmd.helpTitle"));
        sender.sendMessage(help("key <license>", m("cmd.descKey")));
        sender.sendMessage(help("stats",         m("cmd.descStats")));
        sender.sendMessage(help("reload",        m("cmd.descReload")));
        sender.sendMessage(help("blacklist <player> [reason]", m("cmd.descBlacklist")));
        sender.sendMessage(help("unblacklist <player>",        m("cmd.descUnblacklist")));
        sender.sendMessage(help("whitelist <player> [time] [reason]", m("cmd.descWhitelist")));
        sender.sendMessage(help("unwhitelist <player>",               m("cmd.descUnwhitelist")));
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
        sender.sendMessage(PRE + "§7" + m("cmd.blacklistSending"));
        client.blacklistAsync(target, reason, actor, remove).thenAccept(ok -> {

            Bukkit.getScheduler().runTask(plugin, () -> {
                if (ok) sender.sendMessage(PRE + "§a" + m(remove ? "cmd.unblacklistOk" : "cmd.blacklistOk") + " " + target);
                else    sender.sendMessage(PRE + "§c" + m("cmd.blacklistFail"));
            });
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
        String sufijo = time == null ? "" : " (" + time + ")";
        sender.sendMessage(PRE + "§7" + m("cmd.blacklistSending"));
        client.whitelistAsync(target, time, reason, actor, remove).thenAccept(code -> {

            Bukkit.getScheduler().runTask(plugin, () -> {
                if (code >= 200 && code < 300)
                    sender.sendMessage(PRE + "§a" + m(remove ? "cmd.unwhitelistOk" : "cmd.whitelistOk") + " " + target + sufijo);
                else if (code == 400) sender.sendMessage(PRE + "§c" + m("cmd.whitelistBadTime"));
                else                  sender.sendMessage(PRE + "§c" + m("cmd.blacklistFail"));
            });
        });
    }

    private boolean puedeModerar(CommandSender sender) {
        return sender.hasPermission("jarvis.staff") || sender.hasPermission("jarvis.admin");
    }

    private static String kv(String label, String value)  { return "  §7" + label + ": §f" + value; }
    private static String help(String usage, String desc) { return "  §f/antivpn " + usage + " §8- " + desc; }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (args.length == 1) {
            String q = args[0].toLowerCase(Locale.ROOT);
            return SUB.stream().filter(s -> s.startsWith(q)).collect(Collectors.toList());
        }
        return List.of();
    }
}
