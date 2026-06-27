package dev.flamingomg.jarvis.command;

import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.i18n.Messages;
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

    private static final List<String> SUB = List.of("key", "stats", "reload");
    private static final String PRE = "§b§l[Jarvis]§r ";

    private final JarvisClient client;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Plugin plugin;

    public AntiVpnCommand(JarvisClient client, BanCache banCache, ConfigManager config, Plugin plugin) {
        this.client = client;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (args.length == 0) { sendHelp(sender); return true; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"    -> setKey(sender, args);
            case "stats"  -> stats(sender);
            case "reload" -> {
                if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return true; }
                config.reload();
                client.cache().invalidateAll();

                Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
                    client.ensureReady();
                    client.fetchAndSyncBans(banCache);
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
            } else {
                sender.sendMessage(PRE + "§e" + m("cmd.validatefail"));
            }
        });
    }

    private void stats(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { sender.sendMessage(PRE + "§c" + m("cmd.noperm")); return; }
        sender.sendMessage(PRE + "§b" + m("cmd.statsTitle"));
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
