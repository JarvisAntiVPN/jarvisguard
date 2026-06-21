package dev.flamingomg.jarvis.command;

import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.plugin.TabExecutor;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.i18n.Messages;

import net.kyori.adventure.text.serializer.bungeecord.BungeeComponentSerializer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand extends Command implements TabExecutor {

    private static final List<String> SUB = List.of("key", "stats", "reload");

    private final JarvisClient client;
    private final ProxyServer proxy;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Plugin plugin;

    public AntiVpnCommand(JarvisClient client, ProxyServer proxy,
                          BanCache banCache, ConfigManager config,
                          Plugin plugin) {
        super("antivpn", "jarvis.command", "jarvis", "avpn");
        this.client = client;
        this.proxy = proxy;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
    }

    private String m(String key) { return Messages.get(client.locale(), key); }
    private void send(CommandSender s, Component c) { s.sendMessage(BungeeComponentSerializer.get().serialize(c)); }

    @Override
    public void execute(CommandSender sender, String[] args) {
        if (args.length == 0) { sendHelp(sender); return; }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "key"       -> setKey(sender, args);
            case "stats"     -> stats(sender);
            case "reload"    -> {

                if (!sender.hasPermission("jarvis.admin")) { noPermission(sender); return; }
                config.reload();
                client.cache().invalidateAll();
                client.fetchAndSyncBans(banCache);
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
            } else {
                send(sender, pre().append(Component.text(m("cmd.validatefail"), NamedTextColor.YELLOW)));
            }
        });
    }

    private void stats(CommandSender sender) {
        if (!sender.hasPermission("jarvis.admin")) { noPermission(sender); return; }
        send(sender, pre().append(Component.text(m("cmd.statsTitle"), NamedTextColor.AQUA)));
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
        return Component.text("[Jarvis] ", NamedTextColor.AQUA, TextDecoration.BOLD);
    }

    private static Component kv(String label, String value) {
        return Component.text("  " + label + ": ", NamedTextColor.GRAY)
                .append(Component.text(value, NamedTextColor.WHITE));
    }

    private static Component help(String usage, String desc) {
        return Component.text("  /antivpn " + usage, NamedTextColor.WHITE)
                .append(Component.text(" - " + desc, NamedTextColor.DARK_GRAY));
    }

    private void noPermission(CommandSender sender) {
        send(sender, pre().append(Component.text(m("cmd.noperm"), NamedTextColor.RED)));
    }
}
