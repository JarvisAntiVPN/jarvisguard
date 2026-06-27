package dev.flamingomg.jarvis.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.ProxyServer;
import dev.flamingomg.jarvis.client.JarvisClient;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.detection.BanCache;
import dev.flamingomg.jarvis.i18n.Messages;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

public final class AntiVpnCommand implements SimpleCommand {

    private static final List<String> SUB = List.of("key", "stats", "reload");

    private final JarvisClient client;
    private final ProxyServer proxy;
    private final BanCache banCache;
    private final ConfigManager config;
    private final Object plugin;

    public AntiVpnCommand(JarvisClient client, ProxyServer proxy,
                          BanCache banCache, ConfigManager config,
                          Object plugin) {
        this.client = client;
        this.proxy = proxy;
        this.banCache = banCache;
        this.config = config;
        this.plugin = plugin;
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
            case "reload"    -> {

                if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
                config.reload();
                client.ensureReady();
                client.cache().invalidateAll();
                client.fetchAndSyncBans(banCache);
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
            } else {
                src.sendMessage(pre().append(Component.text(m("cmd.validatefail"), NamedTextColor.YELLOW)));
            }
        }).schedule();
    }

    private void stats(CommandSource src) {
        if (!src.hasPermission("jarvis.admin")) { noPermission(src); return; }
        src.sendMessage(pre().append(Component.text(m("cmd.statsTitle"), NamedTextColor.AQUA)));
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

    private void noPermission(CommandSource src) {
        src.sendMessage(pre().append(Component.text(m("cmd.noperm"), NamedTextColor.RED)));
    }
}
