package dev.flamingomg.jarvis.util;

import org.bstats.MetricsBase;
import org.bstats.json.JsonObjectBuilder;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import java.util.logging.Level;

public final class BStats {

    private static final String CABECERA =
            "bStats (https://bStats.org) collects some basic information for plugin authors, like how\n"
          + "many people use their plugin and their total player count. It's recommended to keep bStats\n"
          + "enabled, but if you're not comfortable with this, you can turn this setting off. There is no\n"
          + "performance penalty associated with having metrics enabled, and data sent to bStats is fully\n"
          + "anonymous.";

    private final JavaPlugin plugin;
    private final MetricsBase base;

    @SuppressWarnings("deprecation")
    public BStats(JavaPlugin plugin, int serviceId) {
        this.plugin = plugin;

        File carpeta = new File(plugin.getDataFolder().getParentFile(), "bStats");
        File fichero = new File(carpeta, "config.yml");
        YamlConfiguration cfg = YamlConfiguration.loadConfiguration(fichero);
        if (!cfg.isSet("serverUuid")) {
            cfg.addDefault("enabled", true);
            cfg.addDefault("serverUuid", UUID.randomUUID().toString());
            cfg.addDefault("logFailedRequests", false);
            cfg.addDefault("logSentData", false);
            cfg.addDefault("logResponseStatusText", false);
            cfg.options().header(CABECERA).copyDefaults(true);
            try { cfg.save(fichero); } catch (IOException ignored) {  }
        }

        boolean activo          = cfg.getBoolean("enabled", true);
        String  uuidServidor    = cfg.getString("serverUuid");
        boolean logErrores      = cfg.getBoolean("logFailedRequests", false);
        boolean logEnviado      = cfg.getBoolean("logSentData", false);
        boolean logRespuesta    = cfg.getBoolean("logResponseStatusText", false);

        this.base = new MetricsBase(
                "bukkit", uuidServidor, serviceId, activo,
                this::datosDePlataforma,
                this::datosDelPlugin,
                tarea -> Schedulers.global(plugin, tarea),
                plugin::isEnabled,
                (mensaje, error) -> plugin.getLogger().log(Level.WARNING, mensaje, error),
                mensaje -> plugin.getLogger().log(Level.INFO, mensaje),
                logErrores, logEnviado, logRespuesta);
    }

    public void shutdown() {
        try { base.shutdown(); } catch (Exception ignored) {  }
    }

    private void datosDePlataforma(JsonObjectBuilder b) {
        b.appendField("playerAmount", Bukkit.getOnlinePlayers().size());
        b.appendField("onlineMode",   Bukkit.getOnlineMode() ? 1 : 0);
        b.appendField("bukkitVersion", Bukkit.getVersion());
        b.appendField("bukkitName",    Bukkit.getName());
        b.appendField("javaVersion",   System.getProperty("java.version"));
        b.appendField("osName",        System.getProperty("os.name"));
        b.appendField("osArch",        System.getProperty("os.arch"));
        b.appendField("osVersion",     System.getProperty("os.version"));
        b.appendField("coreCount",     Runtime.getRuntime().availableProcessors());
    }

    private void datosDelPlugin(JsonObjectBuilder b) {
        b.appendField("pluginVersion", plugin.getDescription().getVersion());
    }
}
