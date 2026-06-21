package dev.flamingomg.jarvis.detection;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.logging.Logger;

public final class ProxyDetector {

    private ProxyDetector() {}

    public static boolean behindProxy(Logger logger) {
        return boolAt(logger, "spigot.yml",               "settings", "bungeecord")
            || boolAt(logger, "config/paper-global.yml",  "proxies", "velocity", "enabled")

            || boolAt(logger, "paper.yml",                "settings", "velocity-support", "enabled");
    }

    private static boolean boolAt(Logger logger, String file, String... path) {
        File f = new File(file);
        if (!f.isFile()) return false;
        try (FileInputStream in = new FileInputStream(f)) {
            Object node = new Yaml().load(in);
            for (int i = 0; i < path.length - 1; i++) {
                if (!(node instanceof Map<?, ?> m)) return false;
                node = m.get(path[i]);
            }
            if (node instanceof Map<?, ?> m) {
                return m.get(path[path.length - 1]) instanceof Boolean b && b;
            }
        } catch (Throwable t) {
            logger.fine("[proxy-detect] couldn't read " + file + ": " + t.getMessage());
        }
        return false;
    }
}
