package dev.flamingomg.jarvis.config;

import org.slf4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class ConfigManager {

    private static final String FILE_NAME = "config.yml";

    private static final String PRODUCTION_BACKEND_URL = "https://connector.jarvisguard.com";
    public static final String DEFAULT_BACKEND_URL =
            System.getProperty("jarvis.backend", PRODUCTION_BACKEND_URL);

    private final Path dataDirectory;
    private final Logger logger;
    private volatile Map<String, Object> root = Collections.emptyMap();

    public ConfigManager(Path dataDirectory, Logger logger) {
        this.dataDirectory = dataDirectory;
        this.logger = logger;
    }

    public void load() {
        try {
            Files.createDirectories(dataDirectory);
            Path file = dataDirectory.resolve(FILE_NAME);
            if (Files.notExists(file)) {
                copyDefault(file);
                logger.info("config.yml created at {}", file);
            }
            try (InputStream in = Files.newInputStream(file)) {
                Map<String, Object> loaded = new Yaml().load(in);
                this.root = normalize(loaded != null ? loaded : new java.util.LinkedHashMap<>());
            }
            logger.debug("Jarvis client configuration loaded.");
        } catch (IOException | RuntimeException e) {

            logger.error("Couldn't load {}; using default values.", FILE_NAME, e);
            this.root = Collections.emptyMap();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> normalize(Map<String, Object> r) {
        Object backendObj = r.get("backend");
        Map<String, Object> backend = backendObj instanceof Map<?, ?> m
                ? (Map<String, Object>) m : new java.util.LinkedHashMap<>();
        r.put("backend", backend);

        Object key = r.getOrDefault("key", r.get("license-key"));
        if (key != null && blankOrDefault(backend.get("license-key"))) backend.put("license-key", key);

        backend.put("url", DEFAULT_BACKEND_URL);
        return r;
    }

    private static boolean blankOrDefault(Object v) {
        if (v == null) return true;
        String s = String.valueOf(v).trim();
        return s.isEmpty() || s.equalsIgnoreCase("CHANGE_ME");
    }

    private void copyDefault(Path target) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(FILE_NAME)) {
            if (in == null) {
                throw new IOException("Recurso " + FILE_NAME + " no encontrado en el jar");
            }
            Files.copy(in, target);
        }
    }

    @SuppressWarnings("unchecked")
    private Object resolve(String path) {
        Object current = root;
        for (String part : path.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = ((Map<String, Object>) map).get(part);
        }
        return current;
    }

    public String getString(String path, String def) {
        Object v = resolve(path);
        return v != null ? String.valueOf(v) : def;
    }

    public int getInt(String path, int def) {
        return resolve(path) instanceof Number n ? n.intValue() : def;
    }

    public boolean getBoolean(String path, boolean def) {
        return resolve(path) instanceof Boolean b ? b : def;
    }

    @SuppressWarnings("unchecked")
    public List<Object> getList(String path) {
        return resolve(path) instanceof List<?> list ? (List<Object>) list : Collections.emptyList();
    }

    public void reload() {
        load();
    }

    public boolean setKey(String newKey) {
        String clean = newKey == null ? "" : newKey.trim().replace("\"", "");

        if (clean.chars().anyMatch(c -> c < 0x20 || c == '\\')) {
            logger.warn("License key with invalid characters; not saved.");
            return false;
        }
        Path file = dataDirectory.resolve(FILE_NAME);
        String keyLine = "key: \"" + clean + "\"";
        try {
            Files.createDirectories(dataDirectory);
            List<String> lines = Files.exists(file)
                    ? new java.util.ArrayList<>(Files.readAllLines(file))
                    : new java.util.ArrayList<>();
            boolean replaced = false;
            for (int i = 0; i < lines.size(); i++) {
                String t = lines.get(i).trim();
                if (!t.startsWith("#") && t.startsWith("key:")) {
                    lines.set(i, keyLine);
                    replaced = true;
                    break;
                }
            }
            if (!replaced) lines.add(keyLine);
            Files.write(file, lines);
            load();
            return true;
        } catch (IOException e) {
            logger.error("Couldn't save the key to {}: {}", FILE_NAME, e.getMessage());
            return false;
        }
    }
}
