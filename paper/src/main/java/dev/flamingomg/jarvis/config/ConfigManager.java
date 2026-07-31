package dev.flamingomg.jarvis.config;

import dev.flamingomg.jarvis.util.Log;
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

    public static final String DEFAULT_BACKEND_URL = "https://connector.jarvisguard.com";

    private final Path dataDirectory;
    private final Log logger;
    private volatile Map<String, Object> root = Collections.emptyMap();

    private volatile java.util.Set<String> bypassSet = Collections.emptySet();

    public ConfigManager(Path dataDirectory, Log logger) {
        this.dataDirectory = dataDirectory;
        this.logger = logger;
    }

    private static final String SECRET_CACHE_FILE = ".connector-secret";

    public String readCachedSecret(String forLicenseKey) {
        if (forLicenseKey == null || forLicenseKey.isBlank()) return null;
        try {
            Path f = dataDirectory.resolve(SECRET_CACHE_FILE);
            if (Files.notExists(f)) return null;
            var lines = Files.readAllLines(f);
            if (lines.size() >= 2 && forLicenseKey.equals(lines.get(0).trim())) {
                String s = lines.get(1).trim();
                return s.isBlank() ? null : s;
            }
        } catch (Exception ignore) {}
        return null;
    }

    public void writeCachedSecret(String licenseKey, String secret) {
        if (licenseKey == null || licenseKey.isBlank() || secret == null || secret.isBlank()) return;
        try {
            Files.createDirectories(dataDirectory);
            Path f = dataDirectory.resolve(SECRET_CACHE_FILE);

            if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                java.nio.file.attribute.FileAttribute<?> attr = java.nio.file.attribute.PosixFilePermissions
                        .asFileAttribute(java.util.EnumSet.of(
                                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
                byte[] data = (licenseKey + System.lineSeparator() + secret + System.lineSeparator())
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);

                Files.deleteIfExists(f);
                try (java.nio.channels.SeekableByteChannel ch = Files.newByteChannel(f,
                        java.util.EnumSet.of(java.nio.file.StandardOpenOption.CREATE_NEW,
                                java.nio.file.StandardOpenOption.WRITE), attr)) {
                    ch.write(java.nio.ByteBuffer.wrap(data));
                }
            } else {

                Files.write(f, java.util.List.of(licenseKey, secret));
                try { java.io.File jf = f.toFile(); jf.setReadable(false, false); jf.setReadable(true, true); } catch (Exception ignore) {}
            }
        } catch (Exception ignore) {}
    }

    public void clearCachedSecret() {
        try { Files.deleteIfExists(dataDirectory.resolve(SECRET_CACHE_FILE)); } catch (Exception ignore) {}
    }

    private boolean warnedLegacyKeys = false;

    private void warnLegacyKeysOnce() {
        if (warnedLegacyKeys) return;
        if (resolve("fallback.policy") != null || resolve("unknown.policy") != null) {
            warnedLegacyKeys = true;
            logger.warn("config.yml still has 'fallback.policy'/'unknown.policy'; that option no longer exists. Jarvis always lets players in when the backend is unreachable (fail-open); local bans and the flood limiter still apply.");
        }
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
            rebuildBypassSet();
            warnLegacyKeysOnce();
            logger.debug("Jarvis client configuration loaded.");
        } catch (IOException | RuntimeException e) {

            logger.error("Couldn't load {}; keeping the settings currently in memory.", FILE_NAME, e);
        }
    }

    private void rebuildBypassSet() {
        java.util.Set<String> set = new java.util.HashSet<>();
        for (Object o : getList("bypass.usernames")) {
            if (o == null) continue;
            String u = String.valueOf(o).toLowerCase(java.util.Locale.ROOT).trim();
            if (!u.isEmpty()) set.add(u);
        }
        this.bypassSet = set;
    }

    public java.util.Set<String> bypassUsernames() {
        return bypassSet;
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
        Path tmp  = dataDirectory.resolve(FILE_NAME + ".tmp");
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

            Files.write(tmp, lines);
            try {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException notAtomic) {
                Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            load();
            return true;
        } catch (IOException e) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) {  }
            logger.error("Couldn't save the key to {}: {}", FILE_NAME, e.getMessage());
            return false;
        }
    }
}
