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

    public java.nio.file.Path dataDirectory() { return dataDirectory; }

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

    public boolean load() {
        return cargar(true);
    }

    private boolean cargar(boolean avisar) {
        boolean existia = false;
        try {
            Files.createDirectories(dataDirectory);
            Path file = dataDirectory.resolve(FILE_NAME);
            existia = Files.exists(file);
            if (Files.notExists(file)) {
                copyDefault(file);
                logger.info("config.yml created at {}", file);
            }
            List<String> avisosConPunto;
            try (InputStream in = Files.newInputStream(file)) {
                Map<String, Object> loaded = new Yaml().load(in);
                if (loaded == null) loaded = new java.util.LinkedHashMap<>();
                avisosConPunto = avisosClavesConPunto(loaded);
                this.root = normalize(loaded);
            }
            rebuildBypassSet();
            warnLegacyKeysOnce();
            if (avisar) for (String linea : avisosConPunto) logger.warn("{}", linea);
            logger.debug("Jarvis client configuration loaded.");
        } catch (IOException | RuntimeException e) {
            String causa = causaSinContenido(e);
            if (e instanceof org.yaml.snakeyaml.error.MarkedYAMLException) {
                logger.error("Couldn't load {} ({}); keeping the settings currently in memory.", FILE_NAME, causa);
            } else {
                logger.error("Couldn't load {}; keeping the settings currently in memory.", FILE_NAME, e);
            }
            this.motivoCargaFallida = existia
                    ? "config.yml exists but couldn't be read: " + causa
                    : "config.yml couldn't be created or read: " + causa;
            return false;
        }
        this.motivoCargaFallida = null;
        return true;
    }

    private volatile String motivoCargaFallida;

    public String motivoCargaFallida() { return motivoCargaFallida; }

    static String causaSinContenido(Exception e) {
        if (e instanceof org.yaml.snakeyaml.error.MarkedYAMLException y) {
            org.yaml.snakeyaml.error.Mark m = y.getProblemMark();
            String donde = m == null ? "" : " (line " + (m.getLine() + 1) + ", column " + (m.getColumn() + 1) + ")";
            return "invalid YAML: " + (y.getProblem() != null ? y.getProblem() : "syntax error") + donde;
        }
        return String.valueOf(e);
    }

    public enum Arranque {
         PROTEGER,
         VINCULAR,
         CONFIG_ILEGIBLE
    }

    public static Arranque arranque(boolean cargaOk, boolean claveEnBlanco) {
        if (!cargaOk) return Arranque.CONFIG_ILEGIBLE;
        return claveEnBlanco ? Arranque.VINCULAR : Arranque.PROTEGER;
    }

    private static final java.util.regex.Pattern NOMBRE_CON_PUNTO =
            java.util.regex.Pattern.compile("[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+");

    static List<String> avisosClavesConPunto(Map<?, ?> raiz) {
        List<String> lineas = new java.util.ArrayList<>();
        for (Object k : raiz.keySet()) {
            if (!(k instanceof String nombre) || !NOMBRE_CON_PUNTO.matcher(nombre).matches()) continue;
            String[] partes = nombre.split("\\.");
            lineas.add("config.yml: \"" + nombre + "\" is ignored: Jarvis only reads a dotted setting written nested, "
                    + (raiz.containsKey(partes[0])
                        ? "inside the \"" + partes[0] + ":\" block you already have:"
                        : "like this:"));
            for (int i = 0; i < partes.length; i++) {
                lineas.add("    " + "  ".repeat(i) + partes[i] + ":" + (i == partes.length - 1 ? " <value>" : ""));
            }
        }
        return lineas;
    }

    private void rebuildBypassSet() {
        java.util.Set<String> set = new java.util.HashSet<>();
        for (Object o : getList("bypass.usernames")) {
            if (o == null) continue;
            String name = o.toString().toLowerCase(java.util.Locale.ROOT).trim();
            if (name.isEmpty()) continue;
            set.add(name);
        }
        this.bypassSet = java.util.Collections.unmodifiableSet(set);
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

        Object efectiva = backend.get("license-key");
        EstadoClave estado = estadoClave(efectiva == null ? null : String.valueOf(efectiva));
        if (estado == EstadoClave.VALIDA) backend.put("license-key", normalizarClave(String.valueOf(efectiva)));
        else if (estado == EstadoClave.MAL_FORMADA) backend.put("license-key", "");
        this.estadoClave = estado;

        backend.put("url", DEFAULT_BACKEND_URL);
        return r;
    }

    private static boolean blankOrDefault(Object v) {
        if (v == null) return true;
        String s = String.valueOf(v).trim();
        return s.isEmpty() || s.equalsIgnoreCase("CHANGE_ME");
    }

    private static final java.util.regex.Pattern CLAVE_32_HEX = java.util.regex.Pattern.compile("[0-9A-Fa-f]{32}");

    public enum EstadoClave {
         VACIA,
         VALIDA,
         MAL_FORMADA
    }

    private volatile EstadoClave estadoClave = EstadoClave.VACIA;

    public EstadoClave estadoClave() { return estadoClave; }

    public static String normalizarClave(String pegado) {
        if (pegado == null) return null;
        String encontrada = null;
        for (String token : limpiarPegado(pegado).trim().split(SEPARADOR)) {
            if (!CLAVE_32_HEX.matcher(token).matches()) continue;
            if (encontrada != null) return null;
            encontrada = token;
        }
        return encontrada == null ? null : encontrada.toUpperCase(java.util.Locale.ROOT);
    }

    public static String claveDeLosArgumentos(String[] args) {
        if (args == null || args.length < 2) return null;
        return normalizarClave(String.join(" ", java.util.Arrays.copyOfRange(args, 1, args.length)));
    }

    public static EstadoClave estadoClave(String pegado) {
        if (pegado == null || blankOrDefault(limpiarPegado(pegado).replaceAll(SEPARADOR, " "))) return EstadoClave.VACIA;
        return normalizarClave(pegado) != null ? EstadoClave.VALIDA : EstadoClave.MAL_FORMADA;
    }

    private static final String SEPARADOR = "[\\s\\p{Z}]+";

    private static String limpiarPegado(String s) {
        return sinComillas(s.replaceAll("\\p{Cf}", ""));
    }

    private static String sinComillas(String s) {
        return s.replaceAll("[\"'`\u201C\u201D\u2018\u2019\u00AB\u00BB<>]", " ");
    }

    private void copyDefault(Path target) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(FILE_NAME)) {
            if (in == null) {
                throw new IOException("Resource " + FILE_NAME + " not found in the jar");
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

    public boolean isSet(String path) {
        return resolve(path) != null;
    }

    @SuppressWarnings("unchecked")
    public List<Object> getList(String path) {
        return resolve(path) instanceof List<?> list ? (List<Object>) list : Collections.emptyList();
    }

    public boolean reload() {
        return load();
    }

    public boolean setKey(String newKey) {
        String clean = newKey == null ? "" : newKey.trim().replace("\"", "");

        if (clean.chars().anyMatch(c -> c < 0x20 || c == '\\')) {
            logger.warn("License key with invalid characters; not saved.");
            return false;
        }
        String normalizada = normalizarClave(clean);
        if (normalizada == null) {
            logger.warn("That is not a license key; not saved.");
            return false;
        }
        clean = normalizada;
        Path file = dataDirectory.resolve(FILE_NAME);
        Path tmp  = dataDirectory.resolve(FILE_NAME + ".tmp");
        String keyLine = "key: \"" + clean + "\"";
        try {
            Files.createDirectories(dataDirectory);
            List<String> lines = Files.exists(file)
                    ? new java.util.ArrayList<>(Files.readAllLines(file))
                    : new java.util.ArrayList<>();
            boolean replaced = false;
            boolean enBackend = false;
            for (int i = 0; i < lines.size(); i++) {
                String raw = lines.get(i);
                String t = raw.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                boolean nivelCero = !Character.isWhitespace(raw.charAt(0));
                if (nivelCero) enBackend = t.startsWith("backend:");
                if (nivelCero && (t.startsWith("key:") || t.startsWith("license-key:"))) {
                    lines.set(i, (t.startsWith("key:") ? "key: \"" : "license-key: \"") + clean + "\"");
                    replaced = true;
                } else if (enBackend && !nivelCero && t.startsWith("license-key:")) {
                    String sangria = raw.substring(0, raw.length() - raw.stripLeading().length());
                    lines.set(i, sangria + "license-key: \"" + clean + "\"");
                    replaced = true;
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
            cargar(false);
            if (!clean.equals(getString("backend.license-key", ""))) {
                logger.warn("The license key was written but it is not the one in use; check {} for a duplicate.",
                        FILE_NAME);
                return false;
            }
            return true;
        } catch (IOException e) {
            try { Files.deleteIfExists(tmp); } catch (IOException ignored) {  }
            logger.error("Couldn't save the key to {}: {}", FILE_NAME, e.getMessage());
            return false;
        }
    }
}
