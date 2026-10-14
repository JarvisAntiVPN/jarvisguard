package dev.flamingomg.jarvis.detection;

import dev.flamingomg.jarvis.util.Log;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

public final class RecuerdoBypass {

    static final String FICHERO = "bypass.snapshot";
    static final String CABECERA = "b1";

    static final long CADUCIDAD_MS = 7L * 24 * 60 * 60 * 1000L;
    private static final long CADUCIDAD_NANOS = CADUCIDAD_MS * 1_000_000L;

    static final int MAX_ENTRADAS = 10_000;

    static final long MAX_BYTES = 1_048_576L;

    static final long FUTURO_MAX_MS = 60_000L;

    private static final java.util.regex.Pattern HEX32 = java.util.regex.Pattern.compile("[0-9a-f]{32}");

    private final Path fichero;
    private final Log logger;
    private final LongSupplier relojMs;
    private final LongSupplier relojNanos;
    private final Executor escritor;
    private final String sal;

    private final Map<String, Long> accesos = new ConcurrentHashMap<>();

    private final AtomicBoolean escrituraEnCola = new AtomicBoolean(false);
    private final AtomicLong cambios = new AtomicLong(0L);
    private final Object cerrojoFichero = new Object();
    private long cambiosEscritos = 0L;
    private volatile boolean cerrado = false;
    private boolean descartadoAlCargar = false;

    public RecuerdoBypass(Path dataDirectory, Log logger) {
        this(dataDirectory, logger, System::currentTimeMillis, System::nanoTime, escritorPropio());
    }

    RecuerdoBypass(Path dataDirectory, Log logger, LongSupplier relojMs, LongSupplier relojNanos, Executor escritor) {
        this.fichero = dataDirectory == null ? null : dataDirectory.resolve(FICHERO);
        this.logger = logger;
        this.relojMs = relojMs;
        this.relojNanos = relojNanos;
        this.escritor = escritor;
        this.sal = cargar();
        if (descartadoAlCargar) programarEscritura();
    }

    public boolean alEntrar(String nombre, Supplier<Boolean> permisoAhora) {
        if (nombre == null) return false;
        String h = hash(nombre);
        if (!vigente(h)) return false;
        if (permisoAhora == null) return true;
        Boolean ahora;
        try {
            ahora = permisoAhora.get();
        } catch (Throwable t) {
            ahora = null;
        }
        if (ahora == null || ahora) return true;
        if (accesos.remove(h) != null) programarEscritura();
        return false;
    }

    public void recordar(String nombre) {
        if (nombre == null) return;
        accesos.put(hash(nombre), relojNanos.getAsLong());
        if (accesos.size() > MAX_ENTRADAS) recortar();
        programarEscritura();
    }

    public void olvidar(String nombre) {
        if (nombre == null) return;
        if (accesos.remove(hash(nombre)) != null) programarEscritura();
    }

    public void cerrar() {
        escribirAhora(true);
    }

    int tamano() {
        return accesos.size();
    }

    private boolean vigente(String h) {
        long ahora = relojNanos.getAsLong();
        boolean[] vivo = {false};
        accesos.computeIfPresent(h, (k, ultimo) -> {
            if (ahora - ultimo >= CADUCIDAD_NANOS) return null;
            vivo[0] = true;
            return ahora;
        });
        if (vivo[0]) programarEscritura();
        return vivo[0];
    }

    private void recortar() {
        long ahora = relojNanos.getAsLong();
        accesos.entrySet().removeIf(e -> ahora - e.getValue() >= CADUCIDAD_NANOS);
        while (accesos.size() > MAX_ENTRADAS) {
            String masViejo = null;
            long minimo = Long.MAX_VALUE;
            for (Map.Entry<String, Long> e : accesos.entrySet()) {
                if (e.getValue() < minimo) { minimo = e.getValue(); masViejo = e.getKey(); }
            }
            if (masViejo == null) break;
            accesos.remove(masViejo);
        }
    }

    private void programarEscritura() {
        cambios.incrementAndGet();
        if (fichero == null || cerrado) return;
        if (!escrituraEnCola.compareAndSet(false, true)) return;
        try {
            escritor.execute(() -> {
                escrituraEnCola.set(false);
                escribirAhora(false);
            });
        } catch (RuntimeException rechazada) {
            escrituraEnCola.set(false);
        }
    }

    private void escribirAhora(boolean alCerrar) {
        if (fichero == null) return;
        synchronized (cerrojoFichero) {
            if (cerrado && !alCerrar) return;
            if (alCerrar) cerrado = true;
            long version = cambios.get();
            if (version == cambiosEscritos) return;
            long nanos = relojNanos.getAsLong();
            long pared = relojMs.getAsLong();
            StringBuilder sb = new StringBuilder(64 + accesos.size() * 48);
            sb.append(CABECERA).append('\n').append(sal).append('\n');
            for (Map.Entry<String, Long> e : accesos.entrySet()) {
                long edadNanos = nanos - e.getValue();
                if (edadNanos >= CADUCIDAD_NANOS) continue;
                long ultimoMs = pared - Math.max(0L, edadNanos) / 1_000_000L;
                sb.append(e.getKey()).append('|').append(ultimoMs).append('\n');
            }
            try {
                escribir0600(sb.toString().getBytes(StandardCharsets.UTF_8));
                cambiosEscritos = version;
            } catch (Exception ex) {
                logger.debug("[bypass] could not write the snapshot: {}", ex.toString());
            }
        }
    }

    private String cargar() {
        if (fichero == null) return nuevaSal();
        try {
            if (Files.notExists(fichero)) return nuevaSal();
            if (Files.size(fichero) > MAX_BYTES) {
                logger.debug("[bypass] snapshot too large, ignored.");
                return nuevaSal();
            }
            List<String> lineas = Files.readAllLines(fichero, StandardCharsets.UTF_8);
            if (lineas.size() < 2 || !CABECERA.equals(lineas.get(0).trim())) return ignorado("unknown format");
            String salLeida = lineas.get(1).trim();
            if (!HEX32.matcher(salLeida).matches()) return ignorado("bad salt");
            long pared = relojMs.getAsLong();
            long nanos = relojNanos.getAsLong();
            Map<String, Long> leidas = new java.util.HashMap<>();
            boolean delFuturo = false;
            for (int i = 2; i < lineas.size(); i++) {
                String l = lineas.get(i).trim();
                if (l.isEmpty()) continue;
                int sep = l.indexOf('|');
                if (sep <= 0) return ignorado("bad line");
                String h = l.substring(0, sep);
                long ultimoMs;
                try {
                    ultimoMs = Long.parseLong(l.substring(sep + 1));
                } catch (NumberFormatException mal) {
                    return ignorado("bad line");
                }
                if (!HEX32.matcher(h).matches()) return ignorado("bad line");
                if (ultimoMs > pared + FUTURO_MAX_MS) {
                    delFuturo = true;
                    continue;
                }
                long edadMs = Math.abs(pared - ultimoMs);
                if (edadMs >= CADUCIDAD_MS) continue;
                leidas.merge(h, nanos - edadMs * 1_000_000L, Math::max);
            }
            if (leidas.size() > MAX_ENTRADAS) return ignorado("too many entries");
            accesos.putAll(leidas);
            descartadoAlCargar = delFuturo;
            logger.debug("[bypass] {} names loaded from the last run.", leidas.size());
            return salLeida;
        } catch (Exception e) {
            accesos.clear();
            logger.debug("[bypass] snapshot unreadable: {}", e.toString());
            return nuevaSal();
        }
    }

    private String ignorado(String motivo) {
        accesos.clear();
        logger.debug("[bypass] snapshot ignored ({}).", motivo);
        return nuevaSal();
    }

    String hash(String nombre) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((sal + "|" + nombre.toLowerCase(java.util.Locale.ROOT))
                    .getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(32);
            for (int i = 0; i < 16; i++) sb.append(Character.forDigit((d[i] >> 4) & 0xF, 16))
                                          .append(Character.forDigit(d[i] & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private void escribir0600(byte[] datos) throws Exception {
        Path tmp = fichero.resolveSibling(FICHERO + ".tmp");
        Files.createDirectories(fichero.getParent());
        Files.deleteIfExists(tmp);
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            java.nio.file.attribute.FileAttribute<?> attr = java.nio.file.attribute.PosixFilePermissions
                    .asFileAttribute(java.util.EnumSet.of(
                            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            try (java.nio.channels.SeekableByteChannel ch = Files.newByteChannel(tmp,
                    java.util.EnumSet.of(java.nio.file.StandardOpenOption.CREATE_NEW,
                            java.nio.file.StandardOpenOption.WRITE), attr)) {
                ch.write(java.nio.ByteBuffer.wrap(datos));
            }
        } else {
            Files.write(tmp, datos);
            try { java.io.File jf = tmp.toFile(); jf.setReadable(false, false); jf.setReadable(true, true); }
            catch (Exception ignore) { }
        }
        try {
            Files.move(tmp, fichero, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException noAtomico) {
            Files.move(tmp, fichero, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String nuevaSal() {
        byte[] b = new byte[16];
        new java.security.SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }

    private static Executor escritorPropio() {
        java.util.concurrent.ThreadPoolExecutor ex = new java.util.concurrent.ThreadPoolExecutor(1, 1,
                5L, java.util.concurrent.TimeUnit.SECONDS, new java.util.concurrent.LinkedBlockingQueue<>(), r -> {
                    Thread t = new Thread(r, "Jarvis-bypass-snapshot");
                    t.setDaemon(true);
                    return t;
                });
        ex.allowCoreThreadTimeOut(true);
        return ex;
    }
}
