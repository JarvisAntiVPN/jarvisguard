package dev.flamingomg.jarvis.detection;

import dev.flamingomg.jarvis.util.Log;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;

public final class BanSnapshot {

    static final String FICHERO = "bans.snapshot";

    static final long CADUCIDAD_MS = 7L * 24 * 60 * 60 * 1000L;

    static final long VIDA_MAX_MS = 24L * 60 * 60 * 1000L;

    static final int MAX_ENTRADAS = 20_000;

    private final Path fichero;
    private final Log logger;

    private volatile String sal = null;

    private volatile String deLaLicencia = "";

    private volatile java.util.Map<String, Long> enFrio = java.util.Map.of();

    private volatile boolean vigente = false;

    private volatile boolean avisado = false;

    private volatile long cargadoEnMs = 0L;

    private volatile long selloFicheroMs = 0L;

    public BanSnapshot(Path dataDirectory, Log logger) {
        this.fichero = dataDirectory.resolve(FICHERO);
        this.logger = logger;
    }

    public synchronized void cargar(String licencia, long ahoraMs) {
        try {
            if (Files.notExists(fichero)) return;
            List<String> lineas = Files.readAllLines(fichero, StandardCharsets.UTF_8);
            if (lineas.size() < 4 || !"v3".equals(lineas.get(0).trim())) return;
            String deQuien = lineas.get(1).trim();
            String salLeida = lineas.get(2).trim();
            long escrito = Long.parseLong(lineas.get(3).trim());

            if (salLeida.isEmpty() || Math.abs(ahoraMs - escrito) > CADUCIDAD_MS
                    || !deQuien.equals(licenciaDe(licencia))) {
                Files.deleteIfExists(fichero);
                return;
            }

            java.util.Map<String, Long> h = new java.util.HashMap<>();
            int vencidos = 0;
            for (int i = 4; i < lineas.size(); i++) {
                String l = lineas.get(i).trim();
                if (l.isEmpty()) continue;
                int sep = l.indexOf('|');
                if (sep <= 0) continue;
                long expira;
                try {
                    expira = Long.parseLong(l.substring(sep + 1));
                } catch (NumberFormatException mal) { continue; }
                if (expira <= ahoraMs) { vencidos++; continue; }
                h.put(l.substring(0, sep), expira);
            }
            if (vencidos > 0) logger.debug("[bans] {} expired blocks skipped from the snapshot.", vencidos);
            this.sal = salLeida;
            this.deLaLicencia = deQuien;
            this.enFrio = java.util.Map.copyOf(h);
            this.cargadoEnMs = ahoraMs;
            this.selloFicheroMs = escrito;
            this.vigente = !h.isEmpty();

            logger.debug("[bans] {} blocks loaded from the last sync.", h.size());
        } catch (Exception e) {
            logger.debug("[bans] snapshot unreadable: {}", e.toString());
        }
    }

    public boolean cubre(String claveIp, String licencia) {
        return cubre(claveIp, licencia, System.currentTimeMillis());
    }

    boolean cubre(String claveIp, String licencia, long ahoraMs) {
        if (!vigente || claveIp == null) return false;

        if (cargadoEnMs != 0L && Math.abs(ahoraMs - cargadoEnMs) > VIDA_MAX_MS) return false;
        String s = sal;
        if (s == null || !licenciaDe(licencia).equals(deLaLicencia)) return false;
        Long expira = enFrio.get(hash(s, claveIp));

        if (expira == null || expira <= ahoraMs) return false;

        if (!avisado) {
            avisado = true;
            logger.warn("Jarvis: the backend has not answered yet, so blocks from the last sync are being "
                    + "applied. They stop applying as soon as it does.");
        }
        return true;
    }

    public synchronized void olvidar(String claveIp) {
        if (claveIp != null) olvidar(java.util.List.of(claveIp));
    }

    public synchronized void olvidar(java.util.Collection<String> clavesIp) {
        if (clavesIp == null || clavesIp.isEmpty()) return;
        String s = sal;
        if (s == null) return;
        java.util.Map<String, Long> copia = new java.util.HashMap<>(enFrio);
        boolean alguno = false;
        for (String claveIp : clavesIp) {
            if (claveIp != null && copia.remove(hash(s, claveIp)) != null) alguno = true;
        }
        if (alguno) {
            enFrio = java.util.Map.copyOf(copia);
            if (copia.isEmpty()) vigente = false;
            reescribir();
        }
    }

    public int vigentes(String licencia) {
        return vigentes(licencia, System.currentTimeMillis());
    }

    int vigentes(String licencia, long ahora) {

        if (!vigente || sal == null || !licenciaDe(licencia).equals(deLaLicencia)) return 0;
        if (cargadoEnMs != 0L && Math.abs(ahora - cargadoEnMs) > VIDA_MAX_MS) return 0;
        int n = 0;
        for (Long e : enFrio.values()) if (e != null && e > ahora) n++;
        return n;
    }

    boolean yaAvisado() { return avisado; }

    private void reescribir() {
        String s = sal;
        if (s == null) return;
        StringBuilder sb = new StringBuilder(96 + enFrio.size() * 40);
        sb.append("v3\n").append(deLaLicencia).append('\n').append(s).append('\n')
          .append(selloFicheroMs != 0L ? selloFicheroMs : System.currentTimeMillis()).append('\n');
        for (java.util.Map.Entry<String, Long> e : enFrio.entrySet()) {
            sb.append(e.getKey()).append('|').append(e.getValue()).append('\n');
        }
        try {
            escribir0600(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {

            logger.debug("[bans] could not rewrite the snapshot after an unban: {}", ex.toString());
        }
    }

    public synchronized void descartar() {
        vigente = false;
        avisado = false;
        cargadoEnMs = 0L;

    }

    public synchronized void guardar(String licencia, java.util.Map<String, Long> porClave, long ahoraMs) {
        try {
            String s = sal;
            if (s == null) { s = nuevaSal(); sal = s; }
            String duenyo = licenciaDe(licencia);
            StringBuilder sb = new StringBuilder(96 + porClave.size() * 40);
            sb.append("v3\n").append(duenyo).append('\n').append(s).append('\n').append(ahoraMs).append('\n');
            int n = 0;
            int elegibles = 0;
            java.util.Map<String, Long> escritos = new java.util.HashMap<>();
            for (java.util.Map.Entry<String, Long> e : porClave.entrySet()) {
                String ip = e.getKey();
                if (ip == null || ip.isEmpty()) continue;
                long expira = e.getValue() == null ? 0L : e.getValue();
                if (expira <= ahoraMs) continue;
                elegibles++;
                if (n >= MAX_ENTRADAS) continue;
                String clave = hash(s, ip);
                sb.append(clave).append('|').append(expira).append('\n');
                escritos.put(clave, expira);
                n++;
            }
            if (n < elegibles) {
                logger.warn("[bans] snapshot capped at {} of {} entries; the rest are not covered while offline.",
                        n, elegibles);
            }
            escribir0600(sb.toString().getBytes(StandardCharsets.UTF_8));

            enFrio = java.util.Map.copyOf(escritos);
            selloFicheroMs = ahoraMs;

            deLaLicencia = duenyo;
        } catch (Exception e) {
            logger.debug("[bans] could not write snapshot: {}", e.toString());
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
            catch (Exception ignore) {  }
        }

        try {
            Files.move(tmp, fichero, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException noAtomico) {
            Files.move(tmp, fichero, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    static String hash(String sal, String claveIp) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((sal + "|" + claveIp).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(24);
            for (int i = 0; i < 12; i++) sb.append(Character.forDigit((d[i] >> 4) & 0xF, 16))
                                          .append(Character.forDigit(d[i] & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String licenciaDe(String licencia) {
        if (licencia == null) return "";
        return licencia.trim().replace("\n", "").replace("\r", "");
    }

    private static String nuevaSal() {
        byte[] b = new byte[16];
        new java.security.SecureRandom().nextBytes(b);
        StringBuilder sb = new StringBuilder(32);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        return sb.toString();
    }
}
