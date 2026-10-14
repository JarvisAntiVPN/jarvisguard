package dev.flamingomg.jarvis.client;

import com.google.gson.Gson;
import dev.flamingomg.jarvis.config.ConfigManager;
import dev.flamingomg.jarvis.util.Log;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

public final class PairingClient {

    private static final Gson GSON = new Gson();

    private final ConfigManager config;
    private final Log logger;
    private final java.util.concurrent.ExecutorService httpExecutor =
            HttpExecutors.daemonHttpExecutor("jarvis-pair");
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(6)).executor(httpExecutor).build();

    public PairingClient(ConfigManager config, Log logger) {
        this.config = config;
        this.logger = logger;
    }

    public void shutdown() {
        HttpExecutors.closeQuietly(http);
        HttpExecutors.shutdownQuietly(httpExecutor);
    }

    private String base() {
        return ConfigManager.DEFAULT_BACKEND_URL;
    }

    public record Start(String deviceCode, String userCode, String verificationUri, int interval, int expiresIn) {}

    static final int VIGENCIA_MIN_SEG = 120;
    static final int VIGENCIA_MAX_SEG = 3600;
    static final int POLL_MIN_SEG = 5;
    static final int POLL_MAX_SEG = 60;

    public static long caducidadMs(long ahoraMs, int expiresInSegundos) {
        int seg = Math.max(VIGENCIA_MIN_SEG, Math.min(VIGENCIA_MAX_SEG, expiresInSegundos));
        return ahoraMs + seg * 1000L;
    }

    public static long intervaloPollMs(int intervalSegundos) {
        return Math.max(POLL_MIN_SEG, Math.min(POLL_MAX_SEG, intervalSegundos)) * 1000L;
    }

    public static long intervaloPollNanos(int intervalSegundos) {
        return intervaloPollMs(intervalSegundos) * 1_000_000L;
    }

    public static boolean tocaSondear(long ahoraNanos, long proximoNanos) {
        return ahoraNanos - (proximoNanos - JITTER_NANOS) >= 0;
    }

    static final long JITTER_NANOS = 500_000_000L;

    public Start start(String host, String server, String connVer) {
        try {
            Map<String, Object> body = new java.util.LinkedHashMap<>();
            if (host != null) body.put("host", host);
            if (server != null) body.put("server", server);
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + "/pair/start"))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json");
            if (connVer != null && !connVer.isBlank()) b.header("X-Connector-Version", connVer);
            HttpResponse<String> r = http.send(
                    b.POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body), StandardCharsets.UTF_8)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return null;
            Map<?, ?> m = GSON.fromJson(r.body(), Map.class);
            if (m == null || m.get("deviceCode") == null) return null;
            return new Start(str(m.get("deviceCode")), str(m.get("userCode")), str(m.get("verificationUri")),
                    num(m.get("interval"), 5), num(m.get("expiresIn"), 600));
        } catch (Exception e) {
            logger.debug("pair/start failed: {}", e.getMessage());
            return null;
        }
    }

    public String[] poll(String deviceCode) {
        try {
            String body = GSON.toJson(Map.of("deviceCode", deviceCode));
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base() + "/pair/poll"))
                            .timeout(Duration.ofSeconds(8)).header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) return new String[]{"error", null, null};
            Map<?, ?> m = GSON.fromJson(r.body(), Map.class);
            return new String[]{m == null ? "error" : str(m.get("status")),
                                m == null ? null : str(m.get("licenseKey")),
                                m == null ? null : str(m.get("locale"))};
        } catch (Exception e) {
            return new String[]{"error", null, null};
        }
    }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }
    private static int num(Object o, int d) { return o instanceof Number n ? n.intValue() : d; }

    public static final class Anteriores {

        static final long RECOGIDA_MS = 180_000L;

        static final int MAX = 2;

        private record Codigo(String deviceCode, long hastaMs) {}

        private final java.util.ArrayDeque<Codigo> codigos = new java.util.ArrayDeque<>();
        private long proximoNanos;
        private boolean conRitmo = false;

        public synchronized void guardar(String deviceCode, long caducaMs, long ahoraMs) {
            if (deviceCode == null || ahoraMs - caducaMs > RECOGIDA_MS) return;
            codigos.removeIf(c -> c.deviceCode().equals(deviceCode));
            codigos.addLast(new Codigo(deviceCode, caducaMs + RECOGIDA_MS));
            while (codigos.size() > MAX) codigos.removeFirst();
        }

        public String sondear(java.util.function.Function<String, String[]> sondeo, long ahoraMs, long ahoraNanos,
                              long intervaloNanos) {
            java.util.List<String> lista;
            synchronized (this) {
                codigos.removeIf(c -> ahoraMs > c.hastaMs());
                if (codigos.isEmpty() || (conRitmo && !tocaSondear(ahoraNanos, proximoNanos))) return null;
                conRitmo = true;
                proximoNanos = ahoraNanos + intervaloNanos;
                lista = codigos.stream().map(Codigo::deviceCode).toList();
            }
            for (String dc : lista) {
                String[] res = sondeo.apply(dc);
                String estado = res == null || res.length == 0 || res[0] == null ? "error" : res[0];
                switch (estado) {
                    case "approved" -> {
                        quitar(dc);
                        if (res.length > 1 && res[1] != null && !res[1].isBlank()) return res[1];
                    }
                    case "denied", "expired" -> quitar(dc);
                    default -> { }
                }
            }
            return null;
        }

        public synchronized void quitar(String deviceCode) {
            codigos.removeIf(c -> c.deviceCode().equals(deviceCode));
        }

        public synchronized void olvidar() {
            codigos.clear();
        }

        public synchronized java.util.List<String> sondeados() {
            return codigos.stream().map(Codigo::deviceCode).toList();
        }
    }
}
