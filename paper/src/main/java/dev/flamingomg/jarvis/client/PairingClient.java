package dev.flamingomg.jarvis.client;

import com.google.gson.Gson;
import dev.flamingomg.jarvis.config.ConfigManager;
import java.util.logging.Logger;

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
    private final Logger logger;

    private final java.util.concurrent.ExecutorService httpExecutor =
            HttpExecutors.daemonHttpExecutor("jarvis-pair");
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(6)).executor(httpExecutor).build();

    public PairingClient(ConfigManager config, Logger logger) {
        this.config = config;
        this.logger = logger;
    }

    private String base() {
        return config.getString("backend.url", ConfigManager.DEFAULT_BACKEND_URL);
    }

    public record Start(String deviceCode, String userCode, String verificationUri, int interval, int expiresIn) {}

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
            logger.fine("[jarvis] pair/start failed: " + e.getMessage());
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
            if (r.statusCode() != 200) return new String[]{"error", null};
            Map<?, ?> m = GSON.fromJson(r.body(), Map.class);
            return new String[]{m == null ? "error" : str(m.get("status")), m == null ? null : str(m.get("licenseKey"))};
        } catch (Exception e) {
            return new String[]{"error", null};
        }
    }

    public void shutdown() {
        HttpExecutors.closeQuietly(http);
        HttpExecutors.shutdownQuietly(httpExecutor);
    }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }
    private static int num(Object o, int d) { return o instanceof Number n ? n.intValue() : d; }
}
