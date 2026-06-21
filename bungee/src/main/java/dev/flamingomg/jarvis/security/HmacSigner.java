package dev.flamingomg.jarvis.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class HmacSigner {

    private final String sharedSecret;

    public HmacSigner(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean hasSecret() {
        return sharedSecret != null && !sharedSecret.isBlank();
    }

    public String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 no disponible", e);
        }
    }

    public static String requestPayload(long timestamp, String ip, String username) {
        return timestamp + ":" + ip + ":" + (username == null ? "" : username);
    }
}
