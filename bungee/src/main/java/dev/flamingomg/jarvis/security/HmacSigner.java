package dev.flamingomg.jarvis.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class HmacSigner {

    private final String sharedSecret;

    private final SecretKeySpec key;

    private final ThreadLocal<Mac> macTL;

    public HmacSigner(String sharedSecret) {
        this.sharedSecret = sharedSecret;
        final SecretKeySpec k = (sharedSecret == null || sharedSecret.isEmpty())
                ? null
                : new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        this.key = k;
        this.macTL = ThreadLocal.withInitial(() -> {
            try {
                if (k == null) return null;
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(k);
                return m;
            } catch (Exception e) {
                return null;
            }
        });
    }

    public boolean hasSecret() {
        return sharedSecret != null && !sharedSecret.isBlank();
    }

    public String sign(String payload) {
        try {
            Mac mac = macTL.get();
            if (mac == null) throw new IllegalStateException("HmacSHA256 no disponible");
            return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 no disponible", e);
        }
    }

    public static String requestPayload(long timestamp, String ip, String username) {
        return timestamp + ":" + ip + ":" + (username == null ? "" : username);
    }
}
