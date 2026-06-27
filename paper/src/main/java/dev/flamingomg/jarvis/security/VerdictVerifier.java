package dev.flamingomg.jarvis.security;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class VerdictVerifier {

    private static final String PUBLIC_KEY_B64 =
            "MCowBQYDK2VwAyEAZtDClG8nT+9meqN4Ak7bE4PugGzEfKPnGq/iRRt8cos=";

    private static final PublicKey PUB = load();

    private static final ThreadLocal<Signature> ED = ThreadLocal.withInitial(() -> {
        try { return Signature.getInstance("Ed25519"); } catch (Exception e) { return null; }
    });
    private static final ThreadLocal<java.security.MessageDigest> SHA = ThreadLocal.withInitial(() -> {
        try { return java.security.MessageDigest.getInstance("SHA-256"); } catch (Exception e) { return null; }
    });

    private VerdictVerifier() {}

    public static boolean verifyBans(long timestamp, String body, String sigB64) {
        if (PUB == null || sigB64 == null || sigB64.isEmpty()) return false;
        try {
            Signature sig = ED.get();
            if (sig == null) return false;
            sig.initVerify(PUB);
            sig.update(("bans:" + timestamp + ":" + sha256Hex(body)).getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    private static PublicKey load() {
        try {
            byte[] der = Base64.getDecoder().decode(PUBLIC_KEY_B64);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            return null;
        }
    }

    static boolean keyLoaded() {
        return PUB != null;
    }

    public static boolean verify(long timestamp, String verdict, String sigB64) {
        if (PUB == null || sigB64 == null || sigB64.isEmpty()) return false;
        try {
            Signature sig = ED.get();
            if (sig == null) return false;
            sig.initVerify(PUB);
            sig.update((timestamp + ":" + verdict).getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyV4(long timestamp, String verdict, String ip, String username, String sigB64) {
        if (PUB == null || sigB64 == null || sigB64.isEmpty()) return false;
        try {
            String payload = timestamp + ":" + verdict + ":" + (ip == null ? "" : ip)
                    + ":" + (username == null ? "" : username);
            Signature sig = ED.get();
            if (sig == null) return false;
            sig.initVerify(PUB);
            sig.update(payload.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyEvent(String canonical, String sigB64) {
        if (PUB == null || canonical == null || sigB64 == null || sigB64.isEmpty()) return false;
        try {
            Signature sig = ED.get();
            if (sig == null) return false;
            sig.initVerify(PUB);
            sig.update(canonical.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(sigB64));
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyMessage(long timestamp, String verdict, String message, String msgSigB64) {
        if (PUB == null || msgSigB64 == null || msgSigB64.isEmpty()) return false;
        try {
            String payload = timestamp + ":" + verdict + ":" + sha256Hex(message);
            Signature sig = ED.get();
            if (sig == null) return false;
            sig.initVerify(PUB);
            sig.update(payload.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.getDecoder().decode(msgSigB64));
        } catch (Exception e) {
            return false;
        }
    }

    static String sha256Hex(String s) {
        try {
            var md = SHA.get();
            if (md == null) return "";
            md.reset();
            byte[] d = md.digest((s == null ? "" : s).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
