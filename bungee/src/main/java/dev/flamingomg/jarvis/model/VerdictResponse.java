package dev.flamingomg.jarvis.model;

public record VerdictResponse(
        String verdict,
        String message,
        long timestamp,
        String sig,
        String msgSig,

        String msgKey,

        Boolean cacheIp
) {
    public VerdictType verdictType() {

        return VerdictType.parse(verdict);
    }

    public VerdictResponse sinMensaje() {
        return new VerdictResponse(verdict, null, timestamp, sig, msgSig, msgKey, cacheIp);
    }
}
