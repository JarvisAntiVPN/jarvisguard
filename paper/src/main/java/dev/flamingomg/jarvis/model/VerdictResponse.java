package dev.flamingomg.jarvis.model;

public record VerdictResponse(
        String verdict,
        String message,
        long timestamp,
        String sig,
        String msgSig
) {
    public VerdictType verdictType() {

        return VerdictType.parse(verdict);
    }
}
