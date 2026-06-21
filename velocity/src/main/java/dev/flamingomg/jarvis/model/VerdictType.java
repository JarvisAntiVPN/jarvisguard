package dev.flamingomg.jarvis.model;

public enum VerdictType {
    ALLOW,
    FLAG,

    CHALLENGE,
    BLOCK,

    UNKNOWN;

    public boolean denies() {
        return this == BLOCK;
    }

    public boolean isUnknown() {
        return this == UNKNOWN;
    }

    public static VerdictType parse(String value) {

        if (value == null) return UNKNOWN;
        try {
            return VerdictType.valueOf(value.trim().toUpperCase());
        } catch (Exception e) {
            return UNKNOWN;
        }
    }
}
