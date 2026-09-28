package dev.flamingomg.jarvis.model;

public enum ProtectionState {

    NO_KEY,

    BEHIND_PROXY,

    DEGRADED,

    ACTIVE;

    public static ProtectionState of(boolean canSign, boolean backendHealthy, boolean ipCheckDisabled) {
        if (!canSign) return NO_KEY;
        if (ipCheckDisabled) return BEHIND_PROXY;
        return backendHealthy ? ACTIVE : DEGRADED;
    }

    public boolean isProtecting() {
        return this == ACTIVE;
    }
}
