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

    public enum Causa {
        RED("cmd.degradedWhy"),
        LICENCIA("cmd.degradedAuth"),
        LIMITE("cmd.degradedRate"),
        FIRMA("cmd.degradedSig");

        private final String clave;

        Causa(String clave) { this.clave = clave; }

        public String clave() { return clave; }
    }
}
