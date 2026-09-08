package dev.flamingomg.jarvis.detection;

public final class IntencionDeConexion {

    private IntencionDeConexion() {}

    public static final String LOGIN = "LOGIN";
    public static final String TRANSFER = "TRANSFER";

    public static String deProtocolo(int solicitado) {
        if (solicitado == 3) return TRANSFER;
        if (solicitado == 2) return LOGIN;
        return null;
    }

    public static String deNombre(String nombre) {
        if (nombre == null) return null;
        String n = nombre.trim().toUpperCase(java.util.Locale.ROOT);
        return n.equals(TRANSFER) ? TRANSFER : n.equals(LOGIN) ? LOGIN : null;
    }

    public static String clave(java.net.InetSocketAddress a) {
        if (a == null || a.getAddress() == null) return null;
        return a.getAddress().getHostAddress() + ":" + a.getPort();
    }
}
