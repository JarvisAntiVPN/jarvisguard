package dev.flamingomg.jarvis.util;

public final class IdiomaJugador {

    private IdiomaJugador() {}

    public static String de(Object jugador) {
        if (jugador == null) return null;
        String moderno = texto(ApiPorVersion.invocar(jugador, "getLocale"));
        if (moderno != null) return moderno;
        return texto(ApiPorVersion.invocar(ApiPorVersion.invocar(jugador, "spigot"), "getLocale"));
    }

    private static String texto(Object v) {
        return (v instanceof String s && !s.isBlank()) ? s : null;
    }
}
