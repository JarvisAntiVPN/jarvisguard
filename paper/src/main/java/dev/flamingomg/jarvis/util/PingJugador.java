package dev.flamingomg.jarvis.util;

public final class PingJugador {

    private PingJugador() {}

    public static int de(Object jugador) {
        Object v = ApiPorVersion.invocar(jugador, "getPing");
        if (!(v instanceof Integer)) v = ApiPorVersion.invocar(ApiPorVersion.invocar(jugador, "spigot"), "getPing");
        return (v instanceof Integer i) ? i : -1;
    }
}
