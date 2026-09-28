package dev.flamingomg.jarvis.client;

import dev.flamingomg.jarvis.i18n.Messages;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AvisoSinVincular {

    public static final long MARGEN_MIN_MS = 3 * 60_000L;

    public static final long CADA_MS = 30 * 60_000L;

    static final int MAX_ENLACE = 300;

    static final int MAX_RECORDADOS = 2_000;

    private final Map<UUID, Long> ultimoAviso = new ConcurrentHashMap<>();

    public static boolean enlaceUtil(String enlace, long caducaMs, long ahoraMs) {
        if (enlace == null || enlace.length() > MAX_ENLACE || !enlace.startsWith("https://")) return false;
        for (int i = 0; i < enlace.length(); i++) {
            char c = enlace.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c)) return false;
        }
        return caducaMs - ahoraMs >= MARGEN_MIN_MS;
    }

    public boolean tocaAvisar(UUID jugador, long ahoraMs) {
        if (jugador == null) return false;
        if (ultimoAviso.size() >= MAX_RECORDADOS) ultimoAviso.clear();
        boolean[] toca = {false};
        ultimoAviso.compute(jugador, (k, antes) -> {
            if (antes != null && ahoraMs - antes < CADA_MS) return antes;
            toca[0] = true;
            return ahoraMs;
        });
        return toca[0];
    }

    public enum Contenido { NADA, SIN_ENLACE, CON_ENLACE }

    public static Contenido queEnsenar(boolean sesionAutenticada, boolean detrasDeProxy) {
        if (detrasDeProxy) return Contenido.NADA;
        return sesionAutenticada ? Contenido.CON_ENLACE : Contenido.SIN_ENLACE;
    }

    public void olvidarTodo() {
        ultimoAviso.clear();
    }

    public static String idiomaDelCliente(String localeCliente) {
        return localeCliente == null ? null : localeCliente.replace('_', '-');
    }

    public static List<String> lineas(String localeCliente) {
        String loc = idiomaDelCliente(localeCliente);
        return List.of(
                Messages.get(loc, "log.link.notLinked"),
                Messages.get(loc, "log.link.open"),
                Messages.get(loc, "log.link.manual"));
    }
}
