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

    public static boolean tocaCodigoNuevo(String deviceCode, long caducaMs, long ahoraMs) {
        return deviceCode == null || caducaMs - ahoraMs < MARGEN_MIN_MS;
    }

    public static boolean enlaceParaElComando(String enlace, long caducaMs, long ahoraMs, boolean recienPedido) {
        if (!recienPedido) return enlaceUtil(enlace, caducaMs, ahoraMs);
        return enlaceUtil(enlace, Long.MAX_VALUE, ahoraMs) && ahoraMs < caducaMs;
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

    public static final String PANEL = "https://jarvisguard.com/panel";

    public enum Tono { ROJO, AMBAR, GRIS }

    public record Linea(Tono tono, String texto, String enlace) {}

    public static List<Linea> lineas(String localeCliente, Contenido que, String enlaceDelCodigo) {
        String loc = idiomaDelCliente(localeCliente);
        Linea queNoProtege = new Linea(Tono.ROJO, Messages.get(loc, "log.link.notLinked"), null);
        return switch (que) {
            case CON_ENLACE -> List.of(queNoProtege,
                    new Linea(Tono.AMBAR, Messages.get(loc, "log.link.open"), enlaceDelCodigo),
                    new Linea(Tono.GRIS, Messages.get(loc, "log.link.manual"), null));
            case SIN_ENLACE -> List.of(queNoProtege,
                    new Linea(Tono.AMBAR, Messages.get(loc, "chat.link.console"), null),
                    new Linea(Tono.GRIS, Messages.get(loc, "chat.link.panel"), PANEL));
            case NADA -> List.of();
        };
    }

    public enum Vinculacion {
        VINCULADO,
        PROXY,
        PARADA,
        FALLIDA,
        CON_ENLACE
    }

    public static Vinculacion vinculacion(boolean claveConfigurada, boolean enMarcha, boolean hayEnlace) {
        return vinculacion(claveConfigurada, false, enMarcha, hayEnlace);
    }

    public static Vinculacion vinculacion(boolean claveConfigurada, boolean detrasDeProxy, boolean enMarcha,
                                          boolean hayEnlace) {
        if (claveConfigurada) return Vinculacion.VINCULADO;
        if (detrasDeProxy) return Vinculacion.PROXY;
        if (!enMarcha) return Vinculacion.PARADA;
        return hayEnlace ? Vinculacion.CON_ENLACE : Vinculacion.FALLIDA;
    }

    static final List<String> EJEMPLO_SIN_PROXY = List.of("    server:", "      behind-proxy: false");

    public static List<Linea> lineasDetrasDeProxy(String localeCliente) {
        String loc = idiomaDelCliente(localeCliente);
        List<Linea> l = new java.util.ArrayList<>(List.of(
                new Linea(Tono.AMBAR, Messages.get(loc, "log.link.proxy"), null),
                new Linea(Tono.GRIS, Messages.get(loc, "log.link.proxyDirect"), null)));
        for (String y : EJEMPLO_SIN_PROXY) l.add(new Linea(Tono.GRIS, y, null));
        return List.copyOf(l);
    }

    @FunctionalInterface
    public interface LineasDeLink<J> {
        List<Linea> de(J quien, String idiomaDelCliente, boolean consola);
    }

    public static final long ESPERA_TURNO_MS = 16_000L;

    public static boolean esperarTurno(java.util.concurrent.atomic.AtomicBoolean cerrojo, long maxMs) {
        long fin = System.nanoTime() + maxMs * 1_000_000L;
        while (!cerrojo.compareAndSet(false, true)) {
            if (System.nanoTime() - fin >= 0) return false;
            try {
                Thread.sleep(50L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return true;
    }

    public static List<Linea> respuestaDeLink(String localeCliente, Vinculacion v, Contenido que, String enlace,
                                              boolean errorDeConfig) {
        String loc = idiomaDelCliente(localeCliente);
        if (v == Vinculacion.VINCULADO) {
            return List.of(new Linea(Tono.AMBAR, Messages.get(loc, "cmd.linkAlready"), null));
        }
        if (v == Vinculacion.PROXY || que == Contenido.NADA) return lineasDetrasDeProxy(localeCliente);
        if (v == Vinculacion.CON_ENLACE && (enlace != null || que == Contenido.SIN_ENLACE)) {
            return lineas(localeCliente, que, enlace);
        }
        Linea queNoProtege = new Linea(Tono.ROJO, Messages.get(loc, "log.link.notLinked"), null);
        if (v == Vinculacion.PARADA && errorDeConfig) {
            return List.of(queNoProtege, new Linea(Tono.AMBAR,
                    Messages.get(loc, "cmd.diagConfig") + ": " + Messages.get(loc, "cmd.diagConfigStale"), null));
        }
        return List.of(queNoProtege, new Linea(Tono.AMBAR, Messages.get(loc, "cmd.linkPending"), null));
    }
}
