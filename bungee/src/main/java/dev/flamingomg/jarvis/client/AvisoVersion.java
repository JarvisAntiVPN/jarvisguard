package dev.flamingomg.jarvis.client;

import dev.flamingomg.jarvis.i18n.Messages;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AvisoVersion {

    static final int MAX_RECORDADOS = 2_000;

    private final Map<UUID, String> avisados = new ConcurrentHashMap<>();
    private String enConsola = null;

    public static boolean hayNueva(String actual, String ultima) {
        int[] a = tramos(actual), u = tramos(ultima);
        if (a == null || u == null) return false;
        for (int i = 0; i < Math.max(a.length, u.length); i++) {
            int x = i < a.length ? a[i] : 0;
            int y = i < u.length ? u[i] : 0;
            if (x != y) return y > x;
        }
        return false;
    }

    static int[] tramos(String v) {
        if (v == null) return null;
        String[] p = v.trim().split("\\.", -1);
        if (p.length > 4) return null;
        int[] out = new int[p.length];
        for (int i = 0; i < p.length; i++) {
            if (p[i].isEmpty() || p[i].length() > 6) return null;
            for (int j = 0; j < p[i].length(); j++) {
                char c = p[i].charAt(j);
                if (c < '0' || c > '9') return null;
            }
            out[i] = Integer.parseInt(p[i]);
        }
        return out;
    }

    public synchronized boolean tocaConsola(String nueva) {
        if (nueva == null || nueva.equals(enConsola)) return false;
        enConsola = nueva;
        return true;
    }

    public boolean tocaAvisar(UUID jugador, String nueva) {
        if (jugador == null || nueva == null) return false;
        if (avisados.size() >= MAX_RECORDADOS) avisados.clear();
        return !nueva.equals(avisados.put(jugador, nueva));
    }

    public static final String PANEL = AvisoSinVincular.PANEL;

    public static String lineaDeConsola(String locale, String actual, String nueva) {
        return texto(locale, actual, nueva) + " " + Messages.get(locale, "update.download") + " " + PANEL;
    }

    public static List<AvisoSinVincular.Linea> lineas(String localeCliente, String actual, String nueva) {
        String loc = AvisoSinVincular.idiomaDelCliente(localeCliente);
        return List.of(
                new AvisoSinVincular.Linea(AvisoSinVincular.Tono.AMBAR, texto(loc, actual, nueva), null),
                new AvisoSinVincular.Linea(AvisoSinVincular.Tono.GRIS, Messages.get(loc, "update.download"), PANEL));
    }

    private static String texto(String locale, String actual, String nueva) {
        return Messages.get(locale, "update.available")
                .replace("{latest}", nueva)
                .replace("{current}", actual == null ? "?" : actual);
    }
}
