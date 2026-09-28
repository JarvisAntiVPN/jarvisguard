package dev.flamingomg.jarvis.sync;

public final class SyncWatch {

    public static boolean canalVivo(boolean corriendo, boolean abierto, long ultimaActividadNanos,
                                    long ahoraNanos, long ventanaMs) {
        if (!corriendo || !abierto || ultimaActividadNanos == 0L) return false;
        return ahoraNanos - ultimaActividadNanos < ventanaMs * 1_000_000L;
    }

    static final long VENTANA_MS = 3_600_000L;

    static final long GRACIA_MS = 600_000L;

    static final long RECUPERACION_MS = 300_000L;

    static final long MAX_MUESTRA_MS = 60_000L;

    private long acumuladoMs = 0L;
    private long inicioEpisodio = 0L;
    private long ultimaMuestra = 0L;
    private long vivoDesde = 0L;
    private long ultimoAviso = 0L;

    public synchronized String[] lineas(boolean vinculado, boolean streamVivo, int ultimoRechazo, long ahoraMs) {
        long hueco = paso(ahoraMs);

        if (!vinculado) { olvida(); return new String[0]; }

        if (streamVivo) {
            if (inicioEpisodio == 0L) return new String[0];
            if (vivoDesde == 0L) vivoDesde = ahoraMs;
            if (ahoraMs - vivoDesde >= RECUPERACION_MS) olvida();
            return new String[0];
        }

        vivoDesde = 0L;
        if (inicioEpisodio == 0L) inicioEpisodio = ahoraMs;
        acumuladoMs += hueco;
        if (acumuladoMs < GRACIA_MS) return new String[0];
        if (!reclamaTurno(ahoraMs)) return new String[0];
        return texto(acumuladoMs / 60_000L, ultimoRechazo);
    }

    private long paso(long ahoraMs) {
        long previa = ultimaMuestra;
        ultimaMuestra = ahoraMs;
        if (previa == 0L || ahoraMs <= previa) return 0L;
        return Math.min(ahoraMs - previa, MAX_MUESTRA_MS);
    }

    private void olvida() {
        acumuladoMs = 0L;
        inicioEpisodio = 0L;
        vivoDesde = 0L;
        ultimoAviso = 0L;
    }

    boolean reclamaTurno(long ahoraMs) {
        if (ultimoAviso != 0L && ahoraMs >= ultimoAviso && ahoraMs - ultimoAviso < VENTANA_MS) return false;
        ultimoAviso = ahoraMs;
        return true;
    }

    private static String[] texto(long minutos, int ultimoRechazo) {
        boolean auth = ultimoRechazo == 401 || ultimoRechazo == 403;
        String causa = auth
                ? "  the Jarvis backend rejected this server's credentials (HTTP " + ultimoRechazo + "),"
                : "  this server has not been able to keep the live channel open,";
        String arreglo = auth
                ? "  Check the license key in config.yml and run /antivpn reload."
                : "  Check this server's outbound connectivity to the backend. It keeps retrying on its own.";
        return new String[]{
                "",
                "=============== JARVIS - THE LIVE PANEL CHANNEL IS DOWN ===============",
                causa,
                "  so for the last " + minutos + " minutes your panel has not been able to reach it:",
                "  new blocks, unblocks, kicks and setting changes are NOT being applied here.",
                "  Players ARE still being checked; this only affects what the panel sends.",
                arreglo,
                "======================================================================",
                ""
        };
    }
}
