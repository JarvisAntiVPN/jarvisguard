package dev.flamingomg.jarvis.detection;

import dev.flamingomg.jarvis.model.ProtectionState;

public final class ProtectionWatch {

    static final long VENTANA_MS = 3_600_000L;

    public static final long GRACIA_MS = 300_000L;

    static final long RECUPERACION_MS = 300_000L;

    static final long MAX_MUESTRA_MS = 60_000L;

    private long acumuladoMs = 0L;
    private long inicioEpisodio = 0L;
    private long ultimaMuestra = 0L;
    private long sanoDesde = 0L;
    private long ultimoAviso = 0L;
    private ProtectionState estadoDelEpisodio = null;

    public synchronized String[] lineas(ProtectionState estado, long ahoraMs) {
        long hueco = paso(ahoraMs);

        if (estado == null || estado.isProtecting() || estado == ProtectionState.BEHIND_PROXY) {
            if (inicioEpisodio == 0L) return new String[0];
            if (sanoDesde == 0L) sanoDesde = ahoraMs;
            if (ahoraMs - sanoDesde >= RECUPERACION_MS) olvida();
            return new String[0];
        }

        if (estado != estadoDelEpisodio) {
            olvida();
            estadoDelEpisodio = estado;
            inicioEpisodio = ahoraMs;
            return new String[0];
        }
        sanoDesde = 0L;
        acumuladoMs += hueco;
        if (acumuladoMs < GRACIA_MS) return new String[0];
        if (!reclamaTurno(ahoraMs)) return new String[0];
        long ventana = Math.max(acumuladoMs, ahoraMs - inicioEpisodio);
        return texto(estado, acumuladoMs / 60_000L, ventana / 60_000L);
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
        sanoDesde = 0L;
        ultimoAviso = 0L;
        estadoDelEpisodio = null;
    }

    boolean reclamaTurno(long ahoraMs) {
        if (ultimoAviso != 0L && ahoraMs >= ultimoAviso && ahoraMs - ultimoAviso < VENTANA_MS) return false;
        ultimoAviso = ahoraMs;
        return true;
    }

    private static String[] texto(ProtectionState estado, long minutosSinComprobar, long minutosVentana) {
        String causa, arreglo, segunda;
        if (estado == ProtectionState.NO_KEY) {
            causa   = "  Your license key was rejected or no shared secret could be obtained,";
            arreglo = "  Check the key in config.yml and run /antivpn reload. If it looks right,";
            segunda = "  contact support: until then nobody is being checked.";
        } else {
            causa   = "  The Jarvis backend has not been reachable from this machine,";
            arreglo = "  Check this server's outbound connectivity and DNS. Protection returns on its own";
            segunda = "  as soon as the backend answers again; no action is needed if it was a network blip.";
        }
        return new String[]{
                "",
                "=============== JARVIS · CONNECTIONS ARE NOT BEING CHECKED ===============",
                causa,
                "  so for " + minutosSinComprobar + " of the last " + minutosVentana + " minutes players have been",
                "  let in without being checked. Your server is NOT protected right now.",
                arreglo,
                segunda,
                "=========================================================================",
                ""
        };
    }
}
