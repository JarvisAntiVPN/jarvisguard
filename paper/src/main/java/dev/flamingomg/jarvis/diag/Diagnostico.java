package dev.flamingomg.jarvis.diag;

import dev.flamingomg.jarvis.model.ProtectionState;

import java.util.ArrayList;
import java.util.List;

public final class Diagnostico {

    private Diagnostico() {}

    public enum Nivel { OK, NEUTRO, AVISO, FALLO }

    public record Linea(Nivel nivel, String etiqueta, String detalle, String dato) {}

    public record Datos(ProtectionState estado, boolean claveRechazada, boolean vinculado,
                        boolean claveConfigurada,
                        long desfaseRelojMs, boolean canalVivo, int ultimoRechazoSse,
                        String ipPrivadaVista, boolean ipsVistas, long bansLocales,
                        String errorDeConfig) {}

    public static final long DESFASE_AVISO_MS = 30_000L;

    public static List<Linea> revisar(Datos d) {
        List<Linea> out = new ArrayList<>();
        out.add(licencia(d));
        out.add(proteccion(d));
        out.add(reloj(d));
        out.add(canal(d));
        out.add(ipDelJugador(d));
        out.add(new Linea(Nivel.OK, "cmd.diagBans", null, String.valueOf(d.bansLocales())));
        out.add(config(d));
        return out;
    }

    public static Nivel peor(List<Linea> lineas) {
        Nivel peor = Nivel.OK;
        for (Linea l : lineas) {
            if (l.nivel() == Nivel.FALLO) return Nivel.FALLO;
            if (l.nivel() == Nivel.AVISO) peor = Nivel.AVISO;
            if (l.nivel() == Nivel.NEUTRO && peor == Nivel.OK) peor = Nivel.NEUTRO;
        }
        return peor;
    }

    private static Linea config(Datos d) {
        if (d.errorDeConfig() == null) return new Linea(Nivel.OK, "cmd.diagConfig", null, null);
        return new Linea(Nivel.AVISO, "cmd.diagConfig", "cmd.diagConfigStale", null);
    }

    private static Linea licencia(Datos d) {
        if (d.claveRechazada()) return new Linea(Nivel.FALLO, "cmd.diagLicense", "cmd.keyrejected", null);
        if (!d.vinculado()) {
            return new Linea(Nivel.FALLO, "cmd.diagLicense",
                    d.claveConfigurada() ? "cmd.validatefail" : "cmd.notLinked", null);
        }
        return new Linea(Nivel.OK, "cmd.diagLicense", null, null);
    }

    private static Linea proteccion(Datos d) {
        ProtectionState e = d.estado();
        if (e != null && e.isProtecting()) return new Linea(Nivel.OK, "cmd.diagBackend", null, null);
        if (e == ProtectionState.BEHIND_PROXY) {
            return new Linea(Nivel.AVISO, "cmd.diagBackend", "cmd.behindProxy", null);
        }
        if (e == ProtectionState.DEGRADED) return new Linea(Nivel.FALLO, "cmd.diagBackend", "cmd.degradedWhy", null);
        return new Linea(Nivel.FALLO, "cmd.diagBackend", "cmd.unprotected", null);
    }

    private static Linea reloj(Datos d) {
        long abs = Math.abs(d.desfaseRelojMs());
        if (abs < DESFASE_AVISO_MS) {
            boolean medido = abs > 0 || (d.estado() != null && d.estado().isProtecting());
            return new Linea(medido ? Nivel.OK : Nivel.NEUTRO, "cmd.diagClock", null, null);
        }
        return new Linea(Nivel.AVISO, "cmd.diagClock", "cmd.diagClockOff", String.valueOf(d.desfaseRelojMs()));
    }

    private static Linea canal(Datos d) {
        if (!d.vinculado()) return new Linea(Nivel.NEUTRO, "cmd.diagPanel", null, null);
        if (d.canalVivo())  return new Linea(Nivel.OK, "cmd.diagPanel", null, null);
        boolean auth = d.ultimoRechazoSse() == 401 || d.ultimoRechazoSse() == 403;
        return new Linea(Nivel.AVISO, "cmd.diagPanel", auth ? "cmd.diagPanelAuth" : "cmd.diagPanelDown", null);
    }

    private static Linea ipDelJugador(Datos d) {
        String ip = d.ipPrivadaVista();
        if (ip == null) return new Linea(d.ipsVistas() ? Nivel.OK : Nivel.NEUTRO, "cmd.diagIp", null, null);
        return new Linea(Nivel.FALLO, "cmd.diagIp", "cmd.diagIpPrivate", ip);
    }
}
