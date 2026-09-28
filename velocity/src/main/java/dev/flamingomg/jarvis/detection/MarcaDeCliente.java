package dev.flamingomg.jarvis.detection;

public final class MarcaDeCliente {

    private MarcaDeCliente() {}

    public enum Paso {
         MANDAR,
         ESPERAR
    }

    public static final int INTENTOS_POR_DEFECTO = 3;

    public static int intentos(int configurado) {
        return Math.max(1, Math.min(configurado, 10));
    }

    public static Paso paso(String marca, boolean sigueConectado, int intento, int maxIntentos) {
        if (marca != null && !marca.isBlank()) return Paso.MANDAR;
        if (!sigueConectado) return Paso.MANDAR;
        return intento >= maxIntentos ? Paso.MANDAR : Paso.ESPERAR;
    }
}
