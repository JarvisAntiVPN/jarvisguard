package dev.flamingomg.jarvis.util;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LifeCycle;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.SimpleMessage;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ClaveFueraDelLog implements Filter {

    static final String TAPADA = "********";

    private static final String MARCA = " issued server command: /";

    private static final Pattern LINEA = Pattern.compile(
            "^([^\\s<>\\[\\]]+ issued server command: /(?:jarvis:)?(?:antivpn|jarvis|avpn)\\s+key\\s+)\\S.*$",
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.UNICODE_CHARACTER_CLASS | Pattern.DOTALL);

    private final LoggerContext contexto;
    private volatile boolean activo = true;

    private ClaveFueraDelLog(LoggerContext contexto) {
        this.contexto = contexto;
    }

    public static Runnable instalar(ClassLoader delServidor) {
        return instalarEn((LoggerContext) LogManager.getContext(delServidor, false));
    }

    static Runnable instalarEn(LoggerContext contexto) {
        LoggerConfig raiz = contexto.getConfiguration().getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        ClaveFueraDelLog filtro = new ClaveFueraDelLog(contexto);
        raiz.addFilter(filtro);
        return () -> {
            filtro.activo = false;
            raiz.removeFilter(filtro);
        };
    }

    static String tapar(String linea) {
        if (linea == null || linea.indexOf(MARCA) < 0) return null;
        Matcher m = LINEA.matcher(linea);
        if (!m.matches()) return null;
        String tapada = m.group(1) + TAPADA;
        return tapada.equals(linea) ? null : tapada;
    }

    @Override
    public Result filter(LogEvent event) {
        if (!activo || event == null) return Result.NEUTRAL;
        Message mensaje = event.getMessage();
        String tapada = tapar(mensaje == null ? null : mensaje.getFormattedMessage());
        if (tapada == null) return Result.NEUTRAL;
        try {
            String nombre = event.getLoggerName();
            org.apache.logging.log4j.Logger mismo = contexto.getLogger(nombre == null ? "" : nombre);
            Message linea = new SimpleMessage(tapada);
            mismo.log(event.getLevel(), event.getMarker(), linea, event.getThrown());
        } catch (Throwable ignorado) {
        }
        return Result.DENY;
    }

    @Override public Result getOnMismatch() { return Result.NEUTRAL; }
    @Override public Result getOnMatch() { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object... p) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2) {
        return Result.NEUTRAL;
    }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4, Object p5) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4, Object p5, Object p6) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4, Object p5, Object p6, Object p7) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4, Object p5, Object p6, Object p7, Object p8) {
        return Result.NEUTRAL;
    }
    @Override public Result filter(Logger l, Level v, Marker m, String s, Object p0, Object p1, Object p2,
                                   Object p3, Object p4, Object p5, Object p6, Object p7, Object p8, Object p9) {
        return Result.NEUTRAL;
    }
    @Override public Result filter(Logger l, Level v, Marker m, Object o, Throwable t) { return Result.NEUTRAL; }
    @Override public Result filter(Logger l, Level v, Marker m, Message o, Throwable t) { return Result.NEUTRAL; }

    @Override public LifeCycle.State getState() { return LifeCycle.State.STARTED; }
    @Override public void initialize() { }
    @Override public void start() { }
    @Override public void stop() { }
    @Override public boolean isStarted() { return true; }
    @Override public boolean isStopped() { return false; }
}
