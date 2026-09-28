package dev.flamingomg.jarvis.util;

import java.util.logging.Level;
import java.util.logging.Logger;

public final class Log {

    private final Logger jul;

    public Log(Logger jul) {
        this.jul = jul;
    }

    public void debug(String pattern, Object... args) { log(Level.FINE, pattern, args); }

    public void info(String pattern, Object... args) { log(Level.INFO, pattern, args); }

    public void warn(String pattern, Object... args) { log(Level.WARNING, pattern, args); }

    public void error(String pattern, Object... args) { log(Level.SEVERE, pattern, args); }

    private void log(Level level, String pattern, Object... args) {
        if (!jul.isLoggable(level)) return;

        Throwable throwable = null;
        int interpolable = args == null ? 0 : args.length;
        if (interpolable > 0 && args[interpolable - 1] instanceof Throwable t) {
            throwable = t;
            interpolable--;
        }

        String msg = interpolate(pattern, args, interpolable);
        if (throwable != null) {
            jul.log(level, msg, throwable);
        } else {
            jul.log(level, msg);
        }
    }

    private static String interpolate(String pattern, Object[] args, int count) {
        if (pattern == null || count == 0 || pattern.indexOf("{}") < 0) {
            return pattern;
        }
        StringBuilder sb = new StringBuilder(pattern.length() + 16);
        int from = 0;
        int used = 0;
        while (used < count) {
            int at = pattern.indexOf("{}", from);
            if (at < 0) break;
            sb.append(pattern, from, at);
            sb.append(String.valueOf(args[used]));
            used++;
            from = at + 2;
        }
        sb.append(pattern, from, pattern.length());
        return sb.toString();
    }
}
