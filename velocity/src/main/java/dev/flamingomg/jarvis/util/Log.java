package dev.flamingomg.jarvis.util;

import org.slf4j.Logger;

public final class Log {

    private final Logger slf4j;

    public Log(Logger slf4j) {
        this.slf4j = slf4j;
    }

    public void debug(String pattern, Object... args) {
        slf4j.debug(pattern, args);
    }

    public void info(String pattern, Object... args) {
        slf4j.info(pattern, args);
    }

    public void warn(String pattern, Object... args) {
        slf4j.warn(pattern, args);
    }

    public void error(String pattern, Object... args) {
        slf4j.error(pattern, args);
    }
}
