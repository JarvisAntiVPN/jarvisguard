package dev.flamingomg.jarvis.util;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class ApiPorVersion {

    private ApiPorVersion() {}

    private static final Map<Class<?>, Map<String, Optional<Method>>> CACHE = new ConcurrentHashMap<>();

    public static Object invocar(Object o, String metodo) {
        if (o == null) return null;
        Method m = buscar(o.getClass(), metodo);
        if (m == null) return null;
        try {
            return m.invoke(o);
        } catch (Throwable e) {
            return null;
        }
    }

    static Method buscar(Class<?> tipo, String metodo) {
        return CACHE.computeIfAbsent(tipo, k -> new ConcurrentHashMap<>())
                .computeIfAbsent(metodo, k -> Optional.ofNullable(buscarSinCache(tipo, metodo)))
                .orElse(null);
    }

    private static Method buscarSinCache(Class<?> tipo, String metodo) {
        ArrayDeque<Class<?>> pendientes = new ArrayDeque<>();
        Set<Class<?>> vistos = new HashSet<>();
        pendientes.add(tipo);
        while (!pendientes.isEmpty()) {
            Class<?> c = pendientes.poll();
            if (!vistos.add(c)) continue;
            try {
                Method m = c.getMethod(metodo);
                if (Modifier.isPublic(m.getDeclaringClass().getModifiers())) return m;
            } catch (NoSuchMethodException e) {
            } catch (Throwable e) {
                return null;
            }
            if (c.getSuperclass() != null) pendientes.add(c.getSuperclass());
            pendientes.addAll(List.of(c.getInterfaces()));
        }
        return null;
    }
}
