package dev.flamingomg.jarvis.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

public final class AvisoMismaConexion {

    static final int MAX_NOMBRES = 5;

    static final Duration RECUERDO = Duration.ofHours(12);

    private final Cache<String, Boolean> avisadas = Caffeine.newBuilder()
            .maximumSize(20_000)
            .expireAfterWrite(RECUERDO)
            .build();

    public List<String> aQuienNombrar(String nuevo, Collection<String> yaDentro, Predicate<String> callar) {
        if (nuevo == null || nuevo.isBlank() || yaDentro == null || yaDentro.isEmpty()) return List.of();
        if (callar != null && callar.test(nuevo)) return List.of();
        String yo = nuevo.toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        Set<String> vistos = new HashSet<>();
        for (String otro : yaDentro) {
            if (otro == null || otro.isBlank()) continue;
            String l = otro.toLowerCase(Locale.ROOT);
            if (l.equals(yo) || !vistos.add(l)) continue;
            if (callar != null && callar.test(otro)) continue;
            if (avisadas.asMap().putIfAbsent(pareja(yo, l), Boolean.TRUE) != null) continue;
            out.add(otro);
        }
        out.sort(String.CASE_INSENSITIVE_ORDER);
        return out;
    }

    static String pareja(String a, String b) {
        return a.compareTo(b) <= 0 ? a + "|" + b : b + "|" + a;
    }

    public static String texto(String plantilla, String nuevo, List<String> otros, UnaryOperator<String> escapar) {
        if (plantilla == null || otros == null || otros.isEmpty()) return "";
        StringBuilder lista = new StringBuilder();
        for (int i = 0; i < otros.size() && i < MAX_NOMBRES; i++) {
            if (i > 0) lista.append(", ");
            lista.append(escapar.apply(otros.get(i)));
        }
        if (otros.size() > MAX_NOMBRES) lista.append(" (+").append(otros.size() - MAX_NOMBRES).append(')');
        return plantilla.replace("{name}", escapar.apply(nuevo == null ? "?" : nuevo))
                        .replace("{others}", lista.toString());
    }
}
