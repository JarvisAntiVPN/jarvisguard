package dev.flamingomg.jarvis.i18n;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class Messages {
    private Messages() {}

    public static final String DEFAULT = "en";
    private static final Set<String> SUPPORTED = Set.of("en", "es", "de", "fr", "pl", "ru", "tr", "pt", "it", "cs", "id", "vi", "th", "ro", "ja", "zh", "zh-hant");
    private static final Map<String, Map<String, String>> CAT = new HashMap<>();
    private static final Gson GSON = new Gson();

    static {
        for (String loc : SUPPORTED) CAT.put(loc, load(loc));
    }

    private static Map<String, String> load(String loc) {
        Map<String, String> m = new HashMap<>();
        try (InputStream in = Messages.class.getResourceAsStream("/messages-i18n/" + loc + ".json")) {
            if (in != null) {
                JsonObject o = GSON.fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), JsonObject.class);
                if (o != null) for (Map.Entry<String, com.google.gson.JsonElement> e : o.entrySet()) m.put(e.getKey(), e.getValue().getAsString());
            }
        } catch (Exception ignored) {

        }
        return m;
    }

    public static String normalize(String locale) {
        if (locale == null) return DEFAULT;
        String l = locale.trim().toLowerCase(Locale.ROOT);

        if (l.startsWith("zh")) {
            return (l.contains("hant") || l.contains("-tw") || l.contains("-hk") || l.contains("-mo")) ? "zh-hant" : "zh";
        }
        int dash = l.indexOf('-');
        if (dash > 0) l = l.substring(0, dash);
        return SUPPORTED.contains(l) ? l : DEFAULT;
    }

    public static String get(String locale, String key) {
        String loc = normalize(locale);
        Map<String, String> m = CAT.get(loc);
        String v = m != null ? m.get(key) : null;
        if (v == null && !DEFAULT.equals(loc)) {
            Map<String, String> en = CAT.get(DEFAULT);
            v = en != null ? en.get(key) : null;
        }
        return v != null ? v : key;
    }
}
