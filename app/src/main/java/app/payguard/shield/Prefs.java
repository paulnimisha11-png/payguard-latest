package app.payguard.shield;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Locale;

/** Small wrapper around SharedPreferences. */
public final class Prefs {
    private static final String FILE = "payguard";

    private Prefs() {}

    private static SharedPreferences p(Context c) {
        return c.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    /** Server base URL without a trailing slash, e.g. https://abcd.lhr.life */
    public static String server(Context c) {
        String s = p(c).getString("server", BuildConfig.DEFAULT_SERVER);
        return normalize(s);
    }

    public static void setServer(Context c, String url) {
        p(c).edit().putString("server", normalize(url)).apply();
    }

    public static String normalize(String url) {
        if (url == null) return "";
        String s = url.trim();
        if (s.isEmpty()) return "";
        if (!s.startsWith("http://") && !s.startsWith("https://")) s = "https://" + s;
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** "auto", "en", "hi", "kn", "ta", "te", "mr" or "bn" */
    public static String langSetting(Context c) {
        return p(c).getString("lang", "auto");
    }

    public static void setLang(Context c, String lang) {
        p(c).edit().putString("lang", lang).apply();
    }

    /** Language used for verdict texts coming from the server. */
    public static String lang(Context c) {
        String s = langSetting(c);
        if (!"auto".equals(s)) return s;
        String sys = Locale.getDefault().getLanguage();
        if ("hi".equals(sys) || "kn".equals(sys) || "ta".equals(sys) || "te".equals(sys) || "mr".equals(sys) || "bn".equals(sys)) return sys;
        return "en";
    }

    /** Random id so one phone counts as one scam report (no personal data). */
    public static String voterId(Context c) {
        String v = p(c).getString("voter", "");
        if (v.isEmpty()) {
            v = java.util.UUID.randomUUID().toString();
            p(c).edit().putString("voter", v).apply();
        }
        return v;
    }

    /** "device_id.secret" for family protection; empty until the device registers with the server. */
    public static String deviceToken(Context c) {
        return p(c).getString("device_token", "");
    }

    public static void setDeviceToken(Context c, String token, String server) {
        p(c).edit().putString("device_token", token == null ? "" : token).putString("device_server", server == null ? "" : server)
                .putLong("last_alert_id", 0).apply();
    }

    /** The token belongs to one server; switching servers means registering again. */
    public static String deviceServer(Context c) {
        return p(c).getString("device_server", "");
    }

    public static long lastAlertId(Context c) {
        return p(c).getLong("last_alert_id", 0);
    }

    public static void setLastAlertId(Context c, long id) {
        p(c).edit().putLong("last_alert_id", id).apply();
    }

    public static String lastUpiApp(Context c) {
        return p(c).getString("upi_app", "");
    }

    public static void setLastUpiApp(Context c, String pkg) {
        p(c).edit().putString("upi_app", pkg).apply();
    }
}
