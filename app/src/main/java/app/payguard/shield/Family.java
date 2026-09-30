package app.payguard.shield;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Family guardian mode on the phone.
 *
 * - Registers this phone with the PayGuard server once (a random id + secret; no account, no phone number).
 *   Every check the app sends carries that token (Api.java), so when a PROTECTED parent's phone gets a dangerous
 *   result the server alerts their guardians by itself.
 * - On a GUARDIAN's phone, polls /api/family/alerts every 15 minutes (JobScheduler, survives reboots) and whenever
 *   the app opens, and shows new alerts as notifications. (Instant push needs Firebase; see README.)
 * The linking screens themselves are the website's /family page inside WebActivity, sharing this token.
 */
public final class Family {
    static final String CHANNEL = "family_alerts";
    private static final int JOB_ID = 4242;

    private Family() {}

    /** Blocking; call from a background thread. Returns the token or "" if the server can't be reached. */
    public static String ensureDevice(Context c, boolean verify) {
        String server = Prefs.server(c);
        if (server.isEmpty()) return "";
        String tok = Prefs.deviceToken(c);
        if (!tok.isEmpty() && server.equals(Prefs.deviceServer(c))) {
            if (!verify) return tok;
            try {
                Api.get(c, "/api/family/me");
                return tok;
            } catch (Api.ApiException e) {
                if (e.code != 401) return tok; // offline: keep it
            }
        }
        try {
            JSONObject body = new JSONObject().put("platform", "android").put("lang", Prefs.lang(c)).put("name", "");
            Prefs.setDeviceToken(c, "", "");
            JSONObject r = Api.postJson(c, "/api/family/device", body);
            String t = r.optString("token", "");
            Prefs.setDeviceToken(c, t, server);
            return t;
        } catch (Exception e) {
            return "";
        }
    }

    /** Blocking. Fetches new alerts for this phone (as a guardian) and shows them. Returns /api/family/me or null. */
    public static JSONObject poll(Context c) {
        return poll(c, true);
    }

    /** notify=false just moves the "seen up to" marker (the user already saw the alerts on the Family page). */
    public static JSONObject poll(Context c, boolean notify) {
        if (Prefs.deviceToken(c).isEmpty() || !Prefs.server(c).equals(Prefs.deviceServer(c))) return null;
        try {
            JSONObject me = Api.get(c, "/api/family/me");
            JSONArray protecting = me.optJSONArray("protecting");
            if (protecting == null || protecting.length() == 0) return me;
            long last = Prefs.lastAlertId(c);
            JSONObject r = Api.get(c, "/api/family/alerts?since_id=" + last + "&limit=20");
            JSONArray alerts = r.optJSONArray("alerts");
            if (alerts == null) return me;
            long max = last;
            String lang = Prefs.lang(c);
            // newest first from the server; show oldest first
            for (int i = alerts.length() - 1; i >= 0; i--) {
                JSONObject a = alerts.optJSONObject(i);
                if (a == null) continue;
                long id = a.optLong("id");
                max = Math.max(max, id);
                if (last == 0 && i > 2) continue;           // first run: only the 3 most recent
                if (a.optBoolean("seen") || !notify) continue;
                show(c, (int) id, Ui.tr(a.optJSONObject("title"), lang), Ui.tr(a.optJSONObject("body"), lang),
                        "pay_anyway".equals(a.optString("type")) || "danger".equals(a.optString("level")));
            }
            if (max > last) Prefs.setLastAlertId(c, max);
            return me;
        } catch (Exception e) {
            return null;
        }
    }

    static void createChannel(Context c) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm == null || nm.getNotificationChannel(CHANNEL) != null) return;
        NotificationChannel ch = new NotificationChannel(CHANNEL, c.getString(R.string.notif_channel), NotificationManager.IMPORTANCE_HIGH);
        ch.setDescription(c.getString(R.string.notif_channel_desc));
        ch.enableVibration(true);
        ch.setVibrationPattern(new long[]{0, 300, 120, 300, 120, 300});
        nm.createNotificationChannel(ch);
    }

    private static void show(Context c, int id, String title, String body, boolean urgent) {
        createChannel(c);
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm == null) return;
        if (Build.VERSION.SDK_INT >= 33 && c.checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                != android.content.pm.PackageManager.PERMISSION_GRANTED) return;
        Intent open = new Intent(c, WebActivity.class).putExtra(WebActivity.EXTRA_PATH, "/family")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(c, id, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(c, CHANNEL)
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(new Notification.BigTextStyle().bigText(body))
                .setCategory(urgent ? Notification.CATEGORY_ALARM : Notification.CATEGORY_MESSAGE)
                .setContentIntent(pi)
                .setAutoCancel(true)
                .build();
        nm.notify("pg-alert", id, n);
    }

    /** Periodic background check (every ~15 min, only with network). Safe to call repeatedly. */
    public static void schedule(Context c) {
        JobScheduler js = c.getSystemService(JobScheduler.class);
        if (js == null) return;
        if (js.getPendingJob(JOB_ID) != null) return;
        JobInfo job = new JobInfo.Builder(JOB_ID, new ComponentName(c, AlertJobService.class))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(15 * 60 * 1000L)
                .setPersisted(true)
                .build();
        try {
            js.schedule(job);
        } catch (Exception ignored) { }
    }
}
