package app.payguard.shield;

import android.content.Context;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

/** Talks to the PayGuard backend (same API the website uses). Call from a background thread. */
public final class Api {

    public static final class ApiException extends Exception {
        private static final long serialVersionUID = 1L;
        public final int code; // 0 = network / not configured

        ApiException(int code, String msg) {
            super(msg);
            this.code = code;
        }
    }

    private Api() {}

    private static String base(Context c) throws ApiException {
        String b = Prefs.server(c);
        if (b.isEmpty()) throw new ApiException(0, c.getString(R.string.err_no_server));
        return b;
    }

    private static HttpURLConnection open(Context c, String path, String method, int readTimeoutMs) throws IOException, ApiException {
        URL url = new URL(base(c) + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(12000);
        conn.setReadTimeout(readTimeoutMs);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("X-PayGuard-Client", "android/" + BuildConfig.VERSION_NAME);
        conn.setRequestProperty("ngrok-skip-browser-warning", "1");
        String tok = Prefs.deviceToken(c);
        // Proves this phone to the server, so a protected parent's risky checks alert their family (see Family.java).
        if (!tok.isEmpty() && base(c).equals(Prefs.deviceServer(c))) conn.setRequestProperty("X-PG-Device", tok);
        return conn;
    }

    public static JSONObject get(Context c, String path) throws ApiException {
        try {
            HttpURLConnection conn = open(c, path, "GET", 20000);
            return read(c, conn);
        } catch (IOException e) {
            throw new ApiException(0, c.getString(R.string.err_network));
        }
    }

    public static JSONObject postJson(Context c, String path, JSONObject body) throws ApiException {
        try {
            HttpURLConnection conn = open(c, path, "POST", 60000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bytes);
            }
            return read(c, conn);
        } catch (IOException e) {
            throw new ApiException(0, c.getString(R.string.err_network));
        }
    }

    /** multipart/form-data upload with one file field plus optional text fields. */
    public static JSONObject postFile(Context c, String path, String field, String filename, String mime, byte[] data,
                                      Map<String, String> fields) throws ApiException {
        String boundary = "----payguard" + UUID.randomUUID().toString().replace("-", "");
        try {
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            if (fields != null) {
                for (Map.Entry<String, String> e : fields.entrySet()) {
                    head.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + e.getKey() + "\"\r\n\r\n"
                            + e.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
                }
            }
            String safeName = filename == null ? "upload" : filename.replace("\"", "");
            head.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + field + "\"; filename=\"" + safeName
                    + "\"\r\nContent-Type: " + (mime == null ? "application/octet-stream" : mime) + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
            byte[] h = head.toByteArray();

            HttpURLConnection conn = open(c, path, "POST", 150000);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            conn.setFixedLengthStreamingMode((long) h.length + data.length + tail.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(h);
                os.write(data);
                os.write(tail);
            }
            return read(c, conn);
        } catch (IOException e) {
            throw new ApiException(0, c.getString(R.string.err_network));
        }
    }

    private static JSONObject read(Context c, HttpURLConnection conn) throws IOException, ApiException {
        int code = conn.getResponseCode();
        InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String text = in == null ? "" : readAll(in);
        conn.disconnect();
        JSONObject json;
        try {
            json = new JSONObject(text);
        } catch (JSONException e) {
            // A tunnel or proxy page instead of the PayGuard API
            throw new ApiException(code, c.getString(R.string.err_not_payguard));
        }
        if (code >= 400) {
            throw new ApiException(code, json.optString("error", c.getString(R.string.err_server) + " " + code));
        }
        return json;
    }

    public static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        in.close();
        return out.toString("UTF-8");
    }
}
