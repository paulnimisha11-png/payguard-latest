package app.payguard.shield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.Handler;
import android.os.Looper;
import android.os.Vibrator;
import android.provider.OpenableColumns;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.text.NumberFormat;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The heart of the app. Receives a UPI link (from the camera, Google Lens, WhatsApp, a merchant app, or
 * PayGuard's own scanner), a shared image or an APK; checks it with the PayGuard server; and then either
 * hands the payment to a real UPI app (safe) or stops on a scam warning (dangerous).
 */
public class CheckActivity extends Activity {
    public static final String EXTRA_PAYLOAD = "payguard.payload";
    public static final String EXTRA_IMAGE = "payguard.image";
    public static final String EXTRA_IMAGE_MODE = "payguard.image_mode"; // "qr" or "shot"
    public static final String EXTRA_APK = "payguard.apk";
    public static final String EXTRA_EXPECTED = "payguard.expected";
    public static final String EXTRA_SMS = "payguard.bank_sms";
    public static final String EXTRA_MESSAGE = "payguard.message";
    public static final String SETUP_TEST = "upi://pay?pa=payguard.setup@upi&pn=PayGuard%20setup%20check&tn=setup";

    private static final int REQ_PAY = 7;
    private static final long AUTO_PAY_MS = 3000;
    private static final int MAX_IMAGE = 12 * 1024 * 1024;
    private static final int MAX_APK = 150 * 1024 * 1024;

    private String payload;
    private String messageText;
    private Uri imageUri;
    private String imageMode;
    private Uri apkUri;
    private String expected = "";
    private String bankSms = "";
    private boolean callerWantsResult;
    private String lang;
    private CountDownTimer timer;
    private final Handler main = new Handler(Looper.getMainLooper());

    private View loading, errorBox, content, overrideRow;
    private TextView loadingText, errorText, scoreText, headline, advice, countdown, btnOpenApp, findingsTitle;
    private LinearLayout header, special, findings;
    private Button btnPrimary, btnSecondary, btnOverride, btnCopy, btnReport;
    private CheckBox chkOverride;
    private View voteCard;
    private TextView voteCount, voteMsg;
    private Button btnGotMe, btnFake;
    private JSONObject lastResult;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_check);
        lang = Prefs.lang(this);
        loading = findViewById(R.id.loading);
        errorBox = findViewById(R.id.errorBox);
        content = findViewById(R.id.content);
        overrideRow = findViewById(R.id.overrideRow);
        loadingText = findViewById(R.id.loadingText);
        errorText = findViewById(R.id.errorText);
        scoreText = findViewById(R.id.scoreText);
        headline = findViewById(R.id.headline);
        advice = findViewById(R.id.advice);
        countdown = findViewById(R.id.countdown);
        btnOpenApp = findViewById(R.id.btnOpenApp);
        findingsTitle = findViewById(R.id.findingsTitle);
        header = findViewById(R.id.header);
        special = findViewById(R.id.special);
        findings = findViewById(R.id.findings);
        btnPrimary = findViewById(R.id.btnPrimary);
        btnSecondary = findViewById(R.id.btnSecondary);
        btnOverride = findViewById(R.id.btnOverride);
        btnCopy = findViewById(R.id.btnCopy);
        btnReport = findViewById(R.id.btnReport);
        chkOverride = findViewById(R.id.chkOverride);
        voteCard = findViewById(R.id.voteCard);
        voteCount = findViewById(R.id.voteCount);
        voteMsg = findViewById(R.id.voteMsg);
        btnGotMe = findViewById(R.id.btnGotMe);
        btnFake = findViewById(R.id.btnFake);
        btnGotMe.setOnClickListener(v -> sendVote("got_me"));
        btnFake.setOnClickListener(v -> sendVote("fake"));

        findViewById(R.id.btnRetry).setOnClickListener(v -> start());
        findViewById(R.id.btnErrorSettings).setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        findViewById(R.id.btnDone).setOnClickListener(v -> finishCancelled());
        chkOverride.setOnCheckedChangeListener((b, on) -> btnOverride.setEnabled(on));

        readIntent(getIntent());
        start();
    }

    // ------------------------------------------------------------------ input

    @SuppressWarnings("deprecation")
    private void readIntent(Intent in) {
        String action = in.getAction();
        Uri data = in.getData();
        if (Intent.ACTION_VIEW.equals(action) && data != null && "upi".equalsIgnoreCase(data.getScheme())) {
            payload = data.toString();
            callerWantsResult = getCallingActivity() != null;
            return;
        }
        if (Intent.ACTION_SEND.equals(action)) {
            String type = in.getType() == null ? "" : in.getType();
            if (type.startsWith("text/")) {
                String txt = in.getStringExtra(Intent.EXTRA_TEXT);
                String subj = in.getStringExtra(Intent.EXTRA_SUBJECT);
                if (subj != null && txt != null && !txt.contains(subj)) txt = subj + "\n" + txt;
                // A bare link or UPI QR goes to the link checker; anything with words is a message to check.
                if (isBareLink(txt)) payload = txt.trim(); else messageText = txt;
            } else if (type.startsWith("image/")) {
                imageUri = in.getParcelableExtra(Intent.EXTRA_STREAM);
            } else {
                apkUri = in.getParcelableExtra(Intent.EXTRA_STREAM);
            }
            return;
        }
        payload = in.getStringExtra(EXTRA_PAYLOAD);
        messageText = in.getStringExtra(EXTRA_MESSAGE);
        String img = in.getStringExtra(EXTRA_IMAGE);
        if (img != null) imageUri = Uri.parse(img);
        imageMode = in.getStringExtra(EXTRA_IMAGE_MODE);
        String apk = in.getStringExtra(EXTRA_APK);
        if (apk != null) apkUri = Uri.parse(apk);
        String exp = in.getStringExtra(EXTRA_EXPECTED);
        if (exp != null) expected = exp;
        String sms = in.getStringExtra(EXTRA_SMS);
        if (sms != null) bankSms = sms;
    }

    /** Pull the first upi:// or web link out of shared text; otherwise check the text itself. */
    static String extractLink(String text) {
        if (text == null) return null;
        Matcher m = Pattern.compile("(upi://\\S+|https?://\\S+)", Pattern.CASE_INSENSITIVE).matcher(text);
        return m.find() ? m.group(1) : text.trim();
    }

    /** Only a single upi:// / http(s):// link (or a bare domain) and nothing else. */
    static boolean isBareLink(String text) {
        if (text == null) return false;
        String t = text.trim();
        return !t.isEmpty() && !t.contains(" ") && !t.contains("\n")
                && Pattern.compile("^(upi://|https?://|www\\.|[a-z0-9-]+(\\.[a-z0-9-]+)+(/|$))", Pattern.CASE_INSENSITIVE).matcher(t).find();
    }

    private void start() {
        cancelTimer();
        if (messageText != null && !messageText.trim().isEmpty()) {
            runMessage();
        } else if (payload != null && !payload.isEmpty()) {
            if (payload.startsWith("upi://pay?pa=payguard.setup@upi")) {
                showSetupOk();
            } else {
                runPayload();
            }
        } else if (imageUri != null) {
            if (imageMode == null) askImageMode(); else runImage();
        } else if (apkUri != null) {
            runApk();
        } else {
            Toast.makeText(this, R.string.nothing_to_check, Toast.LENGTH_LONG).show();
            finish();
        }
    }

    private void askImageMode() {
        CharSequence[] items = {getString(R.string.image_is_qr), getString(R.string.image_is_shot)};
        new AlertDialog.Builder(this)
                .setTitle(R.string.image_what)
                .setItems(items, (d, which) -> {
                    imageMode = which == 0 ? "qr" : "shot";
                    runImage();
                })
                .setOnCancelListener(d -> finish())
                .show();
    }

    // ------------------------------------------------------------------ calls

    private void runPayload() {
        showLoading(R.string.checking_link);
        final String p = payload;
        new Thread(() -> {
            JSONObject r;
            try {
                r = Api.postJson(this, "/api/qr/text", new JSONObject().put("text", p));
            } catch (Api.ApiException e) {
                if (e.code == 0) {
                    r = LocalCheck.analyze(p); // no server: basic on-phone rules, never auto-pays
                } else {
                    final String msg = e.getMessage();
                    main.post(() -> showError(msg));
                    return;
                }
            } catch (Exception e) {
                r = LocalCheck.analyze(p);
            }
            final JSONObject res = r;
            main.post(() -> render(res));
        }).start();
    }

    private void runMessage() {
        showLoading(R.string.checking_message);
        final String text = messageText.length() > 20000 ? messageText.substring(0, 20000) : messageText;
        new Thread(() -> {
            try {
                final JSONObject r = Api.postJson(this, "/api/message", new JSONObject().put("text", text));
                main.post(() -> render(r));
            } catch (Api.ApiException e) {
                final String msg = e.getMessage();
                main.post(() -> showError(msg));
            } catch (Exception e) {
                main.post(() -> showError(getString(R.string.err_network)));
            }
        }).start();
    }

    private void runImage() {
        showLoading("shot".equals(imageMode) ? R.string.checking_shot : R.string.checking_qr_image);
        final Uri u = imageUri;
        final boolean shot = "shot".equals(imageMode);
        new Thread(() -> {
            try {
                byte[] bytes = readUri(u, MAX_IMAGE);
                String name = displayName(u, shot ? "screenshot.png" : "qr.png");
                String mime = getContentResolver().getType(u);
                java.util.Map<String, String> fields = new java.util.HashMap<>();
                if (shot && !expected.isEmpty()) fields.put("expected_amount", expected);
                if (shot && !bankSms.isEmpty()) fields.put("bank_sms", bankSms);
                JSONObject r = Api.postFile(this, shot ? "/api/screenshot" : "/api/qr/image", "file", name,
                        mime == null ? "image/png" : mime, bytes, fields);
                if (!shot) payload = r.optString("payload", null);
                main.post(() -> render(r));
            } catch (Api.ApiException e) {
                final String msg = e.getMessage();
                main.post(() -> showError(msg));
            } catch (Exception e) {
                main.post(() -> showError(getString(R.string.err_read_file)));
            }
        }).start();
    }

    private void runApk() {
        showLoading(R.string.checking_apk);
        final Uri u = apkUri;
        new Thread(() -> {
            try {
                byte[] bytes = readUri(u, MAX_APK);
                JSONObject r = Api.postFile(this, "/api/scan", "file", displayName(u, "app.apk"),
                        "application/vnd.android.package-archive", bytes, null);
                main.post(() -> render(r));
            } catch (Api.ApiException e) {
                final String msg = e.getMessage();
                main.post(() -> showError(msg));
            } catch (Exception e) {
                main.post(() -> showError(getString(R.string.err_read_file)));
            }
        }).start();
    }

    private byte[] readUri(Uri u, int max) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            if (in == null) throw new IllegalStateException("no stream");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > max) throw new IllegalStateException("too large");
            }
            return out.toByteArray();
        }
    }

    private String displayName(Uri u, String fallback) {
        try (Cursor c = getContentResolver().query(u, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst()) {
                String s = c.getString(0);
                if (s != null && !s.isEmpty()) return s;
            }
        } catch (Exception ignored) { }
        return fallback;
    }

    // ------------------------------------------------------------------ states

    private void showLoading(int textRes) {
        loadingText.setText(textRes);
        loading.setVisibility(View.VISIBLE);
        errorBox.setVisibility(View.GONE);
        content.setVisibility(View.GONE);
    }

    private void showError(String msg) {
        errorText.setText(msg);
        loading.setVisibility(View.GONE);
        errorBox.setVisibility(View.VISIBLE);
        content.setVisibility(View.GONE);
    }

    private void showSetupOk() {
        loading.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        header.setBackgroundColor(Ui.levelColor("low"));
        scoreText.setText(R.string.app_name);
        headline.setText(R.string.setup_ok_title);
        advice.setText(R.string.setup_ok_body);
        special.setVisibility(View.GONE);
        findingsTitle.setVisibility(View.GONE);
        btnPrimary.setText(R.string.done);
        btnPrimary.setOnClickListener(v -> finish());
    }

    // ------------------------------------------------------------------ result

    private void render(JSONObject r) {
        loading.setVisibility(View.GONE);
        errorBox.setVisibility(View.GONE);
        content.setVisibility(View.VISIBLE);
        content.scrollTo(0, 0);

        JSONObject v = r.optJSONObject("verdict");
        String level = v == null ? "caution" : v.optString("level", "caution");
        int score = v == null ? 0 : v.optInt("score", 0);
        header.setBackgroundColor(Ui.levelColor(level));
        getWindow().setStatusBarColor(Ui.levelColor(level));
        JSONObject comm = r.optJSONObject("community");
        int reports = comm == null ? 0 : comm.optInt("reports", 0);
        scoreText.setText(reports > 0 ? getString(R.string.risk_score, score) + "   🚩 " + reportedBy(reports)
                : getString(R.string.risk_score, score));
        lastResult = r;
        boolean canReport = comm != null && comm.optBoolean("can_report", false) && !r.optBoolean("offline");
        voteCard.setVisibility(canReport ? View.VISIBLE : View.GONE);
        voteCount.setText(reports > 0 ? reportedBy(reports) : getString(R.string.vote_none));
        voteCount.setTextColor(reports > 0 ? Color.parseColor("#B3122F") : Color.parseColor("#5B6078"));
        voteMsg.setVisibility(View.GONE);
        btnGotMe.setEnabled(true);
        btnFake.setEnabled(true);
        headline.setText(Ui.tr(v == null ? null : v.optJSONObject("headline"), lang));
        advice.setText(Ui.tr(v == null ? null : v.optJSONObject("advice"), lang));
        if ("danger".equals(level) || "suspicious".equals(level)) vibrate();

        String kind = r.optString("kind", "apk");
        JSONObject d = r.optJSONObject("details");
        String type = d == null ? "" : d.optString("type", "");
        special.removeAllViews();
        special.setVisibility(View.VISIBLE);
        if (r.optBoolean("offline")) addOffline();
        if ("qr".equals(kind) && "upi".equals(type)) buildUpiCard(d);
        else if ("qr".equals(kind) && "url".equals(type)) buildUrlCard(d);
        else if ("shot".equals(kind)) buildShotCard(r, d);
        else if ("msg".equals(kind)) buildMsgCard(d);
        else if ("qr".equals(kind)) buildTextCard(r.optString("payload"));
        else buildApkCard(r);

        findings.removeAllViews();
        JSONArray fs = r.optJSONArray("findings");
        if (fs != null) {
            for (int i = 0; i < fs.length(); i++) {
                JSONObject f = fs.optJSONObject(i);
                if (f != null) findings.addView(Ui.finding(this, f, lang));
            }
        }
        findingsTitle.setVisibility(fs != null && fs.length() > 0 ? View.VISIBLE : View.GONE);

        configureActions(r, kind, type, level, d);
    }

    private void configureActions(JSONObject r, String kind, String type, String level, JSONObject d) {
        btnSecondary.setVisibility(View.GONE);
        overrideRow.setVisibility(View.GONE);
        chkOverride.setChecked(false);
        btnCopy.setVisibility(View.GONE);
        btnReport.setVisibility(View.GONE);
        btnOpenApp.setVisibility(View.GONE);
        countdown.setVisibility(View.GONE);
        btnPrimary.setVisibility(View.VISIBLE);
        boolean risky = "danger".equals(level) || "suspicious".equals(level);
        btnPrimary.setBackgroundResource(risky ? R.drawable.btn_dark : R.drawable.btn_primary);

        if ("qr".equals(kind) && "upi".equals(type)) {
            final Uri uri = Uri.parse(payload);
            final String vpa = d.optString("payee_vpa", "");
            if (!vpa.isEmpty()) {
                btnCopy.setVisibility(View.VISIBLE);
                btnCopy.setOnClickListener(x -> copy(vpa));
            }
            btnOpenApp.setVisibility(View.VISIBLE);
            btnOpenApp.setOnClickListener(x -> UpiLauncher.openAppHome(this));
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/?check=" + enc(payload)));
            }
            if ("low".equals(level)) {
                btnPrimary.setText(R.string.pay_with_upi);
                btnPrimary.setOnClickListener(x -> pay(uri));
                btnSecondary.setVisibility(View.VISIBLE);
                btnSecondary.setText(R.string.cancel_payment);
                btnSecondary.setOnClickListener(x -> {
                    if (timer != null) {
                        cancelTimer();
                        countdown.setVisibility(View.GONE);
                        btnSecondary.setText(R.string.dont_pay);
                    } else {
                        finishCancelled();
                    }
                });
                startAutoPay(uri);
            } else if ("caution".equals(level)) {
                btnPrimary.setText(R.string.continue_to_pay);
                btnPrimary.setOnClickListener(x -> pay(uri));
                btnSecondary.setVisibility(View.VISIBLE);
                btnSecondary.setText(R.string.dont_pay);
                btnSecondary.setOnClickListener(x -> finishCancelled());
            } else {
                btnPrimary.setText(R.string.dont_pay_close);
                btnPrimary.setOnClickListener(x -> finishCancelled());
                overrideRow.setVisibility(View.VISIBLE);
                btnOverride.setText(R.string.pay_anyway);
                btnOverride.setOnClickListener(x -> {
                    tellFamily("pay_anyway", payload);
                    pay(uri);
                });
            }
        } else if ("qr".equals(kind) && "url".equals(type)) {
            final String url = d.optString("url", payload);
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/?check=" + enc(payload)));
            }
            if (risky) {
                btnPrimary.setText(R.string.dont_open);
                btnPrimary.setOnClickListener(x -> finishCancelled());
                overrideRow.setVisibility(View.VISIBLE);
                btnOverride.setText(R.string.open_anyway);
                btnOverride.setOnClickListener(x -> openUrl(url));
            } else {
                btnPrimary.setText(R.string.open_link);
                btnPrimary.setOnClickListener(x -> openUrl(url));
            }
        } else if ("msg".equals(kind)) {
            final String text = r.optString("payload");
            btnPrimary.setText(risky ? R.string.msg_ok_block : R.string.done);
            btnPrimary.setOnClickListener(x -> finish());
            btnSecondary.setVisibility(View.VISIBLE);
            btnSecondary.setText(R.string.full_report);
            btnSecondary.setOnClickListener(x -> openWeb("/?share_text=" + enc(text)));
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/?share_text=" + enc(text) + "&report=got_me"));
            }
        } else if ("shot".equals(kind)) {
            final String id = r.optString("id");
            btnPrimary.setText(R.string.full_report);
            btnPrimary.setBackgroundResource(R.drawable.btn_primary);
            btnPrimary.setOnClickListener(x -> openWeb("/s/" + id));
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/s/" + id));
            }
        } else if ("qr".equals(kind)) {
            final String text = r.optString("payload");
            btnPrimary.setText(R.string.copy_text);
            btnPrimary.setBackgroundResource(R.drawable.btn_primary);
            btnPrimary.setOnClickListener(x -> copy(text));
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/?check=" + enc(text)));
            }
        } else {
            JSONObject file = r.optJSONObject("file");
            final String sha = file == null ? "" : file.optString("sha256");
            btnPrimary.setText(R.string.full_report);
            btnPrimary.setBackgroundResource(R.drawable.btn_primary);
            btnPrimary.setOnClickListener(x -> openWeb("/r/" + sha));
            if (!"low".equals(level)) {
                btnReport.setVisibility(View.VISIBLE);
                btnReport.setOnClickListener(x -> openWeb("/r/" + sha));
            }
        }
    }

    // ------------------------------------------------------------------ one-tap scam report

    private void sendVote(final String reason) {
        final JSONObject r = lastResult;
        if (r == null) return;
        btnGotMe.setEnabled(false);
        btnFake.setEnabled(false);
        new Thread(() -> {
            try {
                JSONObject body = new JSONObject();
                String kind = r.optString("kind", "apk");
                body.put("kind", kind);
                if ("qr".equals(kind) || "msg".equals(kind)) body.put("payload", r.optString("payload"));
                else if ("shot".equals(kind)) body.put("id", r.optString("id"));
                else body.put("id", r.optJSONObject("file") == null ? "" : r.optJSONObject("file").optString("sha256"));
                body.put("reason", reason);
                body.put("voter", Prefs.voterId(this));
                JSONObject res = Api.postJson(this, "/api/reports", body);
                final int n = res.optInt("reports", 0);
                final boolean already = res.optBoolean("already", false);
                main.post(() -> {
                    voteCount.setText(reportedBy(n));
                    voteCount.setTextColor(Color.parseColor("#B3122F"));
                    voteMsg.setText(already ? R.string.vote_already : R.string.vote_thanks);
                    voteMsg.setVisibility(View.VISIBLE);
                    if ("got_me".equals(reason)) openComplaint(r);
                });
            } catch (Exception e) {
                final String msg = e instanceof Api.ApiException ? e.getMessage() : getString(R.string.err_network);
                main.post(() -> {
                    btnGotMe.setEnabled(true);
                    btnFake.setEnabled(true);
                    Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    /** Someone lost money: take them to the pre-filled complaint (1930 script, cybercrime.gov.in fields, PDF). */
    private void openComplaint(JSONObject r) {
        String kind = r.optString("kind", "apk");
        if ("qr".equals(kind)) openWeb("/?check=" + enc(r.optString("payload")) + "&report=got_me");
        else if ("msg".equals(kind)) openWeb("/?share_text=" + enc(r.optString("payload")) + "&report=got_me");
        else if ("shot".equals(kind)) openWeb("/s/" + r.optString("id"));
        else openWeb("/r/" + (r.optJSONObject("file") == null ? "" : r.optJSONObject("file").optString("sha256")));
    }

    // ------------------------------------------------------------------ cards

    private void addOffline() {
        TextView t = Ui.text(this, getString(R.string.offline_banner), 13, Color.parseColor("#A16207"), true);
        t.setPadding(0, 0, 0, Ui.dp(this, 10));
        special.addView(t);
    }

    private void row(String label, String value, boolean mono, int color) {
        special.addView(Ui.label(this, label));
        TextView t = Ui.text(this, value, 17, color, true);
        if (mono) t.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        t.setPadding(0, Ui.dp(this, 2), 0, Ui.dp(this, 12));
        t.setTextIsSelectable(true);
        special.addView(t);
    }

    private void buildUpiCard(JSONObject d) {
        int ink = Color.parseColor("#161A2C");
        double amt = d.optDouble("amount", Double.NaN);
        String amount = Double.isNaN(amt) ? getString(R.string.any_amount)
                : "₹" + NumberFormat.getNumberInstance(new Locale("en", "IN")).format(amt);
        row(getString(R.string.you_pay), amount, false, Color.parseColor("#B3122F"));
        String name = d.optString("payee_name", "");
        row(getString(R.string.to), name.isEmpty() ? "—" : name, false, ink);
        row(getString(R.string.upi_id), d.optString("payee_vpa", "—"), true, ink);
        row(getString(R.string.account_type), getString(d.optBoolean("is_merchant") ? R.string.merchant : R.string.personal), false, ink);
        String note = d.optString("note", "");
        if (!note.isEmpty()) row(getString(R.string.note), "“" + note + "”", false, ink);
        TextView out = Ui.text(this, getString(R.string.money_leaves), 14, Color.parseColor("#B3122F"), true);
        out.setBackground(Ui.rounded(Color.parseColor("#FDE8EC"), 10, this));
        int p = Ui.dp(this, 10);
        out.setPadding(p, p, p, p);
        special.addView(out);
    }

    private void buildUrlCard(JSONObject d) {
        row(getString(R.string.opens_website), d.optString("registered_domain", d.optString("host")), true, Color.parseColor("#161A2C"));
        row(getString(R.string.full_link), d.optString("url", payload), true, Color.parseColor("#5B6078"));
    }

    private void buildTextCard(String text) {
        row(getString(R.string.qr_contains), text, true, Color.parseColor("#161A2C"));
    }

    private void buildMsgCard(JSONObject d) {
        int ink = Color.parseColor("#161A2C");
        JSONObject cat = d.optJSONObject("category_name");
        if (cat != null) row(getString(R.string.msg_looks_like), Ui.tr(cat, lang), false, Color.parseColor("#B3122F"));
        JSONArray asks = d.optJSONArray("asks");
        if (asks != null && asks.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < asks.length(); i++) {
                JSONObject a = asks.optJSONObject(i);
                if (a != null) sb.append(i > 0 ? "\n" : "").append("✗ ").append(Ui.tr(a.optJSONObject("label"), lang));
            }
            row(getString(R.string.msg_wants), sb.toString(), false, ink);
        }
        JSONArray links = d.optJSONArray("links");
        if (links != null) {
            for (int i = 0; i < links.length() && i < 3; i++) {
                JSONObject l = links.optJSONObject(i);
                if (l == null) continue;
                boolean official = l.optBoolean("official");
                row(getString(official ? R.string.msg_link_official : R.string.msg_link_unofficial), l.optString("url"), true,
                        Color.parseColor(official ? "#15803D" : "#B3122F"));
            }
        }
        JSONArray upis = d.optJSONArray("upi_ids");
        if (upis != null) for (int i = 0; i < upis.length() && i < 3; i++) row(getString(R.string.upi_id), upis.optString(i), true, ink);
        JSONArray phones = d.optJSONArray("phones");
        if (phones != null) for (int i = 0; i < phones.length() && i < 3; i++) row(getString(R.string.msg_phone), phones.optString(i), true, ink);
    }

    /** A protected family member chose to go ahead anyway: the server re-checks and alerts their guardians. */
    private void tellFamily(final String type, final String what) {
        if (Prefs.deviceToken(this).isEmpty()) return;
        new Thread(() -> {
            try {
                Api.postJson(getApplicationContext(), "/api/family/event",
                        new JSONObject().put("type", type).put("kind", "qr").put("payload", what));
            } catch (Exception ignored) { }
        }).start();
    }

    private void buildApkCard(JSONObject r) {
        JSONObject app = r.optJSONObject("app");
        if (app == null) return;
        row(getString(R.string.app_label), app.optString("name", "—"), false, Color.parseColor("#161A2C"));
        row(getString(R.string.package_label), app.optString("package", "—"), true, Color.parseColor("#5B6078"));
    }

    private void buildShotCard(JSONObject r, JSONObject d) {
        String img = r.optString("annotated", "");
        if (img.startsWith("data:image")) {
            try {
                byte[] raw = Base64.decode(img.substring(img.indexOf(',') + 1), Base64.DEFAULT);
                Bitmap bmp = BitmapFactory.decodeByteArray(raw, 0, raw.length);
                ImageView iv = new ImageView(this);
                iv.setImageBitmap(bmp);
                iv.setAdjustViewBounds(true);
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this, 320));
                lp.bottomMargin = Ui.dp(this, 12);
                iv.setLayoutParams(lp);
                special.addView(iv);
            } catch (Exception ignored) { }
        }
        if (d == null) return;
        int ink = Color.parseColor("#161A2C");
        double amt = d.optDouble("amount", Double.NaN);
        row(getString(R.string.shot_status), d.optString("status", "—"), false, ink);
        row(getString(R.string.shot_amount), Double.isNaN(amt) ? "—" : "₹" + NumberFormat.getNumberInstance(new Locale("en", "IN")).format(amt), false, ink);
        row(getString(R.string.shot_utr), d.isNull("utr") ? "—" : d.optString("utr"), true, ink);
        row(getString(R.string.shot_date), d.isNull("date") ? "—" : d.optString("date"), false, ink);
    }

    // ------------------------------------------------------------------ actions

    private void startAutoPay(Uri uri) {
        countdown.setVisibility(View.VISIBLE);
        timer = new CountDownTimer(AUTO_PAY_MS, 250) {
            @Override
            public void onTick(long left) {
                countdown.setText(getString(R.string.opening_in, (int) Math.ceil(left / 1000.0)));
            }

            @Override
            public void onFinish() {
                timer = null;
                countdown.setVisibility(View.GONE);
                pay(uri);
            }
        }.start();
    }

    private void cancelTimer() {
        if (timer != null) {
            timer.cancel();
            timer = null;
        }
    }

    private void pay(Uri uri) {
        cancelTimer();
        countdown.setVisibility(View.GONE);
        UpiLauncher.pay(this, uri, callerWantsResult, REQ_PAY, pkg -> {
            if (!callerWantsResult) finish();
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_PAY) {
            // Pass the UPI app's answer straight back to the merchant app that asked for the payment.
            setResult(resultCode, data);
            finish();
        }
    }

    private void finishCancelled() {
        cancelTimer();
        if (callerWantsResult) {
            Intent d = new Intent();
            d.putExtra("response", "Status=FAILURE&responseCode=ZD&txnRef=");
            d.putExtra("Status", "FAILURE");
            setResult(RESULT_CANCELED, d);
        }
        finish();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        finishCancelled();
    }

    @Override
    protected void onStop() {
        super.onStop();
        // Never auto-open a UPI app while the user isn't looking at the verdict.
        if (timer != null) {
            cancelTimer();
            countdown.setVisibility(View.GONE);
        }
    }

    private void copy(String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("PayGuard", text));
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show();
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url.startsWith("http") ? url : "https://" + url)));
        } catch (Exception e) {
            Toast.makeText(this, R.string.cant_open, Toast.LENGTH_SHORT).show();
        }
    }

    private void openWeb(String path) {
        String base = Prefs.server(this);
        if (base.isEmpty()) {
            Toast.makeText(this, R.string.err_no_server, Toast.LENGTH_LONG).show();
            return;
        }
        openUrl(base + path);
    }

    private static String enc(String s) {
        try {
            return URLEncoder.encode(s == null ? "" : s, "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }

    @SuppressWarnings("deprecation")
    private void vibrate() {
        try {
            Vibrator vib = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            if (vib != null) vib.vibrate(new long[]{0, 120, 80, 120}, -1);
        } catch (Exception ignored) { }
    }

    private String reportedBy(int n) {
        String s = getString(R.string.reported_by, n);
        return n == 1 ? s.replace("by 1 people", "by 1 person") : s;
    }
}
