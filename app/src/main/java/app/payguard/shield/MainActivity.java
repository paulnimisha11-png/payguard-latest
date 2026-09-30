package app.payguard.shield;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

/** Home: scan a shop's QR to pay safely, check a screenshot / APK / link, and set PayGuard up as the UPI checker. */
public class MainActivity extends Activity {
    private static final int REQ_PICK_QR = 11;
    private static final int REQ_PICK_SHOT = 12;
    private static final int REQ_PICK_APK = 13;

    private static final int REQ_NOTIF = 21;
    private TextView serverStatus, defaultStatus, famStatus;
    private Button btnMakeDefault;
    private EditText paste, expected, bankSms, msgText;
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_main);
        serverStatus = findViewById(R.id.serverStatus);
        defaultStatus = findViewById(R.id.defaultStatus);
        btnMakeDefault = findViewById(R.id.btnMakeDefault);
        paste = findViewById(R.id.paste);
        expected = findViewById(R.id.expected);
        bankSms = findViewById(R.id.bankSms);
        msgText = findViewById(R.id.msgText);
        famStatus = findViewById(R.id.famStatus);

        findViewById(R.id.btnCheckMsg).setOnClickListener(v -> checkMessage(msgText.getText().toString()));
        findViewById(R.id.btnPasteMsg).setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = cm == null ? null : cm.getPrimaryClip();
            CharSequence txt = clip != null && clip.getItemCount() > 0 ? clip.getItemAt(0).coerceToText(this) : null;
            if (txt == null || txt.toString().trim().isEmpty()) {
                Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show();
                return;
            }
            msgText.setText(txt);
            checkMessage(txt.toString());
        });
        findViewById(R.id.btnFamily).setOnClickListener(v -> openWebScreen("/family"));
        findViewById(R.id.btnTrends).setOnClickListener(v -> openWebScreen("/trends"));

        findViewById(R.id.btnScan).setOnClickListener(v -> Scanner.scan(this, this::check));
        findViewById(R.id.btnCheckPaste).setOnClickListener(v -> {
            String t = paste.getText().toString().trim();
            if (t.isEmpty()) {
                Toast.makeText(this, R.string.paste_first, Toast.LENGTH_SHORT).show();
                return;
            }
            check(CheckActivity.extractLink(t));
        });
        findViewById(R.id.btnShot).setOnClickListener(v -> pick("image/*", REQ_PICK_SHOT));
        findViewById(R.id.btnQrPhoto).setOnClickListener(v -> pick("image/*", REQ_PICK_QR));
        findViewById(R.id.btnApk).setOnClickListener(v -> pick("application/vnd.android.package-archive", REQ_PICK_APK));
        findViewById(R.id.btnSettings).setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));
        btnMakeDefault.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(CheckActivity.SETUP_TEST)));
            } catch (ActivityNotFoundException e) {
                Toast.makeText(this, R.string.no_upi_app, Toast.LENGTH_LONG).show();
            }
        });
        findViewById(R.id.btnWebsite).setOnClickListener(v -> {
            String s = Prefs.server(this);
            if (s.isEmpty()) startActivity(new Intent(this, SettingsActivity.class));
            else startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(s)));
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshDefaultStatus();
        refreshServerStatus();
        refreshFamily();
    }

    private void checkMessage(String text) {
        String t = text == null ? "" : text.trim();
        if (t.isEmpty()) {
            Toast.makeText(this, R.string.paste_first, Toast.LENGTH_SHORT).show();
            return;
        }
        Intent i = new Intent(this, CheckActivity.class);
        if (CheckActivity.isBareLink(t)) i.putExtra(CheckActivity.EXTRA_PAYLOAD, t);
        else i.putExtra(CheckActivity.EXTRA_MESSAGE, t);
        startActivity(i);
    }

    private void openWebScreen(String path) {
        if (Prefs.server(this).isEmpty()) {
            startActivity(new Intent(this, SettingsActivity.class));
            return;
        }
        startActivity(new Intent(this, WebActivity.class).putExtra(WebActivity.EXTRA_PATH, path));
    }

    /** Register this phone (once), keep the background alert check scheduled, and show the family status. */
    private void refreshFamily() {
        if (Prefs.server(this).isEmpty()) return;
        final Context app = getApplicationContext();
        new Thread(() -> {
            Family.ensureDevice(app, false);
            JSONObject me = Family.poll(app);
            if (me == null) return;
            JSONArray prot = me.optJSONArray("protecting");
            JSONArray by = me.optJSONArray("protected_by");
            int np = prot == null ? 0 : prot.length();
            int unread = me.optInt("unread", 0);
            String status;
            if (np > 0) {
                Family.schedule(app);
                status = getString(R.string.fam_status_guard, np, unread);
            } else if (by != null && by.length() > 0) {
                JSONObject g = by.optJSONObject(0);
                status = getString(R.string.fam_status_protected, g == null ? "" : g.optString("name"));
            } else {
                status = getString(R.string.family_card_body);
            }
            final String st = status;
            final boolean guardian = np > 0;
            main.post(() -> {
                famStatus.setText(st);
                if (guardian && Build.VERSION.SDK_INT >= 33
                        && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, REQ_NOTIF);
                }
            });
        }).start();
    }

    private void check(String payload) {
        Intent i = new Intent(this, CheckActivity.class);
        i.putExtra(CheckActivity.EXTRA_PAYLOAD, payload);
        startActivity(i);
    }

    private void pick(String mime, int req) {
        Intent i = new Intent(Intent.ACTION_GET_CONTENT);
        i.setType(mime);
        i.addCategory(Intent.CATEGORY_OPENABLE);
        try {
            startActivityForResult(Intent.createChooser(i, getString(R.string.choose_file)), req);
        } catch (ActivityNotFoundException e) {
            // Some file pickers don't know the APK mime type
            i.setType("*/*");
            startActivityForResult(i, req);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        Intent i = new Intent(this, CheckActivity.class);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        String uri = data.getData().toString();
        if (requestCode == REQ_PICK_APK) {
            i.putExtra(CheckActivity.EXTRA_APK, uri);
        } else {
            i.putExtra(CheckActivity.EXTRA_IMAGE, uri);
            i.putExtra(CheckActivity.EXTRA_IMAGE_MODE, requestCode == REQ_PICK_SHOT ? "shot" : "qr");
            if (requestCode == REQ_PICK_SHOT) {
                i.putExtra(CheckActivity.EXTRA_EXPECTED, expected.getText().toString().trim());
                i.putExtra(CheckActivity.EXTRA_SMS, bankSms.getText().toString().trim());
            }
        }
        i.setData(null);
        startActivity(i);
    }

    /** Is PayGuard the app that opens upi:// links? */
    @SuppressWarnings("deprecation")
    private void refreshDefaultStatus() {
        Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse("upi://pay?pa=a@b"));
        ResolveInfo ri = getPackageManager().resolveActivity(probe, PackageManager.MATCH_DEFAULT_ONLY);
        String pkg = ri == null || ri.activityInfo == null ? "" : ri.activityInfo.packageName;
        if (getPackageName().equals(pkg)) {
            defaultStatus.setText(R.string.default_yes);
            defaultStatus.setTextColor(getColor(R.color.ok));
            btnMakeDefault.setText(R.string.test_setup);
        } else if (pkg.isEmpty() || "android".equals(pkg) || pkg.contains("resolver") || pkg.contains("intentresolver")) {
            defaultStatus.setText(R.string.default_ask);
            defaultStatus.setTextColor(getColor(R.color.warn));
            btnMakeDefault.setText(R.string.make_default);
        } else {
            CharSequence label = ri.loadLabel(getPackageManager());
            defaultStatus.setText(getString(R.string.default_other, label));
            defaultStatus.setTextColor(getColor(R.color.warn));
            btnMakeDefault.setText(R.string.make_default);
        }
    }

    private void refreshServerStatus() {
        String s = Prefs.server(this);
        if (s.isEmpty()) {
            serverStatus.setText(R.string.server_not_set);
            serverStatus.setTextColor(getColor(R.color.danger));
            return;
        }
        serverStatus.setText(getString(R.string.server_checking, s));
        serverStatus.setTextColor(getColor(R.color.dim));
        new Thread(() -> {
            String msg;
            int color;
            try {
                JSONObject h = Api.get(this, "/api/health");
                msg = getString(R.string.server_ok, s);
                color = getColor(h.optBoolean("ok") ? R.color.ok : R.color.warn);
            } catch (Api.ApiException e) {
                msg = getString(R.string.server_down, s);
                color = getColor(R.color.danger);
            }
            final String m = msg;
            final int c = color;
            main.post(() -> {
                serverStatus.setText(m);
                serverStatus.setTextColor(c);
            });
        }).start();
    }
}
