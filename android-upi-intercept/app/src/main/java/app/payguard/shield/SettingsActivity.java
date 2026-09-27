package app.payguard.shield;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

/** Server address (typed, or scanned from the website's "connect" QR) and language. */
public class SettingsActivity extends Activity {
    private EditText server;
    private TextView testResult;
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_settings);
        server = findViewById(R.id.server);
        testResult = findViewById(R.id.testResult);
        server.setText(Prefs.server(this));

        findViewById(R.id.btnSave).setOnClickListener(v -> {
            Prefs.setServer(this, server.getText().toString());
            server.setText(Prefs.server(this));
            Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show();
            test();
        });
        findViewById(R.id.btnTest).setOnClickListener(v -> {
            Prefs.setServer(this, server.getText().toString());
            test();
        });
        findViewById(R.id.btnScanConnect).setOnClickListener(v -> Scanner.scan(this, text -> {
            if (!applyConnect(Uri.parse(text))) Toast.makeText(this, R.string.not_connect_code, Toast.LENGTH_LONG).show();
        }));
        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        RadioGroup lang = findViewById(R.id.lang);
        String cur = Prefs.langSetting(this);
        lang.check("en".equals(cur) ? R.id.langEn : "hi".equals(cur) ? R.id.langHi : "kn".equals(cur) ? R.id.langKn : R.id.langAuto);
        lang.setOnCheckedChangeListener((g, id) -> Prefs.setLang(this,
                id == R.id.langEn ? "en" : id == R.id.langHi ? "hi" : id == R.id.langKn ? "kn" : "auto"));

        Uri data = getIntent().getData();
        if (data != null) applyConnect(data);
    }

    /** payguard://connect?server=https://... */
    private boolean applyConnect(Uri u) {
        if (u == null || !"payguard".equals(u.getScheme()) || !"connect".equals(u.getHost())) return false;
        String s = u.getQueryParameter("server");
        if (s == null || s.trim().isEmpty()) return false;
        Prefs.setServer(this, s);
        server.setText(Prefs.server(this));
        Toast.makeText(this, getString(R.string.connected_to, Prefs.server(this)), Toast.LENGTH_LONG).show();
        test();
        return true;
    }

    private void test() {
        testResult.setText(R.string.testing);
        new Thread(() -> {
            String msg;
            try {
                JSONObject h = Api.get(this, "/api/health");
                if (!"payguard".equals(h.optString("service")) && !h.has("engine")) throw new Api.ApiException(0, getString(R.string.err_not_payguard));
                msg = getString(R.string.test_ok, h.optString("engine", "?"),
                        getString(h.optBoolean("ocr") ? R.string.yes : R.string.no));
            } catch (Api.ApiException e) {
                msg = getString(R.string.test_fail, e.getMessage());
            }
            final String m = msg;
            main.post(() -> testResult.setText(m));
        }).start();
    }
}
