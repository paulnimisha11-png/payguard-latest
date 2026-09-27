package app.payguard.shield;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Shows the website's Family (/family) or Trends (/trends) page inside the app. The page and the app share one
 * device identity through the "PayGuardApp" bridge, so linking a parent here protects every check this app makes.
 * Only pages from the configured PayGuard server are shown inside; any other link opens in the browser.
 */
public class WebActivity extends Activity {
    public static final String EXTRA_PATH = "payguard.path";
    private static final int REQ_NOTIF = 31;
    private WebView web;
    private ProgressBar progress;
    private TextView error;
    private String server;
    private final Handler main = new Handler(Looper.getMainLooper());

    /** Methods callable from the page's JavaScript (device.js). */
    public class Bridge {
        @JavascriptInterface public String deviceToken() { return Prefs.deviceToken(WebActivity.this); }
        @JavascriptInterface public String lang() { return Prefs.lang(WebActivity.this); }
        @JavascriptInterface public void forget() { Prefs.setDeviceToken(WebActivity.this, "", ""); }
    }

    @SuppressLint({"SetJavaScriptEnabled", "AddJavascriptInterface"})
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_web);
        web = findViewById(R.id.web);
        progress = findViewById(R.id.webProgress);
        error = findViewById(R.id.webError);
        server = Prefs.server(this);
        if (server.isEmpty()) {
            Toast.makeText(this, R.string.err_no_server, Toast.LENGTH_LONG).show();
            startActivity(new Intent(this, SettingsActivity.class));
            finish();
            return;
        }
        final String path = getIntent().getStringExtra(EXTRA_PATH) == null ? "/family" : getIntent().getStringExtra(EXTRA_PATH);
        setTitle("/trends".equals(path) ? R.string.open_trends : R.string.open_family);

        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setUserAgentString(ws.getUserAgentString() + " PayGuardApp/" + BuildConfig.VERSION_NAME);
        web.addJavascriptInterface(new Bridge(), "PayGuardApp");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                String s = u.toString();
                if (s.startsWith(server + "/")) return false;             // our pages stay inside
                try {
                    if ("tel".equals(u.getScheme())) startActivity(new Intent(Intent.ACTION_DIAL, u));
                    else startActivity(new Intent(Intent.ACTION_VIEW, u));
                } catch (Exception e) {
                    Toast.makeText(WebActivity.this, R.string.cant_open, Toast.LENGTH_SHORT).show();
                }
                return true;
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                progress.setVisibility(View.VISIBLE);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                progress.setVisibility(View.GONE);
            }

            @Override
            @SuppressWarnings("deprecation")
            public void onReceivedError(WebView view, int code, String desc, String failingUrl) {
                error.setVisibility(View.VISIBLE);
                error.setText(getString(R.string.err_network));
            }
        });
        if ("/family".equals(path) && Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, REQ_NOTIF);
        }
        // Make sure this phone has its PayGuard identity before the page asks for it.
        new Thread(() -> {
            Family.ensureDevice(getApplicationContext(), true);
            Family.schedule(getApplicationContext());
            main.post(() -> web.loadUrl(server + path));
        }).start();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Alerts seen on the page shouldn't pop up again as notifications.
        new Thread(() -> Family.poll(getApplicationContext(), false)).start();
    }
}
