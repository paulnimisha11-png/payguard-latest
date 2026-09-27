package app.payguard.shield;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/**
 * Hands a checked upi:// link to a real UPI app (never back to PayGuard itself, so there is no loop even when
 * PayGuard is the default UPI handler). If the original caller expects a result (merchant apps call UPI with
 * startActivityForResult), the result is passed straight back to them.
 */
public final class UpiLauncher {
    private UpiLauncher() {}

    public interface Done {
        void launched(String pkg);
    }

    public static List<ResolveInfo> upiApps(Activity a, Uri uri) {
        Intent probe = new Intent(Intent.ACTION_VIEW, uri);
        PackageManager pm = a.getPackageManager();
        List<ResolveInfo> all;
        if (Build.VERSION.SDK_INT >= 33) {
            all = pm.queryIntentActivities(probe, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_ALL));
        } else {
            all = pm.queryIntentActivities(probe, PackageManager.MATCH_ALL);
        }
        List<ResolveInfo> out = new ArrayList<>();
        String me = a.getPackageName();
        String last = Prefs.lastUpiApp(a);
        for (ResolveInfo ri : all) {
            if (ri.activityInfo == null || me.equals(ri.activityInfo.packageName)) continue;
            boolean dup = false;
            for (ResolveInfo o : out) if (o.activityInfo.packageName.equals(ri.activityInfo.packageName)) dup = true;
            if (dup) continue;
            if (ri.activityInfo.packageName.equals(last)) out.add(0, ri); else out.add(ri);
        }
        return out;
    }

    /** Opens the link in a UPI app. Shows a picker when several are installed (last used first). */
    public static void pay(Activity a, Uri uri, boolean forResult, int requestCode, Done done) {
        List<ResolveInfo> apps = upiApps(a, uri);
        if (apps.isEmpty()) {
            Toast.makeText(a, R.string.no_upi_app, Toast.LENGTH_LONG).show();
            return;
        }
        if (apps.size() == 1) {
            start(a, uri, apps.get(0), forResult, requestCode, done);
            return;
        }
        PackageManager pm = a.getPackageManager();
        CharSequence[] labels = new CharSequence[apps.size()];
        for (int i = 0; i < apps.size(); i++) labels[i] = apps.get(i).loadLabel(pm);
        new AlertDialog.Builder(a)
                .setTitle(R.string.pay_with)
                .setItems(labels, (dlg, which) -> start(a, uri, apps.get(which), forResult, requestCode, done))
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private static void start(Activity a, Uri uri, ResolveInfo ri, boolean forResult, int requestCode, Done done) {
        Intent i = new Intent(Intent.ACTION_VIEW, uri);
        // Use setPackage so Google Pay / other UPI apps can resolve to their preferred entry activity
        // (setClassName with internal unexported activities causes ActivityNotFound/SecurityException on GPay)
        i.setPackage(ri.activityInfo.packageName);
        try {
            Prefs.setLastUpiApp(a, ri.activityInfo.packageName);
            if (forResult) a.startActivityForResult(i, requestCode); else a.startActivity(i);
            if (done != null) done.launched(ri.activityInfo.packageName);
        } catch (ActivityNotFoundException | SecurityException e) {
            try {
                i.setClassName(ri.activityInfo.packageName, ri.activityInfo.name);
                if (forResult) a.startActivityForResult(i, requestCode); else a.startActivity(i);
                if (done != null) done.launched(ri.activityInfo.packageName);
            } catch (Exception ex) {
                Toast.makeText(a, R.string.upi_open_failed, Toast.LENGTH_LONG).show();
            }
        }
    }

    /** Fallback when a UPI app refuses link payments: just open the app so the user can pay by UPI ID. */
    public static void openAppHome(Activity a) {
        String pkg = Prefs.lastUpiApp(a);
        Intent launch = pkg.isEmpty() ? null : a.getPackageManager().getLaunchIntentForPackage(pkg);
        if (launch == null) {
            List<ResolveInfo> apps = upiApps(a, Uri.parse("upi://pay"));
            if (!apps.isEmpty()) launch = a.getPackageManager().getLaunchIntentForPackage(apps.get(0).activityInfo.packageName);
        }
        if (launch != null) a.startActivity(launch);
        else Toast.makeText(a, R.string.no_upi_app, Toast.LENGTH_LONG).show();
    }
}
