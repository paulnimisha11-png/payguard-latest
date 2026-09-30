package app.payguard.shield;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.TypedValue;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

/** View helpers shared by the screens. */
public final class Ui {
    private Ui() {}

    public static int dp(Context c, float v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics()));
    }

    public static int levelColor(String level) {
        switch (level == null ? "" : level) {
            case "danger": return Color.parseColor("#B3122F");
            case "suspicious": return Color.parseColor("#C2410C");
            case "caution": return Color.parseColor("#A16207");
            case "low": return Color.parseColor("#1E7D4F");
            default: return Color.parseColor("#4F46E5");
        }
    }

    public static int sevColor(String sev) {
        switch (sev == null ? "" : sev) {
            case "critical": return Color.parseColor("#C02640");
            case "high": return Color.parseColor("#D9480F");
            case "medium": return Color.parseColor("#B7791F");
            case "low": return Color.parseColor("#2F855A");
            default: return Color.parseColor("#5B6078");
        }
    }

    /** Text in the chosen language from a {"en":..,"hi":..,"kn":..} object. */
    public static String tr(JSONObject o, String lang) {
        if (o == null) return "";
        String s = o.optString(lang, "");
        return s.isEmpty() ? o.optString("en", "") : s;
    }

    public static GradientDrawable rounded(int color, float radiusDp, Context c) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(c, radiusDp));
        return g;
    }

    public static TextView text(Context c, String s, float sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    /** One finding: severity chip + title + plain-language detail. */
    public static LinearLayout finding(Context c, JSONObject f, String lang) {
        LinearLayout box = new LinearLayout(c);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(c, 14);
        box.setPadding(pad, pad, pad, pad);
        GradientDrawable bg = rounded(Color.WHITE, 14, c);
        bg.setStroke(dp(c, 1), Color.parseColor("#E2E4EE"));
        box.setBackground(bg);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(c, 10);
        box.setLayoutParams(lp);

        String sev = f.optString("severity", "info");
        TextView chip = text(c, sev.toUpperCase(java.util.Locale.ROOT), 11, sevColor(sev), true);
        chip.setLetterSpacing(0.06f);
        box.addView(chip);

        TextView title = text(c, tr(f.optJSONObject("title"), lang), 16, Color.parseColor("#161A2C"), true);
        title.setPadding(0, dp(c, 4), 0, dp(c, 4));
        box.addView(title);
        box.addView(text(c, tr(f.optJSONObject("detail"), lang), 14, Color.parseColor("#5B6078"), false));
        return box;
    }

    public static TextView label(Context c, String s) {
        TextView t = text(c, s, 12, Color.parseColor("#5B6078"), true);
        t.setAllCaps(true);
        t.setLetterSpacing(0.05f);
        return t;
    }

    public static TextView centered(TextView t) {
        t.setGravity(Gravity.CENTER);
        return t;
    }
}
