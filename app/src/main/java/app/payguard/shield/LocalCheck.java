package app.payguard.shield;

import android.net.Uri;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Offline fallback when the PayGuard server can't be reached. Applies the most important UPI rules on the
 * phone so a scam can still be stopped. It never returns "low": without the server the best it can say is
 * "check before you pay", so safe payments are never auto-forwarded without the full check.
 */
public final class LocalCheck {
    private LocalCheck() {}

    private static final String[] LURE = {"refund", "cashback", "cash back", "reward", "prize", "lottery", "winning", "winner",
            "receive", "credit", "bonus", "kyc", "verify", "unblock", "blocked", "gift", "lucky", "claim", "security deposit",
            "customs", "electricity", "income tax", "loan approved", "army"};
    private static final String[] AUTHORITY = {"customer care", "support", "helpline", "refund", "police", "government", "govt",
            "rbi", "npci", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "google pay", "amazon", "flipkart", "electricity", "army"};
    private static final Pattern VPA = Pattern.compile("^[A-Za-z0-9.\\-_]{2,256}@[A-Za-z0-9]{2,64}$");

    public static JSONObject analyze(String payload) {
        try {
            JSONObject r = new JSONObject();
            r.put("kind", "qr");
            r.put("payload", payload);
            r.put("offline", true);
            JSONArray findings = new JSONArray();
            int score = 0;
            boolean critical = false;
            JSONObject d = new JSONObject();
            String low = payload.toLowerCase(Locale.ROOT);

            if (low.startsWith("upi://")) {
                Uri u = Uri.parse(payload);
                String action = u.getHost() == null ? "pay" : u.getHost().toLowerCase(Locale.ROOT);
                String pa = nz(u.getQueryParameter("pa"));
                String pn = nz(u.getQueryParameter("pn"));
                String tn = nz(u.getQueryParameter("tn"));
                String am = nz(u.getQueryParameter("am"));
                String mc = nz(u.getQueryParameter("mc"));
                d.put("type", "upi");
                d.put("action", action);
                d.put("payee_vpa", pa);
                d.put("payee_name", pn);
                d.put("note", tn);
                try {
                    if (!am.isEmpty()) d.put("amount", Double.parseDouble(am));
                } catch (NumberFormatException ignored) { }
                boolean merchant = (!mc.isEmpty() && !"0000".equals(mc)) || u.getQueryParameter("sign") != null;
                d.put("is_merchant", merchant);

                if ("mandate".equals(action) || u.getQueryParameter("recur") != null) {
                    findings.put(f("AUTOPAY_MANDATE", "critical", 45,
                            "Sets up AUTOMATIC repeated payments", "आपके खाते से अपने-आप बार-बार पैसे कटने की मंज़ूरी लेता है", "ಸ್ವಯಂಚಾಲಿತ ಪುನರಾವರ್ತಿತ ಪಾವತಿ ಹೊಂದಿಸುತ್ತದೆ",
                            "Approving it lets the payee take money again and again.", "मंज़ूर करते ही सामने वाला बार-बार पैसे निकाल सकता है।", "ಒಪ್ಪಿದರೆ ಅವರು ಮತ್ತೆ ಮತ್ತೆ ಹಣ ತೆಗೆಯಬಹುದು."));
                    score += 45; critical = true;
                }
                if ("collect".equals(action)) {
                    findings.put(f("COLLECT_REQUEST", "high", 25,
                            "This is a request for YOU to pay", "इसमें आपसे पैसे माँगे जा रहे हैं", "ಇದು ನಿಮ್ಮಿಂದ ಹಣ ಕೇಳುತ್ತದೆ",
                            "Accepting and entering your PIN pays them.", "स्वीकार करके PIN डालते ही पैसे उनके पास चले जाते हैं।", "ಒಪ್ಪಿ PIN ಹಾಕಿದರೆ ಹಣ ಅವರಿಗೆ ಹೋಗುತ್ತದೆ."));
                    score += 25;
                }
                String hay = (tn + " " + pn).toLowerCase(Locale.ROOT);
                if (containsWord(hay, LURE)) {
                    findings.put(f("RECEIVE_MONEY_LURE", "critical", 50,
                            "Pretends you will RECEIVE money — but you will PAY", "दिखाता है कि आपको पैसे मिलेंगे — असल में आप पैसे देंगे", "ನಿಮಗೆ ಹಣ ಬರುತ್ತದೆ ಎಂದು ನಟಿಸುತ್ತದೆ — ಆದರೆ ನೀವೇ ಪಾವತಿಸುತ್ತೀರಿ",
                            "You never scan a QR or enter your UPI PIN to receive money.", "पैसे पाने के लिए कभी QR स्कैन या UPI PIN डालने की ज़रूरत नहीं होती।", "ಹಣ ಪಡೆಯಲು QR ಸ್ಕ್ಯಾನ್ ಅಥವಾ UPI PIN ಎಂದಿಗೂ ಬೇಕಾಗುವುದಿಲ್ಲ."));
                    score += 50; critical = true;
                }
                if (!merchant && containsWord(pn.toLowerCase(Locale.ROOT), AUTHORITY)) {
                    findings.put(f("IMPERSONATION", "high", 30,
                            "Name looks official, but money goes to a personal account", "नाम सरकारी/कंपनी जैसा है, पर पैसे निजी खाते में जाते हैं", "ಹೆಸರು ಅಧಿಕೃತದಂತೆ, ಆದರೆ ಹಣ ವೈಯಕ್ತಿಕ ಖಾತೆಗೆ",
                            "Banks, companies and government offices never collect money through a personal UPI ID.", "बैंक, कंपनियाँ और सरकारी दफ़्तर निजी UPI ID से पैसे नहीं लेते।", "ಬ್ಯಾಂಕ್‌ಗಳು ಮತ್ತು ಸರ್ಕಾರಿ ಕಚೇರಿಗಳು ವೈಯಕ್ತಿಕ UPI ID ಮೂಲಕ ಹಣ ಪಡೆಯುವುದಿಲ್ಲ."));
                    score += 30;
                }
                if (!VPA.matcher(pa).matches()) {
                    findings.put(f("INVALID_UPI_ID", "high", 25,
                            "The payment address is broken or missing", "पेमेंट का पता गलत है या नहीं है", "ಪಾವತಿ ವಿಳಾಸ ತಪ್ಪಾಗಿದೆ ಅಥವಾ ಇಲ್ಲ",
                            "A genuine UPI QR always has a UPI ID like name@bank.", "असली UPI QR में हमेशा name@bank जैसी UPI ID होती है।", "ನಿಜವಾದ UPI QR ನಲ್ಲಿ name@bank ನಂತಹ UPI ID ಇರುತ್ತದೆ."));
                    score += 25;
                }
            } else {
                d.put("type", low.startsWith("http") ? "url" : "text");
                if (low.startsWith("http")) {
                    Uri u = Uri.parse(payload);
                    d.put("url", payload);
                    d.put("host", nz(u.getHost()));
                    d.put("registered_domain", nz(u.getHost()));
                }
            }
            r.put("details", d);
            findings.put(f("OFFLINE", "info", 0,
                    "Checked on your phone only (server not reachable)", "सिर्फ़ फ़ोन पर जाँचा गया (सर्वर से संपर्क नहीं हुआ)", "ಫೋನ್‌ನಲ್ಲಿ ಮಾತ್ರ ಪರಿಶೀಲಿಸಲಾಗಿದೆ (ಸರ್ವರ್ ಸಿಗಲಿಲ್ಲ)",
                    "Only the basic rules ran. Connect to the internet for the full check.", "सिर्फ़ बुनियादी जाँच हुई। पूरी जाँच के लिए इंटरनेट से जुड़ें।", "ಮೂಲ ಪರಿಶೀಲನೆ ಮಾತ್ರ ನಡೆಯಿತು. ಪೂರ್ಣ ಪರಿಶೀಲನೆಗೆ ಇಂಟರ್ನೆಟ್ ಸಂಪರ್ಕಿಸಿ."));
            r.put("findings", findings);

            if (critical) score = Math.max(score, 70);
            score = Math.min(score, 100);
            JSONObject v = new JSONObject();
            v.put("score", score);
            if (score >= 70) {
                v.put("level", "danger");
                v.put("headline", t("Do NOT pay", "पैसे न भेजें", "ಪಾವತಿಸಬೇಡಿ"));
                v.put("advice", t("This matches a known payment scam. If you already paid, call 1930 now.",
                        "यह जानी-मानी पेमेंट ठगी से मेल खाता है। पैसे भेज चुके हैं तो अभी 1930 पर कॉल करें।",
                        "ಇದು ತಿಳಿದಿರುವ ಪಾವತಿ ವಂಚನೆಗೆ ಹೊಂದುತ್ತದೆ. ಈಗಾಗಲೇ ಪಾವತಿಸಿದ್ದರೆ ಈಗಲೇ 1930 ಗೆ ಕರೆ ಮಾಡಿ."));
            } else if (score >= 40) {
                v.put("level", "suspicious");
                v.put("headline", t("Very suspicious — don't pay", "बहुत संदिग्ध — पैसे न भेजें", "ತುಂಬಾ ಸಂಶಯಾಸ್ಪದ — ಪಾವತಿಸಬೇಡಿ"));
                v.put("advice", t("Only pay if you personally know who this is.", "पैसे तभी भेजें जब आप इन्हें खुद जानते हों।", "ಇವರು ಯಾರು ಎಂದು ಖಚಿತವಾಗಿ ಗೊತ್ತಿದ್ದರೆ ಮಾತ್ರ ಪಾವತಿಸಿ."));
            } else {
                v.put("level", "caution");
                v.put("headline", t("Check before you pay", "पैसे भेजने से पहले जाँचें", "ಪಾವತಿಸುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ"));
                v.put("advice", t("No scam signs in the basic check. Confirm the name your UPI app shows before entering your PIN.",
                        "बुनियादी जाँच में ठगी के संकेत नहीं। PIN डालने से पहले UPI ऐप में दिखा नाम पक्का करें।",
                        "ಮೂಲ ಪರಿಶೀಲನೆಯಲ್ಲಿ ವಂಚನೆ ಲಕ್ಷಣಗಳಿಲ್ಲ. PIN ಹಾಕುವ ಮೊದಲು UPI ಆ್ಯಪ್ ತೋರಿಸುವ ಹೆಸರು ಖಚಿತಪಡಿಸಿ."));
            }
            r.put("verdict", v);
            return r;
        } catch (JSONException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s.trim();
    }

    private static boolean containsWord(String hay, String[] words) {
        for (String w : words) {
            if (Pattern.compile("(?<![a-z])" + Pattern.quote(w) + "(?![a-z])").matcher(hay).find()) return true;
        }
        return false;
    }

    private static JSONObject t(String en, String hi, String kn) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("en", en);
        o.put("hi", hi);
        o.put("kn", kn);
        return o;
    }

    private static JSONObject f(String id, String sev, int pts, String te, String th, String tk, String de, String dh, String dk)
            throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("severity", sev);
        o.put("points", pts);
        o.put("title", t(te, th, tk));
        o.put("detail", t(de, dh, dk));
        o.put("evidence", new JSONArray());
        return o;
    }
}
