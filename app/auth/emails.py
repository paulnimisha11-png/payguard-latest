"""Account emails in English / Hindi / Kannada. Inline styles only (email apps ignore <style>)."""
from __future__ import annotations

import datetime as dt
import html as _h

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))

S = {
    "en": {
        "welcome_subject": "Welcome to PayGuard",
        "welcome_title": "You're in, {name}.",
        "welcome_body": "Your PayGuard account is ready. Your checks, family links and settings are saved to it, and you stay signed in on this device until you sign out.",
        "verify_cta": "Confirm my email",
        "verify_note": "Confirming lets us send you security alerts and password resets. The link works for 24 hours.",
        "login_subject": "New sign-in to your PayGuard account",
        "login_title": "New sign-in",
        "login_body": "Your PayGuard account was just signed in to.",
        "when": "When", "device": "Device", "network": "Network",
        "login_ok": "If this was you, there's nothing to do.",
        "login_bad": "Not you? Reset your password now. That signs out every device.",
        "reset_cta": "Reset my password",
        "reset_subject": "Reset your PayGuard password",
        "reset_title": "Reset your password",
        "reset_body": "Someone (hopefully you) asked to reset the password for this account. The link works for 1 hour and only once.",
        "reset_ignore": "Didn't ask? Ignore this email; your password won't change.",
        "changed_subject": "Your PayGuard password was changed",
        "changed_title": "Password changed",
        "changed_body": "The password for your PayGuard account was just changed and other devices were signed out.",
        "changed_bad": "Not you? Reset your password immediately.",
        "footer": "PayGuard never asks for your OTP, PIN or password by email, phone or chat.",
    },
    "hi": {
        "welcome_subject": "PayGuard में आपका स्वागत है",
        "welcome_title": "स्वागत है, {name}।",
        "welcome_body": "आपका PayGuard खाता तैयार है। आपकी जाँचें, परिवार लिंक और सेटिंग्स इसमें सेव रहती हैं, और साइन आउट करने तक आप इस डिवाइस पर साइन इन रहेंगे।",
        "verify_cta": "मेरा ईमेल पक्का करें",
        "verify_note": "ईमेल पक्का करने से हम आपको सुरक्षा अलर्ट और पासवर्ड रीसेट भेज सकते हैं। लिंक 24 घंटे तक काम करेगा।",
        "login_subject": "आपके PayGuard खाते में नया साइन-इन",
        "login_title": "नया साइन-इन",
        "login_body": "अभी आपके PayGuard खाते में साइन इन किया गया।",
        "when": "कब", "device": "डिवाइस", "network": "नेटवर्क",
        "login_ok": "अगर यह आप थे, तो कुछ करने की ज़रूरत नहीं।",
        "login_bad": "आप नहीं थे? अभी पासवर्ड रीसेट करें। इससे सभी डिवाइस साइन आउट हो जाएँगे।",
        "reset_cta": "पासवर्ड रीसेट करें",
        "reset_subject": "अपना PayGuard पासवर्ड रीसेट करें",
        "reset_title": "पासवर्ड रीसेट करें",
        "reset_body": "किसी ने (उम्मीद है आपने) इस खाते का पासवर्ड रीसेट करने को कहा। लिंक 1 घंटे तक और सिर्फ़ एक बार काम करेगा।",
        "reset_ignore": "आपने नहीं माँगा? यह ईमेल अनदेखा करें; पासवर्ड नहीं बदलेगा।",
        "changed_subject": "आपका PayGuard पासवर्ड बदला गया",
        "changed_title": "पासवर्ड बदला गया",
        "changed_body": "आपके PayGuard खाते का पासवर्ड अभी बदला गया और बाकी डिवाइस साइन आउट कर दिए गए।",
        "changed_bad": "आप नहीं थे? तुरंत पासवर्ड रीसेट करें।",
        "footer": "PayGuard कभी भी ईमेल, फ़ोन या चैट पर आपका OTP, PIN या पासवर्ड नहीं माँगता।",
    },
    "kn": {
        "welcome_subject": "PayGuard ಗೆ ಸ್ವಾಗತ",
        "welcome_title": "ಸ್ವಾಗತ, {name}.",
        "welcome_body": "ನಿಮ್ಮ PayGuard ಖಾತೆ ಸಿದ್ಧವಾಗಿದೆ. ನಿಮ್ಮ ಪರಿಶೀಲನೆಗಳು, ಕುಟುಂಬ ಲಿಂಕ್‌ಗಳು ಮತ್ತು ಸೆಟ್ಟಿಂಗ್‌ಗಳು ಇದರಲ್ಲಿ ಉಳಿಯುತ್ತವೆ; ಸೈನ್ ಔಟ್ ಮಾಡುವವರೆಗೆ ಈ ಸಾಧನದಲ್ಲಿ ಸೈನ್ ಇನ್ ಆಗಿರುತ್ತೀರಿ.",
        "verify_cta": "ನನ್ನ ಇಮೇಲ್ ಖಚಿತಪಡಿಸಿ",
        "verify_note": "ಇಮೇಲ್ ಖಚಿತಪಡಿಸಿದರೆ ಭದ್ರತಾ ಎಚ್ಚರಿಕೆ ಮತ್ತು ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಕಳುಹಿಸಬಹುದು. ಲಿಂಕ್ 24 ಗಂಟೆ ಕೆಲಸ ಮಾಡುತ್ತದೆ.",
        "login_subject": "ನಿಮ್ಮ PayGuard ಖಾತೆಗೆ ಹೊಸ ಸೈನ್-ಇನ್",
        "login_title": "ಹೊಸ ಸೈನ್-ಇನ್",
        "login_body": "ಈಗಷ್ಟೇ ನಿಮ್ಮ PayGuard ಖಾತೆಗೆ ಸೈನ್ ಇನ್ ಮಾಡಲಾಗಿದೆ.",
        "when": "ಯಾವಾಗ", "device": "ಸಾಧನ", "network": "ನೆಟ್‌ವರ್ಕ್",
        "login_ok": "ಇದು ನೀವೇ ಆಗಿದ್ದರೆ ಏನೂ ಮಾಡಬೇಕಿಲ್ಲ.",
        "login_bad": "ನೀವಲ್ಲವೇ? ಈಗಲೇ ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಮಾಡಿ. ಇದರಿಂದ ಎಲ್ಲ ಸಾಧನಗಳು ಸೈನ್ ಔಟ್ ಆಗುತ್ತವೆ.",
        "reset_cta": "ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಮಾಡಿ",
        "reset_subject": "ನಿಮ್ಮ PayGuard ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಮಾಡಿ",
        "reset_title": "ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್",
        "reset_body": "ಯಾರೋ (ಬಹುಶಃ ನೀವು) ಈ ಖಾತೆಯ ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಕೇಳಿದ್ದಾರೆ. ಲಿಂಕ್ 1 ಗಂಟೆ ಮತ್ತು ಒಮ್ಮೆ ಮಾತ್ರ ಕೆಲಸ ಮಾಡುತ್ತದೆ.",
        "reset_ignore": "ನೀವು ಕೇಳಿಲ್ಲವೇ? ಈ ಇಮೇಲ್ ಕಡೆಗಣಿಸಿ; ಪಾಸ್‌ವರ್ಡ್ ಬದಲಾಗುವುದಿಲ್ಲ.",
        "changed_subject": "ನಿಮ್ಮ PayGuard ಪಾಸ್‌ವರ್ಡ್ ಬದಲಾಗಿದೆ",
        "changed_title": "ಪಾಸ್‌ವರ್ಡ್ ಬದಲಾಗಿದೆ",
        "changed_body": "ನಿಮ್ಮ PayGuard ಖಾತೆಯ ಪಾಸ್‌ವರ್ಡ್ ಈಗಷ್ಟೇ ಬದಲಾಗಿದೆ ಮತ್ತು ಇತರ ಸಾಧನಗಳು ಸೈನ್ ಔಟ್ ಆಗಿವೆ.",
        "changed_bad": "ನೀವಲ್ಲವೇ? ತಕ್ಷಣ ಪಾಸ್‌ವರ್ಡ್ ರೀಸೆಟ್ ಮಾಡಿ.",
        "footer": "PayGuard ಎಂದಿಗೂ ಇಮೇಲ್, ಫೋನ್ ಅಥವಾ ಚಾಟ್‌ನಲ್ಲಿ ನಿಮ್ಮ OTP, PIN ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಕೇಳುವುದಿಲ್ಲ.",
    },
}


def _t(lang: str, key: str, **kw) -> str:
    return (S.get(lang) or S["en"]).get(key, S["en"][key]).format(**kw)


def _layout(title: str, paragraphs: list[str], button: tuple[str, str] | None = None, rows: list[tuple[str, str]] | None = None,
            lang: str = "en") -> str:
    e = _h.escape
    body = "".join(f'<p style="margin:0 0 14px;color:#c9ccd6;font-size:15px;line-height:1.6">{e(p)}</p>' for p in paragraphs)
    if rows:
        body += '<table role="presentation" style="width:100%;border-collapse:collapse;margin:4px 0 16px">' + "".join(
            f'<tr><td style="padding:8px 10px;color:#8b90a3;font-size:13px;border-top:1px solid #2a1418;width:32%">{e(k)}</td>'
            f'<td style="padding:8px 10px;color:#f1f2f6;font-size:14px;border-top:1px solid #2a1418">{e(v)}</td></tr>' for k, v in rows) + "</table>"
    if button:
        body += (f'<p style="margin:22px 0"><a href="{e(button[1])}" style="background:#e11d2e;color:#fff;text-decoration:none;'
                 f'padding:13px 22px;border-radius:10px;font-weight:700;letter-spacing:.04em;display:inline-block">{e(button[0])}</a></p>'
                 f'<p style="margin:0 0 14px;color:#6b7086;font-size:12px;word-break:break-all">{e(button[1])}</p>')
    return f"""<!doctype html><html lang="{e(lang)}"><body style="margin:0;background:#050506;padding:24px 12px;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" style="max-width:560px;margin:0 auto;width:100%;background:#0d0d10;border:1px solid #3a0d14;border-radius:16px">
<tr><td style="padding:22px 26px;border-bottom:1px solid #2a1418">
<span style="color:#ff2d3d;font-weight:800;letter-spacing:.18em;font-size:13px">&#9670; PAYGUARD</span></td></tr>
<tr><td style="padding:26px">
<h1 style="margin:0 0 16px;color:#fff;font-size:22px">{e(title)}</h1>{body}</td></tr>
<tr><td style="padding:16px 26px;border-top:1px solid #2a1418;color:#6b7086;font-size:12px">{e(_t(lang, "footer"))}</td></tr>
</table></body></html>"""


def _text(title: str, paragraphs: list[str], button: tuple[str, str] | None = None, rows=None) -> str:
    out = [title, ""] + paragraphs
    if rows:
        out += [f"{k}: {v}" for k, v in rows]
    if button:
        out += ["", f"{button[0]}: {button[1]}"]
    return "\n".join(out)


def when(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, IST).strftime("%d %b %Y, %I:%M %p IST")


def welcome(lang: str, name: str, verify_url: str) -> tuple[str, str, str]:
    title = _t(lang, "welcome_title", name=name or "there")
    paras = [_t(lang, "welcome_body"), _t(lang, "verify_note")]
    btn = (_t(lang, "verify_cta"), verify_url)
    return _t(lang, "welcome_subject"), _layout(title, paras, btn, lang=lang), _text(title, paras, btn)


def login_alert(lang: str, ts: float, device: str, network: str, reset_url: str) -> tuple[str, str, str]:
    title = _t(lang, "login_title")
    rows = [(_t(lang, "when"), when(ts)), (_t(lang, "device"), device), (_t(lang, "network"), network)]
    paras = [_t(lang, "login_body")]
    tail = [_t(lang, "login_ok"), _t(lang, "login_bad")]
    btn = (_t(lang, "reset_cta"), reset_url)
    html = _layout(title, paras, None, rows, lang)
    html = html.replace("</td></tr>\n<tr><td style=\"padding:16px 26px", "".join(
        f'<p style="margin:0 0 14px;color:#c9ccd6;font-size:15px;line-height:1.6">{_h.escape(p)}</p>' for p in tail)
        + f'<p style="margin:18px 0"><a href="{_h.escape(reset_url)}" style="background:#e11d2e;color:#fff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:700;display:inline-block">{_h.escape(btn[0])}</a></p>'
        + "</td></tr>\n<tr><td style=\"padding:16px 26px", 1)
    return _t(lang, "login_subject"), html, _text(title, paras + tail, btn, rows)


def reset(lang: str, url: str) -> tuple[str, str, str]:
    title = _t(lang, "reset_title")
    paras = [_t(lang, "reset_body"), _t(lang, "reset_ignore")]
    btn = (_t(lang, "reset_cta"), url)
    return _t(lang, "reset_subject"), _layout(title, paras, btn, lang=lang), _text(title, paras, btn)


def password_changed(lang: str, url: str) -> tuple[str, str, str]:
    title = _t(lang, "changed_title")
    paras = [_t(lang, "changed_body"), _t(lang, "changed_bad")]
    btn = (_t(lang, "reset_cta"), url)
    return _t(lang, "changed_subject"), _layout(title, paras, btn, lang=lang), _text(title, paras, btn)
