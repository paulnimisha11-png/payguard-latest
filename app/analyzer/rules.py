"""Rule engine.

Each rule looks at the extracted `facts` and may emit a Finding with a
severity, a score contribution, and a plain-language explanation in English,
Hindi and Kannada. Rules are about *combinations* of capabilities, because a
single permission rarely proves anything, while certain combinations are the
recognised fingerprint of banking trojans and SMS stealers.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    id: str
    severity: str
    points: int
    title: dict
    detail: dict
    evidence: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def T(en, hi, kn):
    return {"en": en, "hi": hi, "kn": kn}


RULES: list[Callable[[dict], Finding | None]] = []


def rule(fn):
    RULES.append(fn)
    return fn


# ---------------------------------------------------------------- core combos

@rule
def banking_trojan_triad(f):
    c = f["caps"]
    if c["sms_any"] and c["accessibility"] and c["overlay"]:
        return Finding(
            "BANKING_TROJAN_TRIAD", "critical", 60,
            T("Banking-trojan signature: SMS + Accessibility + Screen overlay",
              "बैंकिंग ट्रोजन की पहचान: SMS + एक्सेसिबिलिटी + स्क्रीन ओवरले",
              "ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್ ಲಕ್ಷಣ: SMS + ಆಕ್ಸೆಸಿಬಿಲಿಟಿ + ಸ್ಕ್ರೀನ್ ಓವರ್‌ಲೇ"),
            T("This app wants to read your SMS messages AND draw over other apps AND use Accessibility services. "
              "This exact combination is how banking trojans steal OTPs and take over your bank app. "
              "Real courier, bill or bank apps never need all three.",
              "यह ऐप आपके SMS पढ़ना चाहता है, दूसरे ऐप्स के ऊपर अपनी स्क्रीन दिखाना चाहता है, और एक्सेसिबिलिटी सर्विस "
              "इस्तेमाल करना चाहता है। बैंकिंग ट्रोजन ठीक इन्हीं तीनों से OTP चुराते हैं और आपका बैंक ऐप अपने कब्ज़े में ले लेते हैं। "
              "असली कूरियर, बिल या बैंक ऐप को इन तीनों की कभी ज़रूरत नहीं होती।",
              "ಈ ಆ್ಯಪ್ ನಿಮ್ಮ SMS ಓದಲು, ಬೇರೆ ಆ್ಯಪ್‌ಗಳ ಮೇಲೆ ತನ್ನ ಪರದೆ ತೋರಿಸಲು ಮತ್ತು ಆಕ್ಸೆಸಿಬಿಲಿಟಿ ಸೇವೆ ಬಳಸಲು ಕೇಳುತ್ತಿದೆ. "
              "ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್‌ಗಳು OTP ಕದಿಯಲು ಮತ್ತು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ಅನ್ನು ನಿಯಂತ್ರಿಸಲು ಇದೇ ಮೂರನ್ನು ಬಳಸುತ್ತವೆ. "
              "ನಿಜವಾದ ಕೊರಿಯರ್, ಬಿಲ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್‌ಗಳಿಗೆ ಈ ಮೂರೂ ಎಂದಿಗೂ ಬೇಕಾಗುವುದಿಲ್ಲ."),
            f["ev"]["sms"] + f["ev"]["accessibility"] + f["ev"]["overlay"],
        )


@rule
def sms_otp_theft(f):
    c = f["caps"]
    if not (c["sms_any"] and c["internet"]):
        return None
    strong = c["sms_receiver"] or c["sms_read_api"] or c["sms_inbox_query"]
    return Finding(
        "SMS_OTP_THEFT", "critical" if strong else "high", 35 if strong else 20,
        T("Can read your OTPs and send them over the internet",
          "आपके OTP पढ़कर इंटरनेट से कहीं और भेज सकता है",
          "ನಿಮ್ಮ OTP ಓದಿ ಇಂಟರ್ನೆಟ್ ಮೂಲಕ ಬೇರೆಡೆಗೆ ಕಳುಹಿಸಬಹುದು"),
        T("The app can read incoming SMS and also has internet access. " +
          ("Its code actually listens for new SMS and pulls out the message text — that is how OTP stealers work. " if strong else "") +
          "Anyone who gets your OTP can empty your bank account or take over your UPI.",
          "यह ऐप आने वाले SMS पढ़ सकता है और इसके पास इंटरनेट भी है। " +
          ("इसका कोड नए SMS का इंतज़ार करता है और उनका मैसेज निकाल लेता है — OTP चोर ऐप ऐसे ही काम करते हैं। " if strong else "") +
          "जिसके पास आपका OTP पहुँच गया, वह आपका बैंक खाता खाली कर सकता है या आपका UPI अपने कब्ज़े में ले सकता है।",
          "ಈ ಆ್ಯಪ್ ಬರುವ SMS ಓದಬಲ್ಲದು ಮತ್ತು ಅದಕ್ಕೆ ಇಂಟರ್ನೆಟ್ ಕೂಡ ಇದೆ. " +
          ("ಇದರ ಕೋಡ್ ಹೊಸ SMS ಗಾಗಿ ಕಾಯುತ್ತದೆ ಮತ್ತು ಸಂದೇಶದ ಪಠ್ಯವನ್ನು ತೆಗೆದುಕೊಳ್ಳುತ್ತದೆ — OTP ಕಳ್ಳ ಆ್ಯಪ್‌ಗಳು ಹೀಗೆಯೇ ಕೆಲಸ ಮಾಡುತ್ತವೆ. " if strong else "") +
          "ನಿಮ್ಮ OTP ಸಿಕ್ಕವರು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಖಾಲಿ ಮಾಡಬಹುದು ಅಥವಾ ನಿಮ್ಮ UPI ಅನ್ನು ತಮ್ಮ ವಶಕ್ಕೆ ಪಡೆಯಬಹುದು."),
        f["ev"]["sms"] + f["ev"]["sms_code"],
    )


@rule
def telegram_exfil(f):
    if f["caps"]["telegram_bot"]:
        return Finding(
            "TELEGRAM_EXFILTRATION", "critical", 40,
            T("Sends data to a hidden Telegram bot",
              "छिपे हुए Telegram बॉट को डेटा भेजता है",
              "ಗುಪ್ತ Telegram ಬಾಟ್‌ಗೆ ಡೇಟಾ ಕಳುಹಿಸುತ್ತದೆ"),
            T("The app contains a Telegram bot address. Many SMS-stealing apps spreading in India forward every OTP and "
              "message to the scammer's Telegram this way. Genuine apps have no reason to do this.",
              "इस ऐप में एक Telegram बॉट का पता छिपा है। भारत में फैल रहे कई SMS-चोर ऐप इसी तरह हर OTP और मैसेज "
              "ठग के Telegram पर भेज देते हैं। असली ऐप ऐसा कभी नहीं करते।",
              "ಈ ಆ್ಯಪ್‌ನಲ್ಲಿ Telegram ಬಾಟ್ ವಿಳಾಸ ಅಡಗಿದೆ. ಭಾರತದಲ್ಲಿ ಹರಡುತ್ತಿರುವ ಅನೇಕ SMS-ಕಳ್ಳ ಆ್ಯಪ್‌ಗಳು ಪ್ರತಿಯೊಂದು OTP ಮತ್ತು "
              "ಸಂದೇಶವನ್ನು ಹೀಗೆಯೇ ವಂಚಕರ Telegram ಗೆ ಕಳುಹಿಸುತ್ತವೆ. ನಿಜವಾದ ಆ್ಯಪ್‌ಗಳು ಹೀಗೆ ಮಾಡುವುದಿಲ್ಲ."),
            f["ev"]["telegram"],
        )


@rule
def accessibility_abuse(f):
    c = f["caps"]
    if c["accessibility"] and not (c["sms_any"] and c["overlay"]):
        return Finding(
            "ACCESSIBILITY_SERVICE", "high", 25,
            T("Wants to watch your screen and tap buttons for you",
              "आपकी स्क्रीन देखना और आपकी जगह बटन दबाना चाहता है",
              "ನಿಮ್ಮ ಪರದೆ ನೋಡಲು ಮತ್ತು ನಿಮ್ಮ ಬದಲು ಬಟನ್ ಒತ್ತಲು ಬಯಸುತ್ತದೆ"),
            T("Accessibility services are meant for people with disabilities. Malware abuses them to read everything on "
              "your screen (including passwords) and to approve payments or permissions on its own.",
              "एक्सेसिबिलिटी सर्विस दिव्यांग लोगों की मदद के लिए होती है। मैलवेयर इसका गलत इस्तेमाल करके आपकी स्क्रीन पर "
              "सब कुछ (पासवर्ड भी) पढ़ लेता है और खुद ही पेमेंट या परमिशन मंज़ूर कर देता है।",
              "ಆಕ್ಸೆಸಿಬಿಲಿಟಿ ಸೇವೆಗಳು ಅಂಗವಿಕಲರಿಗೆ ಸಹಾಯ ಮಾಡಲು ಇರುತ್ತವೆ. ಮಾಲ್‌ವೇರ್ ಇವುಗಳನ್ನು ದುರುಪಯೋಗ ಮಾಡಿ ನಿಮ್ಮ ಪರದೆಯ "
              "ಎಲ್ಲವನ್ನೂ (ಪಾಸ್‌ವರ್ಡ್ ಸಹ) ಓದುತ್ತದೆ ಮತ್ತು ತಾನೇ ಪಾವತಿ ಅಥವಾ ಅನುಮತಿಗಳನ್ನು ಒಪ್ಪಿಕೊಳ್ಳುತ್ತದೆ."),
            f["ev"]["accessibility"] + f["ev"]["accessibility_code"],
        )


@rule
def notification_listener(f):
    if f["caps"]["notif_listener"]:
        return Finding(
            "NOTIFICATION_SNOOPING", "high", 25,
            T("Reads all your notifications (OTPs show up there too)",
              "आपकी सारी नोटिफ़िकेशन पढ़ता है (OTP भी वहीं आते हैं)",
              "ನಿಮ್ಮ ಎಲ್ಲಾ ನೋಟಿಫಿಕೇಶನ್‌ಗಳನ್ನು ಓದುತ್ತದೆ (OTP ಕೂಡ ಅಲ್ಲೇ ಬರುತ್ತದೆ)"),
            T("A notification listener can read every notification — WhatsApp messages, bank alerts and OTPs — even without SMS permission.",
              "नोटिफ़िकेशन लिसनर हर नोटिफ़िकेशन पढ़ सकता है — WhatsApp मैसेज, बैंक अलर्ट और OTP — SMS परमिशन के बिना भी।",
              "ನೋಟಿಫಿಕೇಶನ್ ಲಿಸನರ್ ಪ್ರತಿಯೊಂದು ನೋಟಿಫಿಕೇಶನ್ ಓದಬಲ್ಲದು — WhatsApp ಸಂದೇಶಗಳು, ಬ್ಯಾಂಕ್ ಅಲರ್ಟ್‌ಗಳು ಮತ್ತು OTP — SMS ಅನುಮತಿ ಇಲ್ಲದೆಯೂ."),
            f["ev"]["notif"],
        )


@rule
def overlay_alone(f):
    c = f["caps"]
    if c["overlay"] and not (c["sms_any"] and c["accessibility"]):
        return Finding(
            "SCREEN_OVERLAY", "medium", 10,
            T("Can draw on top of other apps",
              "दूसरे ऐप्स के ऊपर दिख सकता है",
              "ಬೇರೆ ಆ್ಯಪ್‌ಗಳ ಮೇಲೆ ಕಾಣಿಸಿಕೊಳ್ಳಬಹುದು"),
            T("Overlay permission lets an app cover your real bank or UPI app with a fake login page.",
              "ओवरले परमिशन से ऐप आपके असली बैंक या UPI ऐप के ऊपर नकली लॉगिन पेज दिखा सकता है।",
              "ಓವರ್‌ಲೇ ಅನುಮತಿಯಿಂದ ಆ್ಯಪ್ ನಿಮ್ಮ ನಿಜವಾದ ಬ್ಯಾಂಕ್ ಅಥವಾ UPI ಆ್ಯಪ್ ಮೇಲೆ ನಕಲಿ ಲಾಗಿನ್ ಪುಟ ತೋರಿಸಬಹುದು."),
            f["ev"]["overlay"],
        )


@rule
def sms_send(f):
    c = f["caps"]
    if c["sms_send"]:
        return Finding(
            "SILENT_SMS_SENDING", "high", 20,
            T("Can send SMS from your number without telling you",
              "आपके नंबर से चुपचाप SMS भेज सकता है",
              "ನಿಮ್ಮ ನಂಬರ್‌ನಿಂದ ಗೊತ್ತಿಲ್ಲದೆ SMS ಕಳುಹಿಸಬಹುದು"),
            T("Scam apps use this to forward your OTPs, to spread the same scam link to your contacts, or to register "
              "your SIM for UPI on the scammer's phone.",
              "ठग ऐप इससे आपके OTP आगे भेजते हैं, वही धोखे वाला लिंक आपके कॉन्टैक्ट्स को भेजते हैं, या आपके SIM से ठग के फ़ोन पर "
              "UPI रजिस्टर कर लेते हैं।",
              "ವಂಚನೆ ಆ್ಯಪ್‌ಗಳು ಇದರಿಂದ ನಿಮ್ಮ OTP ಗಳನ್ನು ಮುಂದೆ ಕಳುಹಿಸುತ್ತವೆ, ಅದೇ ವಂಚನೆ ಲಿಂಕ್ ಅನ್ನು ನಿಮ್ಮ ಸಂಪರ್ಕಗಳಿಗೆ ಹರಡುತ್ತವೆ, "
              "ಅಥವಾ ನಿಮ್ಮ SIM ಬಳಸಿ ವಂಚಕರ ಫೋನ್‌ನಲ್ಲಿ UPI ನೋಂದಣಿ ಮಾಡುತ್ತವೆ."),
            f["ev"]["sms_send"],
        )


@rule
def call_forwarding(f):
    c = f["caps"]
    if c["call_phone"] and f["ussd_codes"]:
        return Finding(
            "CALL_FORWARDING", "critical", 35,
            T("Can secretly forward your calls to the scammer",
              "आपकी कॉल चुपचाप ठग के नंबर पर फ़ॉरवर्ड कर सकता है",
              "ನಿಮ್ಮ ಕರೆಗಳನ್ನು ರಹಸ್ಯವಾಗಿ ವಂಚಕರಿಗೆ ಫಾರ್ವರ್ಡ್ ಮಾಡಬಹುದು"),
            T("The app can dial numbers by itself and contains call-forwarding codes. Scammers forward your calls so "
              "they receive the bank's verification calls and OTP calls instead of you.",
              "यह ऐप खुद नंबर डायल कर सकता है और इसमें कॉल-फ़ॉरवर्डिंग कोड हैं। ठग आपकी कॉल फ़ॉरवर्ड करके बैंक की "
              "वेरिफ़िकेशन और OTP कॉल खुद ले लेते हैं।",
              "ಈ ಆ್ಯಪ್ ತಾನೇ ನಂಬರ್ ಡಯಲ್ ಮಾಡಬಲ್ಲದು ಮತ್ತು ಇದರಲ್ಲಿ ಕರೆ-ಫಾರ್ವರ್ಡ್ ಕೋಡ್‌ಗಳಿವೆ. ವಂಚಕರು ನಿಮ್ಮ ಕರೆಗಳನ್ನು "
              "ಫಾರ್ವರ್ಡ್ ಮಾಡಿ ಬ್ಯಾಂಕ್‌ನ ಪರಿಶೀಲನಾ ಮತ್ತು OTP ಕರೆಗಳನ್ನು ತಾವೇ ಸ್ವೀಕರಿಸುತ್ತಾರೆ."),
            [f"USSD code in app: {u}" for u in f["ussd_codes"][:5]],
        )


@rule
def device_admin(f):
    if f["caps"]["device_admin"]:
        return Finding(
            "DEVICE_ADMIN", "high", 20,
            T("Wants to be a device administrator (hard to uninstall)",
              "डिवाइस एडमिन बनना चाहता है (हटाना मुश्किल हो जाता है)",
              "ಡಿವೈಸ್ ಅಡ್ಮಿನ್ ಆಗಲು ಬಯಸುತ್ತದೆ (ಅನ್‌ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವುದು ಕಷ್ಟ)"),
            T("Device-admin apps can lock your phone and block you from uninstalling them.",
              "डिवाइस-एडमिन ऐप आपका फ़ोन लॉक कर सकते हैं और आपको उन्हें अनइंस्टॉल करने से रोक सकते हैं।",
              "ಡಿವೈಸ್-ಅಡ್ಮಿನ್ ಆ್ಯಪ್‌ಗಳು ನಿಮ್ಮ ಫೋನ್ ಲಾಕ್ ಮಾಡಬಹುದು ಮತ್ತು ಅವುಗಳನ್ನು ತೆಗೆದುಹಾಕದಂತೆ ತಡೆಯಬಹುದು."),
            f["ev"]["device_admin"],
        )


@rule
def hidden_app(f):
    c = f["caps"]
    if c["no_launcher"] and (c["boot"] or c["hide_icon_api"] or c["sms_any"]):
        return Finding(
            "HIDDEN_APP", "high", 20,
            T("Has no app icon but starts itself in the background",
              "इसका कोई आइकन नहीं दिखता, पर यह बैकग्राउंड में खुद चलता है",
              "ಇದಕ್ಕೆ ಐಕಾನ್ ಕಾಣಿಸುವುದಿಲ್ಲ, ಆದರೆ ಹಿನ್ನೆಲೆಯಲ್ಲಿ ತಾನೇ ಚಾಲನೆಯಾಗುತ್ತದೆ"),
            T("After installing, you won't see this app on your home screen, so you won't know it is running or how to remove it.",
              "इंस्टॉल करने के बाद यह ऐप होम स्क्रीन पर नहीं दिखेगा, इसलिए आपको पता ही नहीं चलेगा कि यह चल रहा है या इसे कैसे हटाएँ।",
              "ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿದ ನಂತರ ಈ ಆ್ಯಪ್ ಹೋಮ್ ಸ್ಕ್ರೀನ್‌ನಲ್ಲಿ ಕಾಣಿಸುವುದಿಲ್ಲ, ಆದ್ದರಿಂದ ಅದು ಚಾಲನೆಯಲ್ಲಿದೆ ಅಥವಾ ಹೇಗೆ ತೆಗೆಯುವುದು ಎಂದು ನಿಮಗೆ ತಿಳಿಯುವುದಿಲ್ಲ."),
            ["No launcher (home-screen) activity declared"] + (["Starts automatically on boot"] if c["boot"] else []),
        )


@rule
def dropper(f):
    c = f["caps"]
    if c["embedded_apk"] or (c["install_packages"] and c["dynamic_code"]):
        sev, pts = "high", 25
    elif c["install_packages"]:
        sev, pts = "medium", 12
    else:
        return None
    return Finding(
        "DROPPER", sev, pts,
        T("Can install other hidden apps", "दूसरे छिपे हुए ऐप इंस्टॉल कर सकता है", "ಬೇರೆ ಗುಪ್ತ ಆ್ಯಪ್‌ಗಳನ್ನು ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬಹುದು"),
        T("This app can install further apps. Scam 'installer' APKs often look harmless and then drop the real malware in a second step.",
          "यह ऐप और ऐप इंस्टॉल कर सकता है। धोखे वाले 'इंस्टॉलर' APK अक्सर मासूम दिखते हैं और फिर असली मैलवेयर बाद में डाल देते हैं।",
          "ಈ ಆ್ಯಪ್ ಇನ್ನಷ್ಟು ಆ್ಯಪ್‌ಗಳನ್ನು ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬಹುದು. ವಂಚನೆಯ 'ಇನ್‌ಸ್ಟಾಲರ್' APK ಗಳು ಮೊದಲು ನಿರುಪದ್ರವಿಯಂತೆ ಕಾಣುತ್ತವೆ, ನಂತರ ನಿಜವಾದ ಮಾಲ್‌ವೇರ್ ಹಾಕುತ್ತವೆ."),
        f["ev"]["dropper"],
    )


@rule
def bank_target_list(f):
    hits = f["bank_targets"]
    if len(hits) >= 2:
        return Finding(
            "BANK_APP_TARGET_LIST", "high", 30,
            T("Contains a list of Indian banking apps to target",
              "इसमें निशाना बनाने के लिए भारतीय बैंक ऐप्स की सूची है",
              "ಇದರಲ್ಲಿ ಗುರಿಯಾಗಿಸಲು ಭಾರತೀಯ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್‌ಗಳ ಪಟ್ಟಿ ಇದೆ"),
            T("The code refers to several real bank apps by their internal names. Banking trojans keep such lists so they know "
              "when you open your bank app — and show a fake screen on top of it.",
              "कोड में कई असली बैंक ऐप्स के अंदरूनी नाम हैं। बैंकिंग ट्रोजन ऐसी सूची रखते हैं ताकि जैसे ही आप अपना बैंक ऐप खोलें, "
              "वे उसके ऊपर नकली स्क्रीन दिखा सकें।",
              "ಕೋಡ್‌ನಲ್ಲಿ ಹಲವು ನಿಜವಾದ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್‌ಗಳ ಒಳಗಿನ ಹೆಸರುಗಳಿವೆ. ನೀವು ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ತೆರೆದ ತಕ್ಷಣ ಅದರ ಮೇಲೆ ನಕಲಿ "
              "ಪರದೆ ತೋರಿಸಲು ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್‌ಗಳು ಇಂತಹ ಪಟ್ಟಿಯನ್ನು ಇಟ್ಟುಕೊಳ್ಳುತ್ತವೆ."),
            [f"Targets: {p}" for p in hits[:8]],
        )


@rule
def phishing_form(f):
    hits = f["phishing_terms"]
    if len(hits) >= 3:
        return Finding(
            "CREDENTIAL_PHISHING_FORM", "high", 30,
            T("Contains a fake form asking for card / UPI / banking details",
              "इसमें कार्ड / UPI / बैंक डिटेल माँगने वाला नकली फ़ॉर्म है",
              "ಇದರಲ್ಲಿ ಕಾರ್ಡ್ / UPI / ಬ್ಯಾಂಕ್ ವಿವರ ಕೇಳುವ ನಕಲಿ ಫಾರ್ಮ್ ಇದೆ"),
            T("The app's text asks for things like CVV, PIN or card number. No courier, bill or government app ever asks for these.",
              "ऐप के अंदर CVV, PIN या कार्ड नंबर जैसी चीज़ें माँगी गई हैं। कोई भी कूरियर, बिल या सरकारी ऐप ये कभी नहीं माँगता।",
              "ಆ್ಯಪ್‌ನ ಒಳಗೆ CVV, PIN ಅಥವಾ ಕಾರ್ಡ್ ನಂಬರ್ ಕೇಳಲಾಗಿದೆ. ಯಾವುದೇ ಕೊರಿಯರ್, ಬಿಲ್ ಅಥವಾ ಸರ್ಕಾರಿ ಆ್ಯಪ್ ಇವುಗಳನ್ನು ಕೇಳುವುದಿಲ್ಲ."),
            [f"Asks for: {t}" for t in hits[:8]],
        )


@rule
def impersonation(f):
    imp = f["impersonation"]
    if imp:
        brand, pkg = imp
        risky = f["dangerous_count"] > 0
        return Finding(
            "BRAND_IMPERSONATION", "critical" if risky else "high", 35 if risky else 20,
            T(f"Pretends to be '{brand}' but is not the official app",
              f"'{brand}' होने का दिखावा करता है, पर यह असली ऐप नहीं है",
              f"'{brand}' ಎಂದು ನಟಿಸುತ್ತದೆ, ಆದರೆ ಇದು ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಲ್ಲ"),
            T(f"The name mentions {brand}, but its internal ID ({pkg}) does not match the real {brand} app.",
              f"नाम में {brand} लिखा है, पर इसकी अंदरूनी ID ({pkg}) असली {brand} ऐप से मेल नहीं खाती।",
              f"ಹೆಸರಿನಲ್ಲಿ {brand} ಇದೆ, ಆದರೆ ಇದರ ಒಳಗಿನ ID ({pkg}) ನಿಜವಾದ {brand} ಆ್ಯಪ್‌ಗೆ ಹೊಂದಿಕೆಯಾಗುವುದಿಲ್ಲ."),
            [f"Package name: {pkg}"],
        )


@rule
def lure_and_mismatch(f):
    cat = f["lure_category"]
    if not cat:
        return None
    extra = f["unexpected_perms"]
    sensitive = [p for p in extra if f["perm_risk"].get(p) in ("critical", "high")]
    never = cat in f["never_sideloaded"] and not f["official_package"]
    pts = (15 if never else 5) + (15 if sensitive else 0)
    sev = "high" if pts >= 25 else "medium" if pts >= 10 else "low"
    label = f["lure_label"]
    en = (f"This looks like a '{label}' app. " +
          ("Real banks, government departments, courier companies and electricity boards do NOT send apps as WhatsApp/SMS files — "
           "they are only on the Play Store. " if never else "") +
          ("It also asks for permissions such an app has no reason to need." if sensitive else ""))
    hi = (f"यह '{label}' वाला ऐप लगता है। " +
          ("असली बैंक, सरकारी विभाग, कूरियर कंपनियाँ और बिजली विभाग WhatsApp/SMS पर ऐप की फ़ाइल नहीं भेजते — "
           "उनके ऐप सिर्फ़ Play Store पर मिलते हैं। " if never else "") +
          ("यह ऐसी परमिशन भी माँग रहा है जिनकी ऐसे ऐप को कोई ज़रूरत नहीं होती।" if sensitive else ""))
    kn = (f"ಇದು '{label}' ಆ್ಯಪ್‌ನಂತೆ ಕಾಣುತ್ತದೆ. " +
          ("ನಿಜವಾದ ಬ್ಯಾಂಕ್‌ಗಳು, ಸರ್ಕಾರಿ ಇಲಾಖೆಗಳು, ಕೊರಿಯರ್ ಕಂಪನಿಗಳು ಮತ್ತು ವಿದ್ಯುತ್ ಮಂಡಳಿಗಳು WhatsApp/SMS ನಲ್ಲಿ ಆ್ಯಪ್ ಫೈಲ್ "
           "ಕಳುಹಿಸುವುದಿಲ್ಲ — ಅವು Play Store ನಲ್ಲಿ ಮಾತ್ರ ಇರುತ್ತವೆ. " if never else "") +
          ("ಇಂತಹ ಆ್ಯಪ್‌ಗೆ ಅಗತ್ಯವಿಲ್ಲದ ಅನುಮತಿಗಳನ್ನೂ ಇದು ಕೇಳುತ್ತಿದೆ." if sensitive else ""))
    return Finding(
        "SCAM_LURE_MISMATCH", sev, pts,
        T(f"Uses a common scam bait: '{label}'",
          f"आम ठगी वाला चारा इस्तेमाल करता है: '{label}'",
          f"ಸಾಮಾನ್ಯ ವಂಚನೆಯ ಆಮಿಷ ಬಳಸುತ್ತದೆ: '{label}'"),
        T(en.strip(), hi.strip(), kn.strip()),
        [f"Matched bait word: “{f['lure_word']}” in {f['lure_where']}"] +
        [f"Unexpected for this kind of app: {p}" for p in sensitive[:6]],
    )


@rule
def untrusted_signature(f):
    s = f["signing"]
    if not s["signed"]:
        return Finding(
            "UNSIGNED", "high", 20,
            T("Not signed by any developer", "किसी भी डेवलपर का हस्ताक्षर नहीं है", "ಯಾವುದೇ ಡೆವಲಪರ್ ಸಹಿ ಇಲ್ಲ"),
            T("Every real app is digitally signed by its maker. This one is not.",
              "हर असली ऐप पर उसके बनाने वाले का डिजिटल हस्ताक्षर होता है। इस पर नहीं है।",
              "ಪ್ರತಿಯೊಂದು ನಿಜವಾದ ಆ್ಯಪ್‌ಗೆ ಅದನ್ನು ತಯಾರಿಸಿದವರ ಡಿಜಿಟಲ್ ಸಹಿ ಇರುತ್ತದೆ. ಇದಕ್ಕೆ ಇಲ್ಲ."),
            [],
        )
    if s["debug_cert"]:
        return Finding(
            "DEBUG_CERTIFICATE", "medium", 15,
            T("Signed with a throw-away test certificate", "टेस्टिंग वाले अस्थायी सर्टिफ़िकेट से साइन किया गया है",
              "ಪರೀಕ್ಷಾ ಉದ್ದೇಶದ ತಾತ್ಕಾಲಿಕ ಪ್ರಮಾಣಪತ್ರದಿಂದ ಸಹಿ ಮಾಡಲಾಗಿದೆ"),
            T("This app is signed with Android's default 'debug' key, which no real company publishes apps with.",
              "यह ऐप Android की डिफ़ॉल्ट 'डीबग' की से साइन है, जिससे कोई असली कंपनी ऐप जारी नहीं करती।",
              "ಈ ಆ್ಯಪ್ Android ನ ಡೀಫಾಲ್ಟ್ 'ಡೀಬಗ್' ಕೀಯಿಂದ ಸಹಿ ಮಾಡಲಾಗಿದೆ, ಯಾವುದೇ ನಿಜವಾದ ಕಂಪನಿ ಇದರಿಂದ ಆ್ಯಪ್ ಬಿಡುಗಡೆ ಮಾಡುವುದಿಲ್ಲ."),
            [f"Signer: {s['subject']}"],
        )
    if s.get("cert_age_days") is not None and s["cert_age_days"] < 60:
        return Finding(
            "FRESH_CERTIFICATE", "low", 8,
            T("Signing key was created very recently", "साइनिंग की हाल ही में बनाई गई है", "ಸಹಿ ಕೀಯನ್ನು ಇತ್ತೀಚೆಗೆ ರಚಿಸಲಾಗಿದೆ"),
            T("Scam apps are usually signed with brand-new keys. Established apps keep the same key for years.",
              "ठगी वाले ऐप अक्सर बिल्कुल नई की से साइन होते हैं। जानी-मानी कंपनियाँ सालों तक एक ही की रखती हैं।",
              "ವಂಚನೆ ಆ್ಯಪ್‌ಗಳಿಗೆ ಸಾಮಾನ್ಯವಾಗಿ ಹೊಚ್ಚ ಹೊಸ ಕೀಯಿಂದ ಸಹಿ ಇರುತ್ತದೆ. ಹೆಸರಾಂತ ಆ್ಯಪ್‌ಗಳು ವರ್ಷಗಟ್ಟಲೆ ಒಂದೇ ಕೀ ಬಳಸುತ್ತವೆ."),
            [f"Certificate created {s['cert_age_days']} days ago", f"Signer: {s['subject']}"],
        )


@rule
def old_target_sdk(f):
    t = f["target_sdk"]
    if t is not None and t < 23 and f["dangerous_count"] > 0:
        return Finding(
            "LEGACY_TARGET_SDK", "medium", 12,
            T("Built to get all permissions without asking", "बिना पूछे सारी परमिशन पाने के लिए बनाया गया है",
              "ಕೇಳದೆಯೇ ಎಲ್ಲಾ ಅನುಮತಿಗಳನ್ನು ಪಡೆಯಲು ಮಾಡಲಾಗಿದೆ"),
            T("The app targets a very old Android version, so its permissions are granted at install time with no pop-up asking you. "
              "Malware authors do this on purpose.",
              "यह ऐप बहुत पुराने Android वर्ज़न के लिए बनाया गया है, जिससे इंस्टॉल होते ही बिना पूछे सारी परमिशन मिल जाती हैं। "
              "मैलवेयर बनाने वाले जानबूझकर ऐसा करते हैं।",
              "ಈ ಆ್ಯಪ್ ತುಂಬಾ ಹಳೆಯ Android ಆವೃತ್ತಿಗಾಗಿ ಮಾಡಲಾಗಿದೆ, ಆದ್ದರಿಂದ ಇನ್‌ಸ್ಟಾಲ್ ಆಗುತ್ತಲೇ ಕೇಳದೆ ಎಲ್ಲಾ ಅನುಮತಿಗಳು ಸಿಗುತ್ತವೆ. "
              "ಮಾಲ್‌ವೇರ್ ತಯಾರಕರು ಉದ್ದೇಶಪೂರ್ವಕವಾಗಿ ಹೀಗೆ ಮಾಡುತ್ತಾರೆ."),
            [f"targetSdkVersion = {t}"],
        )


@rule
def packed(f):
    if f["packers"]:
        return Finding(
            "PACKED_CODE", "medium", 12,
            T("Code is hidden inside a protector / packer", "कोड को प्रोटेक्टर / पैकर के अंदर छिपाया गया है",
              "ಕೋಡ್ ಅನ್ನು ಪ್ರೊಟೆಕ್ಟರ್ / ಪ್ಯಾಕರ್ ಒಳಗೆ ಅಡಗಿಸಲಾಗಿದೆ"),
            T("The real code is encrypted so it cannot be inspected before running. Some legitimate apps do this, but malware does it much more often.",
              "असली कोड एन्क्रिप्ट किया गया है ताकि चलने से पहले उसे जाँचा न जा सके। कुछ असली ऐप भी ऐसा करते हैं, पर मैलवेयर बहुत ज़्यादा करते हैं।",
              "ನಿಜವಾದ ಕೋಡ್ ಅನ್ನು ಎನ್‌ಕ್ರಿಪ್ಟ್ ಮಾಡಲಾಗಿದೆ, ಹಾಗಾಗಿ ಚಾಲನೆಗೆ ಮೊದಲು ಪರಿಶೀಲಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ. ಕೆಲವು ನಿಜವಾದ ಆ್ಯಪ್‌ಗಳೂ ಹೀಗೆ ಮಾಡುತ್ತವೆ, ಆದರೆ ಮಾಲ್‌ವೇರ್ ಹೆಚ್ಚಾಗಿ ಮಾಡುತ್ತದೆ."),
            [f"Packer: {p}" for p in f["packers"]],
        )


@rule
def contact_spreader(f):
    c = f["caps"]
    if c["contacts"] and c["sms_send"]:
        return Finding(
            "CONTACT_SPREADER", "high", 15,
            T("Can message all your contacts", "आपके सभी कॉन्टैक्ट्स को मैसेज भेज सकता है", "ನಿಮ್ಮ ಎಲ್ಲಾ ಸಂಪರ್ಕಗಳಿಗೆ ಸಂದೇಶ ಕಳುಹಿಸಬಹುದು"),
            T("Reading contacts plus sending SMS is how these scams spread from one family member to the next.",
              "कॉन्टैक्ट्स पढ़ना और SMS भेजना — इसी तरह ये ठगी एक रिश्तेदार से दूसरे तक फैलती है।",
              "ಸಂಪರ್ಕಗಳನ್ನು ಓದುವುದು ಮತ್ತು SMS ಕಳುಹಿಸುವುದು — ಹೀಗೆಯೇ ಈ ವಂಚನೆ ಒಬ್ಬ ಕುಟುಂಬದ ಸದಸ್ಯರಿಂದ ಇನ್ನೊಬ್ಬರಿಗೆ ಹರಡುತ್ತದೆ."),
            ["READ_CONTACTS + SEND_SMS"],
        )


@rule
def default_sms_handler(f):
    if f["caps"]["sms_handler"]:
        return Finding(
            "DEFAULT_SMS_APP", "high", 20,
            T("Wants to become your default SMS app", "आपका डिफ़ॉल्ट SMS ऐप बनना चाहता है", "ನಿಮ್ಮ ಡೀಫಾಲ್ಟ್ SMS ಆ್ಯಪ್ ಆಗಲು ಬಯಸುತ್ತದೆ"),
            T("As the default SMS app it can read, hide and delete bank messages so you never see the fraud alert.",
              "डिफ़ॉल्ट SMS ऐप बनकर यह बैंक के मैसेज पढ़, छिपा और मिटा सकता है, ताकि आपको धोखे का अलर्ट दिखे ही नहीं।",
              "ಡೀಫಾಲ್ಟ್ SMS ಆ್ಯಪ್ ಆಗಿ ಇದು ಬ್ಯಾಂಕ್ ಸಂದೇಶಗಳನ್ನು ಓದಬಹುದು, ಮರೆಮಾಡಬಹುದು ಮತ್ತು ಅಳಿಸಬಹುದು, ಹೀಗಾಗಿ ವಂಚನೆಯ ಎಚ್ಚರಿಕೆ ನಿಮಗೆ ಕಾಣಿಸುವುದಿಲ್ಲ."),
            f["ev"]["sms_handler"],
        )


@rule
def screen_capture(f):
    if f["caps"]["screen_capture"]:
        return Finding(
            "SCREEN_RECORDING", "medium", 12,
            T("Can record your screen", "आपकी स्क्रीन रिकॉर्ड कर सकता है", "ನಿಮ್ಮ ಪರದೆಯನ್ನು ರೆಕಾರ್ಡ್ ಮಾಡಬಹುದು"),
            T("Screen recording captures everything you type and see, including PINs and passwords.",
              "स्क्रीन रिकॉर्डिंग से आपकी हर टाइप की और देखी गई चीज़ रिकॉर्ड होती है, PIN और पासवर्ड भी।",
              "ಸ್ಕ್ರೀನ್ ರೆಕಾರ್ಡಿಂಗ್ ನೀವು ಟೈಪ್ ಮಾಡುವ ಮತ್ತು ನೋಡುವ ಎಲ್ಲವನ್ನೂ, PIN ಮತ್ತು ಪಾಸ್‌ವರ್ಡ್ ಸಹ, ದಾಖಲಿಸುತ್ತದೆ."),
            f["ev"]["screen"],
        )


@rule
def suspicious_servers(f):
    ips, bad_tld = f["raw_ip_urls"], f["suspicious_tld_urls"]
    if not (ips or bad_tld):
        return None
    return Finding(
        "SUSPICIOUS_SERVERS", "medium", 10,
        T("Talks to unusual servers", "अजीब सर्वरों से जुड़ता है", "ಅಸಾಮಾನ್ಯ ಸರ್ವರ್‌ಗಳಿಗೆ ಸಂಪರ್ಕಿಸುತ್ತದೆ"),
        T("The app has hard-coded server addresses (bare IP numbers or throw-away domains) commonly used by scam infrastructure.",
          "ऐप में सीधे IP नंबर या सस्ते डिस्पोज़ेबल डोमेन वाले सर्वर पते लिखे हैं, जो अक्सर ठगी में इस्तेमाल होते हैं।",
          "ಆ್ಯಪ್‌ನಲ್ಲಿ ನೇರ IP ಸಂಖ್ಯೆಗಳು ಅಥವಾ ಬಿಸಾಡುವ ಡೊಮೇನ್‌ಗಳ ಸರ್ವರ್ ವಿಳಾಸಗಳನ್ನು ಬರೆಯಲಾಗಿದೆ, ಇವು ವಂಚನೆಯಲ್ಲಿ ಹೆಚ್ಚಾಗಿ ಬಳಕೆಯಾಗುತ್ತವೆ."),
        [f"Server: {u}" for u in (ips + bad_tld)[:6]],
    )


@rule
def persistence(f):
    c = f["caps"]
    if c["boot"] and c["ignore_battery"] and (c["sms_any"] or c["accessibility"] or c["notif_listener"]):
        return Finding(
            "PERSISTENCE", "low", 6,
            T("Designed to keep running all the time", "हमेशा चलते रहने के लिए बनाया गया है", "ಯಾವಾಗಲೂ ಚಾಲನೆಯಲ್ಲಿರಲು ವಿನ್ಯಾಸಗೊಳಿಸಲಾಗಿದೆ"),
            T("It starts when the phone is switched on and asks to be exempt from battery saving, so it can spy continuously.",
              "फ़ोन चालू होते ही यह शुरू हो जाता है और बैटरी सेविंग से छूट माँगता है, ताकि लगातार जासूसी कर सके।",
              "ಫೋನ್ ಆನ್ ಆದ ತಕ್ಷಣ ಇದು ಪ್ರಾರಂಭವಾಗುತ್ತದೆ ಮತ್ತು ಬ್ಯಾಟರಿ ಉಳಿತಾಯದಿಂದ ವಿನಾಯಿತಿ ಕೇಳುತ್ತದೆ, ನಿರಂತರವಾಗಿ ಕಣ್ಗಾವಲು ಮಾಡಲು."),
            ["RECEIVE_BOOT_COMPLETED + REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"],
        )


@rule
def call_control(f):
    c = f["caps"]
    if (c["call_phone"] and not f["ussd_codes"]) or c["call_log"]:
        return Finding(
            "CALL_CONTROL", "low", 6,
            T("Can make calls or read your call history", "कॉल कर सकता है या आपकी कॉल हिस्ट्री पढ़ सकता है",
              "ಕರೆ ಮಾಡಬಹುದು ಅಥವಾ ನಿಮ್ಮ ಕರೆ ಇತಿಹಾಸ ಓದಬಹುದು"),
            T("Only dialer and caller-ID apps genuinely need this.",
              "इसकी असल ज़रूरत सिर्फ़ डायलर और कॉलर-ID ऐप्स को होती है।",
              "ಇದರ ನಿಜವಾದ ಅಗತ್ಯ ಡಯಲರ್ ಮತ್ತು ಕಾಲರ್-ID ಆ್ಯಪ್‌ಗಳಿಗೆ ಮಾತ್ರ."),
            f["ev"]["calls"],
        )


# ---------------------------------------------------------------- verdicts

VERDICTS = [
    (70, "danger", T("Do NOT install this app", "यह ऐप इंस्टॉल न करें", "ಈ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ"),
     T("It shows the fingerprints of a banking trojan / OTP stealer. Delete the file. If you already installed it: switch on "
       "flight mode, uninstall it from Settings → Apps, call your bank to block cards and UPI, and report it at "
       "cybercrime.gov.in or by calling 1930.",
       "इसमें बैंकिंग ट्रोजन / OTP चोर ऐप के लक्षण हैं। फ़ाइल डिलीट कर दें। अगर इंस्टॉल कर चुके हैं: फ़्लाइट मोड चालू करें, "
       "Settings → Apps से इसे अनइंस्टॉल करें, बैंक को फ़ोन करके कार्ड और UPI बंद करवाएँ, और cybercrime.gov.in पर या 1930 पर कॉल करके शिकायत करें।",
       "ಇದರಲ್ಲಿ ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್ / OTP ಕಳ್ಳ ಆ್ಯಪ್‌ನ ಲಕ್ಷಣಗಳಿವೆ. ಫೈಲ್ ಅಳಿಸಿ. ಈಗಾಗಲೇ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿದ್ದರೆ: ಫ್ಲೈಟ್ ಮೋಡ್ ಆನ್ ಮಾಡಿ, "
       "Settings → Apps ನಿಂದ ಅನ್‌ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ, ಬ್ಯಾಂಕ್‌ಗೆ ಕರೆ ಮಾಡಿ ಕಾರ್ಡ್ ಮತ್ತು UPI ನಿರ್ಬಂಧಿಸಿ, ಮತ್ತು cybercrime.gov.in ನಲ್ಲಿ ಅಥವಾ 1930 ಗೆ ಕರೆ ಮಾಡಿ ದೂರು ನೀಡಿ.")),
    (40, "suspicious", T("Very suspicious — don't install", "बहुत संदिग्ध — इंस्टॉल न करें", "ತುಂಬಾ ಸಂಶಯಾಸ್ಪದ — ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ"),
     T("Several warning signs were found. Unless you are completely sure who made this app, don't install it. "
       "Get the official app from the Play Store instead.",
       "कई खतरे के संकेत मिले हैं। जब तक आपको पक्का न पता हो कि यह ऐप किसने बनाया है, इसे इंस्टॉल न करें। "
       "इसकी जगह Play Store से असली ऐप लें।",
       "ಹಲವು ಎಚ್ಚರಿಕೆಯ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿವೆ. ಈ ಆ್ಯಪ್ ಯಾರು ಮಾಡಿದ್ದಾರೆ ಎಂದು ಖಚಿತವಾಗಿ ಗೊತ್ತಿಲ್ಲದಿದ್ದರೆ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ. "
       "ಬದಲಿಗೆ Play Store ನಿಂದ ಅಧಿಕೃತ ಆ್ಯಪ್ ಪಡೆಯಿರಿ.")),
    (15, "caution", T("Be careful", "सावधान रहें", "ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ"),
     T("Some permissions deserve a second look. If a stranger or an unknown number sent you this file, don't install it.",
       "कुछ परमिशन पर ध्यान देना ज़रूरी है। अगर यह फ़ाइल किसी अनजान व्यक्ति या नंबर से आई है, तो इसे इंस्टॉल न करें।",
       "ಕೆಲವು ಅನುಮತಿಗಳನ್ನು ಗಮನಿಸಬೇಕು. ಈ ಫೈಲ್ ಅಪರಿಚಿತರಿಂದ ಅಥವಾ ಗೊತ್ತಿಲ್ಲದ ನಂಬರ್‌ನಿಂದ ಬಂದಿದ್ದರೆ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ.")),
    (0, "low", T("No known danger signs found", "कोई ज्ञात खतरे के संकेत नहीं मिले", "ಯಾವುದೇ ತಿಳಿದಿರುವ ಅಪಾಯದ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ"),
     T("That does not prove it is safe — this scan looks for known trojan patterns. The safest habit is still: "
       "install apps only from the Play Store.",
       "इसका मतलब यह नहीं कि ऐप पूरी तरह सुरक्षित है — यह जाँच जाने-माने ट्रोजन पैटर्न ढूँढती है। सबसे सुरक्षित आदत अब भी यही है: "
       "ऐप सिर्फ़ Play Store से इंस्टॉल करें।",
       "ಇದು ಆ್ಯಪ್ ಸಂಪೂರ್ಣ ಸುರಕ್ಷಿತ ಎಂದು ಸಾಬೀತುಪಡಿಸುವುದಿಲ್ಲ — ಈ ಪರಿಶೀಲನೆ ತಿಳಿದಿರುವ ಟ್ರೋಜನ್ ಮಾದರಿಗಳನ್ನು ಹುಡುಕುತ್ತದೆ. "
       "ಅತ್ಯಂತ ಸುರಕ್ಷಿತ ಅಭ್ಯಾಸ: ಆ್ಯಪ್‌ಗಳನ್ನು Play Store ನಿಂದ ಮಾತ್ರ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ.")),
]


def evaluate(facts: dict) -> dict:
    findings: list[Finding] = []
    for r in RULES:
        try:
            out = r(facts)
        except Exception as e:  # a buggy rule must never kill the scan
            out = None
            facts.setdefault("rule_errors", []).append(f"{r.__name__}: {e}")
        if out:
            findings.append(out)
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], -x.points))
    score = min(100, sum(x.points for x in findings))
    # Any critical finding means at least "suspicious", regardless of total.
    if any(x.severity == "critical" for x in findings):
        score = max(score, 45)
    for threshold, level, headline, advice in VERDICTS:
        if score >= threshold:
            break
    return {
        "score": score,
        "level": level,
        "headline": headline,
        "advice": advice,
        "findings": [x.to_dict() for x in findings],
    }
