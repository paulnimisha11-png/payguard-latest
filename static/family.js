/* Family guardian mode UI: link phones with a 6-digit code, alert inbox, push notifications. Needs device.js. */
(() => {
  const $ = (s) => document.querySelector(s);
  const D = window.PGDev;
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const S = {
    en: { nav_check: "Check", nav_trends: "Trends", nav_family: "Family", title: "Family protection",
      sub: "Link a parent's phone to yours. If they check something dangerous — or try to pay a risky UPI ID anyway — you get an alert straight away.",
      alerts_t: "Alerts", mark_read: "Mark all as read", push_t: "Get alerts as notifications", push_on: "Turn on notifications", push_test: "Send a test alert",
      g_title: "Protect a family member", g_sub: "Do this on YOUR phone. Then type the code on their phone.", your_name: "Your name (they'll see it)",
      make_code: "Create a linking code", code_help: "On their phone: open PayGuard → Family → “I want to be protected”, and type this code:", cancel: "Cancel",
      protecting_t: "People you protect", p_title: "I want to be protected", p_sub: "Do this on the parent's phone, with the code from your family member.",
      code_label: "6-digit code", your_name2: "Your name (your family will see it)", consent_t: "What your family member will see",
      consent_1: "When you check something that looks dangerous: what kind of scam it is and a partly hidden UPI ID, number or website.",
      consent_2: "When you choose to pay a risky UPI ID anyway.",
      consent_3: "Never your messages, photos, bank details or anything that looked safe. You can stop this any time.",
      join: "Link my phone", protected_t: "People protecting you", me_t: "Your details",
      me_sub: "Add your number so the family members you protect can call you from PayGuard with one tap.", save: "Save",
      forget: "Forget this phone (removes all links and alerts)", privacy: "Alerts are kept for 30 days. PayGuard never shares your messages, screenshots or bank details with anyone.",
      expires: "Code expires in {m}:{s}", expired: "This code has expired. Create a new one.", linked_ok: "✓ {name} is now protected.",
      joined_ok: "✓ Linked. {name} will be alerted if you run into a scam.", need_code: "Enter the 6-digit code.", since: "since {d}",
      last_alert: "last alert {d}", no_alerts: "No alerts yet — that's good news.", remove: "Remove", call: "Call", confirm_remove: "Stop sharing alerts with {name}?",
      confirm_forget: "Remove all family links and alerts from this phone?", saved: "Saved.", forgot: "This phone has been forgotten.",
      push_ok: "✓ Notifications are on for this phone.", push_off: "Notifications are off. Alerts still appear on this page.",
      push_help_web: "Alerts appear here whenever you open PayGuard. Turn on notifications to get them even when PayGuard is closed.",
      push_help_ios: "On iPhone, notifications work only after you add PayGuard to your Home Screen (Share → Add to Home Screen) and open it from there. Needs iOS 16.4 or newer.",
      push_help_app: "Using the PayGuard Android app? It checks for alerts by itself — open it once and allow notifications.",
      push_denied: "Notifications are blocked. Allow them in your browser's site settings, then try again.",
      push_na: "This browser can't show notifications. Keep this page open, or use Chrome on Android / the Home Screen app on iPhone.",
      push_https: "Notifications need the secure https:// address of PayGuard.", test_sent: "Test alert sent — it should appear in a few seconds.",
      now: "just now", mins: "{n} min ago", hours: "{n} h ago", call_them: "Call {name}", unseen: "new" },
    hi: { nav_check: "जाँचें", nav_trends: "ट्रेंड्स", nav_family: "परिवार", title: "परिवार सुरक्षा",
      sub: "माता-पिता के फ़ोन को अपने फ़ोन से जोड़ें। अगर वे कुछ ख़तरनाक जाँचें — या ख़तरनाक UPI ID पर फिर भी पैसे भेजने लगें — तो आपको तुरंत अलर्ट मिलेगा।",
      alerts_t: "अलर्ट", mark_read: "सब पढ़ा हुआ मानें", push_t: "अलर्ट नोटिफ़िकेशन के रूप में पाएँ", push_on: "नोटिफ़िकेशन चालू करें", push_test: "टेस्ट अलर्ट भेजें",
      g_title: "परिवार के सदस्य को सुरक्षित करें", g_sub: "यह अपने फ़ोन पर करें। फिर उनके फ़ोन पर कोड डालें।", your_name: "आपका नाम (वे इसे देखेंगे)",
      make_code: "लिंक कोड बनाएँ", code_help: "उनके फ़ोन पर: PayGuard खोलें → परिवार → “मैं सुरक्षित होना चाहता/चाहती हूँ”, और यह कोड डालें:", cancel: "रद्द करें",
      protecting_t: "जिन्हें आप सुरक्षित रखते हैं", p_title: "मैं सुरक्षित होना चाहता/चाहती हूँ", p_sub: "यह माता-पिता के फ़ोन पर करें, परिवार से मिले कोड के साथ।",
      code_label: "6 अंकों का कोड", your_name2: "आपका नाम (परिवार इसे देखेगा)", consent_t: "आपके परिजन क्या देखेंगे",
      consent_1: "जब आप कुछ ख़तरनाक जाँचें: किस तरह की ठगी है और आंशिक रूप से छिपा UPI ID, नंबर या वेबसाइट।",
      consent_2: "जब आप किसी ख़तरनाक UPI ID पर फिर भी पैसे भेजना चुनें।",
      consent_3: "आपके मैसेज, फ़ोटो, बैंक विवरण या सुरक्षित दिखी चीज़ें कभी नहीं। आप इसे कभी भी बंद कर सकते हैं।",
      join: "मेरा फ़ोन जोड़ें", protected_t: "जो आपको सुरक्षित रखते हैं", me_t: "आपकी जानकारी",
      me_sub: "अपना नंबर जोड़ें ताकि जिन्हें आप सुरक्षित रखते हैं, वे PayGuard से एक टैप में आपको कॉल कर सकें।", save: "सेव करें",
      forget: "इस फ़ोन को भूल जाएँ (सभी लिंक और अलर्ट हटेंगे)", privacy: "अलर्ट 30 दिन रखे जाते हैं। PayGuard आपके मैसेज, स्क्रीनशॉट या बैंक विवरण किसी से साझा नहीं करता।",
      expires: "कोड {m}:{s} में ख़त्म होगा", expired: "यह कोड ख़त्म हो गया। नया बनाएँ।", linked_ok: "✓ {name} अब सुरक्षित हैं।",
      joined_ok: "✓ जुड़ गया। अगर आप किसी ठगी में फँसें तो {name} को अलर्ट मिलेगा।", need_code: "6 अंकों का कोड डालें।", since: "{d} से",
      last_alert: "आख़िरी अलर्ट {d}", no_alerts: "अभी कोई अलर्ट नहीं — अच्छी ख़बर है।", remove: "हटाएँ", call: "कॉल", confirm_remove: "{name} के साथ अलर्ट साझा करना बंद करें?",
      confirm_forget: "इस फ़ोन से सभी पारिवारिक लिंक और अलर्ट हटाएँ?", saved: "सेव हो गया।", forgot: "यह फ़ोन भुला दिया गया।",
      push_ok: "✓ इस फ़ोन पर नोटिफ़िकेशन चालू हैं।", push_off: "नोटिफ़िकेशन बंद हैं। अलर्ट फिर भी इस पेज पर दिखेंगे।",
      push_help_web: "PayGuard खोलने पर अलर्ट यहाँ दिखते हैं। PayGuard बंद होने पर भी पाने के लिए नोटिफ़िकेशन चालू करें।",
      push_help_ios: "iPhone पर नोटिफ़िकेशन तभी काम करते हैं जब आप PayGuard को होम स्क्रीन पर जोड़कर (Share → Add to Home Screen) वहीं से खोलें। iOS 16.4 या नया चाहिए।",
      push_help_app: "PayGuard Android ऐप इस्तेमाल कर रहे हैं? वह ख़ुद अलर्ट जाँचता है — एक बार खोलें और नोटिफ़िकेशन की अनुमति दें।",
      push_denied: "नोटिफ़िकेशन ब्लॉक हैं। ब्राउज़र की साइट सेटिंग में अनुमति दें, फिर कोशिश करें।",
      push_na: "यह ब्राउज़र नोटिफ़िकेशन नहीं दिखा सकता। यह पेज खुला रखें, या Android पर Chrome / iPhone पर होम स्क्रीन ऐप इस्तेमाल करें।",
      push_https: "नोटिफ़िकेशन के लिए PayGuard का सुरक्षित https:// पता चाहिए।", test_sent: "टेस्ट अलर्ट भेजा — कुछ सेकंड में दिखना चाहिए।",
      now: "अभी", mins: "{n} मिनट पहले", hours: "{n} घंटे पहले", call_them: "{name} को कॉल करें", unseen: "नया" },
    kn: { nav_check: "ಪರಿಶೀಲಿಸಿ", nav_trends: "ಟ್ರೆಂಡ್‌ಗಳು", nav_family: "ಕುಟುಂಬ", title: "ಕುಟುಂಬ ರಕ್ಷಣೆ",
      sub: "ಪೋಷಕರ ಫೋನ್ ಅನ್ನು ನಿಮ್ಮ ಫೋನ್‌ಗೆ ಜೋಡಿಸಿ. ಅವರು ಅಪಾಯಕಾರಿ ಏನನ್ನಾದರೂ ಪರಿಶೀಲಿಸಿದರೆ — ಅಥವಾ ಅಪಾಯಕಾರಿ UPI ID ಗೆ ಪಾವತಿಸಲು ಮುಂದಾದರೆ — ನಿಮಗೆ ತಕ್ಷಣ ಎಚ್ಚರಿಕೆ ಬರುತ್ತದೆ.",
      alerts_t: "ಎಚ್ಚರಿಕೆಗಳು", mark_read: "ಎಲ್ಲವನ್ನೂ ಓದಲಾಗಿದೆ", push_t: "ಎಚ್ಚರಿಕೆಗಳನ್ನು ನೋಟಿಫಿಕೇಶನ್ ಆಗಿ ಪಡೆಯಿರಿ", push_on: "ನೋಟಿಫಿಕೇಶನ್ ಆನ್ ಮಾಡಿ", push_test: "ಪರೀಕ್ಷಾ ಎಚ್ಚರಿಕೆ ಕಳುಹಿಸಿ",
      g_title: "ಕುಟುಂಬದವರನ್ನು ರಕ್ಷಿಸಿ", g_sub: "ಇದನ್ನು ನಿಮ್ಮ ಫೋನ್‌ನಲ್ಲಿ ಮಾಡಿ. ನಂತರ ಅವರ ಫೋನ್‌ನಲ್ಲಿ ಕೋಡ್ ಹಾಕಿ.", your_name: "ನಿಮ್ಮ ಹೆಸರು (ಅವರು ನೋಡುತ್ತಾರೆ)",
      make_code: "ಲಿಂಕ್ ಕೋಡ್ ರಚಿಸಿ", code_help: "ಅವರ ಫೋನ್‌ನಲ್ಲಿ: PayGuard ತೆರೆಯಿರಿ → ಕುಟುಂಬ → “ನಾನು ರಕ್ಷಣೆ ಬಯಸುತ್ತೇನೆ”, ಈ ಕೋಡ್ ಹಾಕಿ:", cancel: "ರದ್ದುಮಾಡಿ",
      protecting_t: "ನೀವು ರಕ್ಷಿಸುತ್ತಿರುವವರು", p_title: "ನಾನು ರಕ್ಷಣೆ ಬಯಸುತ್ತೇನೆ", p_sub: "ಇದನ್ನು ಪೋಷಕರ ಫೋನ್‌ನಲ್ಲಿ, ಕುಟುಂಬದವರಿಂದ ಬಂದ ಕೋಡ್‌ನೊಂದಿಗೆ ಮಾಡಿ.",
      code_label: "6-ಅಂಕಿಯ ಕೋಡ್", your_name2: "ನಿಮ್ಮ ಹೆಸರು (ಕುಟುಂಬ ನೋಡುತ್ತದೆ)", consent_t: "ನಿಮ್ಮ ಕುಟುಂಬದವರು ಏನು ನೋಡುತ್ತಾರೆ",
      consent_1: "ನೀವು ಅಪಾಯಕಾರಿ ಏನನ್ನಾದರೂ ಪರಿಶೀಲಿಸಿದಾಗ: ಯಾವ ರೀತಿಯ ವಂಚನೆ ಮತ್ತು ಭಾಗಶಃ ಮರೆಮಾಡಿದ UPI ID, ನಂಬರ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್.",
      consent_2: "ನೀವು ಅಪಾಯಕಾರಿ UPI ID ಗೆ ಆದರೂ ಪಾವತಿಸಲು ಆರಿಸಿದಾಗ.",
      consent_3: "ನಿಮ್ಮ ಸಂದೇಶಗಳು, ಫೋಟೋಗಳು, ಬ್ಯಾಂಕ್ ವಿವರಗಳು ಅಥವಾ ಸುರಕ್ಷಿತವೆನಿಸಿದವು ಎಂದಿಗೂ ಅಲ್ಲ. ಯಾವಾಗ ಬೇಕಾದರೂ ನಿಲ್ಲಿಸಬಹುದು.",
      join: "ನನ್ನ ಫೋನ್ ಜೋಡಿಸಿ", protected_t: "ನಿಮ್ಮನ್ನು ರಕ್ಷಿಸುತ್ತಿರುವವರು", me_t: "ನಿಮ್ಮ ವಿವರಗಳು",
      me_sub: "ನೀವು ರಕ್ಷಿಸುವವರು PayGuard ನಿಂದ ಒಂದೇ ಟ್ಯಾಪ್‌ನಲ್ಲಿ ಕರೆ ಮಾಡಲು ನಿಮ್ಮ ನಂಬರ್ ಸೇರಿಸಿ.", save: "ಉಳಿಸಿ",
      forget: "ಈ ಫೋನ್ ಮರೆತುಬಿಡಿ (ಎಲ್ಲ ಲಿಂಕ್ ಮತ್ತು ಎಚ್ಚರಿಕೆ ಅಳಿಸುತ್ತದೆ)", privacy: "ಎಚ್ಚರಿಕೆಗಳನ್ನು 30 ದಿನ ಇಡಲಾಗುತ್ತದೆ. PayGuard ನಿಮ್ಮ ಸಂದೇಶ, ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ವಿವರ ಯಾರಿಗೂ ಹಂಚುವುದಿಲ್ಲ.",
      expires: "ಕೋಡ್ {m}:{s} ರಲ್ಲಿ ಮುಗಿಯುತ್ತದೆ", expired: "ಈ ಕೋಡ್ ಅವಧಿ ಮುಗಿದಿದೆ. ಹೊಸದನ್ನು ರಚಿಸಿ.", linked_ok: "✓ {name} ಈಗ ರಕ್ಷಿತರು.",
      joined_ok: "✓ ಜೋಡಿಸಲಾಗಿದೆ. ನೀವು ವಂಚನೆಗೆ ಸಿಲುಕಿದರೆ {name} ಅವರಿಗೆ ಎಚ್ಚರಿಕೆ ಹೋಗುತ್ತದೆ.", need_code: "6-ಅಂಕಿಯ ಕೋಡ್ ಹಾಕಿ.", since: "{d} ರಿಂದ",
      last_alert: "ಕೊನೆಯ ಎಚ್ಚರಿಕೆ {d}", no_alerts: "ಇನ್ನೂ ಯಾವುದೇ ಎಚ್ಚರಿಕೆ ಇಲ್ಲ — ಒಳ್ಳೆಯ ಸುದ್ದಿ.", remove: "ತೆಗೆದುಹಾಕಿ", call: "ಕರೆ", confirm_remove: "{name} ಜೊತೆ ಎಚ್ಚರಿಕೆ ಹಂಚುವುದನ್ನು ನಿಲ್ಲಿಸುವುದೇ?",
      confirm_forget: "ಈ ಫೋನ್‌ನಿಂದ ಎಲ್ಲ ಕುಟುಂಬ ಲಿಂಕ್ ಮತ್ತು ಎಚ್ಚರಿಕೆ ಅಳಿಸುವುದೇ?", saved: "ಉಳಿಸಲಾಗಿದೆ.", forgot: "ಈ ಫೋನ್ ಮರೆತುಬಿಡಲಾಗಿದೆ.",
      push_ok: "✓ ಈ ಫೋನ್‌ನಲ್ಲಿ ನೋಟಿಫಿಕೇಶನ್ ಆನ್ ಆಗಿದೆ.", push_off: "ನೋಟಿಫಿಕೇಶನ್ ಆಫ್ ಆಗಿದೆ. ಎಚ್ಚರಿಕೆಗಳು ಈ ಪುಟದಲ್ಲಿ ಕಾಣುತ್ತವೆ.",
      push_help_web: "PayGuard ತೆರೆದಾಗ ಎಚ್ಚರಿಕೆಗಳು ಇಲ್ಲಿ ಕಾಣುತ್ತವೆ. PayGuard ಮುಚ್ಚಿದಾಗಲೂ ಪಡೆಯಲು ನೋಟಿಫಿಕೇಶನ್ ಆನ್ ಮಾಡಿ.",
      push_help_ios: "iPhone ನಲ್ಲಿ PayGuard ಅನ್ನು ಹೋಮ್ ಸ್ಕ್ರೀನ್‌ಗೆ ಸೇರಿಸಿ (Share → Add to Home Screen) ಅಲ್ಲಿಂದ ತೆರೆದರೆ ಮಾತ್ರ ನೋಟಿಫಿಕೇಶನ್ ಕೆಲಸ ಮಾಡುತ್ತದೆ. iOS 16.4 ಅಥವಾ ಹೊಸದು ಬೇಕು.",
      push_help_app: "PayGuard Android ಆ್ಯಪ್ ಬಳಸುತ್ತಿದ್ದೀರಾ? ಅದು ತಾನಾಗಿಯೇ ಎಚ್ಚರಿಕೆ ಪರಿಶೀಲಿಸುತ್ತದೆ — ಒಮ್ಮೆ ತೆರೆದು ನೋಟಿಫಿಕೇಶನ್ ಅನುಮತಿಸಿ.",
      push_denied: "ನೋಟಿಫಿಕೇಶನ್ ತಡೆಹಿಡಿಯಲಾಗಿದೆ. ಬ್ರೌಸರ್ ಸೈಟ್ ಸೆಟ್ಟಿಂಗ್‌ನಲ್ಲಿ ಅನುಮತಿಸಿ, ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ.",
      push_na: "ಈ ಬ್ರೌಸರ್ ನೋಟಿಫಿಕೇಶನ್ ತೋರಿಸಲಾರದು. ಈ ಪುಟ ತೆರೆದಿಡಿ, ಅಥವಾ Android ನಲ್ಲಿ Chrome / iPhone ನಲ್ಲಿ ಹೋಮ್ ಸ್ಕ್ರೀನ್ ಆ್ಯಪ್ ಬಳಸಿ.",
      push_https: "ನೋಟಿಫಿಕೇಶನ್‌ಗೆ PayGuard ನ ಸುರಕ್ಷಿತ https:// ವಿಳಾಸ ಬೇಕು.", test_sent: "ಪರೀಕ್ಷಾ ಎಚ್ಚರಿಕೆ ಕಳುಹಿಸಲಾಗಿದೆ — ಕೆಲವು ಸೆಕೆಂಡಿನಲ್ಲಿ ಕಾಣಬೇಕು.",
      now: "ಈಗಷ್ಟೇ", mins: "{n} ನಿಮಿಷ ಹಿಂದೆ", hours: "{n} ಗಂಟೆ ಹಿಂದೆ", call_them: "{name} ಗೆ ಕರೆ ಮಾಡಿ", unseen: "ಹೊಸದು" },
    ta: { nav_check: "சரிபார்க்கவும்", nav_trends: "ட்ரெண்டுகள்", nav_family: "குடும்பம்", title: "குடும்பப் பாதுகாப்பு",
      sub: "பெற்றோரின் மொபைலை உங்களுடன் இணைக்கவும். அவர்கள் ஏதேனும் ஆபத்தானவற்றைச் சரிபார்த்தாலோ — அல்லது ஆபத்தான UPI IDக்கு பணம் செலுத்த முயன்றாலோ — உங்களுக்கு உடனே எச்சரிக்கை வரும்.",
      alerts_t: "எச்சரிக்கைகள்", mark_read: "அனைத்தையும் படித்ததாகக் குறிக்கவும்", push_t: "அறிவிப்புகளாக எச்சரிக்கைகளைப் பெறுங்கள்", push_on: "அறிவிப்புகளை இயக்கு", push_test: "சோதனை எச்சரிக்கை அனுப்புக",
      g_title: "குடும்ப உறுப்பினரைப் பாதுகாக்கவும்", g_sub: "இதை உங்கள் மொபைலில் செய்யவும். பிறகு அவர்களின் மொபைலில் குறியீட்டை உள்ளிடவும்.", your_name: "உங்கள் பெயர் (அவர்கள் பார்ப்பார்கள்)",
      make_code: "இணைப்புக் குறியீட்டை உருவாக்கு", code_help: "அவர்களின் மொபைலில்: PayGuard திறக்கவும் → குடும்பம் → “நான் பாதுகாக்கப்பட விரும்புகிறேன்”, பிறகு இந்தக் குறியீட்டை உள்ளிடவும்:", cancel: "ரத்துசெய்",
      protecting_t: "நீங்கள் பாதுகாப்பவர்கள்", p_title: "நான் பாதுகாக்கப்பட விரும்புகிறேன்", p_sub: "இதை பெற்றோரின் மொபைலில், குடும்பத்தினர் அளித்த குறியீட்டைக் கொண்டு செய்யவும்.",
      code_label: "6 இலக்க குறியீடு", your_name2: "உங்கள் பெயர் (குடும்பத்தினர் பார்ப்பார்கள்)", consent_t: "உங்கள் குடும்பத்தினர் என்ன பார்ப்பார்கள்",
      consent_1: "ஆபத்தான எதையாவது நீங்கள் சரிபார்க்கும்போது: என்ன வகையான மோசடி மற்றும் பகுதி மறைக்கப்பட்ட UPI ID, எண் அல்லது வலைத்தளம்.",
      consent_2: "ஆபத்தான UPI IDக்கு நீங்கள் பணம் செலுத்த முயற்சிக்கும்போது.",
      consent_3: "உங்கள் தனிப்பட்ட செய்திகள், புகைப்படங்கள், வங்கி விவரங்கள் எப்போதும் பகிரப்படாது. எப்போது வேண்டுமானாலும் இதை நிறுத்தலாம்.",
      join: "என் மொபைலை இணைக்கவும்", protected_t: "உங்களைப் பாதுகாப்பவர்கள்", me_t: "உங்கள் விவரங்கள்",
      me_sub: "உங்கள் எண்ணைச் சேர்க்கவும்; நீங்கள் பாதுகாப்பவர்கள் ஒரே தட்டில் PayGuard இலிருந்து உங்களை அழைக்கலாம்.", save: "சேமி",
      forget: "இந்த மொபைலை நீக்கு (அனைத்து இணைப்புகளும் எச்சரிக்கைகளும் நீக்கப்படும்)", privacy: "எச்சரிக்கைகள் 30 நாட்களுக்கு வைக்கப்படும். PayGuard உங்கள் செய்திகள், ரசீதுகள் அல்லது வங்கி விவரங்களை யாருடனும் பகிர்வதில்லை.",
      expires: "குறியீடு {m}:{s} இல் காலாவதியாகும்", expired: "குறியீடு காலாவதியானது. புதிய ஒன்றை உருவாக்கவும்.", linked_ok: "✓ {name} இப்போது பாதுகாக்கப்படுகிறார்.",
      joined_ok: "✓ இணைக்கப்பட்டது. நீங்கள் ஏதேனும் மோசடியில் சிக்கினால் {name} எச்சரிக்கப்படுவார்.", need_code: "6 இலக்க குறியீட்டை உள்ளிடவும்.", since: "{d} முதல்",
      last_alert: "கடைசி எச்சரிக்கை {d}", no_alerts: "எச்சரிக்கைகள் எதுவும் இல்லை — நற்செய்தி.", remove: "நீக்கு", call: "அழை", confirm_remove: "{name} உடன் எச்சரிக்கைகளைப் பகிர்வதை நிறுத்தவா?",
      confirm_forget: "இந்த மொபைலிலிருந்து அனைத்து இணைப்புகளையும் எச்சரிக்கைகளையும் நீக்கவா?", saved: "சேமிக்கப்பட்டது.", forgot: "இந்த மொபைல் நீக்கப்பட்டது.",
      push_ok: "✓ இந்த மொபைலில் அறிவிப்புகள் இயக்கப்பட்டுள்ளன.", push_off: "அறிவிப்புகள் முடக்கப்பட்டுள்ளன. எச்சரிக்கைகள் இந்தப் பக்கத்தில் தோன்றும்.",
      push_help_web: "PayGuard ஐத் திறக்கும் போது எச்சரிக்கைகள் இங்கு தோன்றும். ஆப் மூடியிருக்கும் போதும் பெற அறிவிப்புகளை இயக்கவும்.",
      push_help_ios: "iPhone இல், PayGuard ஐ முகப்புத் திரையில் சேர்த்த பிறகு மட்டுமே அறிவிப்புகள் வேலை செய்யும் (பகிர் → Add to Home Screen). iOS 16.4 அல்லது புதியது தேவை.",
      push_help_app: "PayGuard Android ஆப் பயன்படுத்துகிறீர்களா? அது தானாகவே எச்சரிக்கைகளைச் சரிபார்க்கும் — ஒருமுறை திறந்து அறிவிப்புகளை அனுமதிக்கவும்.",
      push_denied: "அறிவிப்புகள் தடுக்கப்பட்டுள்ளன. உலாவி அமைப்புகளில் அனுமதித்து மீண்டும் முயற்சிக்கவும்.",
      push_na: "இந்த உலாவியால் அறிவிப்புகளைக் காட்ட முடியாது. இந்தப் பக்கத்தைத் திறந்து வைக்கவும்.",
      push_https: "அறிவிப்புகளுக்கு PayGuard இன் பாதுகாப்பான https:// முகவரி தேவை.", test_sent: "சோதனை எச்சரிக்கை அனுப்பப்பட்டது — சில வினாடிகளில் தோன்றும்.",
      now: "சற்று முன்", mins: "{n} நிமிடம் முன்", hours: "{n} மணி நேரம் முன்", call_them: "{name} ஐ அழைக்கவும்", unseen: "புதியது" },
    te: { nav_check: "తనిఖీ", nav_trends: "ట్రెండ్స్", nav_family: "కుటుంబం", title: "కుటుంబ రక్షణ",
      sub: "తల్లిదండ్రుల ఫోన్‌ను మీ ఫోన్‌తో లింక్ చేయండి. వారు ఏదైనా ప్రమాదకరమైనదాన్ని తనిఖీ చేస్తే — లేదా ప్రమాదకరమైన UPI IDకి చెల్లించడానికి ప్రయత్నిస్తే — మీకు వెంటనే హెచ్చరిక వస్తుంది.",
      alerts_t: "హెచ్చరికలు", mark_read: "అన్నీ చదివినట్లు గుర్తించు", push_t: "హెచ్చరికలను నోటిఫికేషన్‌లుగా పొందండి", push_on: "నోటిఫికేషన్‌లను ప్రారంభించండి", push_test: "టెస్ట్ హెచ్చరిక పంపండి",
      g_title: "కుటుంబ సభ్యుడిని రక్షించండి", g_sub: "దీన్ని మీ ఫోన్‌లో చేయండి. తర్వాత వారి ఫోన్‌లో కోడ్ నమోదు చేయండి.", your_name: "మీ పేరు (వారు చూస్తారు)",
      make_code: "లింకింగ్ కోడ్ సృష్టించండి", code_help: "వారి ఫోన్‌లో: PayGuard తెరవండి → కుటుంబం → “నేను రక్షణ కోరుకుంటున్నాను”, ఈ కోడ్‌ను నమోదు చేయండి:", cancel: "రద్దు",
      protecting_t: "మీరు రక్షిస్తున్న వ్యక్తులు", p_title: "నేను రక్షణ కోరుకుంటున్నాను", p_sub: "దీన్ని తల్లిదండ్రుల ఫోన్‌లో, కుటుంబ సభ్యుడు ఇచ్చిన కోడ్‌తో చేయండి.",
      code_label: "6 అంకెల కోడ్", your_name2: "మీ పేరు (మీ కుటుంబం చూస్తుంది)", consent_t: "మీ కుటుంబ సభ్యుడు ఏమి చూస్తారు",
      consent_1: "మీరు ప్రమాదకరమైనదాన్ని తనిఖీ చేసినప్పుడు: అది ఏ రకమైన మోసం మరియు పాక్షికంగా దాచిన UPI ID, నంబర్ లేదా వెబ్‌సైట్.",
      consent_2: "మీరు ప్రమాదకరమైన UPI IDకి చెల్లించాలని ఎంచుకున్నప్పుడు.",
      consent_3: "మీ వ్యక్తిగత సందేశాలు, ఫోటోలు, బ్యాంక్ వివరాలు ఎప్పటికీ షేర్ చేయబడవు. మీరు ఎప్పుడైనా దీన్ని ఆపవచ్చు.",
      join: "నా ఫోన్‌ను లింక్ చేయండి", protected_t: "మిమ్మల్ని రక్షిస్తున్న వ్యక్తులు", me_t: "మీ వివరాలు",
      me_sub: "మీరు రక్షించేవారు ఒకే ట్యాప్‌తో కాల్ చేయడానికి మీ నంబర్‌ను జోడించండి.", save: "సేవ్",
      forget: "ఈ ఫోన్‌ను తీసివేయండి (అన్ని లింక్‌లు, హెచ్చరికలు తొలగించబడతాయి)", privacy: "హెచ్చరికలు 30 రోజుల పాటు ఉంచబడతాయి. PayGuard మీ వివరాలను ఎవరితోనూ పంచుకోదు.",
      expires: "కోడ్ {m}:{s}లో ముగుస్తుంది", expired: "ఈ కోడ్ గడువు ముగిసింది. కొత్తదాన్ని సృష్టించండి.", linked_ok: "✓ {name} ఇప్పుడు రక్షించబడ్డారు.",
      joined_ok: "✓ లింక్ చేయబడింది. మీరు ఏదైనా మోసంలో పడితే {name}కి హెచ్చరిక వెళుతుంది.", need_code: "6 అంకెల కోడ్‌ను నమోదు చేయండి.", since: "{d} నుండి",
      last_alert: "చివరి హెచ్చరిక {d}", no_alerts: "ఇంకా ఎలాంటి హెచ్చరికలు లేవు — మంచి వార్త.", remove: "తీసివేయి", call: "కాల్", confirm_remove: "{name}తో హెచ్చరికలను పంచుకోవడం ఆపాలా?",
      confirm_forget: "ఈ ఫోన్ నుండి అన్ని లింక్‌లు, హెచ్చరికలను తొలగించాలా?", saved: "సేవ్ చేయబడింది.", forgot: "ఈ ఫోన్ తీసివేయబడింది.",
      push_ok: "✓ ఈ ఫోన్‌లో నోటిఫికేషన్‌లు ఆన్‌లో ఉన్నాయి.", push_off: "నోటిఫికేషన్‌లు ఆఫ్ చేయబడ్డాయి. హెచ్చరికలు ఈ పేజీలో కనిపిస్తాయి.",
      push_help_web: "PayGuard తెరిచినప్పుడు హెచ్చరికలు ఇక్కడ కనిపిస్తాయి. యాప్ మూసి ఉన్నప్పుడు కూడా పొందడానికి నోటిఫికేషన్‌లను ఆన్ చేయండి.",
      push_help_ios: "iPhoneలో, PayGuardను హోమ్ స్క్రీన్‌కి చేర్చిన తర్వాతే నోటిఫికేషన్‌లు పనిచేస్తాయి (షేర్ → Add to Home Screen). iOS 16.4 లేదా కొత్తది అవసరం.",
      push_help_app: "PayGuard Android యాప్ వాడుతున్నారా? అది స్వయంగా హెచ్చరికలను తనిఖీ చేస్తుంది — ఒకసారి తెరిచి నోటిఫికేషన్‌లను అనుమతించండి.",
      push_denied: "నోటిఫికేషన్‌లు బ్లాక్ చేయబడ్డాయి. బ్రౌజర్ సెట్టింగ్‌లలో అనుమతించి, మళ్లీ ప్రయత్నించండి.",
      push_na: "ఈ బ్రౌజర్ నోటిఫికేషన్‌లను చూపించలేదు. ఈ పేజీని తెరిచి ఉంచండి.",
      push_https: "నోటిఫికేషన్‌ల కోసం PayGuard సురక్షిత https:// చిరునామా అవసరం.", test_sent: "టెస్ట్ హెచ్చరిక పంపబడింది — కొన్ని సెకన్లలో కనిపిస్తుంది.",
      now: "ఇప్పుడే", mins: "{n} నిమిషాల క్రితం", hours: "{n} గంటల క్రితం", call_them: "{name}కి కాల్ చేయండి", unseen: "కొత్తది" },
    mr: { nav_check: "तपासा", nav_trends: "ट्रेंड्स", nav_family: "कुटुंब", title: "कुटुंब संरक्षण",
      sub: "पालकांचा फोन तुमच्या फोनशी जोडा. जर त्यांनी काही धोकादायक तपासले — किंवा धोकादायक UPI ID ला पेमेंट करण्याचा प्रयत्न केला — तर तुम्हाला लगेच अलर्ट मिळेल.",
      alerts_t: "अलर्ट्स", mark_read: "सर्व वाचलेले चिन्हांकित करा", push_t: "सूचना म्हणून अलर्ट मिळवा", push_on: "सूचना चालू करा", push_test: "चाचणी अलर्ट पाठवा",
      g_title: "कुटुंबातील सदस्याचे संरक्षण करा", g_sub: "हे तुमच्या फोनवर करा. नंतर त्यांच्या फोनवर कोड प्रविष्ट करा.", your_name: "तुमचे नाव (त्यांना दिसेल)",
      make_code: "लिंकिंग कोड तयार करा", code_help: "त्यांच्या फोनवर: PayGuard उघडा → कुटुंब → “मला संरक्षित व्हायचे आहे”, आणि हा कोड टाका:", cancel: "रद्द करा",
      protecting_t: "तुम्ही संरक्षित केलेले लोक", p_title: "मला संरक्षित व्हायचे आहे", p_sub: "हे पालकांच्या फोनवर, कुटुंबाकडून मिळालेल्या कोडसह करा.",
      code_label: "६ अंकी कोड", your_name2: "तुमचे नाव (कुटुंब बघेल)", consent_t: "तुमचे कुटुंब काय बघेल",
      consent_1: "जेव्हा तुम्ही काही धोकादायक तपासता: कोणत्या प्रकारची फसवणूक आहे आणि अंशतः लपवलेला UPI ID, नंबर किंवा वेबसाइट.",
      consent_2: "जेव्हा तुम्ही धोकादायक UPI ID ला पेमेंट करायचे निवडता.",
      consent_3: "तुमचे वैयक्तिक मेसेज, फोटो, बँक तपशील कधीही शेअर केले जात नाहीत. तुम्ही हे कधीही थांबवू शकता.",
      join: "माझा फोन लिंक करा", protected_t: "तुमचे संरक्षण करणारे लोक", me_t: "तुमचे तपशील",
      me_sub: "तुमचा नंबर जोडा जेणेकरून तुम्ही ज्यांचे रक्षण करता ते एका टॅपने तुम्हाला कॉल करू शकतील.", save: "जतन करा",
      forget: "हा फोन विसरा (सर्व लिंक्स आणि अलर्ट हटवले जातील)", privacy: "अलर्ट 30 दिवस ठेवले जातात. PayGuard तुमचे मेसेज किंवा बँक तपशील कधीही कोणाशीही शेअर करत नाही.",
      expires: "कोड {m}:{s} मध्ये संपेल", expired: "हा कोड कालबाह्य झाला आहे. नवीन तयार करा.", linked_ok: "✓ {name} आता संरक्षित आहेत.",
      joined_ok: "✓ लिंक झाले. तुम्ही एखाद्या फसवणुकीत अडकल्यास {name} यांना अलर्ट मिळेल.", need_code: "६ अंकी कोड प्रविष्ट करा.", since: "{d} पासून",
      last_alert: "शेवटचा अलर्ट {d}", no_alerts: "अद्याप कोणताही अलर्ट नाही — चांगली बातमी.", remove: "काढून टाका", call: "कॉल", confirm_remove: "{name} सह अलर्ट शेअर करणे थांबवायचे?",
      confirm_forget: "या फोनवरून सर्व कौटुंबिक लिंक्स आणि अलर्ट काढायचे?", saved: "जतन केले.", forgot: "हा फोन विसरला गेला आहे.",
      push_ok: "✓ या फोनवर सूचना चालू आहेत.", push_off: "सूचना बंद आहेत. अलर्ट या पानावर दिसतील.",
      push_help_web: "PayGuard उघडल्यावर अलर्ट येथे दिसतात. ॲप बंद असतानाही मिळवण्यासाठी सूचना चालू करा.",
      push_help_ios: "iPhone वर, PayGuard होम स्क्रीनवर जोडल्यानंतरच सूचना काम करतात (Share → Add to Home Screen). iOS 16.4 किंवा नवीन आवश्यक.",
      push_help_app: "PayGuard Android ॲप वापरत आहात? ते स्वतः अलर्ट तपासते — एकदा उघडा आणि सूचनांना अनुमती द्या.",
      push_denied: "सूचना ब्लॉक केल्या आहेत. ब्राउझर सेटिंग्जमध्ये अनुमती द्या, नंतर पुन्हा प्रयत्न करा.",
      push_na: "हा ब्राउझर सूचना दाखवू शकत नाही. हे पान उघडे ठेवा.",
      push_https: "सूचनांसाठी PayGuard चा सुरक्षित https:// पत्ता आवश्यक आहे.", test_sent: "चाचणी अलर्ट पाठवला — काही सेकंदात दिसेल.",
      now: "आत्ताच", mins: "{n} मिनिटांपूर्वी", hours: "{n} तासांपूर्वी", call_them: "{name} यांना कॉल करा", unseen: "नवीन" },
    bn: { nav_check: "যাচাই", nav_trends: "ট্রেন্ডস", nav_family: "পরিবার", title: "পারিবারিক সুরক্ষা",
      sub: "পিতামাতার ফোনটি আপনার ফোনের সাথে যুক্ত করুন। তারা যদি সন্দেহজনক কিছু পরীক্ষা করেন — বা বিপজ্জনক UPI ID-তে টাকা পাঠাতে যান — আপনি সাথে সাথে সতর্কবার্তা পাবেন।",
      alerts_t: "সতর্কবার্তা", mark_read: "সব পঠিত হিসেবে চিহ্নিত করুন", push_t: "নোটিফিকেশন হিসেবে সতর্কতা পান", push_on: "নোটিফিকেশন চালু করুন", push_test: "টেস্ট সতর্কতা পাঠান",
      g_title: "পরিবারের সদস্যকে সুরক্ষিত করুন", g_sub: "এটি আপনার ফোনে করুন। তারপর তাদের ফোনে কোডটি লিখুন।", your_name: "আপনার নাম (তারা দেখতে পাবেন)",
      make_code: "লিঙ্কিং কোড তৈরি করুন", code_help: "তাদের ফোনে: PayGuard খুলুন → পরিবার → “আমি সুরক্ষিত হতে চাই”, এবং এই কোডটি লিখুন:", cancel: "বাতিল",
      protecting_t: "যাদের আপনি সুরক্ষা দিচ্ছেন", p_title: "আমি সুরক্ষিত হতে চাই", p_sub: "এটি পিতামাতার ফোনে, পরিবারের সদস্যের থেকে পাওয়া কোড দিয়ে করুন।",
      code_label: "৬ সংখ্যার কোড", your_name2: "আপনার নাম (পরিবার দেখতে পাবে)", consent_t: "আপনার পরিবারের সদস্য যা দেখতে পাবেন",
      consent_1: "আপনি যখন বিপজ্জনক কিছু পরীক্ষা করবেন: কী ধরনের প্রতারণা এবং আংশিক লুকানো UPI ID, নম্বর বা ওয়েবসাইট।",
      consent_2: "আপনি যখন ঝুঁকিপূর্ণ UPI ID-তে তবুও টাকা পাঠানোর সিদ্ধান্ত নেবেন।",
      consent_3: "আপনার কোনো মেসেজ, ছবি বা ব্যাঙ্কের তথ্য কখনোই নয়। আপনি যেকোনো সময় এটি বন্ধ করতে পারেন।",
      join: "আমার ফোন যুক্ত করুন", protected_t: "যারা আপনাকে সুরক্ষা দিচ্ছেন", me_t: "আপনার তথ্য",
      me_sub: "আপনার নম্বর যোগ করুন যাতে সুরক্ষিত সদস্যরা এক ট্যাপে আপনাকে কল করতে পারেন।", save: "সংরক্ষণ করুন",
      forget: "এই ফোনটি ভুলে যান (সমস্ত লিঙ্ক এবং সতর্কতা মুছে যাবে)", privacy: "সতর্কবার্তা ৩০ দিন রাখা হয়। PayGuard কখনোই আপনার মেসেজ বা ব্যাঙ্কের তথ্য কারো সাথে শেয়ার করে না।",
      expires: "কোড {m}:{s}-এ শেষ হবে", expired: "কোডের মেয়াদ শেষ। নতুন কোড তৈরি করুন।", linked_ok: "✓ {name} এখন সুরক্ষিত।",
      joined_ok: "✓ যুক্ত হয়েছে। আপনি প্রতারণার মুখে পড়লে {name}-এর কাছে সতর্কতা যাবে।", need_code: "৬ সংখ্যার কোড লিখুন।", since: "{d} থেকে",
      last_alert: "শেষ সতর্কতা {d}", no_alerts: "এখনো কোনো সতর্কতা নেই — সুখবর।", remove: "সরিয়ে দিন", call: "কল", confirm_remove: "{name}-এর সাথে সতর্কতা ভাগ করা বন্ধ করবেন?",
      confirm_forget: "এই ফোন থেকে সমস্ত পারিবারিক লিঙ্ক এবং সতর্কতা মুছে ফেলবেন?", saved: "সংরক্ষিত।", forgot: "এই ফোনটি মুছে ফেলা হয়েছে।",
      push_ok: "✓ এই ফোনে নোটিফিকেশন চালু আছে।", push_off: "নোটিফিকেশন বন্ধ আছে। সতর্কতা এই পেজে দেখা যাবে।",
      push_help_web: "PayGuard খুললে সতর্কতা এখানে দেখা যাবে। অ্যাপ বন্ধ থাকলেও পেতে নোটিফিকেশন চালু করুন।",
      push_help_ios: "iPhone-এ, PayGuard হোম স্ক্রিনে যোগ করার পরেই নোটিফিকেশন কাজ করে (শেয়ার → Add to Home Screen)। iOS 16.4 বা নতুন প্রয়োজন।",
      push_help_app: "PayGuard Android অ্যাপ ব্যবহার করছেন? এটি নিজে থেকেই সতর্কতা পরীক্ষা করে — একবার খুলে অনুমতি দিন।",
      push_denied: "নোটিফিকেশন ব্লক করা আছে। ব্রাউজার সেটিংসে অনুমতি দিন, তারপর আবার চেষ্টা করুন।",
      push_na: "এই ব্রাউজার নোটিফিকেশন সমর্থন করে না। এই পেজটি খোলা রাখুন।",
      push_https: "নোটিফিকেশনের জন্য PayGuard-এর নিরাপদ https:// ঠিকানা প্রয়োজন।", test_sent: "টেস্ট সতর্কতা পাঠানো হয়েছে — কিছু সেকেন্ডে দেখতে পাবেন।",
      now: "এইমাত্র", mins: "{n} মিনিট আগে", hours: "{n} ঘণ্টা আগে", call_them: "{name}-কে কল করুন", unseen: "নতুন" },
  };
  let lang = "en";
  try { lang = localStorage.getItem("apkx_lang") || "en"; } catch (_) {}
  if (!S[lang]) lang = "en";
  const t = (k, v = {}) => ((S[lang] || S.en)[k] ?? S.en[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
  const loc = () => (lang === "en" ? "en-IN" : lang + "-IN");
  let me = null, alerts = [], codeTimer = null, pollTimer = null;

  function toast(msg) {
    const el = $("#toast"); el.textContent = msg; el.hidden = false;
    clearTimeout(toast._t); toast._t = setTimeout(() => (el.hidden = true), 3200);
  }
  function err(msg) { const e = $("#err"); e.hidden = !msg; e.textContent = msg || ""; }
  async function api(path, opts = {}) {
    const res = await fetch(path, { ...opts, headers: { "content-type": "application/json", ...(opts.headers || {}) } });
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error(data.error || "Error " + res.status);
    return data;
  }
  const ago = (ts) => {
    const s = Date.now() / 1000 - ts;
    if (s < 60) return t("now");
    if (s < 3600) return t("mins", { n: Math.round(s / 60) });
    if (s < 86400) return t("hours", { n: Math.round(s / 3600) });
    return new Date(ts * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short" });
  };
  const day = (ts) => new Date(ts * 1000).toLocaleDateString(loc(), { day: "numeric", month: "short", year: "numeric" });
  const initial = (n) => esc((n || "?").trim().charAt(0).toUpperCase());

  function setLang(l) {
    lang = l;
    try { localStorage.setItem("apkx_lang", l); } catch (_) {}
    document.documentElement.lang = l;
    document.querySelectorAll(".lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === l));
    document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
    if (me && D.token()) api("/api/family/device", { method: "PATCH", body: JSON.stringify({ lang: l }) }).catch(() => {});
    render();
  }
  document.querySelectorAll(".lang button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));

  // ------------------------------------------------------------------ data
  async function load() {
    if (!D.token()) { me = null; alerts = []; render(); return; }
    try {
      me = await api("/api/family/me");
      if (me.protecting.length) alerts = (await api("/api/family/alerts?limit=50")).alerts;
      else alerts = [];
      err("");
    } catch (e) {
      if (/set up/.test(e.message)) { D.forgetLocal(); me = null; } else err(e.message);
    }
    render();
    D.refresh();
  }

  function render() {
    const prot = (me && me.protecting) || [], by = (me && me.protected_by) || [];
    // guardians
    $("#protecting-wrap").hidden = !prot.length;
    $("#protecting").innerHTML = prot.map((p) => `<li><span class="av">${initial(p.name)}</span><span class="who"><b>${esc(p.name)}</b>
      <small>${esc(t("since", { d: day(p.since) }))}${p.last_alert ? " · " + esc(t("last_alert", { d: ago(p.last_alert) })) : ""}</small></span>
      ${p.phone ? `<a class="btn small" href="tel:+91${esc(p.phone)}">📞 ${esc(t("call"))}</a>` : ""}
      <button class="linkbtn danger-txt" data-unlink="${esc(p.id)}" data-name="${esc(p.name)}">${esc(t("remove"))}</button></li>`).join("");
    $("#alerts-sec").hidden = !prot.length;
    $("#push-sec").hidden = !prot.length;
    $("#alerts").innerHTML = alerts.length ? alerts.map((a) => `<li class="alert ${esc(a.level || "")} ${esc(a.type)} ${a.seen ? "" : "unseen"}">
      <h4>${esc(a.title[lang] || a.title.en)}</h4><p>${esc(a.body[lang] || a.body.en)}</p>
      <div class="when"><span>${esc(ago(a.created))}</span>${a.seen ? "" : `<b>● ${esc(t("unseen"))}</b>`}
      ${a.from.phone && a.type !== "linked" && a.type !== "test" ? `<a class="btn small" href="tel:+91${esc(a.from.phone)}">📞 ${esc(t("call_them", { name: a.from.name }))}</a>` : ""}</div></li>`).join("")
      : `<li class="empty">${esc(t("no_alerts"))}</li>`;
    // protected
    $("#protected-wrap").hidden = !by.length;
    $("#protected").innerHTML = by.map((g) => `<li><span class="av">${initial(g.name)}</span><span class="who"><b>${esc(g.name)}</b>
      <small>${esc(t("since", { d: day(g.since) }))}</small></span>
      ${g.phone ? `<a class="btn small" href="tel:+91${esc(g.phone)}">📞 ${esc(t("call"))}</a>` : ""}
      <button class="linkbtn danger-txt" data-unlink="${esc(g.id)}" data-name="${esc(g.name)}">${esc(t("remove"))}</button></li>`).join("");
    // me
    $("#me-sec").hidden = !me;
    if (me && document.activeElement !== $("#me-name") && document.activeElement !== $("#me-phone")) {
      $("#me-name").value = me.device.name || "";
      $("#me-phone").value = me.device.phone || "";
    }
    if (me && me.device.name && !$("#g-name").value) $("#g-name").value = me.device.name;
    pushHelp();
  }

  // ------------------------------------------------------------------ guardian: make a code
  $("#make-code").addEventListener("click", async () => {
    const name = $("#g-name").value.trim();
    if (!name) { $("#g-name").focus(); return; }
    try {
      await D.ensure(name);
      const inv = await api("/api/family/invite", { method: "POST", body: JSON.stringify({ name }) });
      $("#code").textContent = inv.code.slice(0, 3) + " " + inv.code.slice(3);
      $("#code-qr").src = "/api/qr/render.png?data=" + encodeURIComponent(inv.join_url);
      $("#guard-start").hidden = true;
      $("#guard-code").hidden = false;
      const before = new Set(((me && me.protecting) || []).map((p) => p.id));
      const end = inv.expires_at * 1000;
      clearInterval(codeTimer);
      const tick = async () => {
        const left = Math.max(0, Math.round((end - Date.now()) / 1000));
        $("#code-exp").textContent = left ? t("expires", { m: Math.floor(left / 60), s: String(left % 60).padStart(2, "0") }) : t("expired");
        if (!left) { clearInterval(codeTimer); return; }
        if (left % 3 === 0) {
          try {
            me = await api("/api/family/me");
            const added = me.protecting.find((p) => !before.has(p.id));
            if (added) { clearInterval(codeTimer); cancelCode(); toast(t("linked_ok", { name: added.name })); await load(); }
          } catch (_) {}
        }
      };
      tick();
      codeTimer = setInterval(tick, 1000);
    } catch (e) { err(e.message); }
  });
  function cancelCode() { clearInterval(codeTimer); $("#guard-code").hidden = true; $("#guard-start").hidden = false; }
  $("#code-cancel").addEventListener("click", cancelCode);

  // ------------------------------------------------------------------ protected: join with a code
  $("#join-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = $("#j-code").value.replace(/\D/g, "");
    if (code.length !== 6) { toast(t("need_code")); $("#j-code").focus(); return; }
    try {
      await D.ensure($("#j-name").value.trim());
      const r = await api("/api/family/join", { method: "POST", body: JSON.stringify({ code, name: $("#j-name").value.trim() }) });
      $("#j-code").value = "";
      toast(t("joined_ok", { name: r.guardian.name }));
      history.replaceState({}, "", "/family");
      await load();
    } catch (e2) { err(e2.message); }
  });
  const joinCode = new URLSearchParams(location.search).get("join");
  if (joinCode) { $("#j-code").value = joinCode.replace(/\D/g, "").slice(0, 6); setTimeout(() => $("#prot").scrollIntoView({ behavior: "smooth" }), 300); }

  // ------------------------------------------------------------------ lists
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-unlink]");
    if (!b) return;
    if (!confirm(t("confirm_remove", { name: b.dataset.name }))) return;
    try { await api("/api/family/link/" + encodeURIComponent(b.dataset.unlink), { method: "DELETE" }); await load(); } catch (e2) { err(e2.message); }
  });
  $("#mark-read").addEventListener("click", async () => {
    if (!alerts.length) return;
    try { await api("/api/family/alerts/seen", { method: "POST", body: JSON.stringify({ up_to_id: alerts[0].id }) }); await load(); } catch (e) { err(e.message); }
  });
  $("#me-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      me = await api("/api/family/device", { method: "PATCH", body: JSON.stringify({ name: $("#me-name").value, phone: $("#me-phone").value }) });
      $("#me-state").textContent = t("saved");
      render();
    } catch (e2) { $("#me-state").textContent = e2.message; }
  });
  $("#forget").addEventListener("click", async () => {
    if (!confirm(t("confirm_forget"))) return;
    try { await unsubscribePush(); await api("/api/family/device", { method: "DELETE" }); } catch (_) {}
    D.forgetLocal();
    me = null; alerts = [];
    toast(t("forgot"));
    render();
  });

  // ------------------------------------------------------------------ push notifications
  const ua = navigator.userAgent || "";
  const ios = D.platform === "ios";
  const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  const secure = location.protocol === "https:" || ["localhost", "127.0.0.1"].includes(location.hostname);
  const pushable = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  const inApp = /PayGuardApp/i.test(ua);

  async function currentSub() {
    if (!pushable || !secure) return null;
    try { const reg = await navigator.serviceWorker.ready; return await reg.pushManager.getSubscription(); } catch (_) { return null; }
  }
  async function pushHelp() {
    const help = $("#push-help"), state = $("#push-state"), on = $("#push-on");
    if (inApp) { help.textContent = t("push_help_app"); on.hidden = true; state.textContent = ""; return; }
    if (!secure) { help.textContent = t("push_https"); on.hidden = true; return; }
    if (ios && !standalone) { help.textContent = t("push_help_ios"); on.hidden = true; return; }
    if (!pushable) { help.textContent = t("push_na"); on.hidden = true; return; }
    help.textContent = t("push_help_web");
    const sub = await currentSub();
    const enabled = !!sub && Notification.permission === "granted";
    on.hidden = enabled;
    state.textContent = Notification.permission === "denied" ? t("push_denied") : enabled ? t("push_ok") : t("push_off");
  }
  const b64ToU8 = (s) => { const b = atob((s + "=".repeat((4 - (s.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/")); return Uint8Array.from(b, (c) => c.charCodeAt(0)); };
  $("#push-on").addEventListener("click", async () => {
    try {
      if ((await Notification.requestPermission()) !== "granted") { $("#push-state").textContent = t("push_denied"); return; }
      const reg = await navigator.serviceWorker.register("/sw.js");
      await navigator.serviceWorker.ready;
      const { key } = await api("/api/family/push-key");
      let sub = await reg.pushManager.getSubscription();
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToU8(key) });
      await api("/api/family/push", { method: "POST", body: JSON.stringify({ subscription: sub.toJSON() }) });
      await pushHelp();
    } catch (e) { $("#push-state").textContent = e.message; }
  });
  async function unsubscribePush() {
    const sub = await currentSub();
    if (sub) { try { await sub.unsubscribe(); } catch (_) {} }
  }
  $("#push-test").addEventListener("click", async () => {
    try { await api("/api/family/test", { method: "POST" }); toast(t("test_sent")); setTimeout(load, 1500); } catch (e) { err(e.message); }
  });

  setLang(lang);
  load();
  pollTimer = setInterval(() => { if (!document.hidden && D.token()) load(); }, 20000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && D.token()) load(); });
})();
