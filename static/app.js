/* APK X-Ray front end — vanilla JS, no build step. */
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ------------------------------------------------------------ UI strings
  const UI = {
    en: {},
    hi: {
      eyebrow: "पैसे भेजने, टैप या इंस्टॉल करने से पहले ठगी रोकें",
      nav_trends: "ट्रेंड्स", nav_family: "परिवार", mode_msg: "मैसेज / SMS",
      msg_label: "आपको मिला SMS, WhatsApp मैसेज या ईमेल यहाँ पेस्ट करें", msg_paste: "पेस्ट करें", msg_example: "उदाहरण देखें", msg_check: "मैसेज जाँचें",
      msg_privacy: "हम आपका मैसेज सेव नहीं करते। सिर्फ़ जाँचते हैं, और रिपोर्ट करने पर सिर्फ़ ठग के लिंक, UPI ID और नंबर गिने जाते हैं — आपका टेक्स्ट कभी नहीं।",
      msg_res: "मैसेज", msg_asks: "यह आपसे क्या करवाना चाहता है", msg_found: "इसमें मिले लिंक, UPI ID और नंबर", msg_marked: "ख़तरे वाले हिस्से हाइलाइट किए गए हैं",
      l_link: "लिंक", l_upi: "UPI ID", l_phone: "मोबाइल नंबर", l_tollfree: "टोल-फ़्री नंबर", l_official: "आधिकारिक", l_notofficial: "आधिकारिक नहीं", l_reported: "{n} रिपोर्ट",
      g_title: "पैसे भेजने से पहले {name} से बात करें", g_call: "{name} को कॉल करें", g_alerted: "{name} को सूचना भेज दी गई है।", g_alerted_many: "आपके परिवार को सूचना भेज दी गई है।",
      paste_denied: "पेस्ट नहीं हो सका — मैसेज बॉक्स में लंबा दबाकर पेस्ट करें।",
      h1: "कोई शक वाला मैसेज, QR कोड या ऐप मिला? <span>पहले जाँचें।</span>",
      lead: "“बिजली कटेगी”, “KYC ब्लॉक” और “पार्सल रुका” जैसे नकली मैसेज, “पैसे पाने के लिए स्कैन करें” वाले QR, एडिट किए पेमेंट स्क्रीनशॉट और ट्रोजन ऐप। यहाँ पेस्ट या अपलोड करें — हम आसान भाषा में बताते हैं कि यह ठगी है या नहीं।",
      drop_title: ".apk फ़ाइल चुनें", drop_sub: "या यहाँ खींचकर छोड़ें · कुछ भी इंस्टॉल या चलाया नहीं जाता",
      privacy: "फ़ाइल की जाँच के बाद उसे मिटा दिया जाता है। हम सिर्फ़ रिपोर्ट रखते हैं, जो फ़ाइल के फ़िंगरप्रिंट (SHA-256) से पहचानी जाती है।",
      how1: "खोलना", how1p: "APK असल में एक ZIP फ़ाइल है। हम उसे बिना इंस्टॉल किए या चलाए खोलते हैं।",
      how2: "मैनिफ़ेस्ट और कोड पढ़ना", how2p: "परमिशन, छिपी सर्विस, कोड के API कॉल, किन सर्वरों से जुड़ता है, और किसने साइन किया।",
      how3: "ट्रोजन पैटर्न मिलाना", how3p: "खतरनाक <em>जोड़ियाँ</em> — जैसे SMS + एक्सेसिबिलिटी + ओवरले — बैंकिंग ट्रोजन की पहचान हैं।",
      st0: "अपलोड हो रहा है", st1: "ऐप खोला जा रहा है", st2: "AndroidManifest.xml पढ़ा जा रहा है", st3: "कोड की जाँच", st4: "हस्ताक्षर और ट्रोजन पैटर्न की जाँच",
      err_t: "हम इस फ़ाइल की जाँच नहीं कर पाए", again: "दूसरी फ़ाइल जाँचें", risk: "जोखिम",
      speak: "सुनें", share: "परिवार को WhatsApp पर भेजें",
      triad_t: "बैंकिंग ट्रोजन की तिकड़ी", triad_p: "अकेले-अकेले ये जायज़ हो सकते हैं। तीनों एक साथ — यही OTP चोर ट्रोजन का तरीका है।",
      tri_sms: "SMS पढ़ता है", tri_sms_s: "आपके OTP देखता है", tri_acc: "एक्सेसिबिलिटी", tri_acc_s: "आपकी स्क्रीन चलाता है", tri_ovl: "ऐप्स के ऊपर दिखता है", tri_ovl_s: "नकली लॉगिन पेज",
      findings_t: "हमें क्या मिला", tech_t: "तकनीकी जानकारी",
      t_perms: "परमिशन", t_code: "कोड", t_net: "नेटवर्क", t_sign: "हस्ताक्षर", t_file: "फ़ाइल",
      foot1: "संदिग्ध ऐप इंस्टॉल कर लिया या पैसे गए?",
      lure_t: "यह किस बहाने से आया है", lure_need: "ऐसे असली ऐप को चाहिए", lure_asks: "यह ऐप इसके अलावा माँगता है",
      none: "कोई खतरे का संकेत नहीं मिला।", seen: "यही फ़ाइल {n} बार जाँची जा चुकी है — यह शायद कई लोगों को भेजी जा रही है।",
      copied: "मैसेज कॉपी हो गया", no_voice: "इस भाषा की आवाज़ आपके डिवाइस पर उपलब्ध नहीं है",
      evidence: "सबूत देखें", stats: "अब तक {n} ऐप फ़ाइलों की जाँच · {d} खतरनाक पाई गईं",
    },
    kn: {
      eyebrow: "ಪಾವತಿಸುವ, ಟ್ಯಾಪ್ ಅಥವಾ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವ ಮೊದಲೇ ವಂಚನೆ ತಡೆಯಿರಿ",
      nav_trends: "ಟ್ರೆಂಡ್‌ಗಳು", nav_family: "ಕುಟುಂಬ", mode_msg: "ಸಂದೇಶ / SMS",
      msg_label: "ನಿಮಗೆ ಬಂದ SMS, WhatsApp ಸಂದೇಶ ಅಥವಾ ಇಮೇಲ್ ಇಲ್ಲಿ ಅಂಟಿಸಿ", msg_paste: "ಅಂಟಿಸಿ", msg_example: "ಉದಾಹರಣೆ ನೋಡಿ", msg_check: "ಸಂದೇಶ ಪರಿಶೀಲಿಸಿ",
      msg_privacy: "ನಾವು ನಿಮ್ಮ ಸಂದೇಶ ಉಳಿಸುವುದಿಲ್ಲ. ಕೇವಲ ಪರಿಶೀಲಿಸುತ್ತೇವೆ; ವರದಿ ಮಾಡಿದರೆ ವಂಚಕರ ಲಿಂಕ್, UPI ID, ನಂಬರ್ ಮಾತ್ರ ಎಣಿಸುತ್ತೇವೆ — ನಿಮ್ಮ ಪಠ್ಯ ಎಂದಿಗೂ ಅಲ್ಲ.",
      msg_res: "ಸಂದೇಶ", msg_asks: "ಇದು ನಿಮ್ಮಿಂದ ಏನು ಮಾಡಿಸಲು ಬಯಸುತ್ತದೆ", msg_found: "ಇದರಲ್ಲಿರುವ ಲಿಂಕ್, UPI ID ಮತ್ತು ನಂಬರ್‌ಗಳು", msg_marked: "ಅಪಾಯದ ಭಾಗಗಳನ್ನು ಹೈಲೈಟ್ ಮಾಡಲಾಗಿದೆ",
      l_link: "ಲಿಂಕ್", l_upi: "UPI ID", l_phone: "ಮೊಬೈಲ್ ನಂಬರ್", l_tollfree: "ಟೋಲ್-ಫ್ರೀ ನಂಬರ್", l_official: "ಅಧಿಕೃತ", l_notofficial: "ಅಧಿಕೃತವಲ್ಲ", l_reported: "{n} ವರದಿ",
      g_title: "ಪಾವತಿಸುವ ಮೊದಲು {name} ಜೊತೆ ಮಾತನಾಡಿ", g_call: "{name} ಗೆ ಕರೆ ಮಾಡಿ", g_alerted: "{name} ಅವರಿಗೆ ತಿಳಿಸಲಾಗಿದೆ.", g_alerted_many: "ನಿಮ್ಮ ಕುಟುಂಬಕ್ಕೆ ತಿಳಿಸಲಾಗಿದೆ.",
      paste_denied: "ಅಂಟಿಸಲಾಗಲಿಲ್ಲ — ಸಂದೇಶ ಪೆಟ್ಟಿಗೆಯಲ್ಲಿ ಒತ್ತಿ ಹಿಡಿದು ಅಂಟಿಸಿ.",
      h1: "ಅನುಮಾನಾಸ್ಪದ ಸಂದೇಶ, QR ಕೋಡ್ ಅಥವಾ ಆ್ಯಪ್ ಬಂದಿದೆಯೇ? <span>ಮೊದಲು ಪರಿಶೀಲಿಸಿ.</span>",
      lead: "“ವಿದ್ಯುತ್ ಕಡಿತ”, “KYC ಬ್ಲಾಕ್”, “ಪಾರ್ಸೆಲ್ ತಡೆ” ನಕಲಿ ಸಂದೇಶಗಳು, “ಹಣ ಪಡೆಯಲು ಸ್ಕ್ಯಾನ್ ಮಾಡಿ” QR, ಎಡಿಟ್ ಮಾಡಿದ ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಮತ್ತು ಟ್ರೋಜನ್ ಆ್ಯಪ್‌ಗಳು. ಇಲ್ಲಿ ಅಂಟಿಸಿ ಅಥವಾ ಅಪ್‌ಲೋಡ್ ಮಾಡಿ — ಇದು ವಂಚನೆಯೇ ಎಂದು ಸರಳ ಭಾಷೆಯಲ್ಲಿ ಹೇಳುತ್ತೇವೆ.",
      drop_title: ".apk ಫೈಲ್ ಆಯ್ಕೆಮಾಡಿ", drop_sub: "ಅಥವಾ ಇಲ್ಲಿ ಎಳೆದು ಬಿಡಿ · ಏನನ್ನೂ ಇನ್‌ಸ್ಟಾಲ್ ಅಥವಾ ಚಾಲನೆ ಮಾಡುವುದಿಲ್ಲ",
      privacy: "ಪರಿಶೀಲನೆಯ ನಂತರ ಫೈಲ್ ಅಳಿಸಲಾಗುತ್ತದೆ. ನಾವು ವರದಿಯನ್ನು ಮಾತ್ರ ಇಡುತ್ತೇವೆ, ಅದನ್ನು ಫೈಲ್‌ನ ಫಿಂಗರ್‌ಪ್ರಿಂಟ್ (SHA-256) ಮೂಲಕ ಗುರುತಿಸಲಾಗುತ್ತದೆ.",
      how1: "ತೆರೆಯುವುದು", how1p: "APK ಒಂದು ZIP ಫೈಲ್ ಅಷ್ಟೇ. ಇನ್‌ಸ್ಟಾಲ್ ಅಥವಾ ಚಾಲನೆ ಮಾಡದೆ ನಾವು ಅದನ್ನು ತೆರೆಯುತ್ತೇವೆ.",
      how2: "ಮ್ಯಾನಿಫೆಸ್ಟ್ ಮತ್ತು ಕೋಡ್ ಓದುವುದು", how2p: "ಅನುಮತಿಗಳು, ಗುಪ್ತ ಸೇವೆಗಳು, ಕೋಡ್‌ನ API ಕರೆಗಳು, ಸಂಪರ್ಕಿಸುವ ಸರ್ವರ್‌ಗಳು ಮತ್ತು ಸಹಿ ಮಾಡಿದವರು.",
      how3: "ಟ್ರೋಜನ್ ಮಾದರಿ ಹೊಂದಿಸುವುದು", how3p: "ಅಪಾಯಕಾರಿ <em>ಸಂಯೋಜನೆಗಳು</em> — SMS + ಆಕ್ಸೆಸಿಬಿಲಿಟಿ + ಓವರ್‌ಲೇ — ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್‌ನ ಗುರುತು.",
      st0: "ಅಪ್‌ಲೋಡ್ ಆಗುತ್ತಿದೆ", st1: "ಆ್ಯಪ್ ತೆರೆಯಲಾಗುತ್ತಿದೆ", st2: "AndroidManifest.xml ಓದಲಾಗುತ್ತಿದೆ", st3: "ಕೋಡ್ ಪರಿಶೀಲನೆ", st4: "ಸಹಿ ಮತ್ತು ಟ್ರೋಜನ್ ಮಾದರಿ ಪರಿಶೀಲನೆ",
      err_t: "ಈ ಫೈಲ್ ಪರಿಶೀಲಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ", again: "ಇನ್ನೊಂದು ಫೈಲ್ ಪರಿಶೀಲಿಸಿ", risk: "ಅಪಾಯ",
      speak: "ಕೇಳಿ", share: "ಕುಟುಂಬಕ್ಕೆ WhatsApp ನಲ್ಲಿ ಕಳುಹಿಸಿ",
      triad_t: "ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್ ತ್ರಿವಳಿ", triad_p: "ಒಂದೊಂದಾಗಿ ಇವು ನ್ಯಾಯಸಮ್ಮತವಾಗಿರಬಹುದು. ಮೂರೂ ಒಟ್ಟಿಗೆ — ಇದೇ OTP ಕಳ್ಳ ಟ್ರೋಜನ್‌ಗಳ ವಿಧಾನ.",
      tri_sms: "SMS ಓದುತ್ತದೆ", tri_sms_s: "ನಿಮ್ಮ OTP ನೋಡುತ್ತದೆ", tri_acc: "ಆಕ್ಸೆಸಿಬಿಲಿಟಿ", tri_acc_s: "ನಿಮ್ಮ ಪರದೆ ನಿಯಂತ್ರಿಸುತ್ತದೆ", tri_ovl: "ಆ್ಯಪ್‌ಗಳ ಮೇಲೆ ಕಾಣುತ್ತದೆ", tri_ovl_s: "ನಕಲಿ ಲಾಗಿನ್ ಪುಟ",
      findings_t: "ನಮಗೆ ಏನು ಸಿಕ್ಕಿತು", tech_t: "ತಾಂತ್ರಿಕ ವಿವರಗಳು",
      t_perms: "ಅನುಮತಿಗಳು", t_code: "ಕೋಡ್", t_net: "ನೆಟ್‌ವರ್ಕ್", t_sign: "ಸಹಿ", t_file: "ಫೈಲ್",
      foot1: "ಸಂಶಯಾಸ್ಪದ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಆಗಿದೆಯೇ ಅಥವಾ ಹಣ ಕಳೆದುಕೊಂಡಿರಾ?",
      lure_t: "ಇದು ಯಾವ ನೆಪದಲ್ಲಿ ಬಂದಿದೆ", lure_need: "ಇಂತಹ ನಿಜವಾದ ಆ್ಯಪ್‌ಗೆ ಬೇಕಾಗಿರುವುದು", lure_asks: "ಈ ಆ್ಯಪ್ ಹೆಚ್ಚುವರಿಯಾಗಿ ಕೇಳುವುದು",
      none: "ಯಾವುದೇ ಅಪಾಯದ ಲಕ್ಷಣ ಕಂಡುಬಂದಿಲ್ಲ.", seen: "ಇದೇ ಫೈಲ್ ಅನ್ನು {n} ಬಾರಿ ಪರಿಶೀಲಿಸಲಾಗಿದೆ — ಇದು ಬಹುಶಃ ಹಲವರಿಗೆ ಕಳುಹಿಸಲಾಗುತ್ತಿದೆ.",
      copied: "ಸಂದೇಶ ಕಾಪಿ ಆಯಿತು", no_voice: "ಈ ಭಾಷೆಯ ಧ್ವನಿ ನಿಮ್ಮ ಸಾಧನದಲ್ಲಿ ಲಭ್ಯವಿಲ್ಲ",
      evidence: "ಸಾಕ್ಷ್ಯ ನೋಡಿ", stats: "ಇದುವರೆಗೆ {n} ಆ್ಯಪ್ ಫೈಲ್‌ಗಳ ಪರಿಶೀಲನೆ · {d} ಅಪಾಯಕಾರಿ",
    },
    ta: {
      eyebrow: "பணம் அனுப்பும், தட்டும் அல்லது நிறுவும் முன்பே மோசடியைத் தடுங்கள்",
      nav_trends: "ட்ரெண்டுகள்", nav_family: "குடும்பம்", mode_msg: "செய்தி / SMS",
      msg_label: "உங்களுக்கு வந்த SMS, WhatsApp செய்தி அல்லது மின்னஞ்சலை இங்கே ஒட்டவும்", msg_paste: "ஒட்டவும்", msg_example: "உதாரணம் காண்க", msg_check: "செய்தியைச் சரிபார்க்கவும்",
      msg_privacy: "உங்கள் செய்தியை நாங்கள் சேமிப்பதில்லை. சரிபார்க்க மட்டுமே செய்கிறோம்; புகாரளித்தால் மோசடி செய்பவரின் இணைப்பு, UPI ID மற்றும் எண் மட்டுமே கணக்கிடப்படும் — உங்கள் உரை ஒருபோதும் சேமிக்கப்படாது.",
      msg_res: "செய்தி", msg_asks: "இது உங்களிடம் என்ன செய்யச் சொல்கிறது", msg_found: "இதில் உள்ள இணைப்புகள், UPI ID மற்றும் எண்கள்", msg_marked: "ஆபத்தான பகுதிகள் முன்னிலைப்படுத்தப்பட்டுள்ளன",
      l_link: "இணைப்பு", l_upi: "UPI ID", l_phone: "மொபைல் எண்", l_tollfree: "கட்டணமில்லா எண்", l_official: "அதிகாரப்பூர்வமானது", l_notofficial: "அதிகாரப்பூர்வமற்றது", l_reported: "{n} புகார்கள்",
      g_title: "பணம் செலுத்தும் முன் {name} உடன் பேசுங்கள்", g_call: "{name} ஐ அழைக்கவும்", g_alerted: "{name}க்கு எச்சரிக்கை அனுப்பப்பட்டது.", g_alerted_many: "உங்கள் குடும்பத்திற்கு எச்சரிக்கை அனுப்பப்பட்டது.",
      paste_denied: "ஒட்ட முடியவில்லை — கட்டத்தின் மேல் நீண்ட நேரம் அழுத்தி ஒட்டவும்.",
      h1: "சந்தேகத்திற்குரிய செய்தி, QR குறியீடு அல்லது ஆப் வந்ததா? <span>முதலில் சரிபாருங்கள்.</span>",
      lead: "“மின்சாரம் துண்டிக்கப்படும்”, “KYC முடக்கம்”, “பார்சல் நிறுத்தம்” போன்ற போலி செய்திகள், “பணம் பெற ஸ்கேன் செய்” QR, எடிட் செய்யப்பட்ட ரசீதுகள் மற்றும் ட்ரோஜன் ஆப்ஸ். இங்கே ஒட்டவும் அல்லது பதிவேற்றவும் — இது மோசடியா என்பதை எளிய தமிழில் விளக்குகிறோம்.",
      drop_title: ".apk கோப்பைத் தேர்ந்தெடுக்கவும்", drop_sub: "அல்லது இங்கே இழுத்து விடவும் · எதுவும் நிறுவவோ இயக்கவோ படாது",
      privacy: "சரிபார்த்த பிறகு கோப்பு நீக்கப்படும். கோப்பின் கைரேகை (SHA-256) மூலம் அடையாளம் காணப்படும் அறிக்கையை மட்டுமே நாங்கள் வைத்திருக்கிறோம்.",
      how1: "திறத்தல்", how1p: "APK என்பது ஒரு ZIP கோப்பு மட்டுமே. நிறுவவோ இயக்கவோ செய்யாமல் அதைத் திறந்து பார்க்கிறோம்.",
      how2: "மேனிஃபெஸ்ட் & குறியீட்டைப் படித்தல்", how2p: "அனுமதிகள், மறைக்கப்பட்ட சேவைகள், API அழைப்புகள், இணைக்கும் சேவையகங்கள் மற்றும் கையொப்பமிட்டவர்.",
      how3: "ட்ரோஜன் முறைகளைக் கண்டறிதல்", how3p: "ஆபத்தான <em>கூட்டணி</em> — SMS + அக்சசிபிலிட்டி + மேலடுக்கு — பேங்கிங் ட்ரோஜனின் அடையாளம்.",
      st0: "பதிவேற்றப்படுகிறது", st1: "ஆப் திறக்கப்படுகிறது", st2: "AndroidManifest.xml படிக்கப்படுகிறது", st3: "குறியீடு ஆய்வு", st4: "கையொப்பம் மற்றும் ட்ரோஜன் முறை சரிபார்ப்பு",
      err_t: "இந்தக் கோப்பைச் சரிபார்க்க முடியவில்லை", again: "மற்றொரு கோப்பைச் சோதிக்கவும்", risk: "ஆபத்து",
      speak: "கேளுங்கள்", share: "குடும்பத்திற்கு WhatsApp-ல் பகிரவும்",
      triad_t: "பேங்கிங் ட்ரோஜனின் மும்மை", triad_p: "தனித்தனியாக இவை வழக்கமாக இருக்கலாம். மூன்றும் ஒன்றாக — OTP திருடும் ட்ரோஜன்களின் தந்திரம் இதுவே.",
      tri_sms: "SMS படிக்கிறது", tri_sms_s: "உங்கள் OTP ஐப் பார்க்கிறது", tri_acc: "அக்சசிபிலிட்டி", tri_acc_s: "திரையைக் கட்டுப்படுத்துகிறது", tri_ovl: "ஆப்ஸ்களின் மேல் திரையிடுகிறது", tri_ovl_s: "போலி உள்நுழைவுப் பக்கம்",
      findings_t: "கண்டறியப்பட்டவை", tech_t: "தொழில்நுட்ப விவரங்கள்",
      t_perms: "அனுமதிகள்", t_code: "குறியீடு", t_net: "நெட்வொர்க்", t_sign: "கையொப்பம்", t_file: "கோப்பு",
      foot1: "சந்தேகத்திற்குரிய ஆப் நிறுவிவிட்டீர்களா அல்லது பணத்தை இழந்துவிட்டீர்களா?",
      lure_t: "இது எதன் பெயரில் ஏமாற்றுகிறது", lure_need: "இத்தகைய அசல் ஆப்பிற்கு தேவையானது", lure_asks: "இந்த ஆப் கூடுதலாகக் கேட்பது",
      none: "ஆபத்துக்கான அறிகுறிகள் எதுவும் இல்லை.", seen: "இதே கோப்பு {n} முறை சோதிக்கப்பட்டுள்ளது — இது பலருக்கு அனுப்பப்படலாம்.",
      copied: "செய்தி நகலெடுக்கப்பட்டது", no_voice: "இந்த மொழிக்கான குரல் உங்கள் சாதனத்தில் இல்லை",
      evidence: "ஆதாரத்தைக் காட்டு", stats: "இதுவரை {n} ஆப் கோப்புகள் சோதிக்கப்பட்டன · {d} ஆபத்தானவை",
    },
    te: {
      eyebrow: "డబ్బు పంపే, ట్యాప్ చేసే లేదా ఇన్‌స్టాల్ చేసే ముందే మోసాన్ని ఆపండి",
      nav_trends: "ట్రెండ్స్", nav_family: "కుటుంబం", mode_msg: "సందేశం / SMS",
      msg_label: "మీకు వచ్చిన SMS, WhatsApp సందేశం లేదా ఇమెయిల్‌ను ఇక్కడ పేస్ట్ చేయండి", msg_paste: "పేస్ట్ చేయండి", msg_example: "ఉదాహరణ చూడండి", msg_check: "సందేశాన్ని తనిఖీ చేయండి",
      msg_privacy: "మేము మీ సందేశాన్ని సేవ్ చేయము. కేవలం తనిఖీ చేస్తాము; నివేదిస్తే మోసగాడి లింక్, UPI ID, నంబర్ మాత్రమే లెక్కించబడతాయి — మీ టెక్స్ట్ ఎప్పటికీ కాదు.",
      msg_res: "సందేశం", msg_asks: "ఇది మిమ్మల్ని ఏమి చేయమని అడుగుతోంది", msg_found: "ఇందులో ఉన్న లింకులు, UPI IDలు మరియు నంబర్లు", msg_marked: "ప్రమాదకర భాగాలు హైలైట్ చేయబడ్డాయి",
      l_link: "లింక్", l_upi: "UPI ID", l_phone: "మొబైల్ నంబర్", l_tollfree: "టోల్-ఫ్రీ నంబర్", l_official: "అధికారికమైనది", l_notofficial: "అధికారికం కాదు", l_reported: "{n} రిపోర్టులు",
      g_title: "చెల్లించే ముందు {name}తో మాట్లాడండి", g_call: "{name}కి కాల్ చేయండి", g_alerted: "{name}కి హెచ్చరిక పంపబడింది.", g_alerted_many: "మీ కుటుంబానికి హెచ్చరిక పంపబడింది.",
      paste_denied: "పేస్ట్ చేయలేకపోయాము — బాక్స్‌పై ఎక్కువసేపు నొక్కి పేస్ట్ చేయండి.",
      h1: "అనుమానాస్పద సందేశం, QR కోడ్ లేదా యాప్ వచ్చిందా? <span>ముందు తనిఖీ చేయండి.</span>",
      lead: "“కరెంట్ కట్”, “KYC బ్లాక్”, “పార్శిల్ ఆగింది” వంటి నకిలీ మెసేజ్‌లు, “డబ్బు పొందడానికి స్కాన్ చేయండి” QRలు, ఎడిట్ చేసిన రశీదులు మరియు ట్రోజన్ యాప్‌లు. ఇక్కడ పేస్ట్ చేయండి లేదా అప్‌లోడ్ చేయండి — ఇది మోసమా కాదా అని సులభంగా చెబుతాము.",
      drop_title: ".apk ఫైల్‌ను ఎంచుకోండి", drop_sub: "లేదా ఇక్కడ లాగి వదలండి · ఏదీ ఇన్‌స్టాల్ లేదా రన్ చేయబడదు",
      privacy: "తనిఖీ చేసిన తర్వాత ఫైల్ తొలగించబడుతుంది. ఫైల్ యొక్క వేలిముద్ర (SHA-256) ద్వారా గుర్తించబడే నివేదికను మాత్రమే మేము ఉంచుతాము.",
      how1: "తెరవడం", how1p: "APK అనేది ఒక ZIP ఫైల్ మాత్రమే. ఇన్‌స్టాల్ లేదా రన్ చేయకుండానే దాన్ని తెరుస్తాము.",
      how2: "మేనిఫెస్ట్ & కోడ్ చదవడం", how2p: "అనుమతులు, దాగివున్న సేవలు, API కాల్స్, కనెక్ట్ అయ్యే సర్వర్లు మరియు సంతకం చేసిన వివరాలు.",
      how3: "ట్రోజన్ నమూనాలను గుర్తించడం", how3p: "ప్రమాదకరమైన <em>కలయికలు</em> — SMS + యాక్సెసిబిలిటీ + ఓవర్‌లే — బ్యాంకింగ్ ట్రోజన్ లక్షణాలు.",
      st0: "అప్‌లోడ్ అవుతోంది", st1: "యాప్ తెరవబడుతోంది", st2: "AndroidManifest.xml చదవబడుతోంది", st3: "కోడ్ తనిఖీ", st4: "సంతకం మరియు ట్రోజన్ నమూనాల తనిఖీ",
      err_t: "ఈ ఫైల్‌ను తనిఖీ చేయలేకపోయాము", again: "మరొక ఫైల్‌ను తనిఖీ చేయండి", risk: "ప్రమాదం",
      speak: "వినండి", share: "కుటుంబానికి WhatsAppలో పంపండి",
      triad_t: "బ్యాంకింగ్ ట్రోజన్ త్రయం", triad_p: "విడిగా ఇవి మామూలే కావచ్చు. మూడూ కలిసి ఉంటే — OTP దొంగిలించే ట్రోజన్ పద్ధతి ఇదే.",
      tri_sms: "SMS చదువుతుంది", tri_sms_s: "మీ OTPలను చూస్తుంది", tri_acc: "యాక్సెసిబిలిటీ", tri_acc_s: "మీ స్క్రీన్‌ను నియంత్రిస్తుంది", tri_ovl: "యాప్‌లపై కనిపిస్తుంది", tri_ovl_s: "నకిలీ లాగిన్ పేజీ",
      findings_t: "కనుగొన్న వివరాలు", tech_t: "సాంకేతిక వివరాలు",
      t_perms: "అనుమతులు", t_code: "కోడ్", t_net: "నెట్‌వర్క్", t_sign: "సంతకం", t_file: "ఫైల్",
      foot1: "అనుమానాస్పద యాప్ ఇన్‌స్టాల్ చేశారా లేదా డబ్బు పోగొట్టుకున్నారా?",
      lure_t: "ఇది ఏ రూపంలో మోసం చేస్తోంది", lure_need: "ఇలాంటి నిజమైన యాప్‌కు కావాల్సింది", lure_asks: "ఈ యాప్ అదనంగా అడుగుతున్నది",
      none: "ఎలాంటి ప్రమాద సంకేతాలు కనిపించలేదు.", seen: "ఇదే ఫైల్ {n} సార్లు తనిఖీ చేయబడింది — ఇది బహుశా చాలా మందికి పంపబడుతోంది.",
      copied: "సందేశం కాపీ చేయబడింది", no_voice: "ఈ భాష వాయిస్ మీ పరికరంలో అందుబాటులో లేదు",
      evidence: "సాక్ష్యం చూడండి", stats: "ఇప్పటివరకు {n} యాప్ ఫైళ్లు తనిఖీ చేయబడ్డాయి · {d} ప్రమాదకరమైనవి",
    },
    mr: {
      eyebrow: "पैसे पाठवण्यापूर्वी, टॅप किंवा इन्स्टॉल करण्यापूर्वी फसवणूक थांबवा",
      nav_trends: "ट्रेंड्स", nav_family: "कुटुंब", mode_msg: "मेसेज / SMS",
      msg_label: "तुम्हाला आलेला SMS, WhatsApp मेसेज किंवा ईमेल इथे पेस्ट करा", msg_paste: "पेस्ट करा", msg_example: "उदाहरण पहा", msg_check: "मेसेज तपासा",
      msg_privacy: "आम्ही तुमचा मेसेज सेव्ह करत नाही. फक्त तपासतो; तक्रार केल्यास फसवणूक करणाऱ्याची लिंक, UPI ID आणि नंबरच मोजले जातात — तुमचा मजकूर कधीही नाही.",
      msg_res: "मेसेज", msg_asks: "हे तुमच्याकडून काय करून घेऊ इच्छिते", msg_found: "यामध्ये सापडलेल्या लिंक्स, UPI ID आणि नंबर", msg_marked: "धोकादायक भाग हायलाइट केले आहेत",
      l_link: "लिंक", l_upi: "UPI ID", l_phone: "मोबाईल नंबर", l_tollfree: "टोल-फ्री नंबर", l_official: "अधिकृत", l_notofficial: "अनधिकृत", l_reported: "{n} तक्रारी",
      g_title: "पैसे पाठवण्यापूर्वी {name} यांच्याशी बोला", g_call: "{name} यांना कॉल करा", g_alerted: "{name} यांना सूचना पाठवली गेली आहे.", g_alerted_many: "तुमच्या कुटुंबाला सूचना पाठवली गेली आहे.",
      paste_denied: "पेस्ट करता आले नाही — बॉक्सवर दाबून धरून पेस्ट करा.",
      h1: "संशयास्पद मेसेज, QR कोड किंवा ॲप आले आहे? <span>आधी तपासा.</span>",
      lead: "“वीज कापली जाईल”, “KYC ब्लॉक”, “पार्सल अडकले” असे बनावट मेसेज, “पैसे मिळवण्यासाठी स्कॅन करा” QR, एडिट केलेले स्क्रीनशॉट आणि ट्रोजन ॲप्स. येथे पेस्ट किंवा अपलोड करा — ही फसवणूक आहे का ते आम्ही सोप्या भाषेत सांगतो.",
      drop_title: ".apk फाइल निवडा", drop_sub: "किंवा इथे ड्रॅग करून टाका · काहीही इन्स्टॉल किंवा चालवले जात नाही",
      privacy: "तपासणीनंतर फाइल हटवली जाते. आम्ही फक्त अहवाल ठेवतो, जो फाइलच्या फिंगरप्रिंटने (SHA-256) ओळखला जातो.",
      how1: "उघडणे", how1p: "APK ही मुळात एक ZIP फाइल असते. आम्ही ती इन्स्टॉल न करता किंवा न चालवता उघडतो.",
      how2: "मॅनिफेस्ट आणि कोड वाचणे", how2p: "परवानग्या, लपवलेल्या सर्व्हिसेस, API कॉल्स, कनेक्ट होणारे सर्व्हर्स आणि स्वाक्षरी.",
      how3: "ट्रोजन पॅटर्न जुळवणे", how3p: "धोकादायक <em>जोड्या</em> — जसे SMS + ॲक्सेसिबिलिटी + ओव्हरले — बँकिंग ट्रोजनची ओळख आहेत.",
      st0: "अपलोड होत आहे", st1: "ॲप उघडले जात आहे", st2: "AndroidManifest.xml वाचले जात आहे", st3: "कोड तपासणी", st4: "स्वाक्षरी आणि ट्रोजन पॅटर्न तपासणी",
      err_t: "आम्ही ही फाइल तपासू शकलो नाही", again: "दुसरी फाइल तपासा", risk: "धोका",
      speak: "ऐका", share: "कुटुंबाला WhatsApp वर पाठवा",
      triad_t: "बँकिंग ट्रोजनची तिहेरी युती", triad_p: "स्वतंत्रपणे या परवानग्या योग्य असू शकतात. तिन्ही एकत्र — हीच OTP चोराने ट्रोजनची पद्धत असते.",
      tri_sms: "SMS वाचतो", tri_sms_s: "तुमचे OTP पाहतो", tri_acc: "ॲक्सेसिबिलिटी", tri_acc_s: "तुमची स्क्रीन चालवतो", tri_ovl: "ॲप्सच्या वर दिसते", tri_ovl_s: "बनावट लॉगिन पेज",
      findings_t: "आम्हाला काय आढळले", tech_t: "तांत्रिक तपशील",
      t_perms: "परवानग्या", t_code: "कोड", t_net: "नेटवर्क", t_sign: "स्वाक्षरी", t_file: "फाइल",
      foot1: "संशयास्पद ॲप इन्स्टॉल केले किंवा पैसे गेले?",
      lure_t: "हे कोणत्या बहाण्याने आले आहे", lure_need: "अशा खऱ्या ॲपला आवश्यक", lure_asks: "हे ॲप याव्यतिरिक्त मागते",
      none: "कोणतेही धोक्याचे चिन्ह आढळले नाही.", seen: "हीच फाइल {n} वेळा तपासली गेली आहे — ही कदाचित अनेकांना पाठवली जात आहे.",
      copied: "मेसेज कॉपी केला", no_voice: "या भाषेचा आवाज तुमच्या डिव्हाइसवर उपलब्ध नाही",
      evidence: "पुरावा पहा", stats: "आतापर्यंत {n} ॲप फाइल्स तपासल्या · {d} धोकादायक आढळल्या",
    },
    bn: {
      eyebrow: "টাকা পাঠানো, ট্যাপ বা ইনস্টল করার আগেই প্রতারণা রুখুন",
      nav_trends: "ট্রেন্ডস", nav_family: "পরিবার", mode_msg: "মেসেজ / SMS",
      msg_label: "আপনার পাওয়া SMS, WhatsApp মেসেজ বা ইমেল এখানে পেস্ট করুন", msg_paste: "পেস্ট করুন", msg_example: "উদাহরণ দেখুন", msg_check: "মেসেজ যাচাই করুন",
      msg_privacy: "আমরা আপনার মেসেজ সংরক্ষণ করি না। কেবল যাচাই করি; রিপোর্ট করলে শুধু প্রতারকের লিঙ্ক, UPI ID ও নম্বর গণনা করা হয় — আপনার টেক্সট কখনোই নয়।",
      msg_res: "মেসেজ", msg_asks: "এটি আপনাকে দিয়ে কী করাতে চাইছে", msg_found: "এতে পাওয়া লিঙ্ক, UPI ID এবং নম্বরসমূহ", msg_marked: "ঝুঁকিপূর্ণ অংশগুলি হাইলাইট করা হয়েছে",
      l_link: "লিঙ্ক", l_upi: "UPI ID", l_phone: "মোবাইল নম্বর", l_tollfree: "টোল-ফ্রি নম্বর", l_official: "অফিসিয়াল", l_notofficial: "অননুমোদিত", l_reported: "{n}টি রিপোর্ট",
      g_title: "টাকা দেওয়ার আগে {name}-এর সাথে কথা বলুন", g_call: "{name}-কে কল করুন", g_alerted: "{name}-কে সতর্কবার্তা পাঠানো হয়েছে।", g_alerted_many: "আপনার পরিবারকে সতর্কবার্তা পাঠানো হয়েছে।",
      paste_denied: "পেস্ট করা যায়নি — বক্সের উপর চেপে ধরে পেস্ট করুন।",
      h1: "সন্দেহজনক মেসেজ, QR কোড বা অ্যাপ পেয়েছেন? <span>আগে যাচাই করুন।</span>",
      lead: "“বিদ্যুৎ বিচ্ছিন্ন”, “KYC ব্লক”, “পার্সেল আটকে গেছে” সংক্রান্ত ভুয়ো মেসেজ, “টাকা পাওয়ার জন্য স্ক্যান করুন” QR, এডিট করা পেমেন্ট স্ক্রিনশট ও ট্রোজান অ্যাপ। এখানে পেস্ট বা আপলোড করুন — এটি প্রতারণা কি না আমরা সহজ ভাষায় বুঝিয়ে দিই।",
      drop_title: ".apk ফাইল বেছে নিন", drop_sub: "অথবা টেনে এনে ড্রপ করুন · কিছুই ইনস্টল বা চালানো হয় না",
      privacy: "যাচাইয়ের পর ফাইল মুছে ফেলা হয়। আমরা কেবল রিপোর্টটি সংরক্ষণ করি, যা ফাইলের ফিঙ্গারপ্রিন্ট (SHA-256) দ্বারা চিহ্নিত হয়।",
      how1: "আনপ্যাক করা", how1p: "APK আসলে একটি ZIP ফাইল। আমরা ইনস্টল বা রান না করেই এটি আনপ্যাক করি।",
      how2: "ম্যানিফেস্ট ও কোড বিশ্লেষণ", how2p: "অনুমতিসমূহ, গোপন সার্ভিস, API কল, সংযুক্ত সার্ভার এবং ডিজিটাল স্বাক্ষর।",
      how3: "ট্রোজান প্যাটার্ন শনাক্তকরণ", how3p: "বিপজ্জনক <em>সমন্বয়</em> — যেমন SMS + অ্যাক্সেসিবিলিটি + ওভারলে — ব্যাংকিং ট্রোজানের প্রধান লক্ষণ।",
      st0: "আপলোড হচ্ছে", st1: "অ্যাপ খোলা হচ্ছে", st2: "AndroidManifest.xml পড়া হচ্ছে", st3: "কোড বিশ্লেষণ", st4: "স্বাক্ষর ও ট্রোজান প্যাটার্ন যাচাই",
      err_t: "এই ফাইলটি যাচাই করা যায়নি", again: "অন্য ফাইল যাচাই করুন", risk: "ঝুঁকি",
      speak: "শুনুন", share: "পরিবারকে WhatsApp-এ পাঠান",
      triad_t: "ব্যাংকিং ট্রোজানের ত্রয়ী", triad_p: "আলাদাভাবে এগুলো বৈধ হতে পারে। কিন্তু একসাথে তিনটিই — OTP চোর ট্রোজানের প্রধান কৌশল।",
      tri_sms: "SMS পড়তে পারে", tri_sms_s: "আপনার OTP দেখতে পারে", tri_acc: "অ্যাক্সেসিবিলিটি", tri_acc_s: "স্ক্রিন নিয়ন্ত্রণ করে", tri_ovl: "অন্য অ্যাপের উপরে ভেসে ওঠে", tri_ovl_s: "ভুয়ো লগইন পেজ",
      findings_t: "আমরা যা পেয়েছি", tech_t: "প্রযুক্তিগত বিবরণ",
      t_perms: "অনুমতিসমূহ", t_code: "কোড", t_net: "নেটওয়ার্ক", t_sign: "ডিজিটাল স্বাক্ষর", t_file: "ফাইল",
      foot1: "সন্দেহজনক অ্যাপ ইনস্টল করেছেন বা টাকা খুইয়েছেন?",
      lure_t: "এটি কী অছিলায় এসেছে", lure_need: "আসল অ্যাপের যা প্রয়োজন", lure_asks: "এই অ্যাপ অতিরিক্ত যা চাইছে",
      none: "কোনো বিপদের লক্ষণ পাওয়া যায়নি।", seen: "এই একই ফাইল {n} বার পরীক্ষা করা হয়েছে — সম্ভবত এটি অনেকের কাছে পাঠানো হচ্ছে।",
      copied: "মেসেজ কপি করা হয়েছে", no_voice: "এই ভাষার ভয়েস আপনার ডিভাইসে উপলব্ধ নেই",
      evidence: "প্রমাণ দেখুন", stats: "এখনও পর্যন্ত {n}টি অ্যাপ ফাইল পরীক্ষা হয়েছে · {d}টি ঝুঁকিপূর্ণ পাওয়া গেছে",
    },
  };
  const EN_EXTRA = {
    msg_res: "Message", msg_asks: "What it wants you to do", msg_found: "Links, UPI IDs and numbers in it", msg_marked: "Warning signs are highlighted",
    l_link: "Link", l_upi: "UPI ID", l_phone: "Mobile number", l_tollfree: "Toll-free number", l_official: "official", l_notofficial: "not official", l_reported: "{n} reports",
    g_title: "Talk to {name} before you pay", g_call: "Call {name}", g_alerted: "{name} has been alerted.", g_alerted_many: "Your family has been alerted.",
    paste_denied: "Couldn't paste — long-press inside the box and choose Paste.",
    lure_t: "What bait it uses", lure_need: "A real app like this needs", lure_asks: "This app additionally asks for",
    none: "No danger signs found.", seen: "This exact file has been checked {n} times — it is probably being sent to many people.",
    copied: "Message copied", no_voice: "No voice for this language is installed on your device",
    reported_by: "🚩 Reported as a scam by {n} people",
    evidence: "Show evidence", stats: "{n} app files checked so far · {d} found dangerous",
    shot_label: "Payment screenshot", shot_read: "What we read", shot_marked: "Areas marked in red look edited",
    f_app: "App", f_status: "Status", f_amount: "Amount", f_utr: "Reference number (UTR)", f_date: "Date", f_payee: "Paid to", not_read: "couldn't read",
    flow_you: "You", flow_to: "Money goes to", flow_out: "⚠ Money leaves YOUR account — this is not how you receive money.",
    dest_t: "This will take you to", qr_content: "What's inside the QR", what_t: "What this QR does",
    cam_denied: "Couldn't open the camera. Allow camera access, or upload a screenshot of the QR.", merchant: "registered shop", personal: "personal account",
    any_amount: "any amount you type", more_codes: "{n} QR codes found in this image; showing the most dangerous one.",
  };
  Object.assign(UI.hi, {
    and_t: "Android के लिए PayGuard", and_p: "किसी भी दुकान का QR PayGuard से स्कैन करें। सुरक्षित पेमेंट सीधे आपके UPI ऐप में जाते हैं; ठगी पेमेंट से पहले रुक जाती है। आप PayGuard को हर UPI लिंक पहले खोलने वाला ऐप भी बना सकते हैं।",
    and_dl: "ऐप डाउनलोड करें (APK)", and_missing: "ऐप अभी इस सर्वर पर अपलोड नहीं हुआ है।", and_qr: "ऐप में: Settings → कनेक्ट कोड स्कैन करें",
    reported_by: "🚩 {n} लोगों ने इसे ठगी बताया है", report_btn: "शिकायत दर्ज करें", mode_apk: "ऐप फ़ाइल (.apk)", mode_shot: "पेमेंट स्क्रीनशॉट",
    shot_title: "आपको दिखाया गया पेमेंट स्क्रीनशॉट अपलोड करें", shot_sub: "हम एडिटिंग, नकली जानकारी और पेंडिंग पेमेंट ढूँढते हैं",
    shot_expect: "आपको कितने पैसे मिलने चाहिए (वैकल्पिक)", shot_sms: "आपके बैंक का भेजा SMS / नोटिफ़िकेशन पेस्ट करें (सबसे पक्की जाँच)", shot_label: "पेमेंट स्क्रीनशॉट",
    shot_privacy: "ठगी की चाल: “मैंने पेमेंट कर दिया, स्क्रीनशॉट देखो।” स्क्रीनशॉट कभी सबूत नहीं — पैसे तभी आपके हैं जब आपका बैंक ऐप दिखाए।",
    shot_read: "हमने क्या पढ़ा", shot_marked: "लाल निशान वाले हिस्से संदिग्ध हैं", f_app: "ऐप", f_status: "स्टेटस", f_amount: "रकम", f_utr: "रेफ़रेंस नंबर (UTR)", f_date: "तारीख़", f_payee: "किसे", not_read: "नहीं पढ़ा जा सका", mode_qr: "QR कोड / UPI लिंक",
    qr_title: "QR की फ़ोटो या स्क्रीनशॉट अपलोड करें", qr_sub: "हम इसे पढ़ते हैं — कोई पेमेंट या लिंक नहीं खुलता",
    cam: "कैमरे से स्कैन करें", check: "जाँचें", cam_stop: "कैमरा बंद करें",
    qr_privacy: "ठगी की चाल: “पैसे पाने के लिए यह QR स्कैन करें”। UPI QR से हमेशा आपके पैसे जाते हैं, आते नहीं।",
    flow_you: "आप", flow_to: "पैसे किसे जाएँगे", flow_out: "⚠ पैसे आपके खाते से बाहर जाएँगे — यह पैसे पाने का तरीका नहीं है।",
    dest_t: "यह आपको इस वेबसाइट पर ले जाएगा", qr_content: "QR के अंदर क्या है", what_t: "यह QR क्या करता है",
    cam_denied: "कैमरा नहीं खुल सका। अनुमति दें, या QR का स्क्रीनशॉट अपलोड करें।", merchant: "रजिस्टर्ड दुकान", personal: "निजी खाता",
    any_amount: "जितनी रकम आप डालें", more_codes: "इस तस्वीर में {n} QR कोड मिले; सबसे खतरनाक वाला दिखाया गया है।",
  });
  Object.assign(UI.kn, {
    and_t: "Android ಗಾಗಿ PayGuard", and_p: "ಯಾವುದೇ ಅಂಗಡಿಯ QR ಅನ್ನು PayGuard ನಿಂದ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ. ಸುರಕ್ಷಿತ ಪಾವತಿಗಳು ನೇರವಾಗಿ ನಿಮ್ಮ UPI ಆ್ಯಪ್‌ಗೆ ಹೋಗುತ್ತವೆ; ವಂಚನೆ ಪಾವತಿಗೆ ಮೊದಲೇ ನಿಲ್ಲುತ್ತದೆ. ಪ್ರತಿ UPI ಲಿಂಕ್ ಅನ್ನು ಮೊದಲು PayGuard ತೆರೆಯುವಂತೆಯೂ ಮಾಡಬಹುದು.",
    and_dl: "ಆ್ಯಪ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಿ (APK)", and_missing: "ಆ್ಯಪ್ ಇನ್ನೂ ಈ ಸರ್ವರ್‌ಗೆ ಅಪ್‌ಲೋಡ್ ಆಗಿಲ್ಲ.", and_qr: "ಆ್ಯಪ್‌ನಲ್ಲಿ: Settings → ಕನೆಕ್ಟ್ ಕೋಡ್ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ",
    reported_by: "🚩 {n} ಜನರು ಇದನ್ನು ವಂಚನೆ ಎಂದು ವರದಿ ಮಾಡಿದ್ದಾರೆ", report_btn: "ದೂರು ದಾಖಲಿಸಿ", mode_apk: "ಆ್ಯಪ್ ಫೈಲ್ (.apk)", mode_shot: "ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್",
    shot_title: "ನಿಮಗೆ ತೋರಿಸಿದ ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಪ್‌ಲೋಡ್ ಮಾಡಿ", shot_sub: "ನಾವು ಎಡಿಟ್‌ಗಳು, ನಕಲಿ ವಿವರಗಳು ಮತ್ತು ಬಾಕಿ ಪಾವತಿಗಳನ್ನು ಹುಡುಕುತ್ತೇವೆ",
    shot_expect: "ನಿಮಗೆ ಬರಬೇಕಾದ ಮೊತ್ತ (ಐಚ್ಛಿಕ)", shot_sms: "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಕಳುಹಿಸಿದ SMS / ನೋಟಿಫಿಕೇಶನ್ ಅಂಟಿಸಿ (ಅತ್ಯಂತ ಖಚಿತ ಪರಿಶೀಲನೆ)", shot_label: "ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್",
    shot_privacy: "ವಂಚನೆಯ ತಂತ್ರ: “ನಾನು ಪಾವತಿಸಿದ್ದೇನೆ, ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ನೋಡಿ.” ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಎಂದಿಗೂ ಸಾಕ್ಷಿ ಅಲ್ಲ — ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ತೋರಿಸಿದಾಗ ಮಾತ್ರ ಹಣ ನಿಮ್ಮದು.",
    shot_read: "ನಾವು ಓದಿದ್ದು", shot_marked: "ಕೆಂಪು ಗುರುತಿನ ಭಾಗಗಳು ಸಂಶಯಾಸ್ಪದ", f_app: "ಆ್ಯಪ್", f_status: "ಸ್ಥಿತಿ", f_amount: "ಮೊತ್ತ", f_utr: "ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ (UTR)", f_date: "ದಿನಾಂಕ", f_payee: "ಯಾರಿಗೆ", not_read: "ಓದಲಾಗಲಿಲ್ಲ", mode_qr: "QR ಕೋಡ್ / UPI ಲಿಂಕ್",
    qr_title: "QR ನ ಫೋಟೋ ಅಥವಾ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಪ್‌ಲೋಡ್ ಮಾಡಿ", qr_sub: "ನಾವು ಅದನ್ನು ಓದುತ್ತೇವೆ — ಯಾವುದೇ ಪಾವತಿ ಅಥವಾ ಲಿಂಕ್ ತೆರೆಯುವುದಿಲ್ಲ",
    cam: "ಕ್ಯಾಮೆರಾದಿಂದ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ", check: "ಪರಿಶೀಲಿಸಿ", cam_stop: "ಕ್ಯಾಮೆರಾ ನಿಲ್ಲಿಸಿ",
    qr_privacy: "ವಂಚನೆಯ ತಂತ್ರ: “ಹಣ ಪಡೆಯಲು ಈ QR ಸ್ಕ್ಯಾನ್ ಮಾಡಿ”. UPI QR ಯಾವಾಗಲೂ ನಿಮ್ಮಿಂದ ಹಣ ತೆಗೆದುಕೊಳ್ಳುತ್ತದೆ.",
    flow_you: "ನೀವು", flow_to: "ಹಣ ಯಾರಿಗೆ ಹೋಗುತ್ತದೆ", flow_out: "⚠ ಹಣ ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಹೊರಗೆ ಹೋಗುತ್ತದೆ — ಇದು ಹಣ ಪಡೆಯುವ ವಿಧಾನವಲ್ಲ.",
    dest_t: "ಇದು ನಿಮ್ಮನ್ನು ಈ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಕರೆದೊಯ್ಯುತ್ತದೆ", qr_content: "QR ಒಳಗೆ ಏನಿದೆ", what_t: "ಈ QR ಏನು ಮಾಡುತ್ತದೆ",
    cam_denied: "ಕ್ಯಾಮೆರಾ ತೆರೆಯಲಾಗಲಿಲ್ಲ. ಅನುಮತಿ ನೀಡಿ, ಅಥವಾ QR ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಪ್‌ಲೋಡ್ ಮಾಡಿ.", merchant: "ನೋಂದಾಯಿತ ಅಂಗಡಿ", personal: "ವೈಯಕ್ತಿಕ ಖಾತೆ",
    any_amount: "ನೀವು ಹಾಕುವ ಯಾವುದೇ ಮೊತ್ತ", more_codes: "ಈ ಚಿತ್ರದಲ್ಲಿ {n} QR ಕೋಡ್‌ಗಳು ಸಿಕ್ಕಿವೆ; ಅತ್ಯಂತ ಅಪಾಯಕಾರಿಯನ್ನು ತೋರಿಸಲಾಗಿದೆ.",
  });
  // capture English defaults from the markup
  $$("[data-i]").forEach((el) => (UI.en[el.dataset.i] = el.innerHTML));
  Object.assign(UI.en, EN_EXTRA);

  let lang = "en";
  try { lang = localStorage.getItem("apkx_lang") || (navigator.language || "").slice(0, 2); } catch (_) {}
  if (!UI[lang]) lang = "en";
  let current = null; // current report

  const t = (k, vars = {}) => (UI[lang][k] ?? UI.en[k] ?? k).replace(/\{(\w+)\}/g, (_, v) => vars[v]).replace(/\bby 1 people\b/, "by 1 person");

  function setLang(l) {
    lang = l;
    try { localStorage.setItem("apkx_lang", l); } catch (_) {}
    document.documentElement.lang = l;
    $$(".lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === l));
    $$("[data-i]").forEach((el) => (el.innerHTML = t(el.dataset.i)));
    if (current) render(current);
    loadStats();
  }
  $$(".lang button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));

  // ------------------------------------------------------------ views
  const views = ["home", "progress", "error", "result", "report", "complaint"];
  function show(v) {
    views.forEach((x) => ($("#" + x).hidden = x !== v));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function toast(msg) {
    const el = $("#toast"); el.textContent = msg; el.hidden = false;
    clearTimeout(toast._t); toast._t = setTimeout(() => (el.hidden = true), 2600);
  }

  // ------------------------------------------------------------ upload
  const drop = $("#drop"), input = $("#file");
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  input.addEventListener("change", () => input.files[0] && upload(input.files[0]));
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && upload(e.dataTransfer.files[0]));

  function setStep(i) {
    $$(".steps li").forEach((li) => {
      const s = +li.dataset.step;
      li.className = s < i ? "done" : s === i ? "doing" : "";
    });
  }

  function upload(file) {
    $("#prog-file").textContent = file.name;
    $("#bar").style.width = "0%";
    setStep(0);
    show("progress");
    const fd = new FormData();
    fd.append("file", file);
    const xhr = new XMLHttpRequest();
    let fake;
    xhr.open("POST", "/api/scan");
    const devTok = window.PGDev && window.PGDev.token();
    if (devTok) xhr.setRequestHeader("x-pg-device", devTok);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) $("#bar").style.width = (e.loaded / e.total) * 60 + "%"; };
    xhr.upload.onload = () => {
      let s = 1; setStep(s); $("#bar").style.width = "65%";
      fake = setInterval(() => { if (s < 4) { s++; setStep(s); $("#bar").style.width = 60 + s * 9 + "%"; } }, 450);
    };
    xhr.onload = () => {
      clearInterval(fake);
      let data;
      try { data = JSON.parse(xhr.responseText); } catch (_) { data = { error: "Server error (" + xhr.status + ")" }; }
      if (xhr.status !== 200) return fail(data.error || "Error " + xhr.status);
      setStep(5); $("#bar").style.width = "100%";
      setTimeout(() => {
        history.pushState({}, "", "/r/" + data.file.sha256);
        render(data); show("result");
      }, 250);
    };
    xhr.onerror = () => { clearInterval(fake); fail("Network error — is the server running?"); };
    xhr.send(fd);
    input.value = "";
  }
  function fail(msg) { $("#err-msg").textContent = msg; show("error"); }

  // ------------------------------------------------------------ render
  const SEV = {
    en: { critical: "critical", high: "high", medium: "medium", low: "low" },
    hi: { critical: "गंभीर", high: "ज़्यादा", medium: "मध्यम", low: "कम" },
    kn: { critical: "ಗಂಭೀರ", high: "ಹೆಚ್ಚು", medium: "ಮಧ್ಯಮ", low: "ಕಡಿಮೆ" },
    ta: { critical: "மிக ஆபத்தானது", high: "அதிகம்", medium: "நடுத்தரம்", low: "குறைவு" },
    te: { critical: "తీవ్రమైనది", high: "ఎక్కువ", medium: "మధ్యస్థం", low: "తక్కువ" },
    mr: { critical: "गंभीर", high: "जास्त", medium: "मध्यम", low: "कमी" },
    bn: { critical: "মারাত্মক", high: "উচ্চ", medium: "মাঝারি", low: "কম" }
  };

  function render(r) {
    current = r;
    const v = r.verdict;
    const box = $("#verdict");
    box.className = "verdict " + v.level;
    $("#report-btn").hidden = v.level === "low";
    const isQR = r.kind === "qr", isShot = r.kind === "shot", isMsg = r.kind === "msg";
    [".triad-card", "#tech"].forEach((sel) => ($(sel).hidden = isQR || isShot || isMsg));
    $("#qrcard").hidden = !isQR;
    $("#shotcard").hidden = !isShot;
    $("#msgcard").hidden = !isMsg;
    if (isMsg) {
      $("#lure").hidden = true; $("#seen").hidden = true; $("#app-icon").hidden = true;
      const d = r.details;
      $("#app-name").textContent = d.category_name ? (d.category_name[lang] || d.category_name.en) : t("msg_res");
      $("#app-pkg").textContent = r.payload.replace(/\s+/g, " ").slice(0, 90) + (r.payload.length > 90 ? "…" : "");
      $("#score").textContent = v.score;
      requestAnimationFrame(() => ($("#g-arc").style.strokeDashoffset = 157 - (157 * v.score) / 100));
      $("#headline").textContent = (v.headline && (v.headline[lang] || v.headline.en)) || "";
      $("#advice").textContent = (v.advice && (v.advice[lang] || v.advice.en)) || "";
      window.renderMsgCard && window.renderMsgCard(r);
      afterRender(r);
      renderFindings(r.findings);
      $("#limits").textContent = r.limitations.join(" ");
      return;
    }
    if (isShot) {
      $("#lure").hidden = true; $("#seen").hidden = true; $("#app-icon").hidden = true;
      const d = r.details;
      $("#app-name").textContent = d.app ? d.app + " receipt" : t("shot_label");
      $("#app-pkg").textContent = r.file.name + " · " + r.file.width + "×" + r.file.height;
      $("#score").textContent = v.score;
      requestAnimationFrame(() => ($("#g-arc").style.strokeDashoffset = 157 - (157 * v.score) / 100));
      $("#headline").textContent = (v.headline && (v.headline[lang] || v.headline.en)) || "";
      $("#advice").textContent = (v.advice && (v.advice[lang] || v.advice.en)) || "";
      window.renderShotCard && window.renderShotCard(r);
      afterRender(r);
      renderFindings(r.findings);
      $("#limits").textContent = r.limitations.join(" ");
      return;
    }
    if (isQR) {
      $("#lure").hidden = true; $("#seen").hidden = true; $("#app-icon").hidden = true;
      const d = r.details;
      $("#app-name").textContent = d.type === "upi" ? (d.payee_name || d.payee_vpa || "UPI") : d.type === "url" ? d.host : d.type.toUpperCase();
      $("#app-pkg").textContent = d.type === "upi" ? d.payee_vpa : r.payload.slice(0, 90);
      $("#score").textContent = v.score;
      requestAnimationFrame(() => ($("#g-arc").style.strokeDashoffset = 157 - (157 * v.score) / 100));
      $("#headline").textContent = (v.headline && (v.headline[lang] || v.headline.en)) || "";
      $("#advice").textContent = (v.advice && (v.advice[lang] || v.advice.en)) || "";
      renderQRCard(r);
      afterRender(r);
      renderFindings(r.findings);
      $("#limits").textContent = r.limitations.join(" ");
      return;
    }
    $("#app-name").textContent = r.app.name || r.file.name;
    $("#app-pkg").textContent = r.app.package + (r.app.version_name ? " · v" + r.app.version_name : "");
    const icon = $("#app-icon");
    if (r.app.icon) { icon.src = r.app.icon; icon.hidden = false; } else icon.hidden = true;
    $("#score").textContent = v.score;
    $("#gauge").setAttribute("aria-label", `Risk score ${v.score} out of 100`);
    requestAnimationFrame(() => ($("#g-arc").style.strokeDashoffset = 157 - (157 * v.score) / 100));
    $("#headline").textContent = (v.headline && (v.headline[lang] || v.headline.en)) || "";
    $("#advice").textContent = (v.advice && (v.advice[lang] || v.advice.en)) || "";
    const seen = r.community?.seen_count || 1;
    $("#seen").hidden = !(seen > 1 && (v.level === "danger" || v.level === "suspicious"));
    $("#seen").textContent = t("seen", { n: seen });

    // triad
    const c = r.capabilities;
    $("#tri-sms").classList.toggle("on", c.sms_any);
    $("#tri-acc").classList.toggle("on", c.accessibility);
    $("#tri-ovl").classList.toggle("on", c.overlay);
    $(".triad").classList.toggle("all", c.sms_any && c.accessibility && c.overlay);

    // lure
    const lure = $("#lure");
    if (r.lure.category && r.lure.unexpected_permissions.length) {
      lure.hidden = false;
      lure.innerHTML = `<h3>${esc(t("lure_t"))}: “${esc(r.lure.label)}”</h3>
        <p class="dim">“${esc(r.lure.word)}” — ${esc(r.lure.where)}</p>
        <div class="cmp">
          <div class="need"><b>✓ ${esc(t("lure_need"))}</b>${r.lure.expected_permissions.map((p) => `<span class="chip">${esc(p)}</span>`).join("")}</div>
          <div class="asks"><b>✗ ${esc(t("lure_asks"))}</b>${r.lure.unexpected_permissions.map((p) => `<span class="chip">${esc(p)}</span>`).join("")}</div>
        </div>`;
    } else lure.hidden = true;

    renderFindings(r.findings);
    $("#limits").textContent = r.limitations.join(" ");
    renderTab($(".tabs button.on").dataset.tab);
    afterRender(r);
  }

  // Shared extras for every kind of result: community badge, one-tap reports, UPI pay buttons.
  function afterRender(r) {
    const n = r.community?.reports || 0;
    const pill = $("#reported");
    pill.hidden = n < 1;
    pill.textContent = t("reported_by", { n });
    window.renderVote && window.renderVote(r);
    window.renderPay && window.renderPay(r);
    renderGuard(r);
  }

  // A protected family member gets a "call your son/daughter first" button on risky results.
  function renderGuard(r) {
    const card = $("#guardcard");
    const fam = window.PGDev && window.PGDev.family();
    const risky = r.verdict.level === "danger" || r.verdict.level === "suspicious";
    const gs = (fam && fam.protected_by) || [];
    if (!risky || !gs.length) { card.hidden = true; return; }
    const g = gs.find((x) => x.phone) || gs[0];
    const name = g.name || "family";
    card.hidden = false;
    card.innerHTML = `<div class="guard-row"><span class="guard-ico" aria-hidden="true">👨‍👩‍👧</span>
      <div><h3>${esc(t("g_title", { name }))}</h3>
      ${r.family_alerted ? `<p class="dim">${esc(gs.length > 1 ? t("g_alerted_many") : t("g_alerted", { name }))}</p>` : ""}</div></div>
      ${g.phone ? `<a class="btn primary guard-call" href="tel:+91${esc(g.phone)}">📞 ${esc(t("g_call", { name }))}</a>` : ""}`;
  }

  function renderFindings(fs) {
    $("#findings").innerHTML = fs.length ? fs.map((f) => `
      <article class="finding ${f.severity}">
        <div class="f-head"><h4>${esc((f.title && (f.title[lang] || f.title.en)) || f.title || "")}</h4><span class="sev ${f.severity}">${esc((SEV[lang] && SEV[lang][f.severity]) || (SEV.en && SEV.en[f.severity]) || f.severity)}</span></div>
        <p>${esc((f.detail && (f.detail[lang] || f.detail.en)) || f.detail || "")}</p>
        ${f.evidence.length ? `<details><summary>${esc(t("evidence"))} (${f.evidence.length})</summary><ul>${f.evidence.map((e) => `<li class="mono">${esc(e)}</li>`).join("")}</ul></details>` : ""}
      </article>`).join("") : `<div class="card none">✓ ${esc(t("none"))}</div>`;
  }

  function renderQRCard(r) {
    const d = r.details, card = $("#qrcard");
    let html = "";
    if (d.type === "upi") {
      const amt = d.amount != null ? "₹" + d.amount.toLocaleString("en-IN", { maximumFractionDigits: 2 }) : t("any_amount");
      html = `<h3>${esc(t("what_t"))}</h3>
        <div class="flow">
          <div class="party"><small>${esc(t("flow_you"))}</small><b>👤 ${esc(t("flow_you"))}</b></div>
          <div class="arrow"><span class="amt">${esc(amt)}</span><svg viewBox="0 0 70 20"><path d="M2 10h60m-10-8 10 8-10 8" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
          <div class="party"><small>${esc(t("flow_to"))}</small><b>${esc(d.payee_name || "—")}</b>
            <span class="mono">${esc(d.payee_vpa || "?")}</span><br><small>${esc(d.is_merchant ? t("merchant") : t("personal"))}${d.note ? " · “" + esc(d.note) + "”" : ""}</small></div>
        </div>
        <div class="out-banner">${esc(t("flow_out"))}</div>`;
    } else if (d.type === "url") {
      const bad = r.verdict.level === "danger" || r.verdict.level === "suspicious";
      html = `<h3>${esc(t("dest_t"))}</h3><div class="dest ${bad ? "bad" : "ok"}">${esc(d.registered_domain || d.host)}</div>
        <div class="dim mono">${esc(d.host)}${d.https ? " · https" : " · http (not secure)"}</div>`;
    } else {
      html = `<h3>${esc(t("what_t"))}</h3><div class="dest">${esc(d.type.toUpperCase())}</div>`;
    }
    html += `<div class="raw"><b>${esc(t("qr_content"))}:</b> <span class="mono">${esc(r.payload)}</span></div>`;
    if (r.all_codes > 1) html += `<p class="dim">${esc(t("more_codes", { n: r.all_codes }))}</p>`;
    card.innerHTML = html;
  }

  // ------------------------------------------------------------ tabs
  $$(".tabs button").forEach((b) => b.addEventListener("click", () => {
    $$(".tabs button").forEach((x) => x.classList.toggle("on", x === b));
    renderTab(b.dataset.tab);
  }));
  const kv = (rows) => `<dl class="kv">${rows.filter((r) => r[1] !== undefined && r[1] !== null && r[1] !== "").map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;

  function renderTab(tab) {
    const r = current; if (!r) return;
    const body = $("#tab-body");
    if (tab === "perms") {
      body.innerHTML = r.permissions.length ? `<table><thead><tr><th>Permission</th><th>What it lets the app do</th></tr></thead><tbody>${
        r.permissions.map((p) => `<tr><td><span class="risk-dot ${p.risk}"></span><span class="mono">${esc(p.short)}</span>${p.via !== "uses-permission" ? `<br><small class="dim">${esc(p.via)}</small>` : ""}</td><td>${esc(p.description || "—")}</td></tr>`).join("")
      }</tbody></table>` : `<p class="dim">No permissions requested.</p>`;
    } else if (tab === "code") {
      const cd = r.code, comp = r.components;
      body.innerHTML = `<h4 class="subh">Suspicious API calls in the code</h4>${
        cd.suspicious_apis.length ? `<table><tbody>${cd.suspicious_apis.map((a) => `<tr><td>${esc(a.description)}</td><td>${a.refs.map((x) => `<div class="mono">${esc(x)}</div>`).join("")}</td></tr>`).join("")}</tbody></table>` : `<p class="dim">None found.</p>`}
        <h4 class="subh">Components</h4>${kv([
          ["Activities / services / receivers", `${comp.counts.activities} / ${comp.counts.services} / ${comp.counts.receivers}`],
          ["Accessibility services", comp.accessibility_services.map(esc).join("<br>") || "—"],
          ["SMS listeners", comp.sms_receivers.map(esc).join("<br>") || "—"],
          ["Notification listeners", comp.notification_listeners.map(esc).join("<br>") || "—"],
          ["Device admin", comp.device_admin_receivers.map(esc).join("<br>") || "—"],
          ["Starts on boot", comp.boot_receivers.map(esc).join("<br>") || "—"],
          ["Home-screen icon", r.app.has_launcher_icon ? "yes" : "<b>no (hidden)</b>"],
        ])}
        <h4 class="subh">Code facts</h4>${kv([
          ["DEX files scanned", cd.dex_files], ["Strings scanned", cd.strings_scanned.toLocaleString()],
          ["Methods referenced", cd.methods_referenced.toLocaleString()],
          ["Bank apps referenced", cd.bank_app_references.map((x) => `<span class="chip">${esc(x)}</span>`).join("") || "—"],
          ["UPI apps referenced", cd.upi_app_references.map((x) => `<span class="chip">${esc(x)}</span>`).join("") || "—"],
          ["Credential words", cd.phishing_terms.map((x) => `<span class="chip">${esc(x)}</span>`).join("") || "—"],
          ["USSD / call codes", cd.ussd_codes.map((x) => `<span class="chip">${esc(x)}</span>`).join("") || "—"],
          ["Native libraries", r.native.libraries.length ? r.native.libraries.map((x) => `<span class="chip">${esc(x)}</span>`).join("") : "—"],
          ["Packer", r.native.packers.join(", ") || "—"],
          ["Embedded payloads", r.native.embedded_payloads.map(esc).join("<br>") || "—"],
        ])}`;
    } else if (tab === "net") {
      const n = r.network;
      body.innerHTML = `${kv([
          ["Telegram bot", r.code.telegram.map((x) => `<div class="mono">${esc(x)}</div>`).join("") || "—"],
          ["Raw IP servers", n.raw_ip_urls.map((x) => `<div class="mono">${esc(x)}</div>`).join("") || "—"],
          ["Throw-away domains", n.suspicious_tld_urls.map((x) => `<div class="mono">${esc(x)}</div>`).join("") || "—"],
          ["URLs found", n.url_count],
        ])}<h4 class="subh">Hosts referenced in the app (common SDK hosts hidden)</h4>${
        n.domains.length ? `<table><tbody>${n.domains.map((d) => `<tr><td class="mono">${esc(d.host)}</td><td class="dim">${d.count}×</td></tr>`).join("")}</tbody></table>` : `<p class="dim">None.</p>`}`;
    } else if (tab === "sign") {
      const s = r.signing;
      body.innerHTML = kv([
        ["Signed", s.signed ? "yes" : "<b>no</b>"], ["Schemes", s.schemes.join(", ") || "—"],
        ["Signer", esc(s.subject || "—")], ["Issuer", esc(s.issuer || "—")],
        ["Debug key", s.debug_cert ? "<b>yes</b>" : "no"],
        ["Valid from", esc(s.not_before || "—")], ["Valid until", esc(s.not_after || "—")],
        ["Key age", s.cert_age_days != null ? s.cert_age_days + " days" : "—"],
        ["Cert SHA-256", `<span class="mono">${esc(s.sha256 || "—")}</span>`],
      ]);
    } else if (tab === "file") {
      const f = r.file, a = r.app, vt = r.external?.virustotal;
      body.innerHTML = kv([
        ["File name", esc(f.name)], ["Size", (f.size / 1048576).toFixed(2) + " MB"],
        ["Inside bundle", f.bundle_member ? esc(f.bundle_member) : undefined],
        ["Package", `<span class="mono">${esc(a.package)}</span>`], ["Version", esc(`${a.version_name || "?"} (${a.version_code || "?"})`)],
        ["Min / target SDK", `${a.min_sdk ?? "?"} / ${a.target_sdk ?? "?"}`],
        ["SHA-256", `<span class="mono">${f.sha256}</span>`], ["SHA-1", `<span class="mono">${f.sha1}</span>`], ["MD5", `<span class="mono">${f.md5}</span>`],
        ["VirusTotal", vt ? (vt.known ? `${vt.malicious}/${vt.engines} engines flag it as malicious` : "not seen before") + ` · <a target="_blank" rel="noopener" href="${r.external.virustotal_url}">open</a>`
                          : `<a target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${f.sha256}">Look up this hash</a>`],
        ["Analysis", `${r.analysis_ms} ms · engine ${esc(r.engine_version)}${r.cached ? " · cached" : ""}`],
        ["Report", `<a href="/api/report/${f.sha256}" target="_blank">JSON</a> · <a href="/r/${f.sha256}">shareable link</a>`],
      ]);
    }
  }

  // ------------------------------------------------------------ actions
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const act = b.dataset.act;
    if (act === "again") { speechSynthesis?.cancel(); history.pushState({}, "", "/"); current = null; show("home"); }
    if (act === "speak") speak();
    if (act === "share") share();
  });

  function speak() {
    if (!("speechSynthesis" in window) || !current) return;
    speechSynthesis.cancel();
    const v = current.verdict;
    const top = current.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 2).map((f) => (f.title && (f.title[lang] || f.title.en)) || f.title);
    const text = [(v.headline && (v.headline[lang] || v.headline.en)) || "", ...top, (v.advice && (v.advice[lang] || v.advice.en)) || ""].join(". ");
    const code = { en: "en-IN", hi: "hi-IN", kn: "kn-IN", ta: "ta-IN", te: "te-IN", mr: "mr-IN", bn: "bn-IN" }[lang] || "en-IN";
    const u = new SpeechSynthesisUtterance(text);
    u.lang = code; u.rate = 0.92;
    const voices = speechSynthesis.getVoices();
    const voice = voices.find((x) => x.lang === code) || voices.find((x) => x.lang.startsWith(lang));
    if (voice) u.voice = voice; else if (lang !== "en" && voices.length) toast(t("no_voice"));
    speechSynthesis.speak(u);
  }

  async function share() {
    if (!current) return;
    let msg;
    if (current.kind === "qr") {
      const v = current.verdict;
      const top = current.findings.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3).map((f) => "• " + ((f.title && (f.title[lang] || f.title.en)) || f.title));
      const h = (v.headline && (v.headline[lang] || v.headline.en)) || "";
      const a = (v.advice && (v.advice[lang] || v.advice.en)) || "";
      msg = [`*${h}* (${v.score}/100)`, ...top, "", a, "", "QR: " + current.payload.slice(0, 200)].join("\n");
      try { await navigator.clipboard.writeText(msg); toast(t("copied")); } catch (_) {}
      window.open("https://wa.me/?text=" + encodeURIComponent(msg), "_blank", "noopener");
      return;
    }
    try {
      const res = await fetch("/api/explain", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ sha256: current.file.sha256, lang }) });
      msg = (await res.json()).message;
    } catch (_) {}
    const h = (current.verdict.headline && (current.verdict.headline[lang] || current.verdict.headline.en)) || "";
    const a = (current.verdict.advice && (current.verdict.advice[lang] || current.verdict.advice.en)) || "";
    msg = (msg || h + "\n" + a) + "\n\n" + location.origin + "/r/" + current.file.sha256;
    try { await navigator.clipboard.writeText(msg); toast(t("copied")); } catch (_) {}
    window.open("https://wa.me/?text=" + encodeURIComponent(msg), "_blank", "noopener");
  }

  // ------------------------------------------------------------ stats + routing
  async function loadHealth() {
    try {
      const h = await (await fetch("/api/health")).json();
      $("#apk-dl").hidden = !h.android_apk;
      $("#ocr-warn").hidden = !!h.ocr;
      $("#apk-missing").hidden = !!h.android_apk;
    } catch (_) {}
  }

  async function loadStats() {
    try {
      const s = await (await fetch("/api/stats")).json();
      if (s.total_scans > 0) $("#stats").textContent = t("stats", { n: s.total_scans, d: (s.by_level.danger || 0) + (s.by_level.suspicious || 0) });
    } catch (_) {}
  }

  async function route() {
    if (location.pathname.startsWith("/c/")) return; // complaint pages are handled by report.js
    const sm = location.pathname.match(/^\/s\/([0-9a-f]{64})$/i);
    if (sm) {
      try {
        const res = await fetch("/api/screenshot/" + sm[1]);
        const data = await res.json();
        if (!res.ok) return fail(data.error);
        render(data); show("result");
      } catch (_) { fail("Could not load this screenshot check"); }
      return;
    }
    const m = location.pathname.match(/^\/r\/([0-9a-f]{64})$/i);
    if (!m) { show("home"); return; }
    try {
      const res = await fetch("/api/report/" + m[1]);
      const data = await res.json();
      if (!res.ok) return fail(data.error);
      render(data); show("result");
    } catch (_) { fail("Could not load report"); }
  }
  window.addEventListener("popstate", route);

  window.APKX = { show, render, fail, toast, t, setStep, esc, lang: () => lang, current: () => current };
  setLang(lang);
  loadHealth();
  route();
})();
