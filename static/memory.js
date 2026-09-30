/* Scam Memory: the user's own scam history, kept only on this device (localStorage).
   Every risky check is remembered as a small pattern (identifiers, scam type, tricks, app fingerprint; never the
   message text). A later check that matches one gets "This looks just like a scam you dealt with before".
   On the main page it hooks into app.js (window.renderMemory); on /memory it renders the history timeline. */
(() => {
  const KEY = "pg_scam_memory_v1", MAX = 200;
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const S = {
    en: { nav_check: "Check", nav_trends: "Trends", nav_family: "Family", nav_memory: "My scams",
      hit_t: "⚠️ This looks just like a scam you dealt with before", hit_on: "You checked “{title}” on {date}.", see: "See your scam history",
      why_same: "It's the exact same {thing}.", why_upi: "Same UPI ID: {v}", why_domain: "Same website: {v}", why_phone: "Same phone number: {v}",
      why_utr: "Same reference number: {v}", why_pkg: "Same app package: {v}", why_upi_like: "UPI ID {v} is {p}% the same as {o} from that scam",
      why_apk_like: "Built the same way as that app ({p}% match)", why_template: "Same message wording", why_category: "Same kind of scam: {v}", why_trick: "Same trick: {v}",
      title: "Scam memory", sub: "Scams you checked on this device. If a new one looks like any of them, PayGuard warns you. Saved only on this phone or computer, never sent anywhere.",
      k_total: "Scams remembered", k_danger: "Dangerous", k_month: "Last 30 days",
      empty: "Nothing here yet. When a check finds a scam or something suspicious, it's remembered here.", check_now: "Check something",
      seen_n: "checked {n} times", open: "Open result", forget: "Forget", clear: "Clear all", clear_q: "Forget all {n} scams on this device?",
      kind_msg: "Message", kind_qr: "QR / UPI", kind_shot: "Screenshot", kind_apk: "App",
      lvl_danger: "Dangerous", lvl_suspicious: "Suspicious", thing_msg: "message", thing_qr: "QR code", thing_shot: "screenshot", thing_apk: "app file",
      no_storage: "Your browser is blocking storage, so Scam Memory can't save anything on this device." },
    hi: { nav_check: "जाँचें", nav_trends: "ट्रेंड्स", nav_family: "परिवार", nav_memory: "मेरी ठगी",
      hit_t: "⚠️ यह बिल्कुल उस ठगी जैसा है जिसका आप पहले सामना कर चुके हैं", hit_on: "आपने {date} को “{title}” जाँचा था।", see: "अपनी ठगी की सूची देखें",
      why_same: "यह वही {thing} है।", why_upi: "वही UPI ID: {v}", why_domain: "वही वेबसाइट: {v}", why_phone: "वही फ़ोन नंबर: {v}",
      why_utr: "वही रेफ़रेंस नंबर: {v}", why_pkg: "वही ऐप पैकेज: {v}", why_upi_like: "UPI ID {v} उस ठगी के {o} से {p}% मिलता है",
      why_apk_like: "उसी ऐप की तरह बना है ({p}% मेल)", why_template: "मैसेज के वही शब्द", why_category: "उसी तरह की ठगी: {v}", why_trick: "वही चाल: {v}",
      title: "ठगी की याद", sub: "इस डिवाइस पर आपने जो ठगी जाँची। कोई नई ठगी इनमें से किसी जैसी दिखे तो PayGuard आपको चेतावनी देता है। सिर्फ़ इसी फ़ोन या कंप्यूटर पर सेव, कहीं भेजा नहीं जाता।",
      k_total: "याद रखी ठगी", k_danger: "ख़तरनाक", k_month: "पिछले 30 दिन",
      empty: "अभी यहाँ कुछ नहीं है। जब कोई जाँच ठगी या कुछ संदिग्ध पकड़ती है, वह यहाँ याद रखी जाती है।", check_now: "कुछ जाँचें",
      seen_n: "{n} बार जाँचा", open: "नतीजा खोलें", forget: "भूल जाएँ", clear: "सब मिटाएँ", clear_q: "इस डिवाइस से सभी {n} ठगी मिटा दें?",
      kind_msg: "मैसेज", kind_qr: "QR / UPI", kind_shot: "स्क्रीनशॉट", kind_apk: "ऐप",
      lvl_danger: "ख़तरनाक", lvl_suspicious: "संदिग्ध", thing_msg: "मैसेज", thing_qr: "QR कोड", thing_shot: "स्क्रीनशॉट", thing_apk: "ऐप फ़ाइल",
      no_storage: "आपका ब्राउज़र स्टोरेज रोक रहा है, इसलिए ठगी की याद इस डिवाइस पर कुछ सेव नहीं कर सकती।" },
    kn: { nav_check: "ಪರಿಶೀಲಿಸಿ", nav_trends: "ಟ್ರೆಂಡ್‌ಗಳು", nav_family: "ಕುಟುಂಬ", nav_memory: "ನನ್ನ ವಂಚನೆಗಳು",
      hit_t: "⚠️ ಇದು ನೀವು ಹಿಂದೆ ಎದುರಿಸಿದ ವಂಚನೆಯಂತೆಯೇ ಇದೆ", hit_on: "ನೀವು {date} ರಂದು “{title}” ಪರಿಶೀಲಿಸಿದ್ದಿರಿ.", see: "ನಿಮ್ಮ ವಂಚನೆ ಇತಿಹಾಸ ನೋಡಿ",
      why_same: "ಇದು ಅದೇ {thing}.", why_upi: "ಅದೇ UPI ID: {v}", why_domain: "ಅದೇ ವೆಬ್‌ಸೈಟ್: {v}", why_phone: "ಅದೇ ಫೋನ್ ನಂಬರ್: {v}",
      why_utr: "ಅದೇ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ: {v}", why_pkg: "ಅದೇ ಆ್ಯಪ್ ಪ್ಯಾಕೇಜ್: {v}", why_upi_like: "UPI ID {v} ಆ ವಂಚನೆಯ {o} ಗೆ {p}% ಹೋಲುತ್ತದೆ",
      why_apk_like: "ಆ ಆ್ಯಪ್‌ನಂತೆಯೇ ನಿರ್ಮಿತ ({p}% ಹೊಂದಾಣಿಕೆ)", why_template: "ಸಂದೇಶದ ಅದೇ ಪದಗಳು", why_category: "ಅದೇ ರೀತಿಯ ವಂಚನೆ: {v}", why_trick: "ಅದೇ ತಂತ್ರ: {v}",
      title: "ವಂಚನೆ ನೆನಪು", sub: "ಈ ಸಾಧನದಲ್ಲಿ ನೀವು ಪರಿಶೀಲಿಸಿದ ವಂಚನೆಗಳು. ಹೊಸದು ಇವುಗಳಲ್ಲಿ ಯಾವುದಾದರೂ ಹಾಗೆ ಕಂಡರೆ PayGuard ಎಚ್ಚರಿಸುತ್ತದೆ. ಈ ಫೋನ್ ಅಥವಾ ಕಂಪ್ಯೂಟರ್‌ನಲ್ಲಿ ಮಾತ್ರ ಉಳಿಸಲಾಗುತ್ತದೆ, ಎಲ್ಲಿಗೂ ಕಳುಹಿಸುವುದಿಲ್ಲ.",
      k_total: "ನೆನಪಿನಲ್ಲಿರುವ ವಂಚನೆಗಳು", k_danger: "ಅಪಾಯಕಾರಿ", k_month: "ಕಳೆದ 30 ದಿನ",
      empty: "ಇಲ್ಲಿ ಇನ್ನೂ ಏನೂ ಇಲ್ಲ. ಪರಿಶೀಲನೆ ವಂಚನೆ ಅಥವಾ ಸಂಶಯಾಸ್ಪದವಾದದ್ದನ್ನು ಕಂಡಾಗ ಅದು ಇಲ್ಲಿ ನೆನಪಿನಲ್ಲಿರುತ್ತದೆ.", check_now: "ಏನಾದರೂ ಪರಿಶೀಲಿಸಿ",
      seen_n: "{n} ಬಾರಿ ಪರಿಶೀಲಿಸಲಾಗಿದೆ", open: "ಫಲಿತಾಂಶ ತೆರೆಯಿರಿ", forget: "ಮರೆಯಿರಿ", clear: "ಎಲ್ಲವನ್ನೂ ಅಳಿಸಿ", clear_q: "ಈ ಸಾಧನದಿಂದ ಎಲ್ಲಾ {n} ವಂಚನೆಗಳನ್ನು ಮರೆಯಬೇಕೇ?",
      kind_msg: "ಸಂದೇಶ", kind_qr: "QR / UPI", kind_shot: "ಸ್ಕ್ರೀನ್‌ಶಾಟ್", kind_apk: "ಆ್ಯಪ್",
      lvl_danger: "ಅಪಾಯಕಾರಿ", lvl_suspicious: "ಸಂಶಯಾಸ್ಪದ", thing_msg: "ಸಂದೇಶ", thing_qr: "QR ಕೋಡ್", thing_shot: "ಸ್ಕ್ರೀನ್‌ಶಾಟ್", thing_apk: "ಆ್ಯಪ್ ಫೈಲ್",
      no_storage: "ನಿಮ್ಮ ಬ್ರೌಸರ್ ಸಂಗ್ರಹಣೆಯನ್ನು ತಡೆಯುತ್ತಿದೆ, ಹಾಗಾಗಿ ವಂಚನೆ ನೆನಪು ಈ ಸಾಧನದಲ್ಲಿ ಏನನ್ನೂ ಉಳಿಸಲಾಗದು." },
    ta: { nav_check: "சரிபார்", nav_trends: "ட்ரெண்டுகள்", nav_family: "குடும்பம்", nav_memory: "என் மோசடிகள்",
      hit_t: "⚠️ இது நீங்கள் முன்பு சந்தித்த மோசடியைப் போலவே உள்ளது", hit_on: "நீங்கள் {date} அன்று “{title}” சரிபார்த்தீர்கள்.", see: "உங்கள் மோசடி வரலாற்றைப் பார்க்கவும்",
      why_same: "இது அதே {thing}.", why_upi: "அதே UPI ID: {v}", why_domain: "அதே இணையதளம்: {v}", why_phone: "அதே தொலைபேசி எண்: {v}",
      why_utr: "அதே குறிப்பு எண்: {v}", why_pkg: "அதே ஆப் தொகுப்பு: {v}", why_upi_like: "UPI ID {v}, அந்த மோசடியின் {o} உடன் {p}% ஒத்துள்ளது",
      why_apk_like: "அந்த ஆப் போலவே உருவாக்கப்பட்டது ({p}% பொருத்தம்)", why_template: "அதே செய்தி வாசகம்", why_category: "அதே வகை மோசடி: {v}", why_trick: "அதே தந்திரம்: {v}",
      title: "மோசடி நினைவு", sub: "இந்தச் சாதனத்தில் நீங்கள் சரிபார்த்த மோசடிகள். புதியது இவற்றில் ஏதாவது போல் இருந்தால் PayGuard எச்சரிக்கும். இந்த ஃபோன் அல்லது கணினியில் மட்டுமே சேமிக்கப்படும், எங்கும் அனுப்பப்படாது.",
      k_total: "நினைவில் உள்ள மோசடிகள்", k_danger: "ஆபத்தானவை", k_month: "கடந்த 30 நாள்",
      empty: "இங்கே இன்னும் எதுவும் இல்லை. சரிபார்ப்பில் மோசடி அல்லது சந்தேகத்திற்குரியது கண்டறியப்பட்டால் இங்கே நினைவில் வைக்கப்படும்.", check_now: "ஏதாவது சரிபார்க்கவும்",
      seen_n: "{n} முறை சரிபார்க்கப்பட்டது", open: "முடிவைத் திற", forget: "மறந்துவிடு", clear: "அனைத்தையும் அழி", clear_q: "இந்தச் சாதனத்திலிருந்து {n} மோசடிகளையும் மறக்கவா?",
      kind_msg: "செய்தி", kind_qr: "QR / UPI", kind_shot: "ஸ்கிரீன்ஷாட்", kind_apk: "ஆப்",
      lvl_danger: "ஆபத்தானது", lvl_suspicious: "சந்தேகத்திற்குரியது", thing_msg: "செய்தி", thing_qr: "QR குறியீடு", thing_shot: "ஸ்கிரீன்ஷாட்", thing_apk: "ஆப் கோப்பு",
      no_storage: "உங்கள் உலாவி சேமிப்பைத் தடுக்கிறது, எனவே மோசடி நினைவு இந்தச் சாதனத்தில் எதையும் சேமிக்க முடியாது." },
    te: { nav_check: "తనిఖీ", nav_trends: "ట్రెండ్స్", nav_family: "కుటుంబం", nav_memory: "నా మోసాలు",
      hit_t: "⚠️ ఇది మీరు ఇంతకు ముందు ఎదుర్కొన్న మోసంలాగే ఉంది", hit_on: "మీరు {date}న “{title}” తనిఖీ చేశారు.", see: "మీ మోసాల చరిత్ర చూడండి",
      why_same: "ఇది అదే {thing}.", why_upi: "అదే UPI ID: {v}", why_domain: "అదే వెబ్‌సైట్: {v}", why_phone: "అదే ఫోన్ నంబర్: {v}",
      why_utr: "అదే రిఫరెన్స్ నంబర్: {v}", why_pkg: "అదే యాప్ ప్యాకేజీ: {v}", why_upi_like: "UPI ID {v}, ఆ మోసంలోని {o} తో {p}% సరిపోతుంది",
      why_apk_like: "ఆ యాప్ లాగే తయారైంది ({p}% సరిపోలిక)", why_template: "సందేశంలో అవే మాటలు", why_category: "అదే రకం మోసం: {v}", why_trick: "అదే ఉపాయం: {v}",
      title: "మోసాల జ్ఞాపకం", sub: "ఈ పరికరంలో మీరు తనిఖీ చేసిన మోసాలు. కొత్తది వీటిలో దేనిలాగైనా ఉంటే PayGuard హెచ్చరిస్తుంది. ఈ ఫోన్ లేదా కంప్యూటర్‌లో మాత్రమే సేవ్ అవుతుంది, ఎక్కడికీ పంపబడదు.",
      k_total: "గుర్తున్న మోసాలు", k_danger: "ప్రమాదకరం", k_month: "గత 30 రోజులు",
      empty: "ఇక్కడ ఇంకా ఏమీ లేదు. తనిఖీలో మోసం లేదా అనుమానాస్పదమైనది దొరికితే ఇక్కడ గుర్తుంచుకుంటాం.", check_now: "ఏదైనా తనిఖీ చేయండి",
      seen_n: "{n} సార్లు తనిఖీ చేశారు", open: "ఫలితం తెరవండి", forget: "మర్చిపో", clear: "అన్నీ తొలగించు", clear_q: "ఈ పరికరం నుండి మొత్తం {n} మోసాలను మర్చిపోవాలా?",
      kind_msg: "సందేశం", kind_qr: "QR / UPI", kind_shot: "స్క్రీన్‌షాట్", kind_apk: "యాప్",
      lvl_danger: "ప్రమాదకరం", lvl_suspicious: "అనుమానాస్పదం", thing_msg: "సందేశం", thing_qr: "QR కోడ్", thing_shot: "స్క్రీన్‌షాట్", thing_apk: "యాప్ ఫైల్",
      no_storage: "మీ బ్రౌజర్ స్టోరేజ్‌ను అడ్డుకుంటోంది, కాబట్టి మోసాల జ్ఞాపకం ఈ పరికరంలో ఏదీ సేవ్ చేయలేదు." },
    mr: { nav_check: "तपासा", nav_trends: "ट्रेंड्स", nav_family: "कुटुंब", nav_memory: "माझी फसवणूक",
      hit_t: "⚠️ हे तुम्ही आधी सामना केलेल्या फसवणुकीसारखेच दिसते", hit_on: "तुम्ही {date} रोजी “{title}” तपासले होते.", see: "तुमचा फसवणूक इतिहास पहा",
      why_same: "हा तोच {thing} आहे.", why_upi: "तोच UPI ID: {v}", why_domain: "तीच वेबसाइट: {v}", why_phone: "तोच फोन नंबर: {v}",
      why_utr: "तोच संदर्भ क्रमांक: {v}", why_pkg: "तेच ॲप पॅकेज: {v}", why_upi_like: "UPI ID {v} त्या फसवणुकीतील {o} शी {p}% जुळतो",
      why_apk_like: "त्या ॲपसारखेच बनवलेले ({p}% जुळणी)", why_template: "मेसेजमधील तेच शब्द", why_category: "त्याच प्रकारची फसवणूक: {v}", why_trick: "तीच युक्ती: {v}",
      title: "फसवणुकीची आठवण", sub: "या डिव्हाइसवर तुम्ही तपासलेल्या फसवणुकी. नवीन एखादी यांपैकी कशासारखी दिसली तर PayGuard तुम्हाला सावध करते. फक्त याच फोन किंवा कॉम्प्युटरवर सेव्ह, कुठेही पाठवले जात नाही.",
      k_total: "लक्षात ठेवलेल्या फसवणुकी", k_danger: "धोकादायक", k_month: "मागील 30 दिवस",
      empty: "इथे अजून काही नाही. तपासणीत फसवणूक किंवा संशयास्पद काही सापडले की ते इथे लक्षात ठेवले जाते.", check_now: "काहीतरी तपासा",
      seen_n: "{n} वेळा तपासले", open: "निकाल उघडा", forget: "विसरा", clear: "सर्व पुसा", clear_q: "या डिव्हाइसवरून सर्व {n} फसवणुकी विसरायच्या?",
      kind_msg: "मेसेज", kind_qr: "QR / UPI", kind_shot: "स्क्रीनशॉट", kind_apk: "ॲप",
      lvl_danger: "धोकादायक", lvl_suspicious: "संशयास्पद", thing_msg: "मेसेज", thing_qr: "QR कोड", thing_shot: "स्क्रीनशॉट", thing_apk: "ॲप फाइल",
      no_storage: "तुमचा ब्राउझर स्टोरेज रोखत आहे, त्यामुळे फसवणुकीची आठवण या डिव्हाइसवर काही सेव्ह करू शकत नाही." },
    bn: { nav_check: "যাচাই", nav_trends: "ট্রেন্ড", nav_family: "পরিবার", nav_memory: "আমার প্রতারণা",
      hit_t: "⚠️ এটি আপনার আগে দেখা একটি প্রতারণার মতোই দেখাচ্ছে", hit_on: "আপনি {date} তারিখে “{title}” যাচাই করেছিলেন।", see: "আপনার প্রতারণার ইতিহাস দেখুন",
      why_same: "এটি সেই একই {thing}।", why_upi: "একই UPI ID: {v}", why_domain: "একই ওয়েবসাইট: {v}", why_phone: "একই ফোন নম্বর: {v}",
      why_utr: "একই রেফারেন্স নম্বর: {v}", why_pkg: "একই অ্যাপ প্যাকেজ: {v}", why_upi_like: "UPI ID {v} সেই প্রতারণার {o}-এর সঙ্গে {p}% মেলে",
      why_apk_like: "সেই অ্যাপের মতোই তৈরি ({p}% মিল)", why_template: "মেসেজের একই শব্দ", why_category: "একই ধরনের প্রতারণা: {v}", why_trick: "একই কৌশল: {v}",
      title: "প্রতারণার স্মৃতি", sub: "এই ডিভাইসে আপনার যাচাই করা প্রতারণা। নতুন কোনোটি এগুলোর মতো দেখালে PayGuard সতর্ক করে। শুধু এই ফোন বা কম্পিউটারে সংরক্ষিত, কোথাও পাঠানো হয় না।",
      k_total: "মনে রাখা প্রতারণা", k_danger: "বিপজ্জনক", k_month: "গত 30 দিন",
      empty: "এখানে এখনও কিছু নেই। কোনো যাচাইয়ে প্রতারণা বা সন্দেহজনক কিছু পাওয়া গেলে তা এখানে মনে রাখা হয়।", check_now: "কিছু যাচাই করুন",
      seen_n: "{n} বার যাচাই করা হয়েছে", open: "ফলাফল খুলুন", forget: "ভুলে যান", clear: "সব মুছুন", clear_q: "এই ডিভাইস থেকে সব {n}টি প্রতারণা ভুলে যাবেন?",
      kind_msg: "মেসেজ", kind_qr: "QR / UPI", kind_shot: "স্ক্রিনশট", kind_apk: "অ্যাপ",
      lvl_danger: "বিপজ্জনক", lvl_suspicious: "সন্দেহজনক", thing_msg: "মেসেজ", thing_qr: "QR কোড", thing_shot: "স্ক্রিনশট", thing_apk: "অ্যাপ ফাইল",
      no_storage: "আপনার ব্রাউজার স্টোরেজ আটকাচ্ছে, তাই প্রতারণার স্মৃতি এই ডিভাইসে কিছু সংরক্ষণ করতে পারছে না।" },
  };
  const getLang = () => {
    if (window.APKX) return window.APKX.lang();
    try { return localStorage.getItem("apkx_lang") || "en"; } catch (_) { return "en"; }
  };
  const t = (k, v = {}) => ((S[getLang()] || S.en)[k] ?? S.en[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
  const pick = (d) => (d && typeof d === "object" ? d[getLang()] || d.en || "" : d || "");
  const fmtDate = (ms) => new Date(ms).toLocaleDateString(getLang() + "-IN", { day: "numeric", month: "short", year: "numeric" });

  // ------------------------------------------------------------ storage (never throws; works without storage)
  let mem = null, storageOK = true;
  function load() {
    if (mem) return mem;
    try { mem = JSON.parse(localStorage.getItem(KEY) || "[]"); if (!Array.isArray(mem)) mem = []; }
    catch (_) { mem = []; storageOK = false; }
    return mem;
  }
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(mem.slice(0, MAX))); } catch (_) { storageOK = false; }
  }

  // ------------------------------------------------------------ pattern extraction
  const RISKY = new Set(["danger", "suspicious"]);
  const RISKY_CAPS = new Set(["sms_receiver", "sms_read_api", "sms_inbox_query", "sms_send", "accessibility", "overlay", "notif_listener",
    "device_admin", "install_packages", "hide_icon_api", "dynamic_code", "embedded_apk", "telegram_bot", "sms_handler", "screen_capture", "call_phone", "no_launcher"]);
  const kindOf = (r) => r.kind || "apk";
  const idOf = (r) => (r.kind === "qr" || r.kind === "msg" ? r.id : r.file && r.file.sha256) || null;

  function apkFeatures(r) {
    const f = new Set();
    (r.permissions || []).forEach((p) => p.short && f.add("perm:" + p.short));
    Object.entries(r.capabilities || {}).forEach(([k, v]) => v === true && f.add("cap:" + k));
    Object.entries(r.components || {}).forEach(([k, v]) => Array.isArray(v) && v.length && f.add("comp:" + k));
    ((r.code || {}).suspicious_apis || []).forEach((a) => a.key && f.add("api:" + a.key));
    return f;
  }
  const risky = (feats) => [...feats].filter((x) => x.startsWith("cap:") && RISKY_CAPS.has(x.slice(4))).length;

  function pattern(r) {
    const k = kindOf(r), d = r.details || {};
    const sig = { upi: [], domain: [], phone: [], tricks: [] };
    let title = "";
    if (k === "qr") {
      if (d.type === "upi" && d.payee_vpa) sig.upi.push(d.payee_vpa.toLowerCase());
      if (d.type === "url" && !d.official && (d.registered_domain || d.host)) sig.domain.push((d.registered_domain || d.host).toLowerCase());
      if ((d.type === "tel" || d.type === "sms") && d.number) sig.phone.push(String(d.number).replace(/\D/g, "").slice(-10));
      title = d.payee_name || d.payee_vpa || d.host || d.number || "QR";
    } else if (k === "msg") {
      sig.upi = (d.upi_ids || []).map((u) => u.toLowerCase());
      sig.domain = (d.links || []).filter((l) => l.domain && !l.official && !l.whatsapp).map((l) => l.domain.toLowerCase());
      sig.phone = (d.phones || []).map((p) => String(p).replace(/\D/g, "").slice(-10));
      sig.template = d.template || null;
      sig.category = d.category || null;
      sig.category_name = d.category_name || null;
      title = d.category_name || "Message";
    } else if (k === "shot") {
      sig.utr = d.utr || null;
      title = (d.app ? d.app + " " : "") + "receipt";
    } else {
      const feats = apkFeatures(r);
      sig.pkg = (r.app && r.app.package) || null;
      if (risky(feats) >= 2) sig.fp = [...feats];
      title = (r.app && r.app.name) || (r.file && r.file.name) || "App";
    }
    // the tricks it used: its serious findings (a "same trick" match needs the same kind of check)
    sig.tricks = (r.findings || []).filter((f) => f.severity === "critical" || f.severity === "high")
      .filter((f) => !["REPORTED_BY_USERS", "UPI_MUTATION", "APK_REPACKAGED"].includes(f.id))
      .slice(0, 6).map((f) => ({ id: f.id, title: f.title }));
    const link = k === "apk" && r.file ? "/r/" + r.file.sha256 : k === "shot" && r.file ? "/s/" + r.file.sha256 : null;
    return { id: idOf(r), kind: k, level: r.verdict.level, score: r.verdict.score, title, sig, link };
  }

  // ------------------------------------------------------------ similarity (same rules as app/analyzer/mutation.py)
  function lev(a, b) {
    let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
      prev = cur;
    }
    return prev[b.length];
  }
  const bigrams = (s) => { s = "^" + s + "$"; const o = new Set(); for (let i = 0; i < s.length - 1; i++) o.add(s.slice(i, i + 2)); return o; };
  const jaccard = (a, b) => { let n = 0; a.forEach((x) => b.has(x) && n++); const u = a.size + b.size - n; return u ? n / u : 1; };
  const SK = { 0: "o", 1: "l", i: "l", "|": "l", 3: "e", 4: "a", 5: "s", 7: "t", 8: "b" };
  const skeleton = (v) => v.toLowerCase().replace(/rn/g, "m").replace(/vv/g, "w").replace(/[01i|34578]/g, (c) => SK[c]).replace(/[.\-_]/g, "");
  function vpaSim(a, b) {
    const s = 0.5 * (1 - lev(a, b) / Math.max(a.length, b.length, 1)) + 0.5 * jaccard(bigrams(a), bigrams(b));
    return skeleton(a) === skeleton(b) ? Math.max(s, 0.95) : s;
  }
  function comparable(a, b) {
    const [la, ha] = a.split("@"), [lb, hb] = b.split("@");
    if ((la.match(/[a-z]/g) || []).length < 5) return false;          // phone-number / very short IDs
    if (la.replace(/\d/g, "") === (lb || "").replace(/\d/g, "") && ha === hb) return false;  // only digits differ
    return Math.abs(a.length - b.length) <= 4;
  }

  // ------------------------------------------------------------ matching
  // Strongest reason first. Identifier matches count even when today's check looks clean (the scammer may have
  // changed the wording); pattern-only matches (same scam type / trick) only when today's check is risky too.
  function match(p) {
    const cur = RISKY.has(p.level);
    let best = null;
    const take = (e, rank, why) => { if (!best || rank < best.rank || (rank === best.rank && e.at > best.entry.at)) best = { entry: e, rank, why }; };
    for (const e of load()) {
      if (e.id && e.id === p.id) { take(e, 0, t("why_same", { thing: t("thing_" + e.kind) })); continue; }
      const s = e.sig || {};
      for (const [key, why] of [["upi", "why_upi"], ["domain", "why_domain"], ["phone", "why_phone"]]) {
        const hit = (p.sig[key] || []).find((v) => (s[key] || []).includes(v));
        if (hit) take(e, 1, t(why, { v: hit }));
      }
      if (p.sig.utr && p.sig.utr === s.utr) take(e, 1, t("why_utr", { v: s.utr }));
      if (p.sig.pkg && p.sig.pkg === s.pkg && e.kind === "apk") take(e, 1, t("why_pkg", { v: s.pkg }));
      for (const v of p.sig.upi || []) for (const o of s.upi || []) {
        if (v === o || !comparable(v, o)) continue;
        const sim = vpaSim(v, o);
        if (sim >= 0.85) take(e, 2, t("why_upi_like", { v, o, p: Math.round(sim * 100) }));
      }
      if (p.sig.fp && s.fp) {
        const sim = jaccard(new Set(p.sig.fp), new Set(s.fp));
        if (sim >= 0.85) take(e, 2, t("why_apk_like", { p: Math.round(sim * 100) }));
      }
      if (p.sig.template && p.sig.template === s.template) take(e, 3, t("why_template"));
      if (!cur) continue;
      if (p.sig.category && p.sig.category === s.category) take(e, 4, t("why_category", { v: pick(s.category_name) || s.category }));
      if (e.kind === p.kind) {
        const tr = (p.sig.tricks || []).find((x) => (s.tricks || []).some((y) => y.id === x.id));
        if (tr) take(e, 5, t("why_trick", { v: pick(tr.title) }));
      }
    }
    return best;
  }

  function remember(p) {
    if (!RISKY.has(p.level)) return;
    const list = load(), now = Date.now();
    const i = p.id ? list.findIndex((e) => e.id === p.id) : -1;
    if (i >= 0) {
      const e = list.splice(i, 1)[0];
      list.unshift({ ...e, ...p, at: e.at, last: now, count: (e.count || 1) + 1 });
    } else {
      list.unshift({ ...p, at: now, last: now, count: 1 });
    }
    mem = list.slice(0, MAX);
    save();
  }

  // ------------------------------------------------------------ main page: banner inside the verdict card
  // Matched once per result and then cached, so re-renders (language switch) don't match a scan against itself.
  const decided = new Map();
  window.renderMemory = function (r) {
    const box = document.getElementById("memhit");
    if (!box || !r || !r.verdict) return;
    let hit;
    try {
      const p = pattern(r), key = p.id || JSON.stringify(p.sig);
      if (!decided.has(key)) {
        decided.set(key, match(p));
        remember(p);
      }
      hit = decided.get(key);
    } catch (_) { hit = null; }
    if (!hit) { box.hidden = true; return; }
    const e = hit.entry;
    box.hidden = false;
    box.innerHTML = `<b>${esc(t("hit_t"))}</b>
      <span>${esc(t("hit_on", { title: pick(e.title), date: fmtDate(e.at) }))} ${esc(hit.why)}</span>
      <a href="/memory">${esc(t("see"))} →</a>`;
  };

  // ------------------------------------------------------------ /memory page
  const ICON = { msg: "💬", qr: "🔳", shot: "🧾", apk: "📦" };
  function renderPage() {
    const list = load();
    document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
    $("#no-storage").hidden = storageOK;
    const month = Date.now() - 30 * 86400000;
    $("#mkpis").innerHTML = [["k_total", list.length], ["k_danger", list.filter((e) => e.level === "danger").length],
      ["k_month", list.filter((e) => e.last >= month).length]]
      .map(([k, n]) => `<div class="kpi"><div class="k">${esc(t(k))}</div><div class="v">${n}</div></div>`).join("");
    $("#mclear").hidden = !list.length;
    if (!list.length) {
      $("#mlist").innerHTML = `<div class="card mempty"><p>${esc(t("empty"))}</p><a class="btn" href="/app">${esc(t("check_now"))}</a></div>`;
      return;
    }
    let lastMonth = "";
    $("#mlist").innerHTML = list.map((e, i) => {
      const s = e.sig || {};
      const m = new Date(e.last || e.at).toLocaleDateString(getLang() + "-IN", { month: "long", year: "numeric" });
      const head = m !== lastMonth ? `<h2 class="sec-t mmonth">${esc(m)}</h2>` : "";
      lastMonth = m;
      const chips = [...(s.upi || []), ...(s.domain || []), ...(s.phone || []), s.utr, s.pkg].filter(Boolean).slice(0, 4)
        .map((v) => `<code>${esc(v)}</code>`).join("");
      const tricks = (s.tricks || []).slice(0, 2).map((x) => esc(pick(x.title))).join(" · ");
      return `${head}<article class="mitem ${esc(e.level)}">
        <span class="mico" aria-hidden="true">${ICON[e.kind] || "⚠️"}</span>
        <div class="mbody">
          <div class="mtop"><b>${esc(pick(e.title))}</b><span class="mpill">${esc(t("lvl_" + e.level))} · ${e.score}</span></div>
          <p class="dim small">${esc(t("kind_" + e.kind))} · ${esc(fmtDate(e.last || e.at))}${e.count > 1 ? " · " + esc(t("seen_n", { n: e.count })) : ""}</p>
          ${tricks ? `<p class="small">${tricks}</p>` : ""}
          ${chips ? `<div class="mchips">${chips}</div>` : ""}
        </div>
        <div class="mact">
          ${e.link ? `<a class="btn small" href="${esc(e.link)}">${esc(t("open"))}</a>` : ""}
          <button class="btn small ghostish" data-forget="${i}" type="button">${esc(t("forget"))}</button>
        </div>
      </article>`;
    }).join("");
  }
  function initPage() {
    const root = $("#memory-page");
    if (!root) return;
    const setLang = (l) => {
      try { localStorage.setItem("apkx_lang", l); } catch (_) {}
      document.documentElement.lang = l;
      document.querySelectorAll(".lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === l));
      renderPage();
    };
    document.querySelectorAll(".lang button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));
    root.addEventListener("click", (ev) => {
      const f = ev.target.closest("[data-forget]");
      if (f) { load().splice(+f.dataset.forget, 1); save(); renderPage(); }
    });
    $("#mclear").addEventListener("click", () => {
      if (confirm(t("clear_q", { n: load().length }))) { mem = []; save(); renderPage(); }
    });
    window.addEventListener("storage", (ev) => { if (ev.key === KEY) { mem = null; renderPage(); } });
    setLang(S[getLang()] ? getLang() : "en");
  }

  // localized nav link on the main page
  function navLabel() {
    const a = document.querySelector("[data-memnav]");
    if (a) a.textContent = t("nav_memory");
  }
  window.PGMemory = { pattern, match, remember, list: load, navLabel };
  document.addEventListener("click", (ev) => { if (ev.target.closest(".lang button")) setTimeout(navLabel, 0); });
  navLabel();
  initPage();
})();
