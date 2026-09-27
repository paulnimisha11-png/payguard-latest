/* Scam trends page: KPIs, 14-day chart, rising scam types, most-reported identifiers (masked), exact lookup. */
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const S = {
    en: { nav_check: "Check", nav_trends: "Trends", nav_family: "Family", title: "Scam trends",
      sub: "What PayGuard users are checking and reporting right now. No names, messages or screenshots are ever shown here.",
      demo: "This page currently includes demo data for a presentation.", chart_t: "Scams caught per day",
      chart_sub: "Dangerous or suspicious results in the last 14 days. Hover or tap a bar for details.", table: "Show as table",
      rising_t: "Rising this week", types_t: "Scam types this week", top_t: "Most reported", lookup_t: "Were you given a UPI ID, number or website?",
      lookup_btn: "Check", k_checks: "Checks this week", k_threats: "Scams caught", k_reports: "Reports by users", k_listed: "Listed below",
      vs: "{d} vs last week", pending: "{n} more waiting for enough reports", same: "same as last week",
      d_day: "Day", d_checks: "Checks", d_threats: "Scams caught", d_reports: "Reports",
      upi: "UPI IDs", phone: "Phone numbers", domain: "Websites", none_listed: "Nothing has enough reports yet.",
      reports: "{n} reports", lost: "{n} lost money", last: "last {d}", confirmed: "confirmed",
      rule: "Listed only after at least {n} people on different networks report it and it isn't disputed. UPI IDs and numbers are partly hidden — use the check below for an exact match.",
      no_types: "No scams caught this week yet.", new: "new", up: "▲ {n}%", down: "▼ {n}%", this_week: "{n} this week", was: "was {n}",
      r_bad: "⚠ Reported as a scam by {n} {p}{g}. Don't pay or share anything.", r_some: "{n} {p} reported this, not enough to be sure. Be careful.",
      r_ok: "✓ No one has reported this yet. That isn't proof it's safe.", r_disputed: " ({d} say it's genuine)", person: "person", people: "people",
      r_lost: ", {n} of them lost money", updated: "Updated {t}", err: "Couldn't load trends. Check your connection." },
    hi: { nav_check: "जाँचें", nav_trends: "ट्रेंड्स", nav_family: "परिवार", title: "ठगी के ट्रेंड्स",
      sub: "PayGuard उपयोगकर्ता अभी क्या जाँच और रिपोर्ट कर रहे हैं। यहाँ कभी नाम, मैसेज या स्क्रीनशॉट नहीं दिखाए जाते।",
      demo: "इस पेज पर अभी प्रेज़ेंटेशन के लिए डेमो डेटा भी है।", chart_t: "रोज़ पकड़ी गई ठगी",
      chart_sub: "पिछले 14 दिनों के ख़तरनाक या संदिग्ध नतीजे। विवरण के लिए किसी बार पर टैप करें।", table: "टेबल में देखें",
      rising_t: "इस हफ़्ते बढ़ रही ठगी", types_t: "इस हफ़्ते ठगी के प्रकार", top_t: "सबसे ज़्यादा रिपोर्ट", lookup_t: "किसी ने UPI ID, नंबर या वेबसाइट दी है?",
      lookup_btn: "जाँचें", k_checks: "इस हफ़्ते जाँच", k_threats: "पकड़ी गई ठगी", k_reports: "उपयोगकर्ताओं की रिपोर्ट", k_listed: "नीचे सूची में",
      vs: "पिछले हफ़्ते से {d}", pending: "{n} और रिपोर्ट की प्रतीक्षा में", same: "पिछले हफ़्ते जितना",
      d_day: "दिन", d_checks: "जाँच", d_threats: "पकड़ी गई ठगी", d_reports: "रिपोर्ट",
      upi: "UPI ID", phone: "फ़ोन नंबर", domain: "वेबसाइट", none_listed: "अभी किसी पर पर्याप्त रिपोर्ट नहीं हैं।",
      reports: "{n} रिपोर्ट", lost: "{n} के पैसे गए", last: "आख़िरी {d}", confirmed: "पुष्टि",
      rule: "सूची में तभी आता है जब कम से कम {n} लोग अलग-अलग नेटवर्क से रिपोर्ट करें और कोई विवाद न हो। UPI ID और नंबर आंशिक रूप से छिपे हैं — सटीक मिलान के लिए नीचे जाँचें।",
      no_types: "इस हफ़्ते अभी कोई ठगी नहीं पकड़ी गई।", new: "नया", up: "▲ {n}%", down: "▼ {n}%", this_week: "इस हफ़्ते {n}", was: "पहले {n}",
      r_bad: "⚠ {n} {p} ने इसे ठगी बताया है{g}। पैसे न भेजें, कुछ न बताएँ।", r_some: "{n} {p} ने रिपोर्ट किया है, पक्का कहने के लिए काफ़ी नहीं। सावधान रहें।",
      r_ok: "✓ अभी तक किसी ने रिपोर्ट नहीं किया। इसका मतलब यह नहीं कि यह सुरक्षित है।", r_disputed: " ({d} इसे असली बताते हैं)", person: "व्यक्ति", people: "लोगों",
      r_lost: ", इनमें से {n} के पैसे गए", updated: "अपडेट {t}", err: "ट्रेंड्स लोड नहीं हो सके। इंटरनेट जाँचें।" },
    kn: { nav_check: "ಪರಿಶೀಲಿಸಿ", nav_trends: "ಟ್ರೆಂಡ್‌ಗಳು", nav_family: "ಕುಟುಂಬ", title: "ವಂಚನೆ ಟ್ರೆಂಡ್‌ಗಳು",
      sub: "PayGuard ಬಳಕೆದಾರರು ಈಗ ಏನು ಪರಿಶೀಲಿಸುತ್ತಿದ್ದಾರೆ ಮತ್ತು ವರದಿ ಮಾಡುತ್ತಿದ್ದಾರೆ. ಇಲ್ಲಿ ಹೆಸರು, ಸಂದೇಶ ಅಥವಾ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಎಂದಿಗೂ ತೋರಿಸುವುದಿಲ್ಲ.",
      demo: "ಈ ಪುಟದಲ್ಲಿ ಈಗ ಪ್ರಸ್ತುತಿಗಾಗಿ ಡೆಮೊ ಡೇಟಾ ಇದೆ.", chart_t: "ದಿನಕ್ಕೆ ಹಿಡಿದ ವಂಚನೆಗಳು",
      chart_sub: "ಕಳೆದ 14 ದಿನಗಳ ಅಪಾಯಕಾರಿ ಅಥವಾ ಸಂಶಯಾಸ್ಪದ ಫಲಿತಾಂಶಗಳು. ವಿವರಕ್ಕೆ ಬಾರ್ ಒತ್ತಿ.", table: "ಟೇಬಲ್ ಆಗಿ ನೋಡಿ",
      rising_t: "ಈ ವಾರ ಹೆಚ್ಚುತ್ತಿರುವುದು", types_t: "ಈ ವಾರದ ವಂಚನೆ ಪ್ರಕಾರಗಳು", top_t: "ಹೆಚ್ಚು ವರದಿಯಾದವು", lookup_t: "ಯಾರಾದರೂ UPI ID, ನಂಬರ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಕೊಟ್ಟಿದ್ದಾರೆಯೇ?",
      lookup_btn: "ಪರಿಶೀಲಿಸಿ", k_checks: "ಈ ವಾರದ ಪರಿಶೀಲನೆ", k_threats: "ಹಿಡಿದ ವಂಚನೆ", k_reports: "ಬಳಕೆದಾರರ ವರದಿ", k_listed: "ಕೆಳಗೆ ಪಟ್ಟಿಯಲ್ಲಿ",
      vs: "ಕಳೆದ ವಾರಕ್ಕಿಂತ {d}", pending: "ಇನ್ನೂ {n} ಸಾಕಷ್ಟು ವರದಿಗಾಗಿ ಕಾಯುತ್ತಿವೆ", same: "ಕಳೆದ ವಾರದಷ್ಟೇ",
      d_day: "ದಿನ", d_checks: "ಪರಿಶೀಲನೆ", d_threats: "ಹಿಡಿದ ವಂಚನೆ", d_reports: "ವರದಿ",
      upi: "UPI ID ಗಳು", phone: "ಫೋನ್ ನಂಬರ್‌ಗಳು", domain: "ವೆಬ್‌ಸೈಟ್‌ಗಳು", none_listed: "ಇನ್ನೂ ಯಾವುದಕ್ಕೂ ಸಾಕಷ್ಟು ವರದಿ ಇಲ್ಲ.",
      reports: "{n} ವರದಿ", lost: "{n} ಜನ ಹಣ ಕಳೆದುಕೊಂಡರು", last: "ಕೊನೆಯದು {d}", confirmed: "ದೃಢಪಡಿಸಲಾಗಿದೆ",
      rule: "ಕನಿಷ್ಠ {n} ಜನರು ಬೇರೆ ಬೇರೆ ನೆಟ್‌ವರ್ಕ್‌ನಿಂದ ವರದಿ ಮಾಡಿ, ವಿವಾದವಿಲ್ಲದಿದ್ದರೆ ಮಾತ್ರ ಪಟ್ಟಿಗೆ ಸೇರುತ್ತದೆ. UPI ID ಮತ್ತು ನಂಬರ್‌ಗಳು ಭಾಗಶಃ ಮರೆಮಾಡಲಾಗಿದೆ — ನಿಖರ ಹೊಂದಾಣಿಕೆಗೆ ಕೆಳಗೆ ಪರಿಶೀಲಿಸಿ.",
      no_types: "ಈ ವಾರ ಇನ್ನೂ ಯಾವುದೇ ವಂಚನೆ ಹಿಡಿದಿಲ್ಲ.", new: "ಹೊಸದು", up: "▲ {n}%", down: "▼ {n}%", this_week: "ಈ ವಾರ {n}", was: "ಹಿಂದೆ {n}",
      r_bad: "⚠ {n} {p} ಇದನ್ನು ವಂಚನೆ ಎಂದು ವರದಿ ಮಾಡಿದ್ದಾರೆ{g}. ಹಣ ಕಳುಹಿಸಬೇಡಿ, ಏನನ್ನೂ ಹೇಳಬೇಡಿ.", r_some: "{n} {p} ವರದಿ ಮಾಡಿದ್ದಾರೆ, ಖಚಿತವಾಗಿ ಹೇಳಲು ಸಾಕಾಗದು. ಎಚ್ಚರವಿರಲಿ.",
      r_ok: "✓ ಇನ್ನೂ ಯಾರೂ ವರದಿ ಮಾಡಿಲ್ಲ. ಇದು ಸುರಕ್ಷಿತ ಎಂಬುದಕ್ಕೆ ಸಾಕ್ಷಿ ಅಲ್ಲ.", r_disputed: " ({d} ಜನ ಇದು ನಿಜವಾದದ್ದು ಎನ್ನುತ್ತಾರೆ)", person: "ವ್ಯಕ್ತಿ", people: "ಜನರು",
      r_lost: ", ಅವರಲ್ಲಿ {n} ಜನ ಹಣ ಕಳೆದುಕೊಂಡರು", updated: "ಅಪ್‌ಡೇಟ್ {t}", err: "ಟ್ರೆಂಡ್‌ಗಳು ಲೋಡ್ ಆಗಲಿಲ್ಲ. ಸಂಪರ್ಕ ಪರಿಶೀಲಿಸಿ." },
    ta: { nav_check: "சரிபார்க்கவும்", nav_trends: "ட்ரெண்டுகள்", nav_family: "குடும்பம்", title: "மோசடி ட்ரெண்டுகள்",
      sub: "PayGuard பயனர்கள் தற்போது என்ன சரிபார்க்கிறார்கள் மற்றும் புகாரளிக்கிறார்கள். பெயர்கள், செய்திகள் அல்லது ஸ்கிரீன்ஷாட்கள் எதுவும் இங்கு காட்டப்படாது.",
      demo: "இந்த பக்கத்தில் தற்போது விளக்கக்காட்சிக்கான மாதிரி தரவு உள்ளது.", chart_t: "நாளுக்கு நாள் கண்டறியப்பட்ட மோசடிகள்",
      chart_sub: "கடந்த 14 நாட்களில் கண்டறியப்பட்ட ஆபத்தான அல்லது சந்தேகத்திற்கிடமான முடிவுகள். விவரங்களுக்குப் பட்டியைத் தட்டவும்.", table: "அட்டவணையாகக் காட்டு",
      rising_t: "இந்த வாரம் அதிகரித்து வருபவை", types_t: "இந்த வார மோசடி வகைகள்", top_t: "அதிகம் புகாரளிக்கப்பட்டவை", lookup_t: "உங்களுக்கு UPI ID, எண் அல்லது வலைத்தளம் தரப்பட்டதா?",
      lookup_btn: "சரிபார்க்கவும்", k_checks: "இந்த வார சோதனைகள்", k_threats: "கண்டறியப்பட்ட மோசடிகள்", k_reports: "பயனர் புகார்கள்", k_listed: "கீழே பட்டியலிடப்பட்டவை",
      vs: "கடந்த வாரத்தை விட {d}", pending: "போதுமான புகார்களுக்காக இன்னும் {n} காத்திருக்கின்றன", same: "கடந்த வாரத்தைப் போன்றே",
      d_day: "நாள்", d_checks: "சோதனைகள்", d_threats: "கண்டறியப்பட்ட மோசடிகள்", d_reports: "புகார்கள்",
      upi: "UPI IDகள்", phone: "மொபைல் எண்கள்", domain: "வலைத்தளங்கள்", none_listed: "இன்னும் எதற்கும் போதுமான புகார்கள் இல்லை.",
      reports: "{n} புகார்கள்", lost: "{n} பேர் பணத்தை இழந்தனர்", last: "கடைசியாக {d}", confirmed: "உறுதிப்படுத்தப்பட்டது",
      rule: "வெவ்வேறு நெட்வொர்க்குகளில் குறைந்தது {n} பேர் புகாரளித்து, மறுப்பு எதுவும் இல்லாத பின்னரே பட்டியலிடப்படும். UPI ID மற்றும் எண்கள் மறைக்கப்பட்டுள்ளன — துல்லியமாக அறிய கீழே சரிபார்க்கவும்.",
      no_types: "இந்த வாரம் இன்னும் எந்த மோசடியும் கண்டறியப்படவில்லை.", new: "புதியது", up: "▲ {n}%", down: "▼ {n}%", this_week: "இந்த வாரம் {n}", was: "முன்பு {n}",
      r_bad: "⚠ {n} {p} இதை மோசடி என்று தெரிவித்துள்ளனர்{g}. பணம் செலுத்தவோ பகிரவோ வேண்டாம்.", r_some: "{n} {p} புகாரளித்துள்ளனர், உறுதிப்படுத்த போதாது. கவனமாக இருங்கள்.",
      r_ok: "✓ இதுவரை யாரும் புகார் அளிக்கவில்லை. அதற்காக இது பாதுகாப்பானது என்று பொருளல்ல.", r_disputed: " ({d} பேர் இது உண்மையானது என்கிறார்கள்)", person: "நபர்", people: "பேர்",
      r_lost: ", இதில் {n} பேர் பணத்தை இழந்தனர்", updated: "புதுப்பிக்கப்பட்டது {t}", err: "ட்ரெண்டுகளை ஏற்ற முடியவில்லை. இணைப்பைச் சரிபார்க்கவும்." },
    te: { nav_check: "తనిఖీ", nav_trends: "ట్రెండ్స్", nav_family: "కుటుంబం", title: "మోసం ట్రెండ్స్",
      sub: "PayGuard వినియోగదారులు ప్రస్తుతం ఏమి తనిఖీ చేస్తున్నారు మరియు నివేదిస్తున్నారు. పేర్లు, సందేశాలు లేదా స్క్రీన్‌షాట్‌లు ఇక్కడ చూపబడవు.",
      demo: "ఈ పేజీలో ప్రస్తుతం ప్రదర్శన కోసం డెమో డేటా ఉంది.", chart_t: "రోజువారీ పట్టుబడిన మోసాలు",
      chart_sub: "గత 14 రోజుల్లో ప్రమాదకర లేదా అనుమానాస్పద ఫలితాలు. వివరాల కోసం బార్‌ను నొక్కండి.", table: "పట్టికగా చూపించు",
      rising_t: "ఈ వారం పెరుగుతున్నవి", types_t: "ఈ వారం మోసం రకాలు", top_t: "ఎక్కువగా నివేదించబడినవి", lookup_t: "మీకు UPI ID, నంబర్ లేదా వెబ్‌సైట్ ఇవ్వబడిందా?",
      lookup_btn: "తనిఖీ చేయండి", k_checks: "ఈ వారం తనిఖీలు", k_threats: "పట్టుబడిన మోసాలు", k_reports: "వినియోగదారుల రిపోర్టులు", k_listed: "క్రింద జాబితా చేయబడినవి",
      vs: "గత వారం కంటే {d}", pending: "తగినన్ని రిపోర్టుల కోసం ఇంకా {n} వేచి ఉన్నాయి", same: "గత వారం మాదిరిగానే",
      d_day: "రోజు", d_checks: "తనిఖీలు", d_threats: "పట్టుబడిన మోసాలు", d_reports: "రిపోర్టులు",
      upi: "UPI IDలు", phone: "ఫోన్ నంబర్లు", domain: "వెబ్‌సైట్లు", none_listed: "ఇంకా దేనికీ తగినన్ని రిపోర్టులు లేవు.",
      reports: "{n} రిపోర్టులు", lost: "{n} మంది డబ్బు పోగొట్టుకున్నారు", last: "చివరిగా {d}", confirmed: "ధృవీకరించబడింది",
      rule: "వివిధ నెట్‌వర్క్‌లలోని కనీసం {n} మంది నివేదించి, వివాదం లేనప్పుడు మాత్రమే జాబితా చేయబడుతుంది. UPI ID మరియు నంబర్లు పాక్షికంగా దాచబడ్డాయి — ఖచ్చితమైన సరిపోలిక కోసం క్రింద తనిఖీ చేయండి.",
      no_types: "ఈ వారం ఇంకా ఎలాంటి మోసాలు పట్టుబడలేదు.", new: "కొత్తది", up: "▲ {n}%", down: "▼ {n}%", this_week: "ఈ వారం {n}", was: "గతంలో {n}",
      r_bad: "⚠ {n} {p} దీనిని మోసంగా నివేదించారు{g}. చెల్లించవద్దు లేదా సమాచారం పంచుకోవద్దు.", r_some: "{n} {p} నివేదించారు, ఖచ్చితంగా చెప్పడానికి సరిపోదు. జాగ్రత్తగా ఉండండి.",
      r_ok: "✓ ఇప్పటివరకు ఎవరూ నివేదించలేదు. అంటే ఇది సురక్షితమని రుజువు కాదు.", r_disputed: " ({d} మంది ఇది నిజమైనదని చెప్పారు)", person: "వ్యక్తి", people: "మంది",
      r_lost: ", వీరిలో {n} మంది డబ్బు పోగొట్టుకున్నారు", updated: "నవీకరించబడింది {t}", err: "ట్రెండ్స్ లోడ్ కాలేదు. కనెక్షన్‌ని తనిఖీ చేయండి." },
    mr: { nav_check: "तपासा", nav_trends: "ट्रेंड्स", nav_family: "कुटुंब", title: "फसवणूक ट्रेंड्स",
      sub: "PayGuard वापरकर्ते सध्या काय तपासत आहेत आणि तक्रार करत आहेत. येथे नावे, मेसेज किंवा स्क्रीनशॉट कधीही दाखवले जात नाहीत.",
      demo: "या पृष्ठावर सध्या सादरीकरणासाठी डेमो डेटा समाविष्ट आहे.", chart_t: "दररोज पकडलेली फसवणूक",
      chart_sub: "गेल्या १४ दिवसांतील धोकादायक किंवा संशयास्पद निकाल. तपशीलांसाठी बारवर टॅप करा.", table: "तक्त्यामध्ये पहा",
      rising_t: "या आठवड्यात वाढणारी फसवणूक", types_t: "या आठवड्यातील फसवणुकीचे प्रकार", top_t: "सर्वाधिक तक्रारी", lookup_t: "तुम्हाला UPI ID, नंबर किंवा वेबसाइट दिली आहे का?",
      lookup_btn: "तपासा", k_checks: "या आठवड्यातील तपासण्या", k_threats: "पकडलेली फसवणूक", k_reports: "वापरकर्त्यांच्या तक्रारी", k_listed: "खाली सूचीबद्ध",
      vs: "गेल्या आठवड्यापेक्षा {d}", pending: "पुरेशा तक्रारींसाठी अजून {n} प्रतीक्षेत", same: "गेल्या आठवड्याइतकेच",
      d_day: "दिवस", d_checks: "तपासण्या", d_threats: "पकडलेली फसवणूक", d_reports: "तक्रारी",
      upi: "UPI IDs", phone: "फोन नंबर", domain: "वेबसाइट्स", none_listed: "अद्याप कशावरही पुरेशा तक्रारी नाहीत.",
      reports: "{n} तक्रारी", lost: "{n} जणांचे पैसे गेले", last: "शेवटचे {d}", confirmed: "पुष्टी केली",
      rule: "वेगवेगळ्या नेटवर्कवरील किमान {n} लोकांनी तक्रार केल्यावर आणि कोणताही वाद नसल्यासच सूचीमध्ये येते. अचूक तपासणीसाठी खाली शोधा.",
      no_types: "या आठवड्यात अद्याप कोणतीही फसवणूक पकडली गेली नाही.", new: "नवीन", up: "▲ {n}%", down: "▼ {n}%", this_week: "या आठवड्यात {n}", was: "पूर्वी {n}",
      r_bad: "⚠ {n} {p} यांनी याला फसवणूक म्हणून नोंदवले आहे{g}. पैसे पाठवू नका किंवा काहीही शेअर करू नका.", r_some: "{n} {p} यांनी नोंदवले आहे, खात्री करण्यासाठी पुरेसे नाही. सावध रहा.",
      r_ok: "✓ अद्याप कोणीही तक्रार केलेली नाही. याचा अर्थ हे सुरक्षित आहे असा पुरावा नाही.", r_disputed: " ({d} जण हे खरे असल्याचे सांगतात)", person: "व्यक्ती", people: "लोकांनी",
      r_lost: ", यापैकी {n} जणांचे पैसे गेले", updated: "अद्यतनित {t}", err: "ट्रेंड्स लोड करता आले नाहीत. इंटरनेट कनेक्शन तपासा." },
    bn: { nav_check: "যাচাই", nav_trends: "ট্রেন্ডস", nav_family: "পরিবার", title: "প্রতারণার ট্রেন্ডস",
      sub: "PayGuard ব্যবহারকারীরা এখন কী যাচাই এবং রিপোর্ট করছেন। এখানে নাম, মেসেজ বা স্ক্রিনশট কখনোই দেখানো হয় না।",
      demo: "এই পৃষ্ঠায় বর্তমানে উপস্থাপনার জন্য ডেমো ডেটা রয়েছে।", chart_t: "প্রতিদিন ধরা পড়া প্রতারণা",
      chart_sub: "গত ১৪ দিনের বিপজ্জনক বা সন্দেহজনক ফলাফল। বিস্তারিত জানতে বারে ট্যাপ করুন।", table: "সারণী হিসেবে দেখুন",
      rising_t: "এই সপ্তাহে ক্রমবর্ধমান", types_t: "এই সপ্তাহের প্রতারণার ধরন", top_t: "সর্বাধিক রিপোর্ট করা", lookup_t: "আপনাকে কি কোনো UPI ID, নম্বর বা ওয়েবসাইট দেওয়া হয়েছে?",
      lookup_btn: "যাচাই করুন", k_checks: "এই সপ্তাহের পরীক্ষা", k_threats: "ধরা পড়া প্রতারণা", k_reports: "ব্যবহারকারীদের রিপোর্ট", k_listed: "নিচে তালিকাভুক্ত",
      vs: "গত সপ্তাহের চেয়ে {d}", pending: "যথেষ্ট রিপোর্টের জন্য আরো {n}টি অপেক্ষারত", same: "গত সপ্তাহের সমান",
      d_day: "দিন", d_checks: "পরীক্ষা", d_threats: "ধরা পড়া প্রতারণা", d_reports: "রিপোর্ট",
      upi: "UPI IDসমূহ", phone: "ফোন নম্বরসমূহ", domain: "ওয়েবসাইটসমূহ", none_listed: "এখনও পর্যাপ্ত রিপোর্ট জমা পড়েনি।",
      reports: "{n}টি রিপোর্ট", lost: "{n} জন টাকা হারিয়েছেন", last: "সর্বশেষ {d}", confirmed: "নিশ্চিত",
      rule: "বিভিন্ন নেটওয়ার্কের অন্তত {n} জন রিপোর্ট করার পর এবং কোনো বিরোধ না থাকলেই তালিকাভুক্ত হয়। সঠিক মিল দেখতে নিচে যাচাই করুন।",
      no_types: "এই সপ্তাহে এখনও কোনো প্রতারণা শনাক্ত হয়নি।", new: "নতুন", up: "▲ {n}%", down: "▼ {n}%", this_week: "এই সপ্তাহে {n}", was: "আগে ছিল {n}",
      r_bad: "⚠ {n} {p} এটিকে প্রতারণা বলে রিপোর্ট করেছেন{g}। কোনো টাকা পাঠাবেন না বা তথ্য দেবেন না।", r_some: "{n} {p} রিপোর্ট করেছেন, নিশ্চিত হওয়ার জন্য যথেষ্ট নয়। সতর্ক থাকুন।",
      r_ok: "✓ এখনও পর্যন্ত কেউ রিপোর্ট করেনি। তবে এটি নিরাপদ হওয়ার নিশ্চয়তা নয়।", r_disputed: " ({d} জন বলছেন এটি আসল)", person: "জন", people: "জন",
      r_lost: ", তাদের মধ্যে {n} জন টাকা হারিয়েছেন", updated: "আপডেট হয়েছে {t}", err: "ট্রেন্ডস লোড করা যায়নি। ইন্টারনেট সংযোগ যাচাই করুন।" },
  };
  let lang = "en";
  try { lang = localStorage.getItem("apkx_lang") || "en"; } catch (_) {}
  if (!S[lang]) lang = "en";
  const t = (k, v = {}) => ((S[lang] || S.en)[k] ?? S.en[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x] ?? "");
  const nf = () => new Intl.NumberFormat(lang === "en" ? "en-IN" : lang + "-IN");
  const fmt = (n) => nf().format(n);
  let data = null;

  function setLang(l) {
    lang = l;
    try { localStorage.setItem("apkx_lang", l); } catch (_) {}
    document.documentElement.lang = l;
    document.querySelectorAll(".lang button").forEach((b) => b.classList.toggle("on", b.dataset.lang === l));
    document.querySelectorAll("[data-t]").forEach((el) => (el.textContent = t(el.dataset.t)));
    if (data) render(data);
  }
  document.querySelectorAll(".lang button").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.lang)));

  function delta(cur, prev) {
    if (!prev && !cur) return "";
    if (!prev) return t("vs", { d: "▲ " + t("new") });
    const p = Math.round((100 * (cur - prev)) / prev);
    return p === 0 ? t("same") : t("vs", { d: (p > 0 ? "▲ " : "▼ ") + Math.abs(p) + "%" });
  }

  function dayLabel(iso, short) {
    const d = new Date(iso + "T12:00:00");
    return d.toLocaleDateString(lang === "en" ? "en-IN" : lang + "-IN", short ? { day: "numeric" } : { weekday: "short", day: "numeric", month: "short" });
  }

  function chart(daily) {
    const el = $("#chart");
    const W = Math.max(300, Math.round(el.clientWidth || 640)), H = W < 480 ? 200 : 220, padL = 34, padR = 8, padT = 18, padB = 26;
    const max = Math.max(4, ...daily.map((d) => d.threats));
    const step = Math.pow(10, Math.floor(Math.log10(max)));
    const nice = [1, 2, 2.5, 5, 10].map((m) => m * step).find((s) => max / s <= 4) || step * 10;
    const top = Math.ceil(max / nice) * nice;
    const iw = W - padL - padR, ih = H - padT - padB, band = iw / daily.length, bw = Math.min(24, band * 0.62);
    const y = (v) => padT + ih - (v / top) * ih;
    let g = "";
    for (let v = 0; v <= top; v += nice) {
      g += `<line class="grid-l" x1="${padL}" x2="${W - padR}" y1="${y(v)}" y2="${y(v)}"/><text class="axis-t" x="${padL - 6}" y="${y(v) + 4}" text-anchor="end">${fmt(v)}</text>`;
    }
    const maxI = daily.reduce((b, d, i) => (d.threats > daily[b].threats ? i : b), 0);
    daily.forEach((d, i) => {
      const cx = padL + band * i + band / 2, x = cx - bw / 2, h = Math.max(0, y(0) - y(d.threats)), r = Math.min(4, h);
      const path = h > 0 ? `M${x},${y(0)}V${y(0) - h + r}Q${x},${y(0) - h} ${x + r},${y(0) - h}H${x + bw - r}Q${x + bw},${y(0) - h} ${x + bw},${y(0) - h + r}V${y(0)}Z` : "";
      g += `<rect class="bar-hit" data-i="${i}" x="${padL + band * i}" y="${padT}" width="${band}" height="${ih + padB}"/>`;
      if (path) g += `<path class="bar" data-b="${i}" d="${path}"/>`;
      if ((i === maxI || i === daily.length - 1) && d.threats > 0) g += `<text class="val-t" x="${cx}" y="${y(d.threats) - 5}" text-anchor="middle">${fmt(d.threats)}</text>`;
      if (i % (W < 480 ? 3 : 2) === (daily.length - 1) % (W < 480 ? 3 : 2)) g += `<text class="axis-t" x="${cx}" y="${H - 8}" text-anchor="middle">${esc(dayLabel(d.day, true))}</text>`;
    });
    el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(t("chart_t"))}">${g}</svg><div class="tip" hidden></div>`;
    const tip = el.querySelector(".tip");
    const showTip = (i) => {
      const d = daily[i];
      el.querySelectorAll(".bar").forEach((b) => b.classList.toggle("hover", +b.dataset.b === i));
      tip.innerHTML = `<b>${esc(dayLabel(d.day))}</b>${esc(t("d_threats"))}: ${fmt(d.threats)}<br>${esc(t("d_checks"))}: ${fmt(d.checks)}<br>${esc(t("d_reports"))}: ${fmt(d.reports)}`;
      const svg = el.querySelector("svg"), sc = svg.getBoundingClientRect().width / W;
      tip.style.left = Math.min(Math.max((padL + band * i + band / 2) * sc, 70), svg.getBoundingClientRect().width - 70) + "px";
      tip.style.top = y(d.threats) * sc + "px";
      tip.hidden = false;
    };
    el.querySelectorAll(".bar-hit").forEach((r) => {
      r.addEventListener("mouseenter", () => showTip(+r.dataset.i));
      r.addEventListener("click", () => showTip(+r.dataset.i));
    });
    el.addEventListener("mouseleave", () => { tip.hidden = true; el.querySelectorAll(".bar").forEach((b) => b.classList.remove("hover")); });
    $("#chart-table").innerHTML = `<table><thead><tr><th>${esc(t("d_day"))}</th><th>${esc(t("d_checks"))}</th><th>${esc(t("d_threats"))}</th><th>${esc(t("d_reports"))}</th></tr></thead><tbody>${
      daily.map((d) => `<tr><td>${esc(dayLabel(d.day))}</td><td>${fmt(d.checks)}</td><td>${fmt(d.threats)}</td><td>${fmt(d.reports)}</td></tr>`).join("")}</tbody></table>`;
  }

  function render(d) {
    const T = d.totals;
    $("#demo").hidden = !d.includes_demo_data;
    const kpi = (k, v, sub) => `<div class="kpi"><div class="k">${esc(t(k))}</div><div class="v">${fmt(v)}</div><div class="d">${esc(sub)}</div></div>`;
    $("#kpis").innerHTML = kpi("k_checks", T.checks_7d, delta(T.checks_7d, T.checks_prev_7d)) + kpi("k_threats", T.threats_7d, delta(T.threats_7d, T.threats_prev_7d))
      + kpi("k_reports", T.reports_7d, delta(T.reports_7d, T.reports_prev_7d)) + kpi("k_listed", T.public_listed, T.pending_review ? t("pending", { n: T.pending_review }) : "");
    chart(d.daily);

    $("#rising-wrap").hidden = !d.rising.length;
    $("#rising").innerHTML = d.rising.map((c) => `<div class="card rise"><div class="nm">${esc(c.name[lang] || c.name.en)}</div>
      <div class="dim small">${esc(t("this_week", { n: fmt(c.count) }))} · ${esc(c.new ? t("new") : t("was", { n: fmt(c.prev) }))}${c.change != null ? ` <span class="chg up">${esc(t("up", { n: c.change }))}</span>` : ""}</div></div>`).join("");

    const tmax = Math.max(1, ...d.types.map((c) => c.count));
    const types = d.types.filter((c) => c.count > 0);
    $("#types").innerHTML = types.length ? types.map((c) => `<li><span class="nm">${esc(c.name[lang] || c.name.en)}</span>
      <span class="ct">${fmt(c.count)}${c.new ? `<span class="chg up">${esc(t("new"))}</span>` : c.change ? `<span class="chg ${c.change >= 25 ? "up" : ""}">${esc(c.change > 0 ? t("up", { n: c.change }) : t("down", { n: -c.change }))}</span>` : c.change === 0 ? `<span class="chg">=</span>` : ""}</span>
      <span class="track"><span class="fill" style="width:${(100 * c.count) / tmax}%"></span></span></li>`).join("")
      : `<li class="empty">${esc(t("no_types"))}</li>`;

    $("#rule").textContent = t("rule", { n: d.public_min });
    $("#top").innerHTML = ["upi", "phone", "domain"].map((k) => `<div class="card"><h3>${esc(t(k))}</h3>${
      d.top[k].length ? `<ul class="toplist">${d.top[k].map((e) => `<li><span><span class="mono">${esc(e.display)}</span>
        <small>${esc(t("last", { d: e.last_seen ? dayLabel(e.last_seen) : "—" }))}${e.confirmed ? " · ✓ " + esc(t("confirmed")) : ""}</small></span>
        <span class="n">${esc(t("reports", { n: fmt(e.reports) }))}${e.got_me ? `<small class="danger-txt">${esc(t("lost", { n: fmt(e.got_me) }))}</small>` : ""}</span></li>`).join("")}</ul>`
      : `<p class="empty">${esc(t("none_listed"))}</p>`}</div>`).join("");
    $("#updated").textContent = t("updated", { t: new Date(d.generated * 1000).toLocaleTimeString(lang === "en" ? "en-IN" : lang + "-IN", { hour: "2-digit", minute: "2-digit" }) });
  }

  async function load() {
    try {
      const res = await fetch("/api/trends");
      data = await res.json();
      if (!res.ok) throw new Error(data.error);
      $("#load-err").hidden = true;
      render(data);
    } catch (_) {
      $("#load-err").hidden = false;
      $("#load-err").textContent = t("err");
    }
  }

  $("#lookup").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = $("#lookup-res");
    const q = $("#q").value.trim();
    if (!q) return;
    try {
      const res = await fetch("/api/lookup?q=" + encodeURIComponent(q));
      const r = await res.json();
      out.hidden = false;
      if (!res.ok) { out.className = "lookup-res"; out.textContent = r.error; return; }
      const p = r.reports === 1 ? t("person") : t("people");
      const g = (r.got_me ? t("r_lost", { n: r.got_me }) : "") + (r.disputes ? t("r_disputed", { d: r.disputes }) : "");
      if (r.reports >= 2) { out.className = "lookup-res bad"; out.textContent = t("r_bad", { n: r.reports, p, g }); }
      else if (r.reports === 1) { out.className = "lookup-res"; out.textContent = t("r_some", { n: 1, p }); }
      else { out.className = "lookup-res ok"; out.textContent = t("r_ok"); }
    } catch (_) { out.hidden = false; out.textContent = t("err"); }
  });

  let rt;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => data && chart(data.daily), 150); });
  setLang(lang);
  load();
  setInterval(() => { if (!document.hidden) load(); }, 60000);
})();
