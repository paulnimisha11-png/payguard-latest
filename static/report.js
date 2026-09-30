/* PayGuard complaint flow: report form -> ready-to-file complaint page. Depends on window.APKX. */
(() => {
  const A = window.APKX;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = A.esc;

  // ---------------------------------------------------------- strings
  const R = {
    en: {
      c_title: "Your complaint is ready", c_ref: "Reference",
      urgent: "Money was taken recently. Call 1930 right now — reports in the first hours can freeze the money before it's withdrawn.",
      a_call: "Call 1930", a_call_s: "National cyber-fraud helpline", a_portal: "Open cybercrime.gov.in", a_portal_s: "File the written complaint",
      a_pdf: "Evidence PDF", a_pdf_s: "Attach it to the complaint", a_share: "Send to family", a_share_s: "WhatsApp summary",
      script_t: "What to say on the 1930 call", steps_t: "Your next steps", fields_t: "Fields for cybercrime.gov.in",
      fields_p: "On the portal choose ‘Report Cyber Crime’, then copy each value below into the matching box.",
      cat_note: "Category", copy: "Copy", copied: "Copied", copy_all: "Copy everything",
      suspects_t: "Scammer details we found", chakshu: "Report the sender's number on Chakshu (Sanchar Saathi)",
      keep: "Save this private link to come back to your complaint:", del: "Delete my complaint data",
      deleted: "Your complaint data was deleted.", del_confirm: "Tap again to delete permanently",
      expires: "Kept until {d}", q_lost_shot: "Did you hand over goods or money because of this screenshot?",
      yes_lost_shot: "Yes, I handed over goods / money", amount_shot: "Value of what you handed over (₹)", loading: "Preparing your complaint…", phone_note: "If the call button doesn't open your dialer, dial 1930 yourself.",
    },
    hi: {
      back: "स्कैन के नतीजे पर वापस", form_t: "इस ठगी की शिकायत करें",
      form_p: "जो पता हो वह भरें। आपके स्कैन से हम शिकायत, 1930 कॉल की स्क्रिप्ट और सबूत PDF खुद भर देते हैं, ताकि आपको सब कुछ शुरू से न बताना पड़े।",
      q_lost: "क्या आपके पैसे गए?", yes_lost: "हाँ, पैसे कटे हैं", no_lost: "नहीं, मैं सिर्फ़ कोशिश की शिकायत कर रहा/रही हूँ",
      amount: "कितने पैसे गए (₹)", method: "किससे भुगतान हुआ", m_card: "डेबिट / क्रेडिट कार्ड", m_nb: "नेट बैंकिंग", m_wallet: "वॉलेट", m_other: "अन्य",
      txn: "ट्रांज़ैक्शन ID / UTR", txn_h: "बैंक SMS या UPI ऐप में 12 अंकों का नंबर। कई हों तो कॉमा से अलग करें।", bank: "आपका बैंक",
      paid_to: "पैसे किसे गए (UPI ID या खाता)", when: "यह कब हुआ?", channel: "यह आप तक कैसे पहुँचा?", c_call: "फ़ोन कॉल", c_social: "सोशल मीडिया",
      c_web: "वेबसाइट / विज्ञापन", c_print: "छपा हुआ QR", c_other: "अन्य", sender: "भेजने वाले का नंबर या नाम", installed: "क्या आपने ऐप इंस्टॉल किया?",
      yes: "हाँ", no: "नहीं", desc: "कुछ और? (उन्होंने क्या कहा, आपने क्या किया)", you_t: "PDF में अपना नाम और संपर्क जोड़ें (वैकल्पिक)",
      name: "आपका नाम", mobile: "आपका मोबाइल", email: "आपका ईमेल",
      privacy: "आपके जवाब 30 दिन तक सिर्फ़ आपको मिलने वाले निजी लिंक के पीछे रखे जाते हैं, फिर मिटा दिए जाते हैं। आप कभी भी इन्हें मिटा सकते हैं।",
      submit: "मेरी शिकायत तैयार करें",
      c_title: "आपकी शिकायत तैयार है", c_ref: "संदर्भ संख्या",
      urgent: "पैसे हाल ही में गए हैं। अभी 1930 पर कॉल करें — पहले कुछ घंटों में शिकायत से पैसे निकाले जाने से पहले रोके जा सकते हैं।",
      a_call: "1930 पर कॉल करें", a_call_s: "राष्ट्रीय साइबर धोखाधड़ी हेल्पलाइन", a_portal: "cybercrime.gov.in खोलें", a_portal_s: "लिखित शिकायत दर्ज करें",
      a_pdf: "सबूत PDF", a_pdf_s: "शिकायत के साथ लगाएँ", a_share: "परिवार को भेजें", a_share_s: "WhatsApp सारांश",
      script_t: "1930 कॉल पर क्या बोलें", steps_t: "आगे क्या करें", fields_t: "cybercrime.gov.in के लिए जानकारी",
      fields_p: "पोर्टल पर ‘Report Cyber Crime’ चुनें, फिर नीचे की हर जानकारी सही बॉक्स में कॉपी करें।",
      copy: "कॉपी", copied: "कॉपी हुआ", copy_all: "सब कॉपी करें", suspects_t: "ठग की जानकारी जो हमें मिली",
      chakshu: "भेजने वाले का नंबर चक्षु (संचार साथी) पर रिपोर्ट करें", keep: "अपनी शिकायत पर वापस आने के लिए यह निजी लिंक सहेजें:",
      del: "मेरी शिकायत का डेटा मिटाएँ", deleted: "आपकी शिकायत का डेटा मिटा दिया गया।", del_confirm: "पक्का मिटाने के लिए फिर दबाएँ",
      expires: "{d} तक रखा जाएगा", q_lost_shot: "क्या इस स्क्रीनशॉट की वजह से आपने सामान या पैसे दे दिए?",
      yes_lost_shot: "हाँ, मैंने सामान / पैसे दे दिए", amount_shot: "जो दिया उसकी क़ीमत (₹)", loading: "आपकी शिकायत तैयार हो रही है…", phone_note: "अगर कॉल बटन से डायलर न खुले, तो खुद 1930 डायल करें।",
    },
    kn: {
      back: "ಸ್ಕ್ಯಾನ್ ಫಲಿತಾಂಶಕ್ಕೆ ಹಿಂತಿರುಗಿ", form_t: "ಈ ವಂಚನೆಯನ್ನು ವರದಿ ಮಾಡಿ",
      form_p: "ಗೊತ್ತಿರುವುದನ್ನು ತುಂಬಿ. ನಿಮ್ಮ ಸ್ಕ್ಯಾನ್‌ನಿಂದ ದೂರು, 1930 ಕರೆ ಸ್ಕ್ರಿಪ್ಟ್ ಮತ್ತು ಸಾಕ್ಷ್ಯ PDF ಅನ್ನು ನಾವೇ ತುಂಬುತ್ತೇವೆ, ಎಲ್ಲವನ್ನೂ ಮೊದಲಿನಿಂದ ಹೇಳಬೇಕಾಗಿಲ್ಲ.",
      q_lost: "ನೀವು ಹಣ ಕಳೆದುಕೊಂಡಿರಾ?", yes_lost: "ಹೌದು, ಹಣ ಹೋಗಿದೆ", no_lost: "ಇಲ್ಲ, ಪ್ರಯತ್ನವನ್ನು ವರದಿ ಮಾಡುತ್ತಿದ್ದೇನೆ",
      amount: "ಕಳೆದುಕೊಂಡ ಮೊತ್ತ (₹)", method: "ಯಾವುದರಿಂದ ಪಾವತಿ", m_card: "ಡೆಬಿಟ್ / ಕ್ರೆಡಿಟ್ ಕಾರ್ಡ್", m_nb: "ನೆಟ್ ಬ್ಯಾಂಕಿಂಗ್", m_wallet: "ವಾಲೆಟ್", m_other: "ಇತರೆ",
      txn: "ವಹಿವಾಟು ID / UTR", txn_h: "ಬ್ಯಾಂಕ್ SMS ಅಥವಾ UPI ಆ್ಯಪ್‌ನಲ್ಲಿರುವ 12 ಅಂಕಿಯ ಸಂಖ್ಯೆ. ಹಲವು ಇದ್ದರೆ ಅಲ್ಪವಿರಾಮದಿಂದ ಬೇರ್ಪಡಿಸಿ.", bank: "ನಿಮ್ಮ ಬ್ಯಾಂಕ್",
      paid_to: "ಹಣ ಯಾರಿಗೆ ಹೋಯಿತು (UPI ID ಅಥವಾ ಖಾತೆ)", when: "ಇದು ಯಾವಾಗ ನಡೆಯಿತು?", channel: "ಇದು ನಿಮಗೆ ಹೇಗೆ ಬಂತು?", c_call: "ಫೋನ್ ಕರೆ", c_social: "ಸಾಮಾಜಿಕ ಮಾಧ್ಯಮ",
      c_web: "ವೆಬ್‌ಸೈಟ್ / ಜಾಹೀರಾತು", c_print: "ಮುದ್ರಿತ QR", c_other: "ಇತರೆ", sender: "ಕಳುಹಿಸಿದವರ ನಂಬರ್ ಅಥವಾ ಹೆಸರು", installed: "ನೀವು ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿದಿರಾ?",
      yes: "ಹೌದು", no: "ಇಲ್ಲ", desc: "ಇನ್ನೇನಾದರೂ? (ಅವರು ಏನು ಹೇಳಿದರು, ನೀವು ಏನು ಮಾಡಿದಿರಿ)", you_t: "PDF ಗೆ ನಿಮ್ಮ ಹೆಸರು ಮತ್ತು ಸಂಪರ್ಕ ಸೇರಿಸಿ (ಐಚ್ಛಿಕ)",
      name: "ನಿಮ್ಮ ಹೆಸರು", mobile: "ನಿಮ್ಮ ಮೊಬೈಲ್", email: "ನಿಮ್ಮ ಇಮೇಲ್",
      privacy: "ನಿಮ್ಮ ಉತ್ತರಗಳನ್ನು ನಿಮಗೆ ಮಾತ್ರ ಸಿಗುವ ಖಾಸಗಿ ಲಿಂಕ್ ಹಿಂದೆ 30 ದಿನ ಇಡಲಾಗುತ್ತದೆ, ನಂತರ ಅಳಿಸಲಾಗುತ್ತದೆ. ಯಾವಾಗ ಬೇಕಾದರೂ ಅಳಿಸಬಹುದು.",
      submit: "ನನ್ನ ದೂರು ಸಿದ್ಧಪಡಿಸಿ",
      c_title: "ನಿಮ್ಮ ದೂರು ಸಿದ್ಧವಾಗಿದೆ", c_ref: "ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ",
      urgent: "ಹಣ ಇತ್ತೀಚೆಗೆ ಹೋಗಿದೆ. ಈಗಲೇ 1930 ಗೆ ಕರೆ ಮಾಡಿ — ಮೊದಲ ಕೆಲವು ಗಂಟೆಗಳಲ್ಲಿ ದೂರು ನೀಡಿದರೆ ಹಣ ತೆಗೆಯುವ ಮೊದಲೇ ತಡೆಹಿಡಿಯಬಹುದು.",
      a_call: "1930 ಗೆ ಕರೆ ಮಾಡಿ", a_call_s: "ರಾಷ್ಟ್ರೀಯ ಸೈಬರ್ ವಂಚನೆ ಸಹಾಯವಾಣಿ", a_portal: "cybercrime.gov.in ತೆರೆಯಿರಿ", a_portal_s: "ಲಿಖಿತ ದೂರು ದಾಖಲಿಸಿ",
      a_pdf: "ಸಾಕ್ಷ್ಯ PDF", a_pdf_s: "ದೂರಿಗೆ ಲಗತ್ತಿಸಿ", a_share: "ಕುಟುಂಬಕ್ಕೆ ಕಳುಹಿಸಿ", a_share_s: "WhatsApp ಸಾರಾಂಶ",
      script_t: "1930 ಕರೆಯಲ್ಲಿ ಏನು ಹೇಳಬೇಕು", steps_t: "ಮುಂದಿನ ಹಂತಗಳು", fields_t: "cybercrime.gov.in ಗಾಗಿ ವಿವರಗಳು",
      fields_p: "ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ‘Report Cyber Crime’ ಆಯ್ಕೆಮಾಡಿ, ನಂತರ ಕೆಳಗಿನ ಪ್ರತಿ ವಿವರವನ್ನು ಸರಿಯಾದ ಬಾಕ್ಸ್‌ಗೆ ಕಾಪಿ ಮಾಡಿ.",
      copy: "ಕಾಪಿ", copied: "ಕಾಪಿ ಆಯಿತು", copy_all: "ಎಲ್ಲವನ್ನೂ ಕಾಪಿ ಮಾಡಿ", suspects_t: "ನಮಗೆ ಸಿಕ್ಕ ವಂಚಕರ ವಿವರಗಳು",
      chakshu: "ಕಳುಹಿಸಿದವರ ನಂಬರ್ ಅನ್ನು ಚಕ್ಷು (ಸಂಚಾರ ಸಾಥಿ) ನಲ್ಲಿ ವರದಿ ಮಾಡಿ", keep: "ನಿಮ್ಮ ದೂರಿಗೆ ಮರಳಲು ಈ ಖಾಸಗಿ ಲಿಂಕ್ ಉಳಿಸಿಕೊಳ್ಳಿ:",
      del: "ನನ್ನ ದೂರಿನ ಡೇಟಾ ಅಳಿಸಿ", deleted: "ನಿಮ್ಮ ದೂರಿನ ಡೇಟಾ ಅಳಿಸಲಾಗಿದೆ.", del_confirm: "ಶಾಶ್ವತವಾಗಿ ಅಳಿಸಲು ಮತ್ತೆ ಒತ್ತಿ",
      expires: "{d} ವರೆಗೆ ಇಡಲಾಗುತ್ತದೆ", q_lost_shot: "ಈ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ನಂಬಿ ನೀವು ಸಾಮಾನು ಅಥವಾ ಹಣ ಕೊಟ್ಟಿರಾ?",
      yes_lost_shot: "ಹೌದು, ಸಾಮಾನು / ಹಣ ಕೊಟ್ಟೆ", amount_shot: "ಕೊಟ್ಟದ್ದರ ಮೌಲ್ಯ (₹)", loading: "ನಿಮ್ಮ ದೂರು ಸಿದ್ಧವಾಗುತ್ತಿದೆ…", phone_note: "ಕರೆ ಬಟನ್ ಡಯಲರ್ ತೆರೆಯದಿದ್ದರೆ, ನೀವೇ 1930 ಡಯಲ್ ಮಾಡಿ.",
    },
    ta: {
      back: "முடிவுகளுக்குத் திரும்பு", form_t: "இந்த மோசடியைப் புகாரளிக்கவும்",
      form_p: "தெரிந்த விவரங்களை நிரப்பவும். உங்கள் ஸ்கேனில் இருந்து புகார், 1930 அழைப்புக்கான உரை மற்றும் ஆதார PDF ஆகியவற்றை நாங்களே தயார் செய்கிறோம்.",
      q_lost: "பணம் ஏதேனும் இழந்தீர்களா?", yes_lost: "ஆம், பணம் இழக்கப்பட்டது", no_lost: "இல்லை, முயற்சியை மட்டுமே புகாரளிக்கிறேன்",
      amount: "இழந்த தொகை (₹)", method: "எதன் மூலம் செலுத்தினீர்கள்", m_card: "டெபிட் / கிரெடிட் கார்டு", m_nb: "நெட் பேங்கிங்", m_wallet: "வாலட்", m_other: "மற்றவை",
      txn: "பரிவர்த்தனை ID / UTR", txn_h: "வங்கி SMS அல்லது UPI ஆப்பில் உள்ள 12 இலக்க எண். பல இருந்தால் காற்புள்ளியால் பிரிக்கவும்.", bank: "உங்கள் வங்கி",
      paid_to: "பணம் யாருக்கு சென்றது (UPI ID அல்லது கணக்கு)", when: "இது எப்போது நிகழ்ந்தது?", channel: "இது உங்களை எவ்வாறு அடைந்தது?", c_call: "தொலைபேசி அழைப்பு", c_social: "சமூக ஊடகம்",
      c_web: "வலைத்தளம் / விளம்பரம்", c_print: "அச்சிடப்பட்ட QR", c_other: "மற்றவை", sender: "அனுப்பியவரின் எண் அல்லது பெயர்", installed: "ஆப்பை நிறுவினீர்களா?",
      yes: "ஆம்", no: "இல்லை", desc: "வேறு ஏதேனும் தகவல்? (அவர்கள் என்ன சொன்னார்கள், நீங்கள் என்ன செய்தீர்கள்)", you_t: "PDF இல் உங்கள் பெயர் & தொடர்பைச் சேர்க்கவும் (விருப்பத்தேர்வு)",
      name: "உங்கள் பெயர்", mobile: "உங்கள் மொபைல்", email: "உங்கள் மின்னஞ்சல்",
      privacy: "உங்கள் பதில்கள் உங்களுக்கு மட்டுமே கிடைக்கும் தனிப்பட்ட இணைப்பில் 30 நாட்களுக்கு வைக்கப்படும், பின்னர் நீக்கப்படும். எப்போது வேண்டுமானாலும் நீக்கலாம்.",
      submit: "என் புகாரைத் தயார் செய்க",
      c_title: "உங்கள் புகார் தயாராக உள்ளது", c_ref: "குறிப்பு எண்",
      urgent: "சமீபத்தில் பணம் எடுக்கப்பட்டது. உடனே 1930 ஐ அழைக்கவும் — முதல் சில மணிநேரங்களில் புகாரளித்தால் பணத்தை திரும்ப எடுக்கவிடாமல் முடக்கலாம்.",
      a_call: "1930 ஐ அழைக்கவும்", a_call_s: "தேசிய சைபர் மோசடி உதவி எண்", a_portal: "cybercrime.gov.in திறக்கவும்", a_portal_s: "எழுத்துப்பூர்வ புகார் பதிவு செய்க",
      a_pdf: "ஆதார PDF", a_pdf_s: "புகாருடன் இணைக்கவும்", a_share: "குடும்பத்திற்கு அனுப்பவும்", a_share_s: "WhatsApp சுருக்கம்",
      script_t: "1930 அழைப்பில் என்ன பேச வேண்டும்", steps_t: "அடுத்த கட்ட நடவடிக்கைகள்", fields_t: "cybercrime.gov.in க்கான விவரங்கள்",
      fields_p: "போர்ட்டலில் ‘Report Cyber Crime’ என்பதைத் தேர்ந்தெடுத்து, கீழே உள்ள ஒவ்வொரு மதிப்பையும் அதற்கான பெட்டியில் நகலெடுக்கவும்.",
      copy: "நகலெடு", copied: "நகலெடுக்கப்பட்டது", copy_all: "அனைத்தையும் நகலெடு", suspects_t: "நாங்கள் கண்டறிந்த மோசடி விவரங்கள்",
      chakshu: "அனுப்பியவரின் எண்ணை சக்ஷுவில் (சஞ்சார் சாதி) புகாரளிக்கவும்", keep: "புகாரைப் பார்க்க இந்த தனிப்பட்ட இணைப்பைச் சேமிக்கவும்:",
      del: "என் புகார் தரவை நீக்கவும்", deleted: "உங்கள் புகார் தரவு நீக்கப்பட்டது.", del_confirm: "நிரந்தரமாக நீக்க மீண்டும் தட்டவும்",
      expires: "{d} வரை வைக்கப்படும்", q_lost_shot: "இந்த ரசீதை நம்பி நீங்கள் பொருட்கள் அல்லது பணம் கொடுத்தீர்களா?",
      yes_lost_shot: "ஆம், பொருட்கள் / பணம் கொடுத்தேன்", amount_shot: "கொடுக்கப்பட்ட மதிப்பு (₹)", loading: "புகார் தயாராகிறது…", phone_note: "அழைப்பு பொத்தான் டயலரைத் திறக்கவில்லை என்றால், நீங்களே 1930 ஐ டயல் செய்யவும்.",
    },
    te: {
      back: "స్కాన్ ఫలితాలకు తిరిగి వెళ్లు", form_t: "ఈ మోసాన్ని నివేదించండి",
      form_p: "తెలిసిన వివరాలను పూరించండి. మీ స్కాన్ నుండి ఫిర్యాదు, 1930 కాల్ స్క్రిప్ట్ మరియు సాక్ష్యాల PDFను మేమే తయారుచేస్తాము.",
      q_lost: "మీ డబ్బు పోయిందా?", yes_lost: "అవును, డబ్బు పోయింది", no_lost: "లేదు, ప్రయత్నాన్ని మాత్రమే నివేదిస్తున్నాను",
      amount: "పోయిన మొత్తం (₹)", method: "దేని ద్వారా చెల్లించారు", m_card: "డెబిట్ / క్రెడిట్ కార్డ్", m_nb: "నెట్ బ్యాంకింగ్", m_wallet: "వాలెట్", m_other: "ఇతర",
      txn: "లావాదేవీ ID / UTR", txn_h: "బ్యాంక్ SMS లేదా UPI యాప్‌లో ఉండే 12 అంకెల సంఖ్య. ఒకటి కంటే ఎక్కువ ఉంటే కామాతో వేరు చేయండి.", bank: "మీ బ్యాంక్",
      paid_to: "డబ్బు ఎవరికి వెళ్లింది (UPI ID లేదా ఖాతా)", when: "ఇది ఎప్పుడు జరిగింది?", channel: "ఇది మీకు ఎలా వచ్చింది?", c_call: "ఫోన్ కాల్", c_social: "సోషల్ మీడియా",
      c_web: "వెబ్‌సైట్ / ప్రకటన", c_print: "ముద్రించిన QR", c_other: "ఇతర", sender: "పంపినవారి నంబర్ లేదా పేరు", installed: "మీరు యాప్ ఇన్‌స్టాల్ చేశారా?",
      yes: "అవును", no: "లేదు", desc: "ఇంకేమైనా ఉందా? (వారు ఏమి చెప్పారు, మీరు ఏమి చేశారు)", you_t: "PDFలో మీ పేరు మరియు సంప్రదింపు వివరాలు చేర్చండి (ఐచ్ఛికం)",
      name: "మీ పేరు", mobile: "మీ మొబైల్", email: "మీ ఇమెయిల్",
      privacy: "మీ సమాధానాలు మీకు మాత్రమే అందుబాటులో ఉండే ప్రైవేట్ లింక్‌లో 30 రోజులు ఉంచబడతాయి, తర్వాత తొలగించబడతాయి. ఎప్పుడైనా తొలగించవచ్చు.",
      submit: "నా ఫిర్యాదును సిద్ధం చేయండి",
      c_title: "మీ ఫిర్యాదు సిద్ధంగా ఉంది", c_ref: "రిఫరెన్స్ సంఖ్య",
      urgent: "ఇటీవలే డబ్బు తీసుకోబడింది. వెంటనే 1930కి కాల్ చేయండి — మొదటి కొన్ని గంటల్లో నివేదిస్తే విత్‌డ్రా కాకముందే డబ్బును నిలిపివేయవచ్చు.",
      a_call: "1930కి కాల్ చేయండి", a_call_s: "జాతీయ సైబర్ ఫ్రాడ్ హెల్ప్‌లైన్", a_portal: "cybercrime.gov.in తెరవండి", a_portal_s: "రాతపూర్వక ఫిర్యాదు నమోదు చేయండి",
      a_pdf: "సాక్ష్యం PDF", a_pdf_s: "ఫిర్యాదుకు జతచేయండి", a_share: "కుటుంబానికి పంపండి", a_share_s: "WhatsApp సారాంశం",
      script_t: "1930 కాల్‌లో ఏమి చెప్పాలి", steps_t: "తదుపరి చర్యలు", fields_t: "cybercrime.gov.in కోసం వివరాలు",
      fields_p: "పోర్టల్‌లో ‘Report Cyber Crime’ ఎంచుకుని, క్రింద ఉన్న ప్రతి విలువను సంబంధిత బాక్స్‌లో కాపీ చేయండి.",
      copy: "కాపీ", copied: "కాపీ అయింది", copy_all: "అన్నీ కాపీ చేయండి", suspects_t: "మేము గుర్తించిన మోసగాడి వివరాలు",
      chakshu: "పంపినవారి నంబర్‌ను చక్షు (సంచార్ సాథీ)లో నివేదించండి", keep: "ఫిర్యాదును చూడటానికి ఈ ప్రైవేట్ లింక్‌ను సేవ్ చేసుకోండి:",
      del: "నా ఫిర్యాదు డేటాను తొలగించండి", deleted: "మీ ఫిర్యాదు డేటా తొలగించబడింది.", del_confirm: "పూర్తిగా తొలగించడానికి మళ్లీ నొక్కండి",
      expires: "{d} వరకు ఉంచబడుతుంది", q_lost_shot: "ఈ స్క్రీన్‌షాట్ నమ్మి మీరు వస్తువులు లేదా డబ్బు ఇచ్చారా?",
      yes_lost_shot: "అవును, వస్తువులు / డబ్బు ఇచ్చాను", amount_shot: "ఇచ్చిన వస్తువుల విలువ (₹)", loading: "ఫిర్యాదు సిద్ధమవుతోంది…", phone_note: "కాల్ బటన్ డయలర్‌ను తెరవకపోతే, మీరే 1930 డయల్ చేయండి.",
    },
    mr: {
      back: "स्कॅन निकालांवर परत जा", form_t: "या फसवणुकीची तक्रार करा",
      form_p: "माहित असलेली माहिती भरा. तुमच्या स्कॅनवरून तक्रार, 1930 कॉलची स्क्रिप्ट आणि पुरावा PDF आम्ही स्वतः तयार करतो.",
      q_lost: "तुमचे पैसे गेले का?", yes_lost: "होय, पैसे कापले गेले", no_lost: "नाही, मी फक्त प्रयत्नाची तक्रार करत आहे",
      amount: "गेलेली रक्कम (₹)", method: "कशाद्वारे पेमेंट झाले", m_card: "डेबिट / क्रेडिट कार्ड", m_nb: "नेट बँकिंग", m_wallet: "वॉलेट", m_other: "इतर",
      txn: "व्यवहार ID / UTR", txn_h: "बँक SMS किंवा UPI ॲपमधील 12 अंकी क्रमांक. अनेक असल्यास स्वल्पविरामाने वेगळे करा.", bank: "तुमची बँक",
      paid_to: "पैसे कोणाला गेले (UPI ID किंवा खाते)", when: "हे कधी घडले?", channel: "हे तुमच्यापर्यंत कसे पोहोचले?", c_call: "फोन कॉल", c_social: "सोशल मीडिया",
      c_web: "वेबसाइट / जाहिरात", c_print: "छापील QR", c_other: "इतर", sender: "पाठवणाऱ्याचा नंबर किंवा नाव", installed: "तुम्ही ॲप इन्स्टॉल केले का?",
      yes: "होय", no: "नाही", desc: "अजून काही? (ते काय म्हणाले, तुम्ही काय केले)", you_t: "PDF मध्ये तुमचे नाव आणि संपर्क जोडा (पर्यायी)",
      name: "तुमचे नाव", mobile: "तुमचा मोबाईल", email: "तुमचा ईमेल",
      privacy: "तुमची उत्तरे केवळ तुम्हाला उपलब्ध असणाऱ्या खाजगी लिंकमध्ये 30 दिवस ठेवली जातात, नंतर हटवली जातात. तुम्ही कधीही हटवू शकता.",
      submit: "माझी तक्रार तयार करा",
      c_title: "तुमची तक्रार तयार आहे", c_ref: "संदर्भ क्रमांक",
      urgent: "पैसे नुकतेच गेले आहेत. लगेच 1930 वर कॉल करा — पहिल्या काही तासांत तक्रार केल्यास पैसे काढण्यापूर्वी रोखता येतात.",
      a_call: "1930 वर कॉल करा", a_call_s: "राष्ट्रीय सायबर फसवणूक हेल्पलाइन", a_portal: "cybercrime.gov.in उघडा", a_portal_s: "लेखी तक्रार नोंदवा",
      a_pdf: "पुरावा PDF", a_pdf_s: "तक्रारीसोबत जोडा", a_share: "कुटुंबाला पाठवा", a_share_s: "WhatsApp सारांश",
      script_t: "1930 कॉलवर काय बोलायचे", steps_t: "पुढील पावले", fields_t: "cybercrime.gov.in साठी माहिती",
      fields_p: "पोर्टलवर ‘Report Cyber Crime’ निवडा, नंतर खालील प्रत्येक माहिती संबंधित बॉक्समध्ये कॉपी करा.",
      copy: "कॉपी", copied: "कॉपी झाले", copy_all: "सर्व कॉपी करा", suspects_t: "आम्हाला मिळालेले फसवणूक करणाऱ्याचे तपशील",
      chakshu: "पाठवणाऱ्याचा नंबर चक्षू (संचार साथी) वर नोंदवा", keep: "तक्रारीवर परत येण्यासाठी ही खाजगी लिंक सेव्ह करा:",
      del: "माझा तक्रार डेटा हटवा", deleted: "तुमचा तक्रार डेटा हटवला गेला.", del_confirm: "कायमचे हटवण्यासाठी पुन्हा दाबा",
      expires: "{d} पर्यंत ठेवले जाईल", q_lost_shot: "या स्क्रीनशॉटमुळे तुम्ही सामान किंवा पैसे दिले का?",
      yes_lost_shot: "होय, मी सामान / पैसे दिले", amount_shot: "दिलेल्या वस्तूंची किंमत (₹)", loading: "तुमची तक्रार तयार होत आहे…", phone_note: "कॉल बटणाने डायलर उघडले नाही, तर स्वतः 1930 डायल करा.",
    },
    bn: {
      back: "স্ক্যান ফলাফলে ফিরে যান", form_t: "এই প্রতারণার অভিযোগ জানান",
      form_p: "জানা থাকা তথ্যগুলি পূরণ করুন। আপনার স্ক্যান থেকে অভিযোগ, 1930 কল স্ক্রিপ্ট এবং প্রমাণ PDF আমরা নিজেই প্রস্তুত করব।",
      q_lost: "আপনার কি টাকা গেছে?", yes_lost: "হ্যাঁ, টাকা কেটেছে", no_lost: "না, আমি কেবল চেষ্টার রিপোর্ট করছি",
      amount: "কত টাকা গেছে (₹)", method: "কীসের মাধ্যমে পেমেন্ট হয়েছে", m_card: "ডেবিট / ক্রেডিট কার্ড", m_nb: "নেট ব্যাংকিং", m_wallet: "ওয়ালেট", m_other: "অন্যান্য",
      txn: "ট্রানজ্যাকশন ID / UTR", txn_h: "ব্যাঙ্ক SMS বা UPI অ্যাপের 12 সংখ্যার কোড। একাধিক থাকলে কমা দিয়ে আলাদা করুন।", bank: "আপনার ব্যাঙ্ক",
      paid_to: "টাকা কাকে গেছে (UPI ID বা অ্যাকাউন্ট)", when: "এটি কখন ঘটেছে?", channel: "এটি আপনার কাছে কীভাবে এসেছে?", c_call: "ফোন কল", c_social: "সোশ্যাল মিডিয়া",
      c_web: "ওয়েবসাইট / বিজ্ঞাপন", c_print: "ছাপা QR", c_other: "অন্যান্য", sender: "প্রেরকের নম্বর বা নাম", installed: "আপনি কি অ্যাপ ইনস্টল করেছিলেন?",
      yes: "হ্যাঁ", no: "না", desc: "অন্য কিছু? (তারা কী বলেছিল, আপনি কী করেছিলেন)", you_t: "PDF-এ আপনার নাম এবং যোগাযোগের তথ্য যোগ করুন (ঐচ্ছিক)",
      name: "আপনার নাম", mobile: "আপনার মোবাইল", email: "আপনার ইমেল",
      privacy: "আপনার উত্তরগুলি 30 দিনের জন্য কেবল আপনার ব্যক্তিগত লিঙ্কে সংরক্ষিত থাকে, তারপর মুছে ফেলা হয়। আপনি যেকোনো সময় মুছতে পারেন।",
      submit: "আমার অভিযোগ প্রস্তুত করুন",
      c_title: "আপনার অভিযোগ প্রস্তুত", c_ref: "রেফারেন্স নম্বর",
      urgent: "টাকা সম্প্রতি চলে গেছে। এখনই 1930 নম্বরে কল করুন — প্রথম কয়েক ঘণ্টার মধ্যে রিপোর্ট করলে টাকা তুলে নেওয়ার আগেই ফ্রিজ করা সম্ভব।",
      a_call: "1930 নম্বরে কল করুন", a_call_s: "জাতীয় সাইবার জালিয়াতি হেল্পলাইন", a_portal: "cybercrime.gov.in খুলুন", a_portal_s: "লিখিত অভিযোগ জমা দিন",
      a_pdf: "প্রমাণ PDF", a_pdf_s: "অভিযোগের সাথে সংযুক্ত করুন", a_share: "পরিবারকে পাঠান", a_share_s: "WhatsApp সারাংশ",
      script_t: "1930 কলে কী বলতে হবে", steps_t: "পরবর্তী পদক্ষেপ", fields_t: "cybercrime.gov.in-এর জন্য প্রয়োজনীয় তথ্য",
      fields_p: "পোর্টালে ‘Report Cyber Crime’ বেছে নিন, তারপর নিচের মানগুলি সংশ্লিষ্ট বাক্সে কপি করুন।",
      copy: "কপি", copied: "কপি হয়েছে", copy_all: "সব কপি করুন", suspects_t: "চিহ্নিত প্রতারকের তথ্য",
      chakshu: "প্রেরকের নম্বর চক্ষু (সঞ্চার সাথী) পোর্টালে রিপোর্ট করুন", keep: "অভিযোগে ফিরে আসার জন্য এই ব্যক্তিগত লিঙ্কটি সংরক্ষণ করুন:",
      del: "আমার অভিযোগের ডেটা মুছে দিন", deleted: "আপনার অভিযোগের তথ্য মুছে দেওয়া হয়েছে।", del_confirm: "স্থায়ীভাবে মুছতে আবার চাপুন",
      expires: "{d} পর্যন্ত সংরক্ষিত", q_lost_shot: "এই স্ক্রিনশটের কারণে আপনি কি জিনিসপত্র বা টাকা দিয়েছেন?",
      yes_lost_shot: "হ্যাঁ, আমি জিনিসপত্র / টাকা দিয়েছি", amount_shot: "প্রদত্ত জিনিসের মূল্য (₹)", loading: "আপনার অভিযোগ প্রস্তুত হচ্ছে…", phone_note: "কল বোতামে ডায়লার না খুললে, নিজে 1930 ডায়াল করুন।",
    },
  };
  $$("[data-r]").forEach((el) => (R.en[el.dataset.r] ??= el.innerHTML));
  const L = () => A.lang();
  const t = (k, v = {}) => (R[L()][k] ?? R.en[k] ?? k).replace(/\{(\w+)\}/g, (_, x) => v[x]);
  function applyStrings() { $$("[data-r]").forEach((el) => (el.innerHTML = t(el.dataset.r))); }

  let complaint = null, token = null, scanForReport = null;

  // ---------------------------------------------------------- open form
  function localNow() {
    const d = new Date(); d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
    return d.toISOString().slice(0, 16);
  }
  function openForm() {
    const r = A.current(); if (!r) return;
    scanForReport = r;
    applyStrings();
    const isQR = r.kind === "qr", isShot = r.kind === "shot", isMsg = r.kind === "msg";
    $('[data-r="q_lost"]').textContent = isShot ? t("q_lost_shot") : t("q_lost");
    $('[data-r="yes_lost"]').textContent = isShot ? t("yes_lost_shot") : t("yes_lost");
    $('[data-r="amount"]').textContent = isShot ? t("amount_shot") : t("amount");
    const what = isMsg ? `${esc(r.details.category_name ? r.details.category_name[L()] || r.details.category_name.en : A.t("msg_res"))} <span class="mono">${esc(r.payload.slice(0, 80))}</span>` : isShot ? `${esc(A.t("shot_label"))} <span class="mono">${esc(r.details.utr || r.file.name)}</span>` : isQR ? (r.details.type === "upi" ? `${r.details.payee_name || ""} <span class="mono">${esc(r.details.payee_vpa || "")}</span>`
                                                  : `<span class="mono">${esc((r.details.host || r.payload).slice(0, 80))}</span>`)
                      : `${esc(r.app.name || r.file.name)} <span class="mono">${esc(r.app.package)}</span>`;
    $("#rsum").innerHTML = `<span class="pill">${esc(r.verdict.score)}/100</span><div>${isShot || isMsg ? "" : isQR ? "QR · " : "APK · "}${what}</div>`;
    $("#installed-q").hidden = isQR || isShot || isMsg;
    if (isMsg && (r.details.upi_ids || []).length && !$("#f-paidto").value) $("#f-paidto").value = r.details.upi_ids[0];
    $("#f-paidto").closest(".f").hidden = isShot;
    $("#f-txn").closest(".f").hidden = isShot;
    $("#f-method").closest(".f").hidden = isShot;
    $("#f-bank").closest(".f").hidden = isShot;
    $("#f-when").value = $("#f-when").value || localNow();
    $("#f-when").max = localNow();
    if (isQR && r.details.type === "upi" && !$("#f-paidto").value) $("#f-paidto").value = r.details.payee_vpa || "";
    if (isQR && r.details.type === "upi" && r.details.amount && !$("#f-amount").value) $("#f-amount").value = r.details.amount;
    $("#rerr").hidden = true;
    A.show("report");
  }
  $$('input[name="lost"]').forEach((i) => i.addEventListener("change", () => ($("#money-fields").hidden = !$("#lost-yes").checked)));

  // ---------------------------------------------------------- submit
  $("#rform").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = scanForReport; if (!r) return;
    const lost = $("#lost-yes").checked;
    const val = (id) => $(id).value.trim() || null;
    const when = $("#f-when").value ? new Date($("#f-when").value).toISOString() : null;
    const isShot = r.kind === "shot";
    const body = {
      source: r.kind === "qr" ? "qr" : r.kind === "msg" ? "message" : isShot ? "screenshot" : "apk",
      sha256: r.kind === "qr" || r.kind === "msg" ? null : r.file.sha256,
      payload: r.kind === "qr" || r.kind === "msg" ? r.payload : null,
      lang: L(), lost_money: lost,
      amount: lost && $("#f-amount").value ? Number($("#f-amount").value) : null,
      transaction_ids: lost && !isShot ? ($("#f-txn").value || "").split(/[,\n]/).map((x) => x.trim()).filter(Boolean) : [],
      payment_method: lost && !isShot ? $("#f-method").value : null,
      victim_bank: lost && !isShot ? val("#f-bank") : null,
      paid_to: isShot ? null : val("#f-paidto"),
      incident_time: when, channel: $("#f-channel").value, sender_contact: val("#f-sender"),
      app_installed: r.kind ? null :  // only APK reports have no "kind"
                     document.querySelector('input[name="inst"]:checked')?.value === "yes",
      description: val("#f-desc"), victim_name: val("#f-name"), victim_mobile: val("#f-mobile"), victim_email: val("#f-email"),
    };
    $$("#rform [aria-invalid]").forEach((x) => x.removeAttribute("aria-invalid"));
    const btn = $("#rsubmit"); btn.disabled = true; btn.textContent = t("loading");
    try {
      const res = await fetch("/api/complaints", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) {
        $("#rerr").textContent = data.error || "Could not create the complaint.";
        $("#rerr").hidden = false;
        const map = { amount: "#f-amount", transaction_ids: "#f-txn", paid_to: "#f-paidto", sender_contact: "#f-sender",
                      victim_mobile: "#f-mobile", victim_email: "#f-email", incident_time: "#f-when" };
        (data.fields || []).forEach((f) => { const el = $(map[f.split(".")[0]]); if (el) el.setAttribute("aria-invalid", "true"); });
        return;
      }
      token = data.token; complaint = data;
      try { localStorage.setItem("pg_c_" + data.ref, token); } catch (_) {}
      history.pushState({}, "", `/c/${data.ref}#t=${token}`);
      renderComplaint(); A.show("complaint");
    } catch (_) {
      $("#rerr").textContent = "Network error — is the server running?"; $("#rerr").hidden = false;
    } finally {
      btn.disabled = false; btn.textContent = t("submit");
    }
  });

  // ---------------------------------------------------------- complaint page
  function renderComplaint() {
    const c = complaint, lang = L();
    const pdfUrl = `/api/complaints/${c.ref}/pdf?token=${encodeURIComponent(token)}`;
    const link = `${location.origin}/c/${c.ref}#t=${token}`;
    const exp = c.expires_at ? new Date(c.expires_at * 1000).toLocaleDateString(lang === "en" ? "en-IN" : lang + "-IN", { day: "numeric", month: "short", year: "numeric" }) : "";
    const sus = c.suspects.filter((s) => !["qr_payload", "cert", "apk_sha256"].includes(s.kind));
    $("#complaint").innerHTML = `
      <button class="back" type="button" data-act="back-home">← ${esc(A.t("again"))}</button>
      <div class="card">
        <div class="cref"><h2>✓ ${esc(t("c_title"))}</h2><div>${esc(t("c_ref"))}: <span class="mono">${esc(c.ref)}</span></div></div>
        ${c.urgent ? `<div class="urgent">⏱ ${esc(t("urgent"))}</div>` : ""}
        <div class="cacts">
          <a class="cact ${c.incident.lost_money ? "primary" : ""}" href="tel:1930"><span class="ic">📞</span>${esc(t("a_call"))}<small>${esc(t("a_call_s"))}</small></a>
          <a class="cact" href="${c.links.portal}" target="_blank" rel="noopener"><span class="ic">🌐</span>${esc(t("a_portal"))}<small>${esc(t("a_portal_s"))}</small></a>
          <a class="cact" href="${pdfUrl}" download="PayGuard-${esc(c.ref)}.pdf"><span class="ic">📄</span>${esc(t("a_pdf"))}<small>${esc(t("a_pdf_s"))}</small></a>
          <button class="cact" type="button" data-act="c-share"><span class="ic">💬</span>${esc(t("a_share"))}<small>${esc(t("a_share_s"))}</small></button>
        </div>
        <p class="dim small" style="margin-top:8px">${esc(t("phone_note"))}</p>
      </div>

      <div class="card csec">
        <h3>${esc(t("script_t"))}</h3>
        <ol class="script">${((c.call_script && (c.call_script[lang] || c.call_script.en)) || []).map((l) => `<li>${esc(l)}</li>`).join("")}</ol>
      </div>

      <div class="card csec">
        <h3>${esc(t("steps_t"))}</h3>
        <ul class="steps2">${c.checklist.map((s, i) => `<li class="${s.urgent ? "urg" : ""}"><label><input type="checkbox" data-step="${i}"><span>${esc(s[lang] || s.en || "")}${s.id === "chakshu" ? ` · <a href="${c.links.chakshu}" target="_blank" rel="noopener">Chakshu</a>` : s.id === "portal" ? ` · <a href="${c.links.portal}" target="_blank" rel="noopener">cybercrime.gov.in</a>` : ""}</span></label></li>`).join("")}</ul>
      </div>

      ${sus.length ? `<div class="card csec"><h3>${esc(t("suspects_t"))}</h3><div class="pf">${sus.map((s) => row(s.label, s.value)).join("")}</div></div>` : ""}

      <div class="card csec">
        <div class="cref"><h3>${esc(t("fields_t"))}</h3><button class="copy" type="button" data-copy-all>${esc(t("copy_all"))}</button></div>
        <p class="dim small" style="margin:6px 0 8px">${esc(t("fields_p"))}</p>
        <div class="pf">${c.portal_fields.map((f) => row(f.label, f.value, f.key === "description")).join("")}</div>
      </div>

      <div class="cfoot">
        <div class="linkbox"><span class="dim">${esc(t("keep"))}</span></div>
        <div class="linkbox"><input id="c-link" readonly value="${esc(link)}" aria-label="Private complaint link"><button class="copy" type="button" data-copy="${esc(link)}">${esc(t("copy"))}</button></div>
      </div>
      <div class="cfoot"><span class="dim">${esc(t("expires", { d: exp }))}</span><button class="danger-link" type="button" data-act="c-delete">${esc(t("del"))}</button></div>`;
    // restore checklist ticks
    try {
      const saved = JSON.parse(localStorage.getItem("pg_steps_" + c.ref) || "[]");
      saved.forEach((i) => { const b = $(`#complaint input[data-step="${i}"]`); if (b) b.checked = true; });
    } catch (_) {}
  }
  function row(k, v, long) {
    return `<div class="pfrow ${long ? "long" : ""}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div><button class="copy" type="button" data-copy="${esc(v)}">${esc(t("copy"))}</button></div>`;
  }

  async function copyText(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (_) {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (_) {} ta.remove();
    }
    if (btn) { const old = btn.textContent; btn.textContent = t("copied"); btn.classList.add("done"); setTimeout(() => { btn.textContent = old; btn.classList.remove("done"); }, 1400); }
  }

  let delArmed = false;
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act], [data-copy], [data-copy-all]");
    if (!b) return;
    if (b.dataset.copy !== undefined) return copyText(b.dataset.copy, b);
    if (b.dataset.copyAll !== undefined) return copyText(complaint.portal_fields.map((f) => `${f.label}: ${f.value}`).join("\n\n"), b);
    const act = b.dataset.act;
    if (act === "report") openForm();
    if (act === "back-result") A.show("result");
    if (act === "back-home") { history.pushState({}, "", "/app"); A.show("home"); }
    if (act === "c-share") {
      const c = complaint, lang = L();
      const h = (c.scan && c.scan.headline && (c.scan.headline[lang] || c.scan.headline.en)) || "";
      const msg = [`PayGuard ${c.ref}`, h, ...c.suspects.filter((s) => ["upi", "domain", "phone"].includes(s.kind)).map((s) => `${s.label}: ${s.value}`),
                   "", c.checklist.filter((s) => s.urgent).map((s) => "• " + (s[lang] || s.en || "")).join("\n"), "1930 · cybercrime.gov.in"].filter((x) => x !== undefined).join("\n");
      window.open("https://wa.me/?text=" + encodeURIComponent(msg), "_blank", "noopener");
    }
    if (act === "c-delete") {
      if (!delArmed) { delArmed = true; b.textContent = t("del_confirm"); setTimeout(() => { delArmed = false; b.textContent = t("del"); }, 4000); return; }
      const res = await fetch(`/api/complaints/${complaint.ref}?token=${encodeURIComponent(token)}`, { method: "DELETE" });
      if (res.ok) {
        try { localStorage.removeItem("pg_c_" + complaint.ref); localStorage.removeItem("pg_steps_" + complaint.ref); } catch (_) {}
        complaint = null; history.pushState({}, "", "/app"); A.show("home"); A.toast(t("deleted"));
      }
    }
  });
  document.addEventListener("change", (e) => {
    const cb = e.target.closest("#complaint input[data-step]");
    if (!cb || !complaint) return;
    const ticked = $$("#complaint input[data-step]").filter((x) => x.checked).map((x) => +x.dataset.step);
    try { localStorage.setItem("pg_steps_" + complaint.ref, JSON.stringify(ticked)); } catch (_) {}
  });
  // re-render in the new language
  $$(".lang button").forEach((b) => b.addEventListener("click", () => { applyStrings(); if (complaint && !$("#complaint").hidden) renderComplaint(); }));

  // ---------------------------------------------------------- route /c/<ref>#t=<token>
  async function route() {
    const m = location.pathname.match(/^\/c\/(PG-\d{6}-[A-Z2-9]{6})$/);
    if (!m) return;
    let tok = (location.hash.match(/t=([\w-]+)/) || [])[1];
    if (!tok) { try { tok = localStorage.getItem("pg_c_" + m[1]); } catch (_) {} }
    if (!tok) return A.fail("This complaint link is missing its private key. Open the full link you saved.");
    try {
      const res = await fetch(`/api/complaints/${m[1]}?token=${encodeURIComponent(tok)}`);
      const data = await res.json();
      if (!res.ok) return A.fail(data.error);
      complaint = data; token = tok; renderComplaint(); A.show("complaint");
    } catch (_) { A.fail("Could not load the complaint."); }
  }
  window.addEventListener("popstate", route);
  applyStrings();
  route();
})();
