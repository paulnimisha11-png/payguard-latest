"""Scam message checker (SMS / WhatsApp / email text).

analyze_message(text) -> report dict (kind "msg")

What it looks at
  1. What the message is about: known Indian scam scripts (electricity cut-off, KYC/account block, parcel/customs,
     refund/prize, part-time job, instant loan, investment, "digital arrest", SIM block, "hi mum new number",
     "sent by mistake", e-challan, FASTag).
  2. What it wants you to do: share an OTP/PIN, install a remote-access app or APK, call a personal mobile number,
     pay a "small fee", open a link, join a video call, keep it secret.
  3. Pressure: deadlines ("tonight", "within 2 hours") and threats ("will be blocked", "arrested").
  4. Everything it points to — links, UPI IDs, phone numbers — through the same link checks as the QR scanner, and
     the community report counts (added at response time by complaints.community.apply_reports).

A scam script needs a topic AND an action: "Your electricity bill is due" is fine; "Your power will be cut tonight,
call 98xxxxxxxx" is the scam. Genuine OTP messages ("123456 is your OTP. Do not share it") must stay "low".
English, Hindi (Devanagari + Hinglish) and Kannada keywords are covered.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

from ..analyzer.rules import SEVERITY_ORDER, T, Finding
from ..qr.analyzer import AUTHORITY_WORDS, BRAND_DOMAINS, KNOWN_PSP_HANDLES, analyze_payload

MAX_LEN = 5000


def _rx(*terms: str) -> re.Pattern:
    """ASCII terms get word boundaries; Devanagari/Kannada terms don't (combining marks break \\b)."""
    parts = []
    for t in terms:
        parts.append(rf"(?<![a-z0-9]){t}(?![a-z0-9])" if t.isascii() else t)
    return re.compile("|".join(parts), re.I)


# ------------------------------------------------------------------ scam topics
# id: (name, advice, strong patterns (one is enough), weak patterns (two needed))
CATEGORIES: dict[str, tuple[dict, dict, re.Pattern, re.Pattern]] = {
    "electricity": (
        T("Electricity cut-off scam", "बिजली कटने वाली ठगी", "ವಿದ್ಯುತ್ ಕಡಿತದ ವಂಚನೆ"),
        T("Electricity boards never ask you to call a mobile number or pay through a link in an SMS. Check your bill in the board's official app or website.",
          "बिजली विभाग कभी SMS के ज़रिए मोबाइल नंबर पर कॉल करने या लिंक से पेमेंट करने को नहीं कहता। बिल विभाग के आधिकारिक ऐप या वेबसाइट पर देखें।",
          "ವಿದ್ಯುತ್ ಮಂಡಳಿ ಎಂದಿಗೂ SMS ಮೂಲಕ ಮೊಬೈಲ್ ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡಲು ಅಥವಾ ಲಿಂಕ್‌ನಲ್ಲಿ ಪಾವತಿಸಲು ಹೇಳುವುದಿಲ್ಲ. ಮಂಡಳಿಯ ಅಧಿಕೃತ ಆ್ಯಪ್/ವೆಬ್‌ಸೈಟ್‌ನಲ್ಲಿ ಬಿಲ್ ನೋಡಿ."),
        _rx(r"electricity (bill|connection|power|officer|department|dept)", r"power (supply )?(will be )?(cut|disconnected)", r"(light|current|power) (connection )?will be (cut|disconnected)",
            "bijli", "बिजली", "ವಿದ್ಯುತ್", "ಕರೆಂಟ್", r"(bescom|mseb|msedcl|mpeb|mpez|mppkvvcl|tneb|tangedco|bses|uppcl|pspcl|kseb|hescom|gescom|cesc|dhbvn|jvvnl|wbsedcl|tsspdcl|apspdcl)"),
        _rx("electricity", "meter", r"bill (is |was )?not (updated|paid)", r"previous month('s)? bill", "disconnect(ed|ion)?", "connection"),
    ),
    "kyc_bank": (
        T("KYC / bank-account block scam", "KYC / खाता बंद होने वाली ठगी", "KYC / ಖಾತೆ ಬ್ಲಾಕ್ ವಂಚನೆ"),
        T("Banks never block accounts over SMS or ask you to update KYC through a link or a phone call. Visit your branch or use the bank's own app.",
          "बैंक कभी SMS से खाता बंद नहीं करते, न ही लिंक या कॉल से KYC अपडेट करवाते हैं। शाखा जाएँ या बैंक का अपना ऐप इस्तेमाल करें।",
          "ಬ್ಯಾಂಕ್‌ಗಳು SMS ಮೂಲಕ ಖಾತೆ ಬ್ಲಾಕ್ ಮಾಡುವುದಿಲ್ಲ, ಲಿಂಕ್ ಅಥವಾ ಕರೆ ಮೂಲಕ KYC ಅಪ್‌ಡೇಟ್ ಕೇಳುವುದಿಲ್ಲ. ಶಾಖೆಗೆ ಹೋಗಿ ಅಥವಾ ಬ್ಯಾಂಕ್‌ನ ಸ್ವಂತ ಆ್ಯಪ್ ಬಳಸಿ."),
        _rx("e?-?kyc", r"pan( card)? (is )?(not )?(updated?|linked?)", r"update (your )?pan", r"(account|a/c|khata|wallet|card) (will be |has been |is |may be |shall be )?(blocked|suspended|freezed|frozen|deactivated|closed|on hold|restricted)",
            "yono", "केवाईसी", r"खाता (बंद|ब्लॉक)", r"khata (band|block)", "ಕೆವೈಸಿ", r"ಖಾತೆ (ಬ್ಲಾಕ್|ಸ್ಥಗಿತ)"),
        _rx(r"net ?banking", r"debit card", r"credit card", "aadhaa?r", "bank", r"update", "verify", "suspend(ed)?"),
    ),
    "parcel": (
        T("Parcel / courier / customs scam", "पार्सल / कूरियर / कस्टम ठगी", "ಪಾರ್ಸೆಲ್ / ಕೊರಿಯರ್ / ಕಸ್ಟಮ್ಸ್ ವಂಚನೆ"),
        T("Courier companies don't ask for fees or address updates through random links. Track only on the courier's official website or app with your order number.",
          "कूरियर कंपनियाँ अनजान लिंक से फ़ीस या पता अपडेट नहीं माँगतीं। सिर्फ़ आधिकारिक वेबसाइट या ऐप पर ऑर्डर नंबर से ट्रैक करें।",
          "ಕೊರಿಯರ್ ಕಂಪನಿಗಳು ಅಪರಿಚಿತ ಲಿಂಕ್ ಮೂಲಕ ಶುಲ್ಕ ಅಥವಾ ವಿಳಾಸ ಅಪ್‌ಡೇಟ್ ಕೇಳುವುದಿಲ್ಲ. ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್/ಆ್ಯಪ್‌ನಲ್ಲಿ ಮಾತ್ರ ಟ್ರ್ಯಾಕ್ ಮಾಡಿ."),
        _rx("parcel", "courier", "customs", "shipment", "consignment", r"(india ?post|fedex|dhl|blue ?dart|delhivery|dtdc|ekart|xpressbees)", "पार्सल", "कूरियर", "ಪಾರ್ಸೆಲ್", "ಕೊರಿಯರ್"),
        _rx("delivery", "address", "warehouse", r"re-?deliver(y)?", "package", r"held|on hold"),
    ),
    "refund_prize": (
        T("Refund / prize / reward scam", "रिफ़ंड / इनाम / रिवॉर्ड ठगी", "ರೀಫಂಡ್ / ಬಹುಮಾನ / ರಿವಾರ್ಡ್ ವಂಚನೆ"),
        T("Real refunds and rewards arrive on their own. Nobody needs your OTP, PIN, a fee or an app install to send you money.",
          "असली रिफ़ंड और इनाम अपने-आप आते हैं। पैसे भेजने के लिए किसी को आपका OTP, PIN, फ़ीस या ऐप इंस्टॉल नहीं चाहिए।",
          "ನಿಜವಾದ ರೀಫಂಡ್ ಮತ್ತು ಬಹುಮಾನಗಳು ತಾವಾಗಿಯೇ ಬರುತ್ತವೆ. ಹಣ ಕಳುಹಿಸಲು ಯಾರಿಗೂ ನಿಮ್ಮ OTP, PIN, ಶುಲ್ಕ ಅಥವಾ ಆ್ಯಪ್ ಬೇಕಿಲ್ಲ."),
        _rx(r"you (have )?(won|win)", "lottery", r"lucky (draw|winner|customer)", "kbc", r"refund (of|amount)", r"(income ?tax|itr|tax) refund", r"reward points?", "cash ?back", "prize", "redeem",
            "जीत", "इनाम", "लॉटरी", "रिफंड", "ಬಹುಮಾನ", "ಲಾಟರಿ", "ರೀಫಂಡ್"),
        _rx("congratulations?", "refund", "claim", "gift", "bonus", "credited", "reward", "winner"),
    ),
    "job_task": (
        T("Part-time job / task scam", "पार्ट-टाइम जॉब / टास्क ठगी", "ಪಾರ್ಟ್-ಟೈಮ್ ಕೆಲಸ / ಟಾಸ್ಕ್ ವಂಚನೆ"),
        T("'Earn daily by liking videos or rating hotels' ends with you depositing money that you never get back. Real jobs never ask you to pay.",
          "'वीडियो लाइक करके रोज़ कमाएँ' वाले जॉब में आख़िर में आपसे पैसे जमा करवाए जाते हैं जो वापस नहीं आते। असली नौकरी कभी पैसे नहीं माँगती।",
          "'ವೀಡಿಯೊ ಲೈಕ್ ಮಾಡಿ ದಿನಾ ಗಳಿಸಿ' ಕೆಲಸಗಳು ಕೊನೆಗೆ ನಿಮ್ಮಿಂದ ಹಣ ಕಟ್ಟಿಸಿ ವಾಪಸ್ ಕೊಡುವುದಿಲ್ಲ. ನಿಜವಾದ ಕೆಲಸ ಎಂದಿಗೂ ಹಣ ಕೇಳುವುದಿಲ್ಲ."),
        _rx(r"part[- ]?time", r"work from home", r"daily (income|salary|earning|payment)", r"earn (rs\.?|₹|inr)? ?[\d,]+", r"(like|subscribe|rate|review)s? (youtube|videos?|hotels?|products?|restaurants?)",
            r"(prepaid|merchant|online) tasks?", "घर बैठे", r"रोज़? कमा", r"ghar baithe"),
        _rx("job", "hiring", "salary", "telegram", "earn(ing)?", "tasks?", "income", "per day", "commission"),
    ),
    "loan": (
        T("Instant loan scam", "इंस्टेंट लोन ठगी", "ತ್ವರಿತ ಸಾಲದ ವಂಚನೆ"),
        T("Loans 'pre-approved' over SMS with an upfront fee or an app link are traps. Borrow only from RBI-registered lenders through their official apps.",
          "SMS पर 'प्री-अप्रूव्ड' लोन जिनमें पहले फ़ीस या ऐप लिंक हो, जाल हैं। सिर्फ़ RBI-पंजीकृत लेंडर के आधिकारिक ऐप से लोन लें।",
          "SMS ನಲ್ಲಿ ಮುಂಗಡ ಶುಲ್ಕ ಅಥವಾ ಆ್ಯಪ್ ಲಿಂಕ್ ಇರುವ 'ಪೂರ್ವ-ಅನುಮೋದಿತ' ಸಾಲಗಳು ಬಲೆ. RBI-ನೋಂದಾಯಿತ ಸಂಸ್ಥೆಗಳ ಅಧಿಕೃತ ಆ್ಯಪ್‌ನಿಂದ ಮಾತ್ರ ಸಾಲ ಪಡೆಯಿರಿ."),
        _rx(r"(pre-?approved|instant|guaranteed) loan", r"loan (is |has been )?(approved|sanctioned|disbursed)", r"(without|no) cibil", r"loan .{0,20}(in|within) \d+ (minutes?|mins?)"),
        _rx("loan", "emi", r"processing fee", "cibil", "disburse"),
    ),
    "investment": (
        T("Investment / trading scam", "निवेश / ट्रेडिंग ठगी", "ಹೂಡಿಕೆ / ಟ್ರೇಡಿಂಗ್ ವಂಚನೆ"),
        T("Guaranteed or very high returns from a WhatsApp/Telegram group are always a scam. Invest only through SEBI-registered brokers.",
          "WhatsApp/Telegram ग्रुप से 'गारंटीड' या बहुत ज़्यादा मुनाफ़ा हमेशा ठगी है। सिर्फ़ SEBI-पंजीकृत ब्रोकर से निवेश करें।",
          "WhatsApp/Telegram ಗುಂಪಿನ 'ಖಚಿತ' ಅಥವಾ ಅತಿ ಹೆಚ್ಚು ಲಾಭ ಯಾವಾಗಲೂ ವಂಚನೆ. SEBI-ನೋಂದಾಯಿತ ಬ್ರೋಕರ್ ಮೂಲಕ ಮಾತ್ರ ಹೂಡಿಕೆ ಮಾಡಿ."),
        _rx(r"(double|triple) (your )?money", r"guaranteed (returns?|profits?|income)", r"(stock|trading|ipo|crypto|share market) (tips|group|signals)", r"vip (group|member)", r"\d+ ?% (daily|weekly|monthly|per day) (returns?|profits?)"),
        _rx("invest(ment)?", "profits?", "trading", "crypto", "returns"),
    ),
    "digital_arrest": (
        T("'Digital arrest' / fake police scam", "'डिजिटल अरेस्ट' / नकली पुलिस ठगी", "'ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್' / ನಕಲಿ ಪೊಲೀಸ್ ವಂಚನೆ"),
        T("There is no such thing as a 'digital arrest'. Police, CBI or customs never question you on a video call or ask for money to close a case. Hang up and call 1930.",
          "'डिजिटल अरेस्ट' जैसी कोई चीज़ नहीं होती। पुलिस, CBI या कस्टम कभी वीडियो कॉल पर पूछताछ नहीं करते, न केस बंद करने के पैसे माँगते हैं। फ़ोन काटें और 1930 पर कॉल करें।",
          "'ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್' ಎಂಬುದೇ ಇಲ್ಲ. ಪೊಲೀಸ್, CBI ಅಥವಾ ಕಸ್ಟಮ್ಸ್ ವೀಡಿಯೊ ಕರೆಯಲ್ಲಿ ವಿಚಾರಣೆ ಮಾಡುವುದಿಲ್ಲ, ಪ್ರಕರಣ ಮುಗಿಸಲು ಹಣ ಕೇಳುವುದಿಲ್ಲ. ಕರೆ ಕಡಿತಗೊಳಿಸಿ 1930 ಗೆ ಕರೆ ಮಾಡಿ."),
        _rx(r"digital arrest", r"(cbi|ncb|narcotics|enforcement directorate|crime branch|cyber ?(crime|cell)|mumbai police|delhi police)", r"money laundering",
            r"(drugs|narcotics|illegal items|fake passports?).{0,40}(found|seized)", r"arrest warrant", r"(you )?will be arrested", "गिरफ्तार", "ಬಂಧನ"),
        _rx("police", "officer", "inspector", "fir", "court", "case", "skype", r"video call", "arrest(ed)?", "customs"),
    ),
    "telecom": (
        T("SIM / mobile number block scam", "SIM / मोबाइल नंबर बंद होने वाली ठगी", "SIM / ಮೊಬೈಲ್ ನಂಬರ್ ಬ್ಲಾಕ್ ವಂಚನೆ"),
        T("TRAI and telecom companies don't disconnect numbers with a warning call or SMS asking you to press a key or call back.",
          "TRAI और टेलीकॉम कंपनियाँ कोई बटन दबाने या वापस कॉल करने वाले मैसेज से नंबर बंद नहीं करतीं।",
          "TRAI ಮತ್ತು ಟೆಲಿಕಾಂ ಕಂಪನಿಗಳು ಬಟನ್ ಒತ್ತಲು ಅಥವಾ ಮರಳಿ ಕರೆ ಮಾಡಲು ಹೇಳುವ ಸಂದೇಶದಿಂದ ನಂಬರ್ ಕಡಿತಗೊಳಿಸುವುದಿಲ್ಲ."),
        _rx("trai", r"sim( card)? (will be |is being )?(blocked|deactivated|disconnected|suspended)", r"(mobile |phone )?number will be (blocked|disconnected|deactivated|suspended)", r"press \d"),
        _rx("sim", r"mobile number", "disconnect(ed)?", "illegal"),
    ),
    "family_emergency": (
        T("'New number, send money' family scam", "'नया नंबर, पैसे भेजो' वाली ठगी", "'ಹೊಸ ನಂಬರ್, ಹಣ ಕಳುಹಿಸಿ' ವಂಚನೆ"),
        T("Call the person on their OLD number before sending anything. Scammers pose as children, parents or friends with a 'new number'.",
          "कुछ भी भेजने से पहले उस व्यक्ति को उसके पुराने नंबर पर कॉल करें। ठग 'नए नंबर' से बच्चे, माता-पिता या दोस्त बनकर मैसेज करते हैं।",
          "ಏನನ್ನಾದರೂ ಕಳುಹಿಸುವ ಮೊದಲು ಆ ವ್ಯಕ್ತಿಗೆ ಅವರ ಹಳೆಯ ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡಿ. ವಂಚಕರು 'ಹೊಸ ನಂಬರ್'ನಿಂದ ಮಕ್ಕಳು, ಪೋಷಕರು ಅಥವಾ ಸ್ನೇಹಿತರಂತೆ ನಟಿಸುತ್ತಾರೆ."),
        _rx(r"(this is )?my new (number|no\.?|whatsapp)", r"(hi|hello|hey) (mum|mom|mummy|maa|papa|dad|daddy|beta)\b.{0,60}(new|urgent|money|send|phone)", r"(phone|mobile) (is |got )?(broken|lost|stolen|damaged)", "मेरा नया नंबर", "नया नंबर", "ನನ್ನ ಹೊಸ ನಂಬರ್"),
        _rx("accident", "hospital", "urgent(ly)?", "emergency", r"send (me )?money", r"pay (you )?back"),
    ),
    "wrong_transfer": (
        T("'Sent by mistake, please return' scam", "'गलती से भेजे, वापस करो' वाली ठगी", "'ತಪ್ಪಾಗಿ ಕಳುಹಿಸಿದೆ, ವಾಪಸ್ ಕೊಡಿ' ವಂಚನೆ"),
        T("Check your own bank app: usually no money arrived, or it came from a stolen account. Never 'return' money to a number or UPI ID from a message — ask them to raise it with their bank.",
          "अपना बैंक ऐप देखें: अक्सर कोई पैसा आया ही नहीं होता, या चोरी के खाते से आया होता है। मैसेज वाले नंबर/UPI ID पर कभी पैसे 'वापस' न भेजें — उन्हें अपने बैंक से शिकायत करने को कहें।",
          "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ನೋಡಿ: ಹೆಚ್ಚಾಗಿ ಹಣವೇ ಬಂದಿರುವುದಿಲ್ಲ, ಅಥವಾ ಕದ್ದ ಖಾತೆಯಿಂದ ಬಂದಿರುತ್ತದೆ. ಸಂದೇಶದ ನಂಬರ್/UPI ID ಗೆ ಹಣ 'ವಾಪಸ್' ಕಳುಹಿಸಬೇಡಿ — ಅವರ ಬ್ಯಾಂಕ್‌ಗೆ ದೂರು ನೀಡಲು ಹೇಳಿ."),
        _rx(r"(sent|transferred|paid|credited).{0,40}(by mistake|wrongly|accidentally|mistakenly)", r"(by mistake|wrongly|accidentally).{0,30}(sent|transferred|paid|credited)", r"galti se", "गलती से", "ತಪ್ಪಾಗಿ"),
        _rx("return", r"send (it )?back", r"refund (it|me)"),
    ),
    "challan": (
        T("Fake traffic e-challan scam", "नकली ट्रैफ़िक ई-चालान ठगी", "ನಕಲಿ ಟ್ರಾಫಿಕ್ ಇ-ಚಲನ್ ವಂಚನೆ"),
        T("Check challans only on echallan.parivahan.gov.in or your state police app — never through a link in a message or an APK.",
          "चालान सिर्फ़ echallan.parivahan.gov.in या राज्य पुलिस के ऐप पर देखें — मैसेज के लिंक या APK से कभी नहीं।",
          "ಚಲನ್ ಅನ್ನು echallan.parivahan.gov.in ಅಥವಾ ರಾಜ್ಯ ಪೊಲೀಸ್ ಆ್ಯಪ್‌ನಲ್ಲಿ ಮಾತ್ರ ನೋಡಿ — ಸಂದೇಶದ ಲಿಂಕ್ ಅಥವಾ APK ಮೂಲಕ ಎಂದಿಗೂ ಬೇಡ."),
        _rx(r"e-?challan", r"traffic (challan|fine|violation)", r"(vahan|parivahan)"),
        _rx("fine", "vehicle", "penalty", "challan"),
    ),
    "fastag": (
        T("FASTag KYC scam", "FASTag KYC ठगी", "FASTag KYC ವಂಚನೆ"),
        T("Update FASTag KYC only in your issuing bank's app or the NHAI 'My FASTag' app.",
          "FASTag KYC सिर्फ़ अपने बैंक के ऐप या NHAI के 'My FASTag' ऐप में अपडेट करें।",
          "FASTag KYC ಅನ್ನು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ಅಥವಾ NHAI 'My FASTag' ಆ್ಯಪ್‌ನಲ್ಲಿ ಮಾತ್ರ ಅಪ್‌ಡೇಟ್ ಮಾಡಿ."),
        _rx("fastag"),
        _rx("toll", "blacklist(ed)?"),
    ),
}

# ------------------------------------------------------------------ pressure and actions
URGENCY = _rx("today", "tonight", "immediately", "urgent(ly)?", r"right now", "asap", r"within \d+ ?(hours?|hrs?|minutes?|mins?|days?)",
              r"in (the )?next \d+ ?(hours?|hrs?|minutes?|mins?)", r"last (date|day|chance|warning|reminder|notice)", r"expir(es|ing|ed|y) (today|soon|tonight)",
              r"at \d{1,2}[:.]\d\d ?(pm|am)", r"before \d{1,2}([:.]\d\d)? ?(pm|am)", "turant", r"aaj raat", "jaldi",
              "तुरंत", "आज रात", "अभी", "जल्दी", "ತಕ್ಷಣ", "ಇಂದು ರಾತ್ರಿ", "ಈಗಲೇ", "ತುರ್ತು")
THREAT = _rx(r"(will|would|shall|may|going to) be (permanently )?(blocked|suspended|disconnected|deactivated|cancell?ed|closed|terminated|blacklisted|cut|frozen|seized|arrested|penali[sz]ed)",
             r"legal action", r"(arrest|arrested)", r"fir (will|has|is)", r"(court|police) case", "non-?bailable", r"heavy (penalty|fine)",
             r"kaat (di|diya) (jayegi|jayega|jaayegi)", r"band (ho|kar di|kar diya) (jayega|jayegi|jaayega)", r"block ho jayega",
             r"काट दी जाएगी", r"काट दिया जाएगा", r"बंद कर दिया जाएगा", r"बंद हो जाएगा", r"ब्लॉक (हो|कर)", "ಕಡಿತ", r"ಬ್ಲಾಕ್ ಆಗ", "ಸ್ಥಗಿತ")
CRED_WORD = _rx("otp", r"one[- ]time password", "m?pin", r"upi pin", r"atm pin", "cvv", "password", "passcode", r"verification code", r"security code",
                r"card (number|no\.?|details)", r"(net ?banking|login) (id|details|password)", r"debit card details", "ओटीपी", "पिन", "ಒಟಿಪಿ", "ಪಿನ್")
ASK_VERB = _rx("share", "send", "tell", "give", "provide", "forward", "reply", r"read (it )?out", "batao", "bataye?n?", "bhejo", "bheje?n?", r"de do",
               "बताएं", "बताइए", "बताओ", "भेजें", "भेजिए", "भेजो", "साझा करें", "ಹೇಳಿ", "ಕಳುಹಿಸಿ", "ಹಂಚಿ")
ENTER_VERB = _rx("enter", "type", "submit", "fill", "update")
NEGATION = _rx(r"do not", "don'?t", "never", r"not to", r"no one", "nobody", r"na kare?n?", r"mat (batana|bhejna|karna)",
               r"न करें", r"ना करें", "मत", r"कभी नहीं", r"किसी (को|के साथ)", "ಮಾಡಬೇಡಿ", "ಹಂಚಬೇಡಿ", "ಹೇಳಬೇಡಿ", "ಯಾರಿಗೂ")
RECEIVE_PIN = re.compile(r"(enter|put|type|use)\b.{0,25}\b(upi )?pin\b.{0,50}\b(receive|get|credit(ed)?|refund|claim)|"
                         r"(scan|approve|accept)\b.{0,30}\b(qr|request|collect)\b.{0,50}\b(receive|get|credit(ed)?|refund|claim)|"
                         r"\b(receive|get|claim)\b.{0,40}\b(refund|cashback|prize|reward|money|amount|rs\.?|₹)\b.{0,40}\b(enter|put|type|approve)\b.{0,20}\b(upi )?pin\b", re.I)
REMOTE = _rx("anydesk", r"any desk", "teamviewer", r"team viewer", r"quick ?support", "rustdesk", "airdroid", "ultraviewer", "alpemix",
             r"screen ?shar(e|ing)", r"remote (access|support|control) app")
APK_WORDS = re.compile(r"\.apk\b|\b(download|install)\b.{0,30}\bapk\b|\bapk\b.{0,20}\b(download|install)", re.I)
PAY_FEE = _rx(r"(processing|registration|delivery|re-?delivery|customs|clearance|verification|activation|service|file|gst|security|release|insurance) (fee|charges?|deposit|duty|amount)",
              r"pay (a |the )?(small|nominal|token|minimal) (amount|fee|charge)",
              r"pay (rs\.?|₹|inr) ?\d+(\.\d+)? (only )?(to|for|and) (update|re-?activate|re-?deliver|release|claim|activate|verify|confirm|unlock|continue)",
              r"(refundable|security) deposit")
SECRECY = _rx(r"(don'?t|do not|never) (tell|inform|share this with|discuss (this )?with) (anyone|your family|family|anybody|the bank|your bank)",
              r"keep (this|it) (confidential|secret|private)", r"(do not|don'?t) (disconnect|cut|end) the call", r"stay on (the )?(video )?call",
              r"kisi ko (mat|na) (batana|batayein)", r"किसी को (मत|न) बताएं", r"किसी को मत बताना")
VIDEO_CALL = _rx(r"(join|come on|connect on|attend) (a |the )?(skype|video|whatsapp video|zoom|google meet) (call|meeting)", r"skype (call|id)", r"video (call|verification) (with|for) (police|officer|cbi|customs)")
MONEY_LURE = re.compile(r"\byou (have )?(won|received|been selected|are eligible|are selected)\b|"
                        r"\b(amount|refund|cashback|prize|reward|bonus)\b.{0,20}(rs\.?|₹|inr) ?[\d,]+.{0,30}\b(credited|pending|approved|waiting|ready|will be credited)\b", re.I)
ASKS_MONEY = re.compile(r"\b(send|transfer|pay|gpay|phonepe|return|need)\b.{0,15}\b(me )?(rs\.?|₹|inr)? ?\d[\d,]{2,}|\b(send|return|transfer)\b.{0,20}\b(money|amount|it back|paise)\b|"
                        r"पैसे (भेज|लौटा)|paise (bhej|wapas)", re.I)
CALL_ACTION = _rx("call", "contact", "whatsapp", r"message (on|at|us)", "sms", "dial", "ring", r"reach (us|out)", r"call karein", r"sampark karein", "cal+",
                  "कॉल करें", "कॉल करो", "संपर्क करें", "ಕರೆ ಮಾಡಿ", "ಸಂಪರ್ಕಿಸಿ")
AUTHORITY = _rx(*[re.escape(w) for w in AUTHORITY_WORDS], *[re.escape(b) for b in BRAND_DOMAINS], "bank", "officer", "department", "dept", "govt", "customer care")
OTP_CODE = re.compile(r"(?<!\d)\d{4,8}(?!\d)")

# ------------------------------------------------------------------ entities
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'()]+|(?<![@\w.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                    r"(?:com|in|net|org|co|io|me|ly|gd|gl|xyz|top|online|site|info|app|link|live|shop|store|club|vip|win|cc|pw|tk|ml|ga|cf|gq|"
                    r"buzz|click|icu|sbs|rest|cyou|fun|work|support|help|bank|biz|us|uk|to|so|be|at|page|website|tech|cloud|digital|pro|asia|sbi)"
                    r"(?![a-z0-9\-])(?:/[^\s<>\"'()]*)?", re.I)
UPI_RE = re.compile(r"(?<![\w.\-])([a-z0-9][a-z0-9.\-_]{1,63})@([a-z][a-z0-9]{1,31})(?![\w.@])", re.I)
PHONE_RE = re.compile(r"(?<![\d\w])(?:\+?91[\s\-]?|0)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)")
TOLLFREE_RE = re.compile(r"(?<!\d)(1800|1860|1900)[\s\-]?\d{3}[\s\-]?\d{3,4}(?!\d)")
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr)\s?([\d,]+(?:\.\d{1,2})?)", re.I)


def _norm(text: str) -> str:
    t = unicodedata.normalize("NFKC", text or "")
    t = t.replace("​", "").replace("‌", "").replace("‍", "").replace("﻿", "")
    t = re.sub(r"[ \t]+", " ", t)
    return t.strip()[:MAX_LEN]


def template_hash(text: str) -> str | None:
    """Same scam script sent to thousands of people = same hash (links, numbers and names differ per victim)."""
    t = URL_RE.sub(" link ", text.lower())
    t = UPI_RE.sub(" upi ", t)
    t = re.sub(r"\d+", " ", t)
    t = re.sub(r"[^\w\s]", " ", t)
    words = t.split()
    if len(words) < 8:
        return None
    return hashlib.sha256(" ".join(words).encode()).hexdigest()


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?।])\s+|\n+", text) if s.strip()]


def _spans(pattern: re.Pattern, text: str, kind: str, out: list) -> list[str]:
    hits = []
    for m in pattern.finditer(text):
        if m.end() > m.start():
            out.append({"start": m.start(), "end": m.end(), "kind": kind})
            hits.append(m.group(0))
    return hits


def _extract(text: str) -> dict:
    urls, upis, phones, tollfree = [], [], [], []
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;:!?)]}'\"")
        if u.lower() not in [x.lower() for x in urls]:
            urls.append(u)
    for m in UPI_RE.finditer(text):
        handle = m.group(2).lower()
        full = m.group(0)
        if handle in KNOWN_PSP_HANDLES or not re.search(r"\.", text[m.end():m.end() + 1]):
            if handle in ("gmail", "yahoo", "outlook", "hotmail", "rediffmail", "icloud") or "." in full.split("@")[1]:
                continue
            if full.lower() not in upis:
                upis.append(full.lower())
    for u in urls:  # wa.me/91XXXXXXXXXX
        m = re.search(r"wa\.me/(?:\+?91)?([6-9]\d{9})", u, re.I)
        if m and m.group(1) not in phones:
            phones.append(m.group(1))
    for m in PHONE_RE.finditer(text):
        # skip digits that are part of a UPI ID, a URL or an account/reference number
        around = text[max(0, m.start() - 1):m.end() + 1]
        if "@" in around:
            continue
        if any(m.start() >= text.find(u) and m.end() <= text.find(u) + len(u) for u in urls if text.find(u) >= 0):
            continue
        d = re.sub(r"\D", "", m.group(1))
        if d not in phones:
            phones.append(d)
    for m in TOLLFREE_RE.finditer(text):
        tollfree.append(re.sub(r"\D", "", m.group(0)))
    amounts = []
    for m in AMOUNT_RE.finditer(text):
        try:
            amounts.append(float(m.group(1).replace(",", "")))
        except ValueError:
            pass
    return {"urls": urls[:10], "upi_ids": upis[:10], "phones": phones[:10], "tollfree": tollfree[:5], "amounts": amounts[:10]}


SPECIFIC = {"fastag", "challan", "digital_arrest", "family_emergency", "wrong_transfer", "loan", "investment"}  # win ties over generic KYC/refund words


def _category(text: str) -> tuple[str | None, list[str]]:
    best, best_score, best_hits = None, 0, []
    for cid, (_name, _adv, strong, weak) in CATEGORIES.items():
        s = [m.group(0) for m in strong.finditer(text)]
        w = {m.group(0).lower() for m in weak.finditer(text)}
        score = 3 * len(s) + len(w) + (3 if s and cid in SPECIFIC else 0)
        if (s or len(w) >= 2) and score > best_score:
            best, best_score, best_hits = cid, score, s + sorted(w)
    return best, best_hits


MSG_VERDICTS = [
    (70, "danger", T("Scam message — don't click, call or reply", "ठगी का मैसेज — क्लिक, कॉल या जवाब न करें", "ವಂಚನೆ ಸಂದೇಶ — ಕ್ಲಿಕ್, ಕರೆ ಅಥವಾ ಉತ್ತರ ಬೇಡ"),
     T("Don't open the link, call the number, install anything or share any code. Block the sender and delete it. If you already paid or shared an OTP, call 1930 right now and report at cybercrime.gov.in.",
       "लिंक न खोलें, नंबर पर कॉल न करें, कुछ इंस्टॉल न करें, कोई कोड न बताएँ। भेजने वाले को ब्लॉक करके मैसेज डिलीट करें। अगर पैसे भेज दिए या OTP बता दिया, तो अभी 1930 पर कॉल करें और cybercrime.gov.in पर शिकायत करें।",
       "ಲಿಂಕ್ ತೆರೆಯಬೇಡಿ, ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡಬೇಡಿ, ಏನನ್ನೂ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ, ಯಾವುದೇ ಕೋಡ್ ಹೇಳಬೇಡಿ. ಕಳುಹಿಸಿದವರನ್ನು ಬ್ಲಾಕ್ ಮಾಡಿ ಡಿಲೀಟ್ ಮಾಡಿ. ಈಗಾಗಲೇ ಹಣ ಕಳುಹಿಸಿದ್ದರೆ ಅಥವಾ OTP ಹೇಳಿದ್ದರೆ ತಕ್ಷಣ 1930 ಗೆ ಕರೆ ಮಾಡಿ, cybercrime.gov.in ನಲ್ಲಿ ದೂರು ನೀಡಿ.")),
    (35, "suspicious", T("Very likely a scam", "संभवतः ठगी", "ಬಹುಶಃ ವಂಚನೆ"),
     T("Several warning signs. Don't act on this message. If it claims to be from a company or a relative, contact them yourself using a number you already know.",
       "कई खतरे के संकेत हैं। इस मैसेज के कहने पर कुछ न करें। अगर यह किसी कंपनी या रिश्तेदार का होने का दावा करता है, तो पहले से पता नंबर पर ख़ुद संपर्क करें।",
       "ಹಲವು ಎಚ್ಚರಿಕೆಯ ಲಕ್ಷಣಗಳಿವೆ. ಈ ಸಂದೇಶದಂತೆ ಏನೂ ಮಾಡಬೇಡಿ. ಇದು ಕಂಪನಿ ಅಥವಾ ಸಂಬಂಧಿಕರದು ಎಂದರೆ, ನಿಮಗೆ ಮೊದಲೇ ಗೊತ್ತಿರುವ ನಂಬರ್‌ನಲ್ಲಿ ನೀವೇ ಸಂಪರ್ಕಿಸಿ.")),
    (15, "caution", T("Be careful with this message", "इस मैसेज से सावधान रहें", "ಈ ಸಂದೇಶದ ಬಗ್ಗೆ ಎಚ್ಚರವಿರಲಿ"),
     T("Something here deserves a second look. Don't share OTPs or PINs, and open links only if you were expecting this message.",
       "यहाँ कुछ बातों पर ध्यान देना ज़रूरी है। OTP या PIN न बताएँ, और लिंक तभी खोलें जब आप इस मैसेज की उम्मीद कर रहे थे।",
       "ಇಲ್ಲಿ ಕೆಲವು ವಿಷಯಗಳನ್ನು ಗಮನಿಸಬೇಕು. OTP ಅಥವಾ PIN ಹೇಳಬೇಡಿ, ಈ ಸಂದೇಶ ನಿರೀಕ್ಷಿಸಿದ್ದರೆ ಮಾತ್ರ ಲಿಂಕ್ ತೆರೆಯಿರಿ.")),
    (0, "low", T("No scam signs found", "ठगी के कोई संकेत नहीं मिले", "ವಂಚನೆಯ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ"),
     T("Still: banks, police and companies never ask for your OTP, PIN or CVV, and never ask you to install an app to 'help' you.",
       "फिर भी: बैंक, पुलिस या कंपनियाँ कभी आपका OTP, PIN या CVV नहीं माँगतीं, न ही 'मदद' के लिए कोई ऐप इंस्टॉल करवाती हैं।",
       "ಆದರೂ: ಬ್ಯಾಂಕ್, ಪೊಲೀಸ್ ಅಥವಾ ಕಂಪನಿಗಳು ಎಂದಿಗೂ ನಿಮ್ಮ OTP, PIN ಅಥವಾ CVV ಕೇಳುವುದಿಲ್ಲ, 'ಸಹಾಯ'ಕ್ಕಾಗಿ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿಸುವುದಿಲ್ಲ.")),
]

ACTION_LABELS = {
    "share_code": T("Share an OTP / PIN / password", "OTP / PIN / पासवर्ड बताएँ", "OTP / PIN / ಪಾಸ್‌ವರ್ಡ್ ಹೇಳಿ"),
    "enter_pin_to_receive": T("Enter your PIN to 'receive' money", "पैसे 'पाने' के लिए PIN डालें", "ಹಣ 'ಪಡೆಯಲು' PIN ಹಾಕಿ"),
    "install_remote_app": T("Install a screen-sharing app", "स्क्रीन-शेयरिंग ऐप इंस्टॉल करें", "ಸ್ಕ್ರೀನ್-ಶೇರಿಂಗ್ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ"),
    "install_apk": T("Install an app from a link", "लिंक से ऐप इंस्टॉल करें", "ಲಿಂಕ್‌ನಿಂದ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ"),
    "open_link": T("Open a link", "एक लिंक खोलें", "ಲಿಂಕ್ ತೆರೆಯಿರಿ"),
    "call_number": T("Call or WhatsApp a mobile number", "किसी मोबाइल नंबर पर कॉल/WhatsApp करें", "ಮೊಬೈಲ್ ನಂಬರ್‌ಗೆ ಕರೆ/WhatsApp ಮಾಡಿ"),
    "pay_fee": T("Pay a fee or deposit", "फ़ीस या डिपॉज़िट भरें", "ಶುಲ್ಕ ಅಥವಾ ಠೇವಣಿ ಕಟ್ಟಿ"),
    "send_money": T("Send or 'return' money", "पैसे भेजें या 'लौटाएँ'", "ಹಣ ಕಳುಹಿಸಿ ಅಥವಾ 'ವಾಪಸ್' ಮಾಡಿ"),
    "video_call": T("Join a video call", "वीडियो कॉल पर आएँ", "ವೀಡಿಯೊ ಕರೆಗೆ ಸೇರಿ"),
    "keep_secret": T("Keep it secret", "किसी को न बताएँ", "ಯಾರಿಗೂ ಹೇಳಬೇಡಿ"),
}


def _f(id_, sev, pts, title, detail, ev=None) -> Finding:
    return Finding(id_, sev, pts, title, detail, [e for e in (ev or []) if e])


def analyze_message(raw: str) -> dict:
    text = _norm(raw)
    if not text:
        raise ValueError("Paste the message you want to check.")
    if len(text) < 6:
        raise ValueError("That's too short to check. Paste the whole message.")
    low = text.lower()
    marks: list[dict] = []
    F: list[Finding] = []
    actions: list[str] = []
    ent = _extract(text)
    for u in ent["urls"]:
        i = text.find(u)
        if i >= 0:
            marks.append({"start": i, "end": i + len(u), "kind": "link"})
    for p in ent["upi_ids"]:
        i = low.find(p)
        if i >= 0:
            marks.append({"start": i, "end": i + len(p), "kind": "upi"})
    for m in PHONE_RE.finditer(text):
        if re.sub(r"\D", "", m.group(1)) in ent["phones"]:
            marks.append({"start": m.start(), "end": m.end(), "kind": "phone"})

    cat, cat_hits = _category(text)
    authority = bool(AUTHORITY.search(text)) or bool(cat)

    # ---- credentials: sentence by sentence, so "Do not share it with anyone" cancels the request
    cred_hits = []
    has_links = bool(ent["urls"])
    for s in _sentences(text):
        if not CRED_WORD.search(s):
            continue
        if NEGATION.search(s):
            continue
        delivered_code = bool(OTP_CODE.search(s)) and not re.search(r"\b(share|send|tell|forward|give)\b", s, re.I)
        asks = ASK_VERB.search(s) or (ENTER_VERB.search(s) and has_links)
        if asks and not delivered_code:
            cred_hits.append(s.strip()[:160])
            i = text.find(s.strip())
            if i >= 0:
                marks.append({"start": i, "end": i + len(s.strip()), "kind": "danger"})
    if cred_hits:
        actions.append("share_code")
        F.append(_f("ASKS_FOR_CODE", "critical", 50,
                    T("Asks you to share an OTP, PIN or password", "OTP, PIN या पासवर्ड माँगता है", "OTP, PIN ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಕೇಳುತ್ತದೆ"),
                    T("Anyone who asks for your OTP, PIN, CVV or password is a scammer — even if they say they're from your bank, police or a company. With it they empty your account.",
                      "जो भी आपका OTP, PIN, CVV या पासवर्ड माँगे, वह ठग है — चाहे वह ख़ुद को बैंक, पुलिस या किसी कंपनी का बताए। इससे वे आपका खाता खाली कर देते हैं।",
                      "ನಿಮ್ಮ OTP, PIN, CVV ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಕೇಳುವವರು ವಂಚಕರು — ಬ್ಯಾಂಕ್, ಪೊಲೀಸ್ ಅಥವಾ ಕಂಪನಿಯವರು ಎಂದರೂ ಸಹ. ಅದರಿಂದ ಅವರು ನಿಮ್ಮ ಖಾತೆ ಖಾಲಿ ಮಾಡುತ್ತಾರೆ."),
                    [f"“{h}”" for h in cred_hits[:2]]))

    rp = _spans(RECEIVE_PIN, text, "danger", marks)
    if rp:
        actions.append("enter_pin_to_receive")
        F.append(_f("PIN_TO_RECEIVE", "critical", 50,
                    T("Says you must enter your PIN to receive money", "कहता है पैसे पाने के लिए PIN डालना होगा", "ಹಣ ಪಡೆಯಲು PIN ಹಾಕಬೇಕು ಎನ್ನುತ್ತದೆ"),
                    T("Your UPI PIN is only ever used to SEND money. Entering it or approving a request always takes money out of your account.",
                      "UPI PIN सिर्फ़ पैसे भेजने के लिए होता है। इसे डालने या रिक्वेस्ट मंज़ूर करने से हमेशा आपके खाते से पैसे जाते हैं।",
                      "UPI PIN ಹಣ ಕಳುಹಿಸಲು ಮಾತ್ರ. ಅದನ್ನು ಹಾಕಿದರೆ ಅಥವಾ ವಿನಂತಿ ಒಪ್ಪಿದರೆ ಯಾವಾಗಲೂ ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಹಣ ಹೋಗುತ್ತದೆ."),
                    [f"“{rp[0][:120]}”"]))

    ra = _spans(REMOTE, text, "danger", marks)
    if ra:
        actions.append("install_remote_app")
        F.append(_f("REMOTE_ACCESS_APP", "critical", 50,
                    T("Asks you to install a screen-sharing app", "स्क्रीन-शेयरिंग ऐप इंस्टॉल करने को कहता है", "ಸ್ಕ್ರೀನ್-ಶೇರಿಂಗ್ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಲು ಹೇಳುತ್ತದೆ"),
                    T("Apps like AnyDesk or TeamViewer let the caller see and control your phone, including your bank app and OTPs. No real bank or company support needs this.",
                      "AnyDesk या TeamViewer जैसे ऐप से कॉल करने वाला आपका फ़ोन देख और चला सकता है — बैंक ऐप और OTP भी। किसी असली बैंक या कंपनी को इसकी ज़रूरत नहीं होती।",
                      "AnyDesk ಅಥವಾ TeamViewer ನಂತಹ ಆ್ಯಪ್‌ಗಳಿಂದ ಕರೆ ಮಾಡುವವರು ನಿಮ್ಮ ಫೋನ್ ನೋಡಬಹುದು, ನಿಯಂತ್ರಿಸಬಹುದು — ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ಮತ್ತು OTP ಸಹ. ಯಾವ ನಿಜವಾದ ಬ್ಯಾಂಕ್‌ಗೂ ಇದು ಬೇಕಿಲ್ಲ."),
                    ["Mentions: " + ", ".join(sorted({x.lower() for x in ra}))]))

    # ---- links: run each through the same checks as a scanned QR link
    link_reports, worst_link, unofficial = [], None, []
    for u in ent["urls"]:
        try:
            r = analyze_payload(u)
        except ValueError:
            continue
        d = r["details"]
        wa = (d.get("registered_domain") or "") in ("wa.me", "whatsapp.com")
        item = {"url": u, "domain": d.get("registered_domain") or d.get("host"), "official": bool(d.get("official")) or (d.get("host") or "").endswith((".gov.in", ".nic.in")),
                "level": r["verdict"]["level"], "score": r["verdict"]["score"],
                "reasons": [f["title"] for f in r["findings"] if f["severity"] in ("critical", "high", "medium")][:3], "whatsapp": wa}
        link_reports.append(item)
        if not item["official"] and not wa:
            unofficial.append(item)
        if not wa and (worst_link is None or item["score"] > worst_link["score"]):
            worst_link = item
    apk = APK_WORDS.search(text) or any("APK_DOWNLOAD" in str(x.get("reasons")) for x in link_reports) or any(re.search(r"\.apk(\?|$)", x["url"], re.I) for x in link_reports)
    if apk:
        actions.append("install_apk")
        F.append(_f("APK_LINK", "critical", 45,
                    T("Asks you to install an app file (APK)", "ऐप फ़ाइल (APK) इंस्टॉल करने को कहता है", "ಆ್ಯಪ್ ಫೈಲ್ (APK) ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಲು ಹೇಳುತ್ತದೆ"),
                    T("Apps sent over SMS/WhatsApp are the #1 way banking trojans reach phones: they read your OTPs and drain your account. Never install them.",
                      "SMS/WhatsApp पर भेजे गए ऐप ही बैंकिंग ट्रोजन फ़ोन में पहुँचाने का सबसे बड़ा तरीका हैं: वे OTP पढ़कर खाता खाली कर देते हैं। कभी इंस्टॉल न करें।",
                      "SMS/WhatsApp ನಲ್ಲಿ ಬರುವ ಆ್ಯಪ್‌ಗಳೇ ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್‌ಗಳು ಫೋನ್ ತಲುಪುವ ಮುಖ್ಯ ದಾರಿ: ಅವು OTP ಓದಿ ಖಾತೆ ಖಾಲಿ ಮಾಡುತ್ತವೆ. ಎಂದಿಗೂ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ."),
                    [x["url"] for x in link_reports if re.search(r"apk", x["url"], re.I)][:2]))
    if worst_link and worst_link["level"] in ("danger", "suspicious") and not worst_link["official"]:
        actions.append("open_link")
        crit = worst_link["level"] == "danger"
        F.append(_f("DANGEROUS_LINK", "critical" if crit else "high", 45 if crit else 30,
                    T("The link in this message is dangerous" if crit else "The link in this message looks unsafe",
                      "इस मैसेज का लिंक ख़तरनाक है" if crit else "इस मैसेज का लिंक असुरक्षित लगता है",
                      "ಈ ಸಂದೇಶದ ಲಿಂಕ್ ಅಪಾಯಕಾರಿ" if crit else "ಈ ಸಂದೇಶದ ಲಿಂಕ್ ಅಸುರಕ್ಷಿತವಾಗಿದೆ"),
                    T("We checked where it leads without opening it: " + "; ".join(r["en"] for r in worst_link["reasons"]) + ".",
                      "हमने बिना खोले जाँचा कि यह कहाँ ले जाता है: " + "; ".join(r["hi"] for r in worst_link["reasons"]) + "।",
                      "ತೆರೆಯದೆ ಅದು ಎಲ್ಲಿಗೆ ಹೋಗುತ್ತದೆ ಎಂದು ಪರಿಶೀಲಿಸಿದೆವು: " + "; ".join(r["kn"] for r in worst_link["reasons"]) + "."),
                    [f"Link: {worst_link['url']}", f"Website: {worst_link['domain']}"]))
    elif unofficial and (cat or authority):
        actions.append("open_link")
        F.append(_f("UNOFFICIAL_LINK", "high", 30,
                    T("The link isn't an official website", "लिंक किसी आधिकारिक वेबसाइट का नहीं है", "ಲಿಂಕ್ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ನದಲ್ಲ"),
                    T("The message talks about a bank, company or government office, but its link goes to an unrelated website. Type the official address yourself instead.",
                      "मैसेज बैंक, कंपनी या सरकारी विभाग की बात करता है, पर लिंक किसी और वेबसाइट पर ले जाता है। आधिकारिक पता ख़ुद टाइप करें।",
                      "ಸಂದೇಶ ಬ್ಯಾಂಕ್, ಕಂಪನಿ ಅಥವಾ ಸರ್ಕಾರಿ ಕಚೇರಿ ಬಗ್ಗೆ ಹೇಳುತ್ತದೆ, ಆದರೆ ಲಿಂಕ್ ಬೇರೆ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಹೋಗುತ್ತದೆ. ಅಧಿಕೃತ ವಿಳಾಸವನ್ನು ನೀವೇ ಟೈಪ್ ಮಾಡಿ."),
                    [f"Link goes to: {x['domain']}" for x in unofficial[:2]]))

    # ---- call a personal mobile number while claiming to be an organisation
    call = bool(CALL_ACTION.search(text)) or any(x["whatsapp"] for x in link_reports)
    if ent["phones"] and call and authority:
        actions.append("call_number")
        F.append(_f("CALL_PERSONAL_NUMBER", "high", 30,
                    T("Asks you to call a personal mobile number", "किसी निजी मोबाइल नंबर पर कॉल करने को कहता है", "ವೈಯಕ್ತಿಕ ಮೊಬೈಲ್ ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡಲು ಹೇಳುತ್ತದೆ"),
                    T("Banks, electricity boards and companies use official helplines (usually 1800… numbers printed on your card or bill), not someone's 10-digit mobile.",
                      "बैंक, बिजली विभाग और कंपनियाँ आधिकारिक हेल्पलाइन (अक्सर कार्ड या बिल पर छपे 1800… नंबर) इस्तेमाल करती हैं, किसी का 10-अंकों का मोबाइल नहीं।",
                      "ಬ್ಯಾಂಕ್, ವಿದ್ಯುತ್ ಮಂಡಳಿ ಮತ್ತು ಕಂಪನಿಗಳು ಅಧಿಕೃತ ಸಹಾಯವಾಣಿ (ಸಾಮಾನ್ಯವಾಗಿ ಕಾರ್ಡ್/ಬಿಲ್‌ನಲ್ಲಿರುವ 1800… ನಂಬರ್) ಬಳಸುತ್ತವೆ, ಯಾರದೋ 10-ಅಂಕಿಯ ಮೊಬೈಲ್ ಅಲ್ಲ."),
                    ["Number: " + ", ".join(ent["phones"][:3])]))

    fee = _spans(PAY_FEE, text, "danger", marks)
    if fee:
        actions.append("pay_fee")
        F.append(_f("ASKS_FOR_FEE", "high", 30,
                    T("Asks for a fee or deposit first", "पहले फ़ीस या डिपॉज़िट माँगता है", "ಮೊದಲು ಶುಲ್ಕ ಅಥವಾ ಠೇವಣಿ ಕೇಳುತ್ತದೆ"),
                    T("'Pay a small fee to receive / release / reactivate' is how advance-fee scams work. The fee is followed by more fees.",
                      "'पाने / छुड़ाने / चालू करने के लिए छोटी फ़ीस भरें' — यही एडवांस-फ़ीस ठगी का तरीका है। एक फ़ीस के बाद और फ़ीस माँगी जाती है।",
                      "'ಪಡೆಯಲು / ಬಿಡಿಸಲು / ಮರು-ಸಕ್ರಿಯಗೊಳಿಸಲು ಸಣ್ಣ ಶುಲ್ಕ ಕಟ್ಟಿ' — ಇದು ಮುಂಗಡ ಶುಲ್ಕ ವಂಚನೆ. ಒಂದರ ನಂತರ ಇನ್ನಷ್ಟು ಶುಲ್ಕ ಕೇಳುತ್ತಾರೆ."),
                    [f"“{fee[0]}”"]))
    vc = _spans(VIDEO_CALL, text, "danger", marks)
    if vc:
        actions.append("video_call")
    sec = _spans(SECRECY, text, "danger", marks)
    if sec:
        actions.append("keep_secret")
        F.append(_f("ASKS_FOR_SECRECY", "high", 25,
                    T("Tells you to keep it secret or stay on the call", "किसी को न बताने या कॉल पर बने रहने को कहता है", "ಯಾರಿಗೂ ಹೇಳಬೇಡಿ ಅಥವಾ ಕರೆಯಲ್ಲೇ ಇರಿ ಎನ್ನುತ್ತದೆ"),
                    T("Scammers isolate you so no one can warn you. Always tell a family member before paying anyone who contacted you first.",
                      "ठग आपको अकेला रखते हैं ताकि कोई आपको चेतावनी न दे सके। जिसने पहले संपर्क किया हो, उसे पैसे देने से पहले परिवार में किसी को ज़रूर बताएँ।",
                      "ಯಾರೂ ಎಚ್ಚರಿಸದಂತೆ ವಂಚಕರು ನಿಮ್ಮನ್ನು ಒಂಟಿ ಮಾಡುತ್ತಾರೆ. ಮೊದಲು ಸಂಪರ್ಕಿಸಿದವರಿಗೆ ಹಣ ಕೊಡುವ ಮೊದಲು ಕುಟುಂಬದವರಿಗೆ ತಿಳಿಸಿ."),
                    [f"“{sec[0]}”"]))
    money = ASKS_MONEY.search(text)
    if money and (cat in ("family_emergency", "wrong_transfer", "job_task", "investment", "digital_arrest") or ent["upi_ids"]):
        actions.append("send_money")
        marks.append({"start": money.start(), "end": money.end(), "kind": "danger"})

    threat = _spans(THREAT, text, "pressure", marks)
    if threat:
        F.append(_f("THREAT", "high", 20,
                    T("Threatens you (block, cut-off, arrest)", "धमकी देता है (बंद, कनेक्शन कटना, गिरफ़्तारी)", "ಬೆದರಿಕೆ ಹಾಕುತ್ತದೆ (ಬ್ಲಾಕ್, ಕಡಿತ, ಬಂಧನ)"),
                    T("Fear stops you from thinking. Real organisations send notices through official channels and give you time.",
                      "डर से सोचने का समय नहीं मिलता। असली संस्थाएँ आधिकारिक तरीके से नोटिस भेजती हैं और समय देती हैं।",
                      "ಭಯ ಯೋಚಿಸಲು ಬಿಡುವುದಿಲ್ಲ. ನಿಜವಾದ ಸಂಸ್ಥೆಗಳು ಅಧಿಕೃತ ಮಾರ್ಗದಲ್ಲಿ ನೋಟಿಸ್ ಕಳುಹಿಸಿ ಸಮಯ ಕೊಡುತ್ತವೆ."),
                    [f"“{threat[0]}”"]))
    urgent = _spans(URGENCY, text, "pressure", marks)
    if urgent:
        F.append(_f("URGENCY", "medium", 12,
                    T("Pushes you to act fast", "जल्दी करने का दबाव डालता है", "ತಕ್ಷಣ ಮಾಡುವಂತೆ ಒತ್ತಡ ಹೇರುತ್ತದೆ"),
                    T("Deadlines like 'tonight' or 'within 2 hours' are there so you don't stop to check.",
                      "'आज रात' या '2 घंटे में' जैसी समय-सीमा इसलिए होती है ताकि आप रुककर जाँच न करें।",
                      "'ಇಂದು ರಾತ್ರಿ' ಅಥವಾ '2 ಗಂಟೆಯೊಳಗೆ' ಎಂಬ ಗಡುವು ನೀವು ನಿಂತು ಪರಿಶೀಲಿಸದಂತೆ ಮಾಡಲು."),
                    ["Words: " + ", ".join(sorted({u.lower() for u in urgent})[:4])]))
    lure = _spans(MONEY_LURE, text, "pressure", marks)
    if lure:
        F.append(_f("MONEY_BAIT", "medium", 15,
                    T("Dangles money you supposedly won or are owed", "जीते हुए या मिलने वाले पैसों का लालच देता है", "ಗೆದ್ದ ಅಥವಾ ಬರಬೇಕಾದ ಹಣದ ಆಮಿಷ ತೋರಿಸುತ್ತದೆ"),
                    T("Unexpected prizes and refunds are bait to make you click, pay a fee or share a code.",
                      "अचानक इनाम या रिफ़ंड का लालच इसलिए होता है ताकि आप क्लिक करें, फ़ीस दें या कोड बताएँ।",
                      "ಅನಿರೀಕ್ಷಿತ ಬಹುಮಾನ/ರೀಫಂಡ್ ನೀವು ಕ್ಲಿಕ್ ಮಾಡಲು, ಶುಲ್ಕ ಕಟ್ಟಲು ಅಥವಾ ಕೋಡ್ ಹೇಳಲು ಹಾಕುವ ಆಮಿಷ."),
                    [f"“{lure[0][:100]}”"]))

    # ---- the topic: a known scam script. Alone it's a hint; with an action it's the scam.
    if cat:
        name, adv, strong, _weak = CATEGORIES[cat]
        for m in strong.finditer(text):
            marks.append({"start": m.start(), "end": m.end(), "kind": "topic"})
        hard = [a for a in actions if a != "keep_secret"]
        if hard or (cat == "digital_arrest" and (threat or sec or vc)):
            F.append(_f("SCAM_SCRIPT", "critical", 40,
                        T(f"Matches a known scam: {name['en']}", f"जानी-मानी ठगी से मेल खाता है: {name['hi']}", f"ತಿಳಿದಿರುವ ವಂಚನೆಗೆ ಹೊಂದುತ್ತದೆ: {name['kn']}"),
                        adv, ["Key words: " + ", ".join(dict.fromkeys(h.lower() for h in cat_hits))[:120]]))
        elif not (OTP_CODE.search(text) and CRED_WORD.search(text) and NEGATION.search(text)):  # a real OTP message
            F.append(_f("SCAM_TOPIC", "medium", 12,
                        T(f"Topic often used in scams: {name['en']}", f"यह विषय अक्सर ठगी में इस्तेमाल होता है: {name['hi']}", f"ಈ ವಿಷಯ ಹೆಚ್ಚಾಗಿ ವಂಚನೆಯಲ್ಲಿ ಬಳಕೆಯಾಗುತ್ತದೆ: {name['kn']}"),
                        adv, ["Key words: " + ", ".join(dict.fromkeys(h.lower() for h in cat_hits))[:120]]))

    if link_reports and all(x["official"] or x["whatsapp"] for x in link_reports) and not F:
        F.append(_f("OFFICIAL_LINKS", "info", 0,
                    T("Links go to official websites", "लिंक आधिकारिक वेबसाइटों पर जाते हैं", "ಲಿಂಕ್‌ಗಳು ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ಗಳಿಗೆ ಹೋಗುತ್ತವೆ"),
                    T("Still, log in by opening the app or typing the address yourself rather than tapping links in messages.",
                      "फिर भी, मैसेज के लिंक दबाने के बजाय ऐप खोलकर या पता ख़ुद टाइप करके लॉग-इन करें।",
                      "ಆದರೂ, ಸಂದೇಶದ ಲಿಂಕ್ ಒತ್ತುವ ಬದಲು ಆ್ಯಪ್ ತೆರೆದು ಅಥವಾ ವಿಳಾಸ ನೀವೇ ಟೈಪ್ ಮಾಡಿ ಲಾಗಿನ್ ಆಗಿ."),
                    [x["domain"] for x in link_reports][:3]))

    F.sort(key=lambda x: (SEVERITY_ORDER[x.severity], -x.points))
    score = min(100, sum(f.points for f in F))
    if any(f.severity == "critical" for f in F):
        score = max(score, 70)
    for threshold, level, headline, advice in MSG_VERDICTS:
        if score >= threshold:
            break
    # keep highlight spans non-overlapping, strongest kind wins
    rank = {"danger": 0, "link": 1, "upi": 1, "phone": 1, "pressure": 2, "topic": 3}
    marks.sort(key=lambda m: (m["start"], rank.get(m["kind"], 9), -(m["end"] - m["start"])))
    spans, last = [], -1
    for m in marks:
        if m["start"] >= last:
            spans.append(m)
            last = m["end"]
    return {
        "kind": "msg",
        "id": hashlib.sha256(text.encode()).hexdigest(),
        "payload": text,
        "details": {
            "category": cat, "category_name": CATEGORIES[cat][0] if cat else None,
            "asks": [{"id": a, "label": ACTION_LABELS[a]} for a in dict.fromkeys(actions)],
            "links": link_reports, "upi_ids": ent["upi_ids"], "phones": ent["phones"], "tollfree": ent["tollfree"],
            "amounts": ent["amounts"], "highlights": spans, "template": template_hash(text), "length": len(text),
        },
        "verdict": {"score": score, "level": level, "headline": headline, "advice": advice},
        "findings": [f.to_dict() for f in F],
        "limitations": ["The message is checked against known scam scripts and its links are checked without opening them. "
                        "A clean result doesn't prove who sent it — if in doubt, contact the company or person yourself on a number you already know."],
    }
