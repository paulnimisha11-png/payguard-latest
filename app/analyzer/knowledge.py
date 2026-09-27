"""Static knowledge used by the analyzer: permission meanings, suspicious API
signatures, scam-lure vocabulary and Indian banking/UPI app identifiers."""

P = "android.permission."

# risk: "critical" | "high" | "medium" | "low"
PERMISSIONS: dict[str, tuple[str, str]] = {
    P + "RECEIVE_SMS": ("critical", "Read every incoming SMS the moment it arrives, including bank OTPs"),
    P + "READ_SMS": ("critical", "Read all SMS messages already on your phone, including OTPs and bank alerts"),
    P + "SEND_SMS": ("high", "Send SMS from your number without you seeing it (can cost money or register your SIM for UPI elsewhere)"),
    P + "RECEIVE_MMS": ("high", "Receive MMS messages"),
    P + "RECEIVE_WAP_PUSH": ("high", "Receive WAP push messages"),
    P + "BIND_ACCESSIBILITY_SERVICE": ("critical", "Accessibility service: see everything on screen and tap buttons for you"),
    P + "SYSTEM_ALERT_WINDOW": ("high", "Draw over other apps: can put a fake login screen on top of your real bank app"),
    P + "BIND_NOTIFICATION_LISTENER_SERVICE": ("critical", "Read all your notifications, including OTPs and WhatsApp messages"),
    P + "BIND_DEVICE_ADMIN": ("high", "Device administrator: can lock the phone and block uninstalling"),
    P + "REQUEST_INSTALL_PACKAGES": ("high", "Install other apps (used to drop more malware)"),
    P + "REQUEST_DELETE_PACKAGES": ("medium", "Ask to uninstall other apps"),
    P + "QUERY_ALL_PACKAGES": ("medium", "See every app installed on your phone (e.g. which bank apps you use)"),
    P + "READ_CONTACTS": ("medium", "Read your contacts (used to spread the scam to your friends and family)"),
    P + "WRITE_CONTACTS": ("medium", "Change your contacts"),
    P + "READ_CALL_LOG": ("high", "Read your call history"),
    P + "WRITE_CALL_LOG": ("medium", "Change your call history"),
    P + "PROCESS_OUTGOING_CALLS": ("high", "See and redirect the calls you make"),
    P + "CALL_PHONE": ("high", "Make phone calls / dial USSD codes without you pressing call (e.g. call forwarding)"),
    P + "ANSWER_PHONE_CALLS": ("high", "Answer phone calls on its own"),
    P + "READ_PHONE_STATE": ("medium", "Read your phone number, SIM and network details"),
    P + "READ_PHONE_NUMBERS": ("medium", "Read your phone number"),
    P + "CAMERA": ("medium", "Use the camera"),
    P + "RECORD_AUDIO": ("medium", "Record audio with the microphone"),
    P + "ACCESS_FINE_LOCATION": ("medium", "Know your exact location"),
    P + "ACCESS_COARSE_LOCATION": ("low", "Know your approximate location"),
    P + "ACCESS_BACKGROUND_LOCATION": ("high", "Track your location even when the app is closed"),
    P + "READ_EXTERNAL_STORAGE": ("low", "Read photos and files on your phone"),
    P + "WRITE_EXTERNAL_STORAGE": ("low", "Write files to your phone storage"),
    P + "MANAGE_EXTERNAL_STORAGE": ("high", "Full access to all files on your phone"),
    P + "READ_MEDIA_IMAGES": ("low", "Read your photos"),
    P + "GET_ACCOUNTS": ("medium", "See the accounts (Google, WhatsApp...) on the phone"),
    P + "RECEIVE_BOOT_COMPLETED": ("low", "Start automatically every time the phone is switched on"),
    P + "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("medium", "Ask to never be put to sleep, so it can run forever in the background"),
    P + "FOREGROUND_SERVICE": ("low", "Keep running in the background"),
    P + "WAKE_LOCK": ("low", "Keep the phone awake"),
    P + "INTERNET": ("low", "Use the internet (needed to send your data anywhere)"),
    P + "ACCESS_NETWORK_STATE": ("low", "Check whether you are online"),
    P + "DISABLE_KEYGUARD": ("medium", "Disable the screen lock"),
    P + "USE_FULL_SCREEN_INTENT": ("low", "Show full-screen alerts"),
    P + "FOREGROUND_SERVICE_MEDIA_PROJECTION": ("high", "Record your screen"),
    P + "BIND_CARRIER_MESSAGING_SERVICE": ("high", "Act as the phone's SMS handler"),
    P + "BROADCAST_SMS": ("high", "Fake incoming SMS"),
    P + "WRITE_SETTINGS": ("medium", "Change system settings"),
    P + "CHANGE_WIFI_STATE": ("low", "Turn Wi-Fi on/off"),
    P + "USE_BIOMETRIC": ("low", "Use fingerprint/face unlock"),
    P + "VIBRATE": ("low", "Vibrate the phone"),
    P + "POST_NOTIFICATIONS": ("low", "Show notifications"),
}

# Suspicious API references found in the compiled code.
# key -> (list of "Lclass;->method" prefixes, human description)
API_SIGNATURES: dict[str, tuple[list[str], str]] = {
    "sms_send_api": (["Landroid/telephony/SmsManager;->sendTextMessage",
                      "Landroid/telephony/SmsManager;->sendMultipartTextMessage",
                      "Landroid/telephony/gsm/SmsManager;->sendTextMessage"],
                     "Code that silently sends SMS messages"),
    "sms_read_api": (["Landroid/telephony/SmsMessage;->createFromPdu",
                      "Landroid/telephony/SmsMessage;->getMessageBody",
                      "Landroid/telephony/SmsMessage;->getDisplayMessageBody",
                      "Landroid/provider/Telephony$Sms$Intents;->getMessagesFromIntent"],
                     "Code that pulls the text out of incoming SMS messages"),
    "accessibility_api": (["Landroid/accessibilityservice/AccessibilityService;->performGlobalAction",
                           "Landroid/accessibilityservice/AccessibilityService;->dispatchGesture",
                           "Landroid/view/accessibility/AccessibilityNodeInfo;->performAction"],
                          "Code that taps and swipes on the screen by itself"),
    "dynamic_code_api": (["Ldalvik/system/DexClassLoader;-><init>",
                          "Ldalvik/system/InMemoryDexClassLoader;-><init>",
                          "Ldalvik/system/PathClassLoader;-><init>"],
                         "Code that loads hidden extra code after installation"),
    "hide_icon_api": (["Landroid/content/pm/PackageManager;->setComponentEnabledSetting"],
                      "Code that can hide the app's icon from the home screen"),
    "device_admin_api": (["Landroid/app/admin/DevicePolicyManager;->lockNow",
                          "Landroid/app/admin/DevicePolicyManager;->resetPassword",
                          "Landroid/app/admin/DevicePolicyManager;->wipeData"],
                         "Code that can lock or wipe the phone"),
    "installer_api": (["Landroid/content/pm/PackageInstaller;->createSession",
                       "Landroid/content/pm/PackageInstaller$Session;->commit"],
                      "Code that installs other apps"),
    "exec_api": (["Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start"],
                 "Code that runs shell commands"),
    "screen_capture_api": (["Landroid/media/projection/MediaProjectionManager;->createScreenCaptureIntent",
                            "Landroid/media/projection/MediaProjection;->createVirtualDisplay"],
                           "Code that records the screen"),
    "device_id_api": (["Landroid/telephony/TelephonyManager;->getDeviceId",
                       "Landroid/telephony/TelephonyManager;->getSubscriberId",
                       "Landroid/telephony/TelephonyManager;->getLine1Number",
                       "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
                       "Landroid/telephony/TelephonyManager;->getImei"],
                      "Code that reads your phone number / SIM / IMEI"),
    "notification_read_api": (["Landroid/service/notification/NotificationListenerService;->getActiveNotifications",
                               "Landroid/service/notification/StatusBarNotification;->getNotification"],
                              "Code that reads other apps' notifications"),
    "overlay_api": (["Landroid/view/WindowManager;->addView"], "Code that places windows on screen"),
    "call_api": (["Landroid/telecom/TelecomManager;->placeCall"], "Code that places calls"),
    "clipboard_api": (["Landroid/content/ClipboardManager;->getPrimaryClip"], "Code that reads the clipboard"),
    "sms_role_api": (["Landroid/app/role/RoleManager;->createRequestRoleIntent"], "Code that asks to become the default SMS/phone app"),
}

# Words that scam APK files use as bait. Matched against app name, package name
# and the uploaded file name (lower-cased).
LURE_KEYWORDS: dict[str, list[str]] = {
    "courier": ["courier", "delivery", "parcel", "shipment", "tracking", "track order", "speed post",
                "india post", "indiapost", "bluedart", "blue dart", "delhivery", "dtdc", "ekart", "fedex", "dhl"],
    "bill": ["electricity", "bijli", "बिजली", "power bill", "light bill", "bill update", "bill payment",
             "bescom", "mpeb", "mppkvvcl", "msedcl", "tneb", "kseb", "discom", "gas bill", "water bill"],
    "tax": ["income tax", "incometax", "tax refund", "itr refund", "refund", "gst"],
    "bank": ["kyc", "e-kyc", "ekyc", "pan update", "pancard", "pan card", "net banking", "netbanking",
             "reward point", "rewards", "credit card", "customer support", "customer care", "account block",
             "yono", "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "canara", "bank of baroda", "union bank",
             "aadhar", "aadhaar", "आधार", "bank"],
    "government": ["pm kisan", "pmkisan", "pm-kisan", "rto", "challan", "e-challan", "echallan", "parivahan",
                   "traffic fine", "ayushman", "ration card", "voter", "govt", "government", "sarkari", "yojana"],
    "greeting": ["happy new year", "diwali", "holi", "wedding", "invitation", "shaadi", "card.apk", "greeting",
                 "wishes", "photo", "video", "gift"],
    "loan_job": ["instant loan", "loan", "work from home", "part time job", "earn money", "task"],
}

# Categories whose genuine apps never arrive as a WhatsApp file.
NEVER_SIDELOADED = {"bank", "government", "tax", "bill", "courier"}

# What a genuine app in each lure category plausibly needs.
EXPECTED_FOR_CATEGORY: dict[str, set[str]] = {
    "courier": {"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
                "POST_NOTIFICATIONS", "VIBRATE", "WAKE_LOCK"},
    "bill": {"INTERNET", "ACCESS_NETWORK_STATE", "POST_NOTIFICATIONS", "CAMERA"},
    "tax": {"INTERNET", "ACCESS_NETWORK_STATE", "POST_NOTIFICATIONS"},
    "bank": {"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA", "USE_BIOMETRIC", "USE_FINGERPRINT", "POST_NOTIFICATIONS",
             "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "SEND_SMS"},
    "government": {"INTERNET", "ACCESS_NETWORK_STATE", "POST_NOTIFICATIONS", "CAMERA"},
    "greeting": {"INTERNET", "ACCESS_NETWORK_STATE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"},
    "loan_job": {"INTERNET", "ACCESS_NETWORK_STATE", "CAMERA"},
}

# Brand -> official package prefixes (only brands whose package names are well known).
OFFICIAL_PACKAGES: dict[str, list[str]] = {
    "whatsapp": ["com.whatsapp"],
    "phonepe": ["com.phonepe."],
    "paytm": ["net.one97.paytm"],
    "google pay": ["com.google.android.apps.nbu.paisa"],
    "gpay": ["com.google.android.apps.nbu.paisa"],
    "bhim": ["in.org.npci."],
    "yono": ["com.sbi."],
    "sbi": ["com.sbi."],
    "hdfc": ["com.snapwork.hdfc", "com.hdfcbank", "com.enstage.wibmo.hdfc"],
    "icici": ["com.csam.icici", "com.icici"],
    "axis": ["com.axis."],
    "kotak": ["com.msf.kbank", "com.kotak"],
    "flipkart": ["com.flipkart."],
    "amazon": ["in.amazon.", "com.amazon."],
}

# Banking / payment apps a trojan might keep a "target list" of (to know when
# to show a fake overlay). Presence of several of these strings inside code
# that is NOT itself a bank app is a strong trojan indicator.
TARGET_BANK_PACKAGES = [
    "com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus", "com.sbi.upi", "com.snapwork.hdfc", "com.csam.icici.bank.imobile",
    "com.axis.mobile", "com.msf.kbank.mobile", "com.bankofbaroda.mconnect", "com.enstage.wibmo.hdfc",
    "com.infrasofttech.indianBank", "com.canarabank.mobility", "com.unionbankofindia", "com.pnb",
    "com.idbibank", "com.fss.indus", "com.yesbank", "com.rblbank", "com.aubank", "com.federalbank",
]
UPI_APP_PACKAGES = [
    "net.one97.paytm", "com.phonepe.app", "com.google.android.apps.nbu.paisa.user", "in.org.npci.upiapp",
    "in.amazon.mShop.android.shopping", "com.dreamplug.androidapp", "com.mobikwik_new", "com.freecharge.android",
]

# Credential-harvesting vocabulary (fake forms inside the app).
PHISHING_TERMS = [
    "cvv", "atm pin", "upi pin", "mpin", "m-pin", "card number", "card no", "expiry date", "valid thru",
    "net banking password", "netbanking password", "login password", "debit card", "credit card number",
    "aadhaar number", "aadhar number", "pan number", "date of birth", "mother's maiden", "transaction password",
    "enter otp", "profile password", "customer id",
]

# Known commercial packers / protectors (native libraries). Legit apps use some
# of them too, so this is only a supporting signal.
PACKER_LIBS = {
    "libjiagu": "360 Jiagu", "libjiagu_x86": "360 Jiagu", "libsecexe": "Bangcle", "libsecmain": "Bangcle",
    "libDexHelper": "SecNeo", "libprotectClass": "Tencent Legu", "libshella": "Tencent Legu",
    "libshell": "Tencent Legu", "libexec": "Ijiami", "libexecmain": "Ijiami", "libapktoolplus_jiagu": "ApkToolPlus",
    "libnqshield": "NQShield", "libtup": "Tencent", "libAPKProtect": "APKProtect", "libkwscmm": "Kiwisec",
    "libbaiduprotect": "Baidu",
}

# Domains that appear in nearly every app and say nothing about behaviour.
BORING_DOMAINS = (
    "schemas.android.com", "www.w3.org", "w3.org", "apache.org", "xmlpull.org", "ns.adobe.com", "google.com",
    "googleapis.com", "gstatic.com", "android.com", "googlesyndication.com", "doubleclick.net", "crashlytics.com",
    "firebase.google.com", "facebook.com", "fb.com", "github.com", "example.com", "jetbrains.org", "json.org",
    "java.com", "oracle.com", "kotlinlang.org", "mozilla.org", "apple.com", "xml.org", "purl.org",
    "openxmlformats.org", "microsoft.com", "schema.org", "localhost", "127.0.0.1", "0.0.0.0", "youtube.com",
    "goo.gl", "play.google.com", "googleadservices.com", "app-measurement.com", "googleusercontent.com",
    "googletagmanager.com", "bumptech.com", "squareup.com", "okhttp", "www.googleapis.com", "ietf.org",
)
