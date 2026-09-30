# PayGuard for Android — UPI interceptor

The app sits **between a QR code and your UPI app**:

```
Shop QR ──scan──▶ PayGuard ──check on server──▶  safe?     ──▶ your UPI app opens, everything pre-filled
                                                  risky?    ──▶ "Continue to pay" / "Don't pay"
                                                  scam?     ──▶ red scam screen, payment blocked
```

It uses the same backend as the website (`/api/qr/text`, `/api/qr/image`, `/api/screenshot`, `/api/scan`).

## What it does

| Feature | How |
|---|---|
| **Scan a shop's QR to pay** | "Scan QR to pay" opens Google's QR scanner (no camera permission needed). Safe → a 3-second countdown, then your UPI app opens with payee and amount filled in. You can cancel during the countdown. |
| **Check every UPI link automatically** | The app registers for `upi://` links. Choose PayGuard + **Always** once, and QR codes scanned with the phone camera / Google Lens, plus UPI links in WhatsApp, SMS or browsers, open in PayGuard first. |
| **Scam screen** | Danger/suspicious → big red screen, "Don't pay — close". Paying anyway requires ticking "I know this person…". "Report scam" opens the website's pre-filled complaint flow. |
| **Merchant apps keep working** | When a shopping app requests a UPI payment (`startActivityForResult`), PayGuard checks it, forwards to the UPI app, and **passes the UPI app's result back** to the shopping app. |
| **No loop** | Payments are always handed to a specific UPI app (never back to PayGuard), even when PayGuard is the default handler. |
| **Offline fallback** | If the server can't be reached, basic UPI rules run on the phone (refund/prize lures, AutoPay mandates, collect requests, fake official names). It never auto-pays in offline mode. |
| **Payment screenshot check** | "Check a payment screenshot" (or share an image from WhatsApp → PayGuard) → edit detection, pending/failed status, bad reference numbers. |
| **APK check** | Share an .apk to PayGuard, or pick one → APK X-Ray report. |
| **3 languages** | UI in English / हिंदी / ಕನ್ನಡ following the phone language; warning language selectable in Settings. |

## Get the APK onto your phone

### Option A — GitHub builds it for you (no Android Studio needed)
1. Push this whole project to a GitHub repository.
2. GitHub Actions runs `.github/workflows/android.yml` automatically (tab **Actions** → *Build Android app*, about 5 minutes).
3. Open the repo's **Releases** → **PayGuard Android (latest build)** on your phone → tap **PayGuard.apk**.
4. Android asks to allow installing from your browser → allow → **Install**.

Optional: in the repo, **Settings → Secrets and variables → Actions → Variables**, add `PAYGUARD_SERVER` = your server URL (e.g. `https://payguard.onrender.com`). It's then baked in as the default.

### Option B — Android Studio
1. **File → Open** → select the `android-upi-intercept` folder. Let Gradle sync; it downloads Gradle 8.7 and the Android libraries the first time.
2. Plug in your phone (Developer options → USB debugging on) → press **Run ▶**.
   Or **Build → Build App Bundle(s) / APK(s) → Build APK(s)** → the APK is in `app/build/outputs/apk/`.

### Option C — command line (JDK 17 + Android SDK installed)
```
cd android-upi-intercept
./gradlew assembleRelease            # → app/build/outputs/apk/release/app-release.apk
./gradlew installDebug               # installs straight onto a USB-connected phone
```

### Let people download it from your website
Copy the APK to `downloads/payguard.apk` in the backend folder (or set `APKXRAY_APP_APK_URL` to the GitHub release link). The website's "PayGuard for Android" section then shows a **Download the app** button.

All builds are signed with the same demo key (`app/payguard-demo.keystore`), so a newer build installs over an older one. **Before publishing to the Play Store, replace it with a private key kept out of git.**

## First-time setup on the phone
1. **Connect to your server.** Open the PayGuard website on your laptop and scroll to the bottom. In the app: **Settings → Scan connect code** → point at the QR. (Or type the URL, e.g. your `https://….lhr.life` tunnel link.) "Test connection" should say ✓ Working.
2. **Turn on automatic checking.** Home → **Set PayGuard as UPI checker** → pick **PayGuard** → **Always**. You'll see "PayGuard is set up".
   - If your phone opens GPay/PhonePe directly instead of asking: Settings → Apps → *that app* → **Open by default** → **Clear defaults**, then try again. The home screen tells you which app currently owns UPI links.

## Demo script (at a stationery shop, or with the test QR sheet)
1. Open PayGuard → **Scan QR to pay** → scan the *genuine shop* QR → green "No scam signs" → 3-second countdown → your UPI app opens with the shop's details. ✅
2. Scan the *fake SBI refund* QR → red **Do NOT pay** + "Pretends you will RECEIVE money". The pay button is gone. 🛑
3. With PayGuard as the default: close PayGuard, scan the same scam QR with the **phone camera / Google Lens** → tap the link → PayGuard opens first and blocks it.
4. Share a fake payment screenshot from WhatsApp → **PayGuard** → "Likely fake or edited".

Test from a computer with the phone on USB:
```
adb shell am start -a android.intent.action.VIEW -d "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund&am=4999&tn=refund"
```

## Honest limits (tell judges before they ask)
- **UPI apps' own scanners bypass PayGuard.** Scanning *inside* GPay/PhonePe never creates a `upi://` link Android can route, so no app can intercept it. That's why the flow is "scan with PayGuard (or the camera), pay in your UPI app".
- **Some UPI apps limit payments started from links.** For person-to-person QRs, GPay/PhonePe sometimes refuse link payments for security. Shop (merchant) QRs normally work. When that happens, the app shows "UPI app refused the link? Open it and pay using the copied UPI ID"; the UPI ID is one tap to copy.
- **Needs Google Play services** for the QR scanner (almost every Indian Android phone has it). Without it, use "QR from a photo or screenshot".
- `usesCleartextTraffic` is on so you can test against `http://192.168.x.x:8000` on your Wi-Fi. For production, serve the backend over https and turn it off.

## Code map
```
app/src/main/AndroidManifest.xml     upi:// intent-filter, <queries> for UPI apps, share targets, payguard://connect
java/app/payguard/shield/
  MainActivity.java      home: scan to pay, screenshot/APK/link checks, "set as UPI checker" status
  CheckActivity.java     receives upi:// / shared content → server check → verdict screen → forward or block
  UpiLauncher.java       finds UPI apps (excluding PayGuard), forwards the link, passes results back
  LocalCheck.java        offline rules when the server is unreachable
  Api.java               JSON + multipart calls to the PayGuard backend
  Scanner.java           Google code scanner wrapper
  SettingsActivity.java  server URL, connect-QR, warning language
  Prefs.java / Ui.java   settings storage, view helpers
res/values{,-hi,-kn}/strings.xml     all text in 3 languages
```
