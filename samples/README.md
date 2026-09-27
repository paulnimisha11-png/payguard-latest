# Test samples

| File | What it is | Expected verdict |
|---|---|---|
| `Courier_Delivery_Update.apk` | **Inert detection fixture** we built. It copies the *fingerprint* of an Indian SMS-stealer / banking trojan (SMS + Accessibility + Overlay, Telegram bot URL, `*21*` call-forward code, bank-app target list, CVV/PIN form text) but contains no working malicious code — the referencing methods are never called. Safe to demo. | Do NOT install (100) |
| `com.politedroid_4.apk`, `com.teleca.jamendo_35.apk` | Real open-source apps from F-Droid (androguard test set) | No known danger signs |
| `a2dp.Vol_137.apk` | Real open-source app that legitimately reads notifications | Be careful |

`fixture-src/` holds the manifest, strings and smali used to build the fixture with apktool:

```
java -jar apktool.jar d TestActivity.apk -o fake     # any small APK
cp fixture-src/AndroidManifest.xml fake/ ; cp fixture-src/strings.xml fake/res/values/
cp fixture-src/Inert.smali fake/smali/tests/androguard/
java -jar apktool.jar b fake -o out.apk
keytool -genkeypair -keystore k.jks -alias a -keyalg RSA -validity 3650 -dname "CN=Delivery, O=Delivery, C=IN"
jarsigner -keystore k.jks out.apk a
```

For real malware testing, download samples from MalwareBazaar (tag `SMS-Stealer`, `android`) **inside a VM** — never on a personal phone.
