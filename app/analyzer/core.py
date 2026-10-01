"""APK X-Ray analysis pipeline.

analyze_apk(path, original_name) -> report dict

Pipeline
  1. Safety checks on the ZIP (size, entry count, zip-bomb ratio); unwrap
     split bundles (.apks / .xapk) to their base APK.
  2. Decode the binary AndroidManifest.xml (androguard) -> permissions,
     components, intent filters, SDK levels, launcher activity.
  3. Signing certificate(s): scheme, subject, debug key, key age.
  4. Code scan: every classes*.dex -> string constants + referenced APIs.
  5. Resource strings + small asset text files -> phishing vocabulary.
  6. Native libs / embedded payloads -> packers, droppers.
  7. Facts -> rules engine -> score, verdict, plain-language findings.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import re
import time
import zipfile

from loguru import logger

logger.remove()  # androguard is extremely chatty

from androguard.core.apk import APK  # noqa: E402

from . import knowledge as K  # noqa: E402
from .dexscan import DexScan, scan_dex  # noqa: E402
from .rules import evaluate  # noqa: E402

ENGINE_VERSION = "1.0.0"
NS = "{http://schemas.android.com/apk/res/android}"
P = "android.permission."

MAX_ENTRIES = 60_000
MAX_UNCOMPRESSED = 2_000_000_000
MAX_RATIO = 200
MAX_ASSET_TEXT = 3_000_000

URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~%]+(?::\d+)?(?:/[^\s\"'<>\\]*)?")
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TG_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
USSD_RE = re.compile(r"(\*\*?(?:21|61|62|67|002|004|401)\*|%2A%2A?(?:21|61|62|67|401)%2A|##002#)")
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click", ".icu", ".rest",
                   ".cyou", ".sbs", ".monster", ".work", ".link", ".ngrok.io", ".ngrok-free.app", ".trycloudflare.com",
                   ".duckdns.org", ".000webhostapp.com")

LURE_LABELS = {
    "courier": "courier / parcel delivery", "bill": "electricity / utility bill", "tax": "tax refund",
    "bank": "bank / KYC update", "government": "government scheme / challan", "greeting": "greeting / invitation",
    "loan_job": "loan / job offer",
}
LURE_PRIORITY = ["bank", "government", "tax", "bill", "courier", "loan_job", "greeting"]


class AnalysisError(Exception):
    pass


# ------------------------------------------------------------------ helpers

def _hashes(path: str) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _check_zip(zf: zipfile.ZipFile, size: int) -> None:
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise AnalysisError("Archive has too many files to be a normal app.")
    total = sum(i.file_size for i in infos)
    if total > MAX_UNCOMPRESSED or (size and total / max(size, 1) > MAX_RATIO):
        raise AnalysisError("Archive expands to a suspicious size (possible zip bomb). Refusing to unpack.")


def _unwrap_bundle(path: str, workdir: str) -> tuple[str, str | None]:
    """If the upload is a split bundle (.apks/.xapk), return the base APK path."""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "AndroidManifest.xml" in names:
            return path, None
        apks = [n for n in names if n.lower().endswith(".apk") and not n.endswith("/")]
        if not apks:
            raise AnalysisError("This ZIP file does not contain an Android app (no AndroidManifest.xml).")
        base = next((n for n in apks if os.path.basename(n).lower() in ("base.apk",)), None)
        if base is None:
            base = max(apks, key=lambda n: zf.getinfo(n).file_size)
        out = os.path.join(workdir, "base.apk")
        with zf.open(base) as src, open(out, "wb") as dst:
            dst.write(src.read(512 * 1024 * 1024))
        return out, base


def _match_kw(text: str, kw: str) -> bool:
    if len(kw) <= 4:
        return re.search(rf"(?<![a-z]){re.escape(kw)}(?![a-z])", text) is not None
    return kw in text


def _short(perm: str) -> str:
    return perm[len(P):] if perm.startswith(P) else perm


def _fqcn(pkg: str, name: str) -> str:
    if not name:
        return name
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return f"{pkg}.{name}"
    return name


# ------------------------------------------------------------------ manifest

def _components(a: APK, pkg: str) -> dict:
    out = {"activities": [], "services": [], "receivers": [], "providers": []}
    special = {"accessibility": [], "notif_listener": [], "device_admin": [], "sms_receiver": [],
               "sms_handler": [], "boot": [], "exported_count": 0}
    try:
        app = a.get_android_manifest_xml().find("application")
    except Exception:
        app = None
    if app is None:
        return {**out, "special": special}
    tagmap = {"activity": "activities", "activity-alias": "activities", "service": "services",
              "receiver": "receivers", "provider": "providers"}
    for el in app:
        kind = tagmap.get(el.tag)
        if not kind:
            continue
        name = _fqcn(pkg, el.get(NS + "name") or el.get(NS + "targetActivity") or "")
        perm = el.get(NS + "permission") or ""
        actions, prio = [], None
        for ifl in el.findall("intent-filter"):
            if ifl.get(NS + "priority"):
                prio = ifl.get(NS + "priority")
            actions += [x.get(NS + "name") for x in ifl.findall("action") if x.get(NS + "name")]
        if el.get(NS + "exported") == "true":
            special["exported_count"] += 1
        out[kind].append({"name": name, "permission": perm, "actions": actions})

        if perm.endswith("BIND_ACCESSIBILITY_SERVICE") or "android.accessibilityservice.AccessibilityService" in actions:
            special["accessibility"].append(name)
        if perm.endswith("BIND_NOTIFICATION_LISTENER_SERVICE") or \
                "android.service.notification.NotificationListenerService" in actions:
            special["notif_listener"].append(name)
        if perm.endswith("BIND_DEVICE_ADMIN") or "android.app.action.DEVICE_ADMIN_ENABLED" in actions:
            special["device_admin"].append(name)
        if "android.provider.Telephony.SMS_RECEIVED" in actions:
            special["sms_receiver"].append(name + (f" (priority {prio})" if prio else ""))
        if "android.provider.Telephony.SMS_DELIVER" in actions:
            special["sms_handler"].append(name)
        if any(x in actions for x in ("android.intent.action.BOOT_COMPLETED", "android.intent.action.QUICKBOOT_POWERON",
                                      "android.intent.action.LOCKED_BOOT_COMPLETED")):
            special["boot"].append(name)
    return {**out, "special": special}


def _signing(a: APK) -> dict:
    info = {"signed": False, "schemes": [], "subject": None, "issuer": None, "debug_cert": False,
            "not_before": None, "not_after": None, "cert_age_days": None, "sha256": None, "certificates": 0}
    try:
        for label, fn in (("v1", a.is_signed_v1), ("v2", a.is_signed_v2), ("v3", a.is_signed_v3)):
            try:
                if fn():
                    info["schemes"].append(label)
            except Exception:
                pass
        certs = a.get_certificates()
        info["certificates"] = len(certs)
        if certs:
            c = certs[0]
            info["signed"] = True
            info["subject"] = c.subject.human_friendly
            info["issuer"] = c.issuer.human_friendly
            info["sha256"] = c.sha256_fingerprint.replace(" ", ":")
            v = c["tbs_certificate"]["validity"]
            nb, na = v["not_before"].native, v["not_after"].native
            info["not_before"], info["not_after"] = nb.isoformat(), na.isoformat()
            info["cert_age_days"] = (dt.datetime.now(dt.timezone.utc) - nb).days
            subj = (info["subject"] or "").lower()
            info["debug_cert"] = "android debug" in subj
    except Exception as e:
        info["error"] = str(e)
    info["signed"] = info["signed"] or bool(info["schemes"])
    return info


def _icon(a: APK) -> str | None:
    try:
        cands = []
        p = a.get_app_icon()
        if p:
            cands.append(p)
        names = a.get_files()
        for dens in ("xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi"):
            cands += [n for n in names if dens in n and re.search(r"ic_launcher(_round)?\.(png|webp)$", n)]
        for c in cands:
            if c.lower().endswith((".png", ".webp", ".jpg")):
                data = a.get_file(c)
                if data and len(data) < 400_000:
                    mime = "image/png" if c.endswith(".png") else "image/webp" if c.endswith(".webp") else "image/jpeg"
                    return f"data:{mime};base64," + base64.b64encode(data).decode()
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ main

def analyze_apk(path: str, original_name: str = "upload.apk", workdir: str | None = None) -> dict:
    t0 = time.time()
    size = os.path.getsize(path)
    if not zipfile.is_zipfile(path):
        raise AnalysisError("This is not an Android app file. APK files are ZIP archives; this file is not.")
    with zipfile.ZipFile(path) as zf:
        _check_zip(zf, size)
    hashes = _hashes(path)
    workdir = workdir or os.path.dirname(path)
    apk_path, bundle_member = _unwrap_bundle(path, workdir)
    if bundle_member:
        with zipfile.ZipFile(apk_path) as zf:
            _check_zip(zf, os.path.getsize(apk_path))

    try:
        a = APK(apk_path)
    except Exception as e:
        raise AnalysisError(f"Could not decode the app's manifest: {e}")
    if not a.is_valid_APK():
        raise AnalysisError("The file is damaged or not a valid Android app (manifest could not be read).")

    pkg = a.get_package() or ""
    try:
        app_name = a.get_app_name() or ""
    except Exception:
        app_name = ""

    def _int(x):
        try:
            return int(x)
        except Exception:
            return None

    min_sdk, target_sdk = _int(a.get_min_sdk_version()), _int(a.get_target_sdk_version())
    if target_sdk is None:
        target_sdk = min_sdk

    # ---- permissions
    requested = sorted(set(a.get_permissions()))
    comps = _components(a, pkg)
    sp = comps["special"]
    eff = {_short(p) for p in requested}
    if sp["accessibility"]:
        eff.add("BIND_ACCESSIBILITY_SERVICE")
    if sp["notif_listener"]:
        eff.add("BIND_NOTIFICATION_LISTENER_SERVICE")
    if sp["device_admin"]:
        eff.add("BIND_DEVICE_ADMIN")
    perm_risk = {_short(k): v[0] for k, v in K.PERMISSIONS.items()}
    perm_table = []
    for p in sorted(eff, key=lambda s: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(perm_risk.get(s, "low"), 4), s)):
        full = P + p if "." not in p else p
        risk, desc = K.PERMISSIONS.get(full, ("unknown" if "." in p else "low", ""))
        via = "declared service/receiver" if p in ("BIND_ACCESSIBILITY_SERVICE", "BIND_NOTIFICATION_LISTENER_SERVICE",
                                                   "BIND_DEVICE_ADMIN") and full not in requested else "uses-permission"
        perm_table.append({"name": full, "short": p, "risk": risk, "description": desc, "via": via})

    # ---- code
    ds = DexScan()
    zf = zipfile.ZipFile(apk_path)
    names = zf.namelist()
    for n in names:
        if re.fullmatch(r"classes\d*\.dex", n):
            try:
                scan_dex(zf.read(n), ds)
            except Exception as e:
                ds.errors.append(str(e))

    api_hits = []
    hit_keys = set()
    for key, (sigs, desc) in K.API_SIGNATURES.items():
        refs = sorted({r for r in ds.method_refs for s in sigs if r.startswith(s)})
        if refs:
            hit_keys.add(key)
            api_hits.append({"key": key, "description": desc,
                             "refs": [r.replace("/", ".").lstrip("L").replace(";->", ".") for r in refs[:6]]})

    # ---- text corpus (dex strings + resource strings + small asset text files)
    res_strings: list[str] = []
    try:
        sp_main = a.get_android_resources().stringpool_main
        for i in range(min(sp_main.stringCount, 200_000)):
            try:
                res_strings.append(sp_main.getString(i))
            except Exception:
                pass
    except Exception:
        pass
    asset_text, budget = [], MAX_ASSET_TEXT
    for n in names:
        if n.startswith(("assets/", "res/raw/")) and n.lower().endswith((".html", ".htm", ".js", ".json", ".txt", ".xml")):
            info = zf.getinfo(n)
            if info.file_size <= budget:
                budget -= info.file_size
                try:
                    asset_text.append(zf.read(n).decode("utf-8", errors="ignore"))
                except Exception:
                    pass

    all_strings = ds.strings + res_strings
    urls, domains = set(), {}
    for s in all_strings + asset_text:
        if "http" not in s:
            continue
        for u in URL_RE.findall(s[:20000]):
            host = u.split("/")[2].split(":")[0].lower()
            if not host or "." not in host or any(host == b or host.endswith("." + b) for b in K.BORING_DOMAINS):
                continue
            if host.startswith("%") or "{" in host:
                continue
            urls.add(u[:200])
            domains[host] = domains.get(host, 0) + 1
    raw_ip_urls = sorted({u for u in urls if IP_HOST_RE.match(u.split("/")[2].split(":")[0])})[:10]
    bad_tld_urls = sorted({u for u in urls if u.split("/")[2].split(":")[0].lower().endswith(SUSPICIOUS_TLDS)})[:10]

    joined_short = [s for s in all_strings if len(s) < 400]
    telegram = sorted({s[:120] for s in all_strings if "api.telegram.org" in s or "t.me/" in s and "bot" in s.lower()})
    tg_tokens = {m for s in all_strings if ":" in s and len(s) < 200 for m in TG_TOKEN_RE.findall(s)}
    if tg_tokens:
        telegram += [f"Bot token: {t[:14]}…" for t in sorted(tg_tokens)[:3]]
    ussd = sorted({s.strip()[:60] for s in joined_short if USSD_RE.search(s)})[:8]
    sms_inbox = any(s.startswith("content://sms") for s in joined_short)

    low_corpus = "\n".join(x.lower() for x in joined_short + [t[:200_000] for t in asset_text])
    phishing = sorted({t for t in K.PHISHING_TERMS
                       if re.search(rf"(?<![a-z]){re.escape(t)}(?![a-z])", low_corpus)})

    str_set = set(s for s in all_strings if len(s) < 120)
    bank_hits = sorted({b for b in K.TARGET_BANK_PACKAGES
                        if (b in str_set or any(b in s for s in str_set if s.startswith(b)))
                        and not pkg.startswith(b)})
    upi_hits = sorted({b for b in K.UPI_APP_PACKAGES if b in str_set and not pkg.startswith(b)})

    # ---- native libs / embedded payloads
    native_libs = sorted({os.path.basename(n) for n in names if n.startswith("lib/") and n.endswith(".so")})
    packers = sorted({K.PACKER_LIBS[l[:-3]] for l in native_libs if l[:-3] in K.PACKER_LIBS})
    embedded = []
    for n in names:
        if n.startswith(("assets/", "res/raw/")) and not n.endswith("/"):
            low = n.lower()
            try:
                head = zf.open(n).read(4) if zf.getinfo(n).file_size >= 4 else b""
            except Exception:
                head = b""
            if low.endswith((".apk", ".dex", ".jar")) or head == b"dex\n" or \
                    (head == b"PK\x03\x04" and not low.endswith((".zip", ".ttf", ".otf", ".json", ".xlsx", ".docx"))):
                embedded.append(n)
    embedded = embedded[:15]
    zf.close()

    # ---- lure / impersonation
    fname = (original_name or "").lower()
    haystacks = [("app name", app_name.lower()), ("package name", pkg.lower().replace("_", " ")), ("file name", fname)]
    lure_cat = lure_word = lure_where = None
    for cat in LURE_PRIORITY:
        for where, text in haystacks:
            for kw in K.LURE_KEYWORDS[cat]:
                if text and _match_kw(text, kw):
                    lure_cat, lure_word, lure_where = cat, kw, where
                    break
            if lure_cat:
                break
        if lure_cat:
            break

    impersonation, official = None, False
    for brand, prefixes in K.OFFICIAL_PACKAGES.items():
        for where, text in haystacks[::2]:  # app name, file name
            if text and _match_kw(text, brand):
                if any(pkg.startswith(p.rstrip(".")) for p in prefixes):
                    official = True
                elif impersonation is None:
                    impersonation = (brand.upper() if len(brand) <= 4 else brand.title(), pkg)
    if official:
        impersonation = None

    expected = K.EXPECTED_FOR_CATEGORY.get(lure_cat, set())
    unexpected = sorted((p for p in eff if p not in expected and perm_risk.get(p) in ("critical", "high")),
                        key=lambda p: (perm_risk.get(p) != "critical", p))

    # ---- facts
    has = lambda p: p in eff  # noqa: E731
    caps = {
        "sms_any": has("RECEIVE_SMS") or has("READ_SMS") or bool(sp["sms_receiver"]),
        "sms_receiver": bool(sp["sms_receiver"]),
        "sms_read_api": "sms_read_api" in hit_keys,
        "sms_inbox_query": sms_inbox and has("READ_SMS"),
        "sms_send": has("SEND_SMS"),
        "accessibility": bool(sp["accessibility"]),
        "overlay": has("SYSTEM_ALERT_WINDOW"),
        "notif_listener": bool(sp["notif_listener"]),
        "device_admin": bool(sp["device_admin"]),
        "boot": has("RECEIVE_BOOT_COMPLETED") or bool(sp["boot"]),
        "install_packages": has("REQUEST_INSTALL_PACKAGES"),
        "contacts": has("READ_CONTACTS"),
        "call_phone": has("CALL_PHONE"),
        "call_log": has("READ_CALL_LOG") or has("PROCESS_OUTGOING_CALLS"),
        "internet": has("INTERNET"),
        "ignore_battery": has("REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"),
        "no_launcher": not a.get_main_activities(),
        "hide_icon_api": "hide_icon_api" in hit_keys,
        "dynamic_code": "dynamic_code_api" in hit_keys,
        "embedded_apk": bool(embedded),
        "telegram_bot": bool(telegram),
        "sms_handler": bool(sp["sms_handler"]) or ("sms_role_api" in hit_keys and has("READ_SMS")),
        "screen_capture": has("FOREGROUND_SERVICE_MEDIA_PROJECTION") or "screen_capture_api" in hit_keys,
    }

    def pev(*ps):
        return [f"Permission {p}: {K.PERMISSIONS.get(P + p, ('', ''))[1]}".rstrip(": ") for p in ps if has(p)]

    def cev(*keys):
        return [f"Code calls {r}" for h in api_hits if h["key"] in keys for r in h["refs"][:3]]

    ev = {
        "sms": pev("RECEIVE_SMS", "READ_SMS") + [f"SMS listener component: {x}" for x in sp["sms_receiver"]],
        "sms_code": cev("sms_read_api") + (["Code queries the SMS inbox (content://sms)"] if sms_inbox else []),
        "sms_send": pev("SEND_SMS") + cev("sms_send_api"),
        "accessibility": [f"Accessibility service: {x}" for x in sp["accessibility"]],
        "accessibility_code": cev("accessibility_api"),
        "overlay": pev("SYSTEM_ALERT_WINDOW"),
        "notif": [f"Notification listener: {x}" for x in sp["notif_listener"]] + cev("notification_read_api"),
        "device_admin": [f"Device admin receiver: {x}" for x in sp["device_admin"]] + cev("device_admin_api"),
        "dropper": pev("REQUEST_INSTALL_PACKAGES") + [f"Hidden payload inside the app: {x}" for x in embedded[:5]]
                   + cev("dynamic_code_api", "installer_api"),
        "telegram": telegram[:5],
        "sms_handler": [f"SMS handler: {x}" for x in sp["sms_handler"]] + cev("sms_role_api"),
        "screen": pev("FOREGROUND_SERVICE_MEDIA_PROJECTION") + cev("screen_capture_api"),
        "calls": pev("CALL_PHONE", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"),
    }

    dangerous_count = sum(1 for p in eff if perm_risk.get(p) in ("critical", "high"))
    facts = {
        "caps": caps, "ev": ev, "ussd_codes": ussd, "bank_targets": bank_hits, "phishing_terms": phishing,
        "impersonation": impersonation, "official_package": official,
        "lure_category": lure_cat, "lure_label": LURE_LABELS.get(lure_cat), "lure_word": lure_word, "lure_where": lure_where,
        "never_sideloaded": K.NEVER_SIDELOADED, "unexpected_perms": unexpected, "perm_risk": perm_risk,
        "signing": _signing(a), "target_sdk": target_sdk, "dangerous_count": dangerous_count,
        "packers": packers, "raw_ip_urls": raw_ip_urls, "suspicious_tld_urls": bad_tld_urls,
    }
    verdict = evaluate(facts)

    top_domains = sorted(domains.items(), key=lambda kv: -kv[1])[:25]
    return {
        "engine_version": ENGINE_VERSION,
        "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "analysis_ms": int((time.time() - t0) * 1000),
        "file": {"name": original_name, "size": size, **hashes,
                 "bundle_member": bundle_member},
        "app": {
            "name": app_name, "package": pkg,
            "version_name": a.get_androidversion_name(), "version_code": a.get_androidversion_code(),
            "min_sdk": min_sdk, "target_sdk": target_sdk,
            "main_activity": a.get_main_activity(), "icon": _icon(a),
            "has_launcher_icon": not caps["no_launcher"],
        },
        "verdict": {k: verdict[k] for k in ("score", "level", "headline", "advice")},
        "findings": verdict["findings"],
        "capabilities": caps,
        "lure": {"category": lure_cat, "label": LURE_LABELS.get(lure_cat), "word": lure_word, "where": lure_where,
                 "expected_permissions": sorted(expected), "unexpected_permissions": unexpected},
        "permissions": perm_table,
        "components": {
            "counts": {k: len(comps[k]) for k in ("activities", "services", "receivers", "providers")},
            "accessibility_services": sp["accessibility"], "notification_listeners": sp["notif_listener"],
            "device_admin_receivers": sp["device_admin"], "sms_receivers": sp["sms_receiver"],
            "sms_handlers": sp["sms_handler"], "boot_receivers": sp["boot"], "exported": sp["exported_count"],
        },
        "signing": facts["signing"],
        "code": {
            "dex_files": ds.dex_count, "strings_scanned": len(ds.strings), "methods_referenced": len(ds.method_refs),
            "suspicious_apis": api_hits, "telegram": telegram[:5], "ussd_codes": ussd,
            "bank_app_references": bank_hits, "upi_app_references": upi_hits, "phishing_terms": phishing,
            "errors": ds.errors[:5],
        },
        "network": {"domains": [{"host": h, "count": c} for h, c in top_domains],
                    "raw_ip_urls": raw_ip_urls, "suspicious_tld_urls": bad_tld_urls, "url_count": len(urls)},
        "native": {"libraries": native_libs[:40], "packers": packers, "embedded_payloads": embedded},
        "limitations": [
            "Static analysis only: the app is never run. Code downloaded after installation cannot be seen.",
            "A low score is not a guarantee of safety; a high score on a genuine SMS or accessibility app is possible.",
        ],
    }
