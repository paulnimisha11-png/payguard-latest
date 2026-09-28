"""Fake payment screenshot detector.

analyze_screenshot(image_bytes, filename, expected_amount=None, seen_lookup=None, similar_lookup=None, bank_sms=None)

Three layers, each producing findings with en/hi/kn text:

1. File evidence   – editor software in EXIF/PNG/XMP, edit history, camera photo vs
                     real screenshot, odd crop.
2. Pixel forensics – per-field checks on the amount / reference number / date /
                     name found by OCR:
                       * background patch: the colour right behind the text vs the
                         colour just around it (paint-over edits leave a patch)
                       * text style: stroke thickness + ink colour vs other text of
                         the same size (a pasted-in number is often a different font)
                       * error level analysis (JPEG): re-compression error inside the
                         field vs the rest of the text
3. Content logic   – status (pending / failed is not a payment), 12-digit UPI
                     reference number present and well-formed, reference number's
                     date vs the date shown, future / stale dates, conflicting
                     amounts, amount vs what the merchant expected, and the same
                     reference number already seen in a different screenshot.

A screenshot can never prove a payment; the report always says to confirm the
credit in your own bank / UPI app.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import os
import re
import unicodedata
import statistics

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageOps

from ..analyzer.rules import Finding, SEVERITY_ORDER, T

# Limit CPU threads to prevent thread contention and excessive memory in cloud container environments
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

# OCR engines.
# Tesseract is preferred when available: it executes in ~1-2 seconds and uses only ~30MB RAM.
# On cloud/container platforms (e.g. Render free tier with 512MB RAM and 0.5 CPU quota),
# this is critical to avoid 504 timeouts and OOM (Out Of Memory) container crashes.
# RapidOCR (pip install rapidocr_onnxruntime) is used as a fallback when Tesseract is not installed on the system.
_RAPID = None
try:
    from rapidocr_onnxruntime import RapidOCR as _RapidOCR
    HAS_RAPID = True
except Exception:
    HAS_RAPID = False
try:
    import pytesseract
    import shutil as _shutil
    for _p in ("/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract", "/usr/bin/tesseract"):
        if not _shutil.which("tesseract") and os.path.exists(_p):
            pytesseract.pytesseract.tesseract_cmd = _p
    pytesseract.get_tesseract_version()
    HAS_TESS = True
except Exception:
    HAS_TESS = False
HAS_OCR = HAS_TESS or HAS_RAPID

_pref = os.environ.get("OCR_ENGINE", os.environ.get("APKXRAY_OCR_ENGINE", os.environ.get("PAYGUARD_OCR_ENGINE", ""))).lower()
if _pref == "rapidocr" and HAS_RAPID:
    OCR_ENGINE = "rapidocr"
elif _pref == "tesseract" and HAS_TESS:
    OCR_ENGINE = "tesseract"
else:
    OCR_ENGINE = "tesseract" if HAS_TESS else "rapidocr" if HAS_RAPID else None


def _rapid():
    global _RAPID
    if _RAPID is None:
        os.environ["OMP_NUM_THREADS"] = "1"
        os.environ["OPENBLAS_NUM_THREADS"] = "1"
        os.environ["MKL_NUM_THREADS"] = "1"
        # screenshots are always upright; the 180° classifier sometimes flips short tokens ("₹10" -> "0L2")
        _RAPID = _RapidOCR(use_angle_cls=False)
    return _RAPID


IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
MAX_PIXELS = 12_000_000

EDITORS = ["photoshop", "adobe", "gimp", "picsart", "snapseed", "canva", "lightroom", "pixlr", "fotor", "meitu",
           "photodirector", "photo editor", "polarr", "vsco", "paint.net", "affinity", "photopea", "inshot",
           "remini", "facetune", "picmonkey", "ibis", "sketchbook", "photoroom", "lensa", "airbrush", "b612"]
STATUS_BAD = {
    "pending": ["pending", "processing", "in progress", "awaiting", "under process"],
    "failed": ["failed", "declined", "unsuccessful", "reversed", "cancelled", "canceled", "rejected"],
    "request": ["payment request", "request sent", "requested", "collect request", "scheduled"],
}
STATUS_OK = ["successful", "success", "completed", "paid", "sent", "received", "debited", "credited"]
APPS = {
    "Google Pay": ["google pay", "gpay", "g pay", "google transaction id"],
    "PhonePe": ["phonepe", "phone pe"],
    "Paytm": ["paytm"],
    "BHIM": ["bhim"],
    "Amazon Pay": ["amazon pay"],
    "Bank app": ["yono", "imobile", "net banking", "mobile banking"],
}
UTR_LABELS = re.compile(r"(upi\s*(transaction|txn|ref(erence)?)\s*(id|no)?|utr|ref(erence)?\s*(no|number|id)|rrn|transaction\s*id)", re.I)
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

FIELD = {
    "amount": ("amount", "रकम", "ಮೊತ್ತ"),
    "utr": ("reference number", "रेफ़रेंस नंबर", "ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ"),
    "date": ("date", "तारीख़", "ದಿನಾಂಕ"),
    "payee": ("name", "नाम", "ಹೆಸರು"),
}


# ------------------------------------------------------------------ image helpers

def _load(data: bytes) -> tuple[Image.Image, dict]:
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
    except Exception:
        raise ValueError("Could not read this image. Please upload a PNG or JPG screenshot.")
    if im.width * im.height > MAX_PIXELS:
        raise ValueError("Image is too large. Upload the original screenshot, not a scan or collage.")
    meta = {"format": im.format, "mode": im.mode, "info": {k: v for k, v in im.info.items() if isinstance(v, (str, bytes, int, float, tuple))}}
    try:
        exif = im.getexif()
        meta["exif"] = {int(k): (v.decode("latin-1", "ignore") if isinstance(v, bytes) else v) for k, v in exif.items()}
        try:
            meta["exif_ifd"] = {int(k): v for k, v in exif.get_ifd(0x8769).items()}
        except Exception:
            meta["exif_ifd"] = {}
    except Exception:
        meta["exif"], meta["exif_ifd"] = {}, {}
    meta["quant"] = getattr(im, "quantization", None)
    im = ImageOps.exif_transpose(im).convert("RGB")
    return im, meta


def dhash(im: Image.Image, size: int = 16) -> str:
    """Perceptual difference hash: survives recompression/resizing, changes when content changes."""
    g = ImageOps.grayscale(im).resize((size + 1, size), Image.LANCZOS)
    a = np.asarray(g, dtype=np.int16)
    bits = (a[:, 1:] > a[:, :-1]).flatten()
    return "".join("1" if b else "0" for b in bits)


def hamming(a: str, b: str) -> int:
    return sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))


def _xmp(data: bytes) -> str:
    i = data.find(b"<x:xmpmeta")
    if i == -1:
        return ""
    j = data.find(b"</x:xmpmeta>", i)
    return data[i:j + 12].decode("utf-8", "ignore") if j != -1 else ""


def _lum(a):
    return 0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2]


def _clip(box, w, h, pad=0):
    x0, y0, x1, y1 = box
    return max(0, x0 - pad), max(0, y0 - pad), min(w, x1 + pad), min(h, y1 + pad)


def _bg_patch_delta(arr: np.ndarray, box) -> float | None:
    """Distance between the background colour inside the text box and in a ring around it."""
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = _clip(box, w, h)
    bh = max(4, y1 - y0)
    pad_in, ring = max(2, bh // 6), max(4, bh // 3)
    X0, Y0, X1, Y1 = _clip((x0, y0, x1, y1), w, h, ring + pad_in)
    if x1 - x0 < 6 or y1 - y0 < 6 or X1 - X0 < 10:
        return None
    inner = arr[y0:y1, x0:x1].reshape(-1, 3).astype(float)
    outer_mask = np.ones((Y1 - Y0, X1 - X0), bool)
    outer_mask[max(0, y0 - Y0 - pad_in):y1 - Y0 + pad_in, max(0, x0 - X0 - pad_in):x1 - X0 + pad_in] = False
    outer = arr[Y0:Y1, X0:X1][outer_mask].reshape(-1, 3).astype(float)
    if len(outer) < 20:
        return None
    # background = the most common colour (text is the minority)
    def mode_col(px):
        q = (px // 4).astype(int)
        keys = q[:, 0] * 4096 + q[:, 1] * 64 + q[:, 2]
        vals, counts = np.unique(keys, return_counts=True)
        k = vals[np.argmax(counts)]
        sel = px[keys == k]
        return sel.mean(axis=0), counts.max() / len(px)
    ib, ishare = mode_col(inner)
    ob, oshare = mode_col(outer)
    if oshare < 0.35:  # busy surroundings (photo / gradient): not measurable
        return None
    return float(np.linalg.norm(ib - ob))


def _ink_and_stroke(arr: np.ndarray, box) -> tuple[np.ndarray, float] | None:
    """Ink colour and stroke-width / text-height ratio of the text in a box."""
    import cv2
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = _clip(box, w, h)
    crop = arr[y0:y1, x0:x1]
    if crop.size == 0 or (y1 - y0) < 8:
        return None
    L = _lum(crop.astype(float))
    bg = np.median(np.concatenate([L[0], L[-1], L[:, 0], L[:, -1]]))
    ink_mask = np.abs(L - bg) > 60
    if ink_mask.sum() < 15:
        return None
    ink = crop[ink_mask].mean(axis=0)
    dist = cv2.distanceTransform(ink_mask.astype(np.uint8), cv2.DIST_L2, 3)
    stroke = 2 * float(np.percentile(dist[ink_mask], 90))
    return ink, stroke / (y1 - y0)


def _ela(im: Image.Image, quality=90) -> np.ndarray:
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=quality)
    re_ = Image.open(io.BytesIO(buf.getvalue())).convert("RGB")
    diff = np.asarray(ImageChops.difference(im, re_)).astype(float).max(axis=2)
    return diff


# ------------------------------------------------------------------ OCR

OCR_WIDTH = 1080


def _prep_for_ocr(im: Image.Image) -> tuple[Image.Image, float, bool]:
    """Grey, max 1080 px wide, dark text on a light background (dark-mode screenshots are inverted)."""
    scale = min(1.0, OCR_WIDTH / im.width) if im.width > 0 else 1.0
    g = ImageOps.grayscale(im)
    dark = float(np.median(np.asarray(g))) < 110
    if dark:
        g = ImageOps.invert(g)
    if scale < 0.99:
        g = g.resize((OCR_WIDTH, int(round(im.height * scale))), Image.BILINEAR)
    return g, scale, dark


def _spaced(t: str) -> str:
    """RapidOCR often drops spaces ('TransactionSuccessful', '06:28pmon26Sept2026'); put them back for the text rules."""
    t = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", t)
    t = re.sub(r"(?<=[A-Za-z]{2})(?=\d)|(?<=\d)(?=[A-Za-z]{2})", " ", t)
    t = re.sub(r"(?<=\d)\s+(?=(?:st|nd|rd|th)\b)", "", t)
    t = re.sub(r"\b(am|pm|AM|PM)(on|On)\b", r"\1 \2", t)
    return t


def _group_lines(words: list[dict]) -> list[dict]:
    words.sort(key=lambda w: (w["box"][1], w["box"][0]))
    lines: list[dict] = []
    for w in words:
        cy = (w["box"][1] + w["box"][3]) / 2
        for ln in lines:
            if abs(ln["cy"] - cy) < max(ln["h"], w["h"]) * 0.55:
                ln["words"].append(w)
                ln["h"] = max(ln["h"], w["h"])
                break
        else:
            lines.append({"cy": cy, "h": w["h"], "words": [w]})
    for ln in lines:
        ln["words"].sort(key=lambda w: w["box"][0])
        ln["text"] = " ".join(w["text"] for w in ln["words"])
        xs = [w["box"] for w in ln["words"]]
        ln["box"] = (min(b[0] for b in xs), min(b[1] for b in xs), max(b[2] for b in xs), max(b[3] for b in xs))
    lines.sort(key=lambda l: l["cy"])
    return lines


def _norm_ocr(txt: str | None) -> str:
    """Full-width digits -> ASCII ('０' -> '0'); a CJK character glued to digits is the ₹ sign
    (the bundled model is Chinese+English and reads ₹ as e.g. '舌')."""
    t = unicodedata.normalize("NFKC", txt or "").strip()
    return re.sub(r"[\u2E80-\u9FFF\uAC00-\uD7AF](?=\s?\d)", "₹", t)


def _ocr_rapid(im: Image.Image) -> tuple[list[dict], Image.Image, float]:
    g, scale, _dark = _prep_for_ocr(im)
    ga = np.asarray(g)
    res, _ = _rapid()(np.stack([ga, ga, ga], axis=2))
    words = []
    for box, txt, score in res or []:
        txt = _norm_ocr(txt)
        if not txt or float(score) < 0.5:
            continue
        xs = [p[0] for p in box]
        ys = [p[1] for p in box]
        b = (int(min(xs) / scale), int(min(ys) / scale), int(max(xs) / scale), int(max(ys) / scale))
        # "raw" keeps the exact characters (needed to pair glyphs with characters); "text" is readable for the rules
        words.append({"text": _spaced(txt), "raw": txt.replace(" ", ""), "box": b, "h": (b[3] - b[1]), "conf": float(score) * 100})
    # Receipts right-align the amount next to the payee (PhonePe "MITHU_SINGH ....... ₹10").
    # If the first pass already found the amount or reference number, skip expensive second and third passes.
    has_key_info = any(re.search(r"₹|rs\.?|inr", w["text"], re.I) or re.search(r"\b\d{12}\b", w["text"]) for w in words)
    if not has_key_info:
        try:
            W = ga.shape[1]
            x0 = int(W * 0.6)
            col = ga[:, x0:]
            pad = 40
            col = np.pad(col, ((0, 0), (pad, pad)), constant_values=int(np.median(col)))
            res2, _ = _rapid()(np.stack([col, col, col], axis=2))
            for box, txt, score in res2 or []:
                txt = _norm_ocr(txt)
                if not txt or float(score) < 0.45 or not re.search(r"\d", txt):
                    continue
                xs = [p[0] - pad + x0 for p in box]
                ys = [p[1] for p in box]
                b = (int(max(min(xs), x0) / scale), int(min(ys) / scale), int(max(xs) / scale), int(max(ys) / scale))
                cx, cy = (b[0] + b[2]) / 2, (b[1] + b[3]) / 2
                if any(w["box"][0] - 2 <= cx <= w["box"][2] + 2 and w["box"][1] - 2 <= cy <= w["box"][3] + 2 for w in words):
                    continue  # already read in the first pass
                words.append({"text": _spaced(txt), "raw": txt.replace(" ", ""), "box": b, "h": (b[3] - b[1]),
                              "conf": float(score) * 100, "second_pass": True})
        except Exception:
            pass
        try:
            words += _read_unread_right(ga, words, scale)
        except Exception:
            pass
    return _group_lines(words), g, scale


def _read_unread_right(ga: np.ndarray, words: list[dict], scale: float) -> list[dict]:
    """Ink to the right of a text row that no pass has read (e.g. an amount whose digit was erased, leaving '₹ 0').
    Crop each unread cluster and run the recogniser on it alone."""
    eng = _rapid()
    H, W = ga.shape[:2]
    out, done = [], []
    for w in sorted(words, key=lambda w: w["box"][1]):
        if len(out) >= 3:
            break
        y0, y1 = int(w["box"][1] * scale), int(w["box"][3] * scale)
        if y1 - y0 < 12 or y1 > H * 0.75 or any(abs(y0 - a) < 10 and abs(y1 - b) < 10 for a, b in done):
            continue
        done.append((y0, y1))
        cy = (y0 + y1) / 2
        row = [x for x in words + out if x["box"][1] * scale <= cy <= x["box"][3] * scale]
        right = max(x["box"][2] for x in row) * scale + 12
        if right > W * 0.9:
            continue
        band = ga[y0:y1, int(right):W - 4].astype(np.int16)
        if band.size == 0:
            continue
        bg = np.median(band)
        ink = np.abs(band - bg) > 70
        cols = np.where(ink.sum(axis=0) >= 2)[0]
        if len(cols) < 6:
            continue
        # the cluster nearest the right edge (amounts are right-aligned)
        runs, s, p = [], cols[0], cols[0]
        for c in cols[1:]:
            if c - p > (y1 - y0) * 1.5:
                runs.append((s, p)); s = c
            p = c
        runs.append((s, p))
        a, b = runs[-1]
        if b - a < (y1 - y0) * 0.5:
            continue
        pad = int((y1 - y0) * 0.4)
        x0c, x1c = max(0, int(right) + a - pad), min(W, int(right) + b + pad)
        crop = ga[max(0, y0 - pad):min(H, y1 + pad), x0c:x1c]
        res, _ = eng.text_recognizer([np.stack([crop, crop, crop], axis=2)])
        txt, conf = (res[0] if res else ("", 0))
        txt = _norm_ocr(txt)
        if not re.search(r"\d", txt):
            continue
        box = (int((int(right) + a) / scale), int(y0 / scale), int((int(right) + b) / scale), int(y1 / scale))
        out.append({"text": _spaced(txt), "raw": txt.replace(" ", ""), "box": box, "h": box[3] - box[1],
                    "conf": float(conf) * 100, "second_pass": True, "forced": True})
    return out


def _ocr(im: Image.Image) -> tuple[list[dict], Image.Image, float]:
    if OCR_ENGINE == "tesseract" and HAS_TESS:
        try:
            return _ocr_tess(im)
        except Exception:
            if HAS_RAPID:
                return _ocr_rapid(im)
            raise
    if HAS_RAPID:
        try:
            return _ocr_rapid(im)
        except Exception:
            if HAS_TESS:
                return _ocr_tess(im)
            raise
    if HAS_TESS:
        return _ocr_tess(im)
    raise RuntimeError("No OCR engine available")


def _ocr_tess(im: Image.Image) -> tuple[list[dict], Image.Image, float]:
    """Words with boxes (original-image coordinates), grouped into lines, plus the prepared image."""
    g, scale, _dark = _prep_for_ocr(im)
    # Two page-segmentation modes catch different rows; merge them, keeping the more confident word where they overlap.
    words: list[dict] = []

    def iou(a, b):
        ix = max(0, min(a[2], b[2]) - max(a[0], b[0]))
        iy = max(0, min(a[3], b[3]) - max(a[1], b[1]))
        inter = ix * iy
        ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
        return inter / ua if ua else 0

    base_cfg = "--oem 1 -c tessedit_do_invert=0 -c invert_threshold=0"
    for psm in (11, 6):
        d = pytesseract.image_to_data(g, config=f"--psm {psm} {base_cfg}", output_type=pytesseract.Output.DICT)
        for i, raw_txt in enumerate(d["text"]):
            txt = _norm_ocr((raw_txt or "").strip())
            if not txt or float(d["conf"][i]) < 30:
                continue
            x, y, bw, bh = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
            b = (int(x / scale), int(y / scale), int((x + bw) / scale), int((y + bh) / scale))
            w = {"text": _spaced(txt), "raw": txt.replace(" ", ""), "box": b,
                 "h": (b[3] - b[1]), "conf": float(d["conf"][i])}
            clash = next((k for k, o in enumerate(words) if iou(o["box"], w["box"]) > 0.3), None)
            if clash is None:
                words.append(w)
            elif w["conf"] > words[clash]["conf"]:
                words[clash] = w
        # Fast exit: if first pass already found amount/currency and UTR or reference, skip subsequent slow passes!
        has_key_info = any(re.search(r"₹|rs\.?|inr", w["text"], re.I) or re.search(r"\b\d{12}\b", w["text"]) for w in words)
        if has_key_info and len(words) >= 5:
            break

    # Extra pass over the top of the screen only if key info was not found in the main pass
    has_key_info = any(re.search(r"₹|rs\.?|inr", w["text"], re.I) or re.search(r"\b\d{12}\b", w["text"]) for w in words)
    if not has_key_info:
        try:
            import cv2
            ga = np.asarray(g)
            band_h = int(ga.shape[0] * 0.14)
            _, band = cv2.threshold(ga[:band_h], 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            if (band < 128).mean() > 0.5:
                band = 255 - band
            d = pytesseract.image_to_data(Image.fromarray(band), config=f"--psm 6 {base_cfg}", output_type=pytesseract.Output.DICT)
            for i, raw_txt in enumerate(d["text"]):
                txt = _norm_ocr((raw_txt or "").strip())
                if not txt or float(d["conf"][i]) < 40:
                    continue
                x, y, bw, bh = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
                b = (int(x / scale), int(y / scale), int((x + bw) / scale), int((y + bh) / scale))
                w = {"text": _spaced(txt), "raw": txt.replace(" ", ""), "box": b,
                     "h": (b[3] - b[1]), "conf": float(d["conf"][i])}
                clash = next((k for k, o in enumerate(words) if iou(o["box"], w["box"]) > 0.3), None)
                if clash is None:
                    words.append(w)
                elif w["conf"] > words[clash]["conf"]:
                    words[clash] = w
        except Exception:
            pass

    return _group_lines(words), g, scale


def warmup_ocr():
    """Pre-initialize the active OCR engine with a small synthetic image to avoid cold-start delays on requests."""
    if not HAS_OCR:
        return
    try:
        dummy = Image.new("RGB", (120, 60), color="white")
        d = ImageDraw.Draw(dummy)
        d.text((10, 20), "Rs 100", fill="black")
        _ocr(dummy)
    except Exception:
        pass



def _segment_glyphs(a: np.ndarray):
    """Split a word crop (dark text on light) into glyph column-runs; returns (ink image, [(x0,x1)])."""
    import cv2
    _, bm = cv2.threshold(a.astype(np.uint8), 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    bgpx = a[bm == 0]
    bg = float(np.median(bgpx)) if bgpx.size else 255.0
    ink = np.clip(bg - a, 0, None)
    cols = (bm > 0).any(axis=0)
    segs, i = [], 0
    while i < len(cols):
        if cols[i]:
            j = i
            while j < len(cols) and cols[j]:
                j += 1
            segs.append((i, j))
            i = j
        else:
            i += 1
    return ink, segs


def _glyph_consistency(g: Image.Image, scale: float, lines: list[dict]) -> dict | None:
    """A phone's font engine draws every copy of a digit identically, so repeated digits in a line sit at exactly
    the same height. Re-typed or AI-regenerated text doesn't: the same digit lands a fraction of a pixel higher or
    lower each time. Measures the vertical ink centre and profile of every repeated digit in long numbers
    (UTR, transaction ID, account number) at 1080 px width."""
    a_full = np.asarray(g).astype(float)
    spreads, profs, boxes, words = [], [], [], 0
    for l in lines:
        for w in l["words"]:
            t = w.get("raw") or w["text"].replace(" ", "")
            if not re.search(r"\d{8,}", t) or len(t) > 40:
                continue
            x0, y0, x1, y1 = [int(round(v * scale)) for v in w["box"]]
            crop = a_full[max(0, y0 - 3):y1 + 3, max(0, x0 - 3):x1 + 3]
            if crop.size == 0 or crop.shape[0] < 12:
                continue
            ink, segs = _segment_glyphs(crop)
            if len(segs) != len(t):
                continue  # touching glyphs / OCR mismatch: can't pair glyphs with characters reliably
            ys = np.arange(ink.shape[0])
            groups: dict[str, list] = {}
            for (s0, s1), ch in zip(segs, t):
                if not ch.isdigit():
                    continue
                prof = ink[:, s0:s1].sum(axis=1)
                if prof.sum() <= 0:
                    continue
                groups.setdefault(ch, []).append(((prof * ys).sum() / prof.sum(), prof / prof.sum()))
            used = False
            for ch, v in groups.items():
                if len(v) < 2:
                    continue
                used = True
                spreads.append(float(np.ptp([x[0] for x in v])))
                L = min(len(x[1]) for x in v)
                for i in range(len(v)):
                    for j in range(i + 1, len(v)):
                        profs.append(float(np.abs(v[i][1][:L] - v[j][1][:L]).sum()))
            if used:
                words += 1
                boxes.append(w["box"])
    if len(spreads) < 3:
        return None
    return {"spread": float(np.median(spreads)), "profile": float(np.median(profs)) if profs else 0.0,
            "classes": len(spreads), "words": words, "box": _union(boxes) if boxes else None}


def _union(boxes):
    return (min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes))


PROMO_RE = re.compile(r"up\s?to|upto|limit|cashback|cash back|offer|\bsave\b|enjoy|reward|balance|\bwin\b|bonus|off\b", re.I)
AMOUNT_RE = re.compile(r"(?:₹|rs\.?|inr|[%=z]|₹)?\s*([0-9]{1,3}(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)", re.I)


def _first_glyph_is_rupee(arr: np.ndarray, box) -> bool:
    """OCR often reads the ₹ sign as '2', '7' or '%'. Check the first glyph's shape:
    ₹ has a full-width bar at the top and a second bar about a third of the way down."""
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = _clip(box, w, h)
    crop = _lum(arr[y0:y1, x0:x1].astype(float))
    if crop.size == 0:
        return False
    bg = np.median(np.concatenate([crop[0], crop[-1], crop[:, 0], crop[:, -1]]))
    ink = np.abs(crop - bg) > 80
    cols = ink.any(axis=0)
    xs = np.where(cols)[0]
    if len(xs) == 0:
        return False
    start = xs[0]
    end = start
    while end < len(cols) and cols[end]:
        end += 1
    g = ink[:, start:end]
    rows = np.where(g.any(axis=1))[0]
    if len(rows) < 8 or end - start < 4:
        return False
    g = g[rows[0]:rows[-1] + 1]
    gh, gw = g.shape
    fill = g.mean(axis=1)
    wide = fill > 0.7
    top = wide[: max(1, int(gh * 0.14))].any()
    second = wide[int(gh * 0.2): int(gh * 0.45)].any()
    gap = (~wide[int(gh * 0.1): int(gh * 0.3)]).any()
    bottom = (fill[int(gh * 0.88):] > 0.9).any()   # '2' has a solid base; ₹ ends in a thinner diagonal leg
    return bool(top and second and gap and not bottom)


def _glyph_runs(arr: np.ndarray, box) -> int:
    """Number of separate glyph columns inside a box (commas and dots count as glyphs, like in the OCR text)."""
    h, w = arr.shape[:2]
    x0, y0, x1, y1 = _clip(box, w, h)
    crop = _lum(arr[y0:y1, x0:x1].astype(float))
    if crop.size == 0:
        return 0
    bg = np.median(np.concatenate([crop[0], crop[-1], crop[:, 0], crop[:, -1]]))
    cols = (np.abs(crop - bg) > 80).any(axis=0)
    runs, prev = 0, False
    for c in cols:
        if c and not prev:
            runs += 1
        prev = c
    return runs


def _rupee_left_of(arr: np.ndarray, box) -> bool:
    """Is there a ₹ glyph immediately left of (or at the start of) this number's box?"""
    x0, y0, x1, y1 = box
    h = max(4, y1 - y0)
    return _first_glyph_is_rupee(arr, (int(x0 - 1.1 * h), y0 - 1, int(x0 + 0.75 * h), y1 + 1))


def _extract(lines: list[dict], arr: np.ndarray | None = None) -> dict:
    text = "\n".join(l["text"] for l in lines)
    low = text.lower()
    out: dict = {"text": text}

    # app
    out["app"] = next((a for a, keys in APPS.items() if any(k in low for k in keys)), None)

    # status
    out["status"], out["status_word"] = None, None
    for st, keys in STATUS_BAD.items():
        k = next((k for k in keys if re.search(rf"\b{re.escape(k)}\b", low)), None)
        if k:
            out["status"], out["status_word"] = st, k
            break
    if not out["status"] and any(re.search(rf"\b{k}\b", low) for k in STATUS_OK):
        out["status"] = "completed"

    # UTR: 12-digit numbers (digits may be split by spaces within a line)
    utrs = []
    for i, l in enumerate(lines):
        joined = re.sub(r"(?<=\d)\s+(?=\d)", "", l["text"])
        for m in re.finditer(r"(?<![0-9A-Za-z])(\d{12})(?![0-9])", joined):
            near_label = bool(UTR_LABELS.search(l["text"])) or (i > 0 and UTR_LABELS.search(lines[i - 1]["text"]))
            digit_words = [w for w in l["words"] if re.search(r"\d", w["text"])]
            utrs.append({"utr": m.group(1), "labelled": bool(near_label),
                         "box": _union([w["box"] for w in digit_words]) if digit_words else l["box"]})
    utrs.sort(key=lambda u: not u["labelled"])
    out["utr"] = utrs[0] if utrs else None
    out["utr_all"] = sorted({u["utr"] for u in utrs})
    out["has_utr_label"] = bool(UTR_LABELS.search(text))

    # amounts: prefer the tallest numeric line in the top half (the headline amount)
    cands, zeros = [], []
    for l in lines:
        t = re.sub(r"(?<=\d)[Oo]|[Oo](?=\d)", "0", l["text"])  # "1O0" -> "100", but never "STORES" -> "ST0RES"
        # ₹ misread as a leading digit / symbol glued to the number
        if PROMO_RE.search(t):
            continue  # "up to ₹10,000", cashback banners, limits: not the payment amount
        t = re.sub(r"(?<=[Xx×*])\s+(?=[Xx×*])", "", t)  # OCR splits the mask: "Xxx XXXxx Xx 8808"
        t = re.sub(r"\d*\s?\S*[Xx×*]{3,}\S*\s?\d*", " ", t)  # masked account numbers (XXXXXXXX8808 / 8088 XXXXXXXX) are not amounts
        if not re.search(r"₹|rs\.?|inr", t, re.I):
            for dw in [w for w in l["words"] if re.search(r"\d", w["text"])]:
                wt = dw["text"].replace(",", "").replace(" ", "")
                if re.fullmatch(r"[%=zZ¥FR#]\d+(\.\d{1,2})?", wt):
                    t = t.replace(dw["text"], "₹" + dw["text"][1:], 1)      # a symbol glued to digits is the ₹ sign
                    break
                raw = dw["text"].replace(" ", "")
                if arr is not None and re.fullmatch(r"[\d,]+(\.\d{1,2})?", raw) and _rupee_left_of(arr, dw["box"]):
                    if _glyph_runs(arr, dw["box"]) > len(raw):
                        t = t.replace(dw["text"], "₹" + dw["text"], 1)      # OCR dropped the ₹ sign: one more glyph than characters
                    elif re.match(r"^[127]", raw) or (len(raw) > 1 and _first_glyph_is_rupee(arr, dw["box"])):
                        t = t.replace(dw["text"], "₹" + dw["text"][1:], 1)  # OCR read the ₹ sign as a digit
                    else:
                        t = t.replace(dw["text"], "₹" + dw["text"], 1)
                    break
        if re.search(r"\d{10,}", re.sub(r"\s", "", t)):
            continue  # phone numbers / reference numbers
        if re.search(r"\d{1,2}[:/]\d{2}|\b(19|20)\d{2}\b|am\b|pm\b", t.lower()):
            continue  # dates / times
        has_cur = bool(re.search(r"₹|rs\.?|inr|₹", t, re.I))
        zm = re.search(r"(?:₹|\brs\.?|\binr)\s?0+(?:\.0{1,2})?(?![\d.,])", t, re.I)
        if zm:
            zw = next((w for w in l["words"] if re.search(r"(?:₹|rs|inr)?\s?0", w["text"], re.I) and not re.search(r"[1-9]", w["text"])), None)
            zeros.append({"value": 0.0, "box": zw["box"] if zw else l["box"], "text": zm.group(0)})
        for m in AMOUNT_RE.finditer(t):
            v = m.group(1)
            try:
                val = float(v.replace(",", ""))
            except ValueError:
                continue
            if val <= 0 or val > 10_000_000:
                continue
            digit_words = [w for w in l["words"] if re.search(r"\d", w["text"])]
            only_number = bool(re.fullmatch(r"\W{0,3}\s*[\d,.\s]+", t.strip()))
            tok = next((w for w in l["words"] if v.replace(",", "") in re.sub(r"[^\d.]", "", w["text"])), None)
            wh = tok["h"] if tok else l["h"]   # the number's own height; the line can be inflated by a logo or avatar
            cands.append({"value": val, "h": wh, "cur": has_cur or (only_number and wh > 1.6 * statistics.median([x["h"] for x in lines] or [wh])),
                          "box": _union([w["box"] for w in digit_words]) if digit_words else l["box"], "cy": l["cy"]})
    cands = [c for c in cands if c["cur"]]
    cands.sort(key=lambda c: -c["h"])
    out["amount"] = cands[0] if cands else None
    out["amounts_all"] = sorted({c["value"] for c in cands})
    out["zero_amounts"] = zeros

    # PhonePe-style transaction id: T + YYMMDDHHmm + sequence
    out["txn"] = None
    for l in lines:
        m = re.search(r"\bT\s?(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{6,})\b", l["text"])
        if m:
            try:
                ts = dt.datetime(2000 + int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=IST)
            except ValueError:
                ts = None
            out["txn"] = {"id": m.group(0), "ts": ts.isoformat() if ts else None, "box": l["box"]}
            break

    # date
    out["date"] = None
    mon = "(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\\.?"
    pats = [(rf"(\d{{1,2}})\s*{mon},?\s*(\d{{4}})", "dmy_txt"), (rf"{mon}\s*(\d{{1,2}}),?\s*(\d{{4}})", "mdy_txt"),
            (r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})", "dmy_num")]
    for l in lines:
        tl = l["text"].lower()
        for p, kind in pats:
            m = re.search(p, tl)
            if not m:
                continue
            try:
                if kind == "dmy_txt":
                    d, mo, y = int(m.group(1)), MONTHS[m.group(2)[:3]], int(m.group(3))
                elif kind == "mdy_txt":
                    mo, d, y = MONTHS[m.group(1)[:3]], int(m.group(2)), int(m.group(3))
                else:
                    d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                    y = y + 2000 if y < 100 else y
                tm = re.search(r"(\d{1,2}):(\d{2})\s*(am|pm)?", tl)
                hh, mm = (int(tm.group(1)), int(tm.group(2))) if tm else (12, 0)
                if tm and tm.group(3) == "pm" and hh < 12:
                    hh += 12
                if tm and tm.group(3) == "am" and hh == 12:
                    hh = 0
                when = dt.datetime(y, mo, d, min(hh, 23), min(mm, 59), tzinfo=IST)
                out["date"] = {"text": l["text"], "iso": when.isoformat(), "has_time": bool(tm), "box": l["box"]}
                break
            except (ValueError, KeyError):
                continue
        if out["date"]:
            break

    # payee: text after "to" / "paid to"
    out["payee"] = None
    for i, l in enumerate(lines):
        m = re.match(r"^(paid to|to|sent to|payment to)\b[:\s]*(.*)$", l["text"].strip(), re.I)
        if m:
            name = m.group(2).strip() or (lines[i + 1]["text"] if i + 1 < len(lines) else "")
            box = l["box"] if m.group(2).strip() else (lines[i + 1]["box"] if i + 1 < len(lines) else l["box"])
            name = re.sub(r"^\W+\s*", "", name)                              # avatar initials / icons read as symbols
            name = re.sub(r"\s+[₹%z27¥R]?\s?[\d,]+(\.\d{1,2})?\s*$", "", name).strip()  # amount printed on the same row
            if name and not re.search(r"\d{6,}", name):
                out["payee"] = {"text": name[:60], "box": box}
                break
    return out


# ------------------------------------------------------------------ findings

def _f(id_, sev, pts, title, detail, evidence, box=None):
    f = Finding(id_, sev, pts, title, detail, [e for e in evidence if e])
    d = f.to_dict()
    if box:
        d["box"] = [int(v) for v in box]
    return d


def parse_bank_sms(text: str) -> dict:
    """Pull amount, UPI reference and direction out of a bank SMS / UPI notification the merchant received."""
    t = (text or "").strip()
    out = {"amount": None, "utr": None, "direction": None, "raw_len": len(t)}
    if not t:
        return out
    low = t.lower()
    m = re.search(r"(?:rs\.?|inr|₹)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)", t, re.I)
    if m:
        try:
            out["amount"] = float(m.group(1).replace(",", ""))
        except ValueError:
            pass
    m = re.search(r"(?:upi\s*ref(?:erence)?(?:\s*no\.?)?|ref(?:erence)?\s*(?:no\.?|number|id)?|utr(?:\s*no\.?)?|rrn)[\s.:#-]*(\d{12})", low)
    if not m:
        m = re.search(r"(?<!\d)(\d{12})(?!\d)", low)
    if m:
        out["utr"] = m.group(1)
    if re.search(r"credited|received|deposited|added to", low):
        out["direction"] = "credit"
    elif re.search(r"debited|sent|paid|withdrawn", low):
        out["direction"] = "debit"
    return out


def analyze_screenshot(data: bytes, filename: str = "screenshot.png", expected_amount: float | None = None,
                       seen_lookup=None, similar_lookup=None, bank_sms: str | None = None) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    im, meta = _load(data)
    W, H = im.size
    arr = np.asarray(im)
    ph = dhash(im)
    F: list[dict] = []

    # ---------------- 1. file evidence
    exif, ifd = meta["exif"], meta["exif_ifd"]
    software = " ".join(str(x) for x in [exif.get(305, ""), meta["info"].get("Software", ""), meta["info"].get("software", ""),
                                         exif.get(11, ""), meta["info"].get("Comment", ""), meta["info"].get("comment", "")] if x)
    xmp = _xmp(data)
    blob = (software + " " + xmp).lower()
    editor = next((e for e in EDITORS if e in blob), None)
    if editor:
        F.append(_f("EDITOR_SOFTWARE", "critical", 45,
                    T(f"Saved by a photo editor ({editor.title()})", f"फ़ोटो एडिटर ({editor.title()}) से सेव की गई है", f"ಫೋಟೋ ಎಡಿಟರ್ ({editor.title()}) ನಿಂದ ಉಳಿಸಲಾಗಿದೆ"),
                    T("A real screenshot is saved by the phone itself. This file's hidden information says it was last saved by editing software.",
                      "असली स्क्रीनशॉट फ़ोन खुद सेव करता है। इस फ़ाइल की छिपी जानकारी बताती है कि इसे आख़िरी बार एडिटिंग सॉफ़्टवेयर से सेव किया गया।",
                      "ನಿಜವಾದ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅನ್ನು ಫೋನ್ ತಾನೇ ಉಳಿಸುತ್ತದೆ. ಈ ಫೈಲ್‌ನ ಗುಪ್ತ ಮಾಹಿತಿ ಇದನ್ನು ಕೊನೆಯದಾಗಿ ಎಡಿಟಿಂಗ್ ಸಾಫ್ಟ್‌ವೇರ್ ಉಳಿಸಿದೆ ಎನ್ನುತ್ತದೆ."),
                    [f"Software tag: {software.strip()[:80]}" if software.strip() else "", "XMP metadata present" if xmp else ""]))
    if re.search(r"xmpMM:History|stEvt:action|photoshop:", xmp):
        F.append(_f("EDIT_HISTORY", "high", 30,
                    T("File contains an editing history", "फ़ाइल में एडिटिंग का इतिहास है", "ಫೈಲ್‌ನಲ್ಲಿ ಎಡಿಟಿಂಗ್ ಇತಿಹಾಸ ಇದೆ"),
                    T("The image carries a record of edit steps, which phone screenshots never have.",
                      "इस तस्वीर में एडिट करने के कदमों का रिकॉर्ड है, जो फ़ोन के स्क्रीनशॉट में कभी नहीं होता।",
                      "ಈ ಚಿತ್ರದಲ್ಲಿ ಎಡಿಟ್ ಹಂತಗಳ ದಾಖಲೆ ಇದೆ, ಫೋನ್ ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ಗಳಲ್ಲಿ ಇದು ಇರುವುದಿಲ್ಲ."),
                    ["XMP edit history found"]))
    if exif.get(271) or exif.get(272) or ifd.get(0x829A) or ifd.get(0x920A):
        F.append(_f("CAMERA_PHOTO", "low", 5,
                    T("This is a photo of a screen, not a screenshot", "यह स्क्रीन की फ़ोटो है, स्क्रीनशॉट नहीं", "ಇದು ಪರದೆಯ ಫೋಟೋ, ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಲ್ಲ"),
                    T("Photos of screens can't be checked as closely. Ask to see the payment in their app directly.",
                      "स्क्रीन की फ़ोटो को उतनी बारीकी से नहीं जाँचा जा सकता। उनसे सीधे उनके ऐप में पेमेंट दिखाने को कहें।",
                      "ಪರದೆಯ ಫೋಟೋವನ್ನು ಅಷ್ಟು ಸೂಕ್ಷ್ಮವಾಗಿ ಪರಿಶೀಲಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ. ಪಾವತಿಯನ್ನು ಅವರ ಆ್ಯಪ್‌ನಲ್ಲೇ ತೋರಿಸಲು ಕೇಳಿ."),
                    [f"Camera: {exif.get(271, '')} {exif.get(272, '')}".strip()]))
    ratio = max(W, H) / max(1, min(W, H))
    if W < H and not (1.6 <= ratio <= 2.45):
        F.append(_f("CROPPED", "low", 5,
                    T("Screenshot has been cropped", "स्क्रीनशॉट काटा गया है", "ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಕತ್ತರಿಸಲಾಗಿದೆ"),
                    T("Its shape doesn't match a phone screen. Cropping can hide the status bar, time or other clues.",
                      "इसका आकार फ़ोन की स्क्रीन जैसा नहीं है। काटने से समय, स्टेटस बार या दूसरे सुराग छिप सकते हैं।",
                      "ಇದರ ಆಕಾರ ಫೋನ್ ಪರದೆಯಂತಿಲ್ಲ. ಕತ್ತರಿಸುವುದರಿಂದ ಸಮಯ, ಸ್ಟೇಟಸ್ ಬಾರ್ ಅಥವಾ ಇತರ ಸುಳಿವುಗಳು ಮರೆಯಾಗಬಹುದು."),
                    [f"{W}×{H} (ratio {ratio:.2f})"]))

    # ---------------- 2 + 3. OCR-driven checks
    ex = {"app": None, "status": None, "amount": None, "utr": None, "date": None, "payee": None, "amounts_all": [], "utr_all": [], "text": ""}
    lines: list[dict] = []
    if HAS_OCR:
        try:
            lines, ocr_img, ocr_scale = _ocr(im)
            ex = _extract(lines, arr)
        except Exception:
            lines = []
    glyph = None
    if lines and W >= 480:
        try:
            glyph = _glyph_consistency(ocr_img, ocr_scale, lines)
        except Exception:
            glyph = None
    if glyph and glyph["spread"] > 0.15 and glyph["profile"] > 0.026:
        strong = glyph["spread"] > 0.2
        F.append(_f("GLYPH_INCONSISTENT", "critical" if strong else "high", 45 if strong else 35,
                    T("The numbers look re-drawn, not rendered by a phone", "अंक फ़ोन से बने नहीं, दोबारा बनाए गए लगते हैं", "ಅಂಕಿಗಳು ಫೋನ್ ತೋರಿಸಿದಂತಲ್ಲ, ಮತ್ತೆ ಬರೆದಂತಿವೆ"),
                    T("A phone draws every copy of a digit identically. Here the same digits in the reference / transaction numbers sit at slightly "
                      "different heights and shapes each time, which happens when text is edited or the whole image is regenerated by an editing or AI tool.",
                      "फ़ोन हर अंक को हर बार बिल्कुल एक जैसा बनाता है। यहाँ रेफ़रेंस / ट्रांज़ैक्शन नंबर के एक ही अंक हर बार थोड़ी अलग ऊँचाई और आकार में हैं, "
                      "जो टेक्स्ट एडिट करने या एडिटिंग / AI टूल से पूरी तस्वीर दोबारा बनाने पर होता है।",
                      "ಫೋನ್ ಪ್ರತಿ ಅಂಕಿಯನ್ನು ಪ್ರತಿಸಲ ಒಂದೇ ರೀತಿ ಬರೆಯುತ್ತದೆ. ಇಲ್ಲಿ ಉಲ್ಲೇಖ / ವಹಿವಾಟು ಸಂಖ್ಯೆಯ ಒಂದೇ ಅಂಕಿಗಳು ಪ್ರತಿಸಲ ಸ್ವಲ್ಪ ಬೇರೆ ಎತ್ತರ ಮತ್ತು ಆಕಾರದಲ್ಲಿವೆ, "
                      "ಪಠ್ಯ ಎಡಿಟ್ ಮಾಡಿದಾಗ ಅಥವಾ ಎಡಿಟಿಂಗ್ / AI ಉಪಕರಣದಿಂದ ಇಡೀ ಚಿತ್ರವನ್ನು ಮತ್ತೆ ರಚಿಸಿದಾಗ ಹೀಗಾಗುತ್ತದೆ."),
                    [f"Same-digit height spread: {glyph['spread']:.3f} px (genuine phone screenshots: under 0.07)",
                     f"Shape difference: {glyph['profile']:.3f} (genuine: under 0.025)", f"{glyph['classes']} repeated digits in {glyph['words']} number(s) compared"],
                    glyph["box"]))

    if lines and W < 500:
        # Tiny images lose the pixel detail that edits leave behind; don't claim "no signs of editing".
        F.append(_f("LOW_RESOLUTION", "medium", 15,
                    T("This image is too small to check closely", "यह तस्वीर बारीकी से जाँचने के लिए बहुत छोटी है", "ಈ ಚಿತ್ರ ಸೂಕ್ಷ್ಮವಾಗಿ ಪರಿಶೀಲಿಸಲು ತುಂಬಾ ಚಿಕ್ಕದು"),
                    T("Small or heavily compressed screenshots hide the traces an edit leaves. Ask for the original screenshot, or confirm the payment in your bank app.",
                      "छोटे या बहुत दबाए गए स्क्रीनशॉट में एडिट के निशान छिप जाते हैं। असली स्क्रीनशॉट माँगें, या बैंक ऐप में पेमेंट देखें।",
                      "ಚಿಕ್ಕ ಅಥವಾ ತುಂಬಾ ಸಂಕುಚಿತ ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ಗಳಲ್ಲಿ ಎಡಿಟ್ ಗುರುತುಗಳು ಮರೆಯಾಗುತ್ತವೆ. ಮೂಲ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಕೇಳಿ, ಅಥವಾ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್‌ನಲ್ಲಿ ಪಾವತಿ ಖಚಿತಪಡಿಸಿ."),
                    [f"Width: {W}px (phone screenshots are usually 720px or more)"]))

    if not lines:
        # Never report "no signs of editing" when we couldn't even read the text.
        F.append(_f("TEXT_UNREADABLE", "medium", 20,
                    T("We couldn't read the text in this image", "इस तस्वीर का टेक्स्ट पढ़ा नहीं जा सका", "ಈ ಚಿತ್ರದ ಪಠ್ಯವನ್ನು ಓದಲಾಗಲಿಲ್ಲ"),
                    T("So the amount, status and reference-number checks could not run. " +
                      ("The server's text-reading engine isn't installed (run: pip install -r requirements.txt)." if not HAS_OCR
                       else "Upload the original screenshot, not a photo or a cropped part."),
                      "इसलिए रकम, स्टेटस और रेफ़रेंस नंबर की जाँच नहीं हो सकी। " +
                      ("सर्वर पर टेक्स्ट पढ़ने वाला इंजन इंस्टॉल नहीं है (चलाएँ: pip install -r requirements.txt)।" if not HAS_OCR
                       else "असली स्क्रीनशॉट अपलोड करें, फ़ोटो या कटा हुआ हिस्सा नहीं।"),
                      "ಆದ್ದರಿಂದ ಮೊತ್ತ, ಸ್ಥಿತಿ ಮತ್ತು ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಪರಿಶೀಲನೆಗಳು ನಡೆಯಲಿಲ್ಲ. " +
                      ("ಸರ್ವರ್‌ನಲ್ಲಿ ಪಠ್ಯ ಓದುವ ಎಂಜಿನ್ ಇನ್‌ಸ್ಟಾಲ್ ಆಗಿಲ್ಲ (ಚಲಾಯಿಸಿ: pip install -r requirements.txt)." if not HAS_OCR
                       else "ಮೂಲ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಅಪ್‌ಲೋಡ್ ಮಾಡಿ, ಫೋಟೋ ಅಥವಾ ಕತ್ತರಿಸಿದ ಭಾಗವಲ್ಲ.")),
                    [f"OCR engine: {OCR_ENGINE or 'not installed'}"]))

    fields = {k: ex[k]["box"] for k in ("amount", "utr", "date", "payee") if ex.get(k) and ex[k].get("box")}

    # background patch behind key fields
    for key, box in fields.items():
        d = _bg_patch_delta(arr, box)
        if d is not None and d > 6:
            crit = key in ("amount", "utr")
            en, hi, kn = FIELD[key]
            F.append(_f("PATCHED_BACKGROUND", "critical" if crit else "high", 45 if crit else 30,
                        T(f"The background behind the {en} doesn't match", f"{hi} के पीछे का बैकग्राउंड मेल नहीं खाता", f"{kn} ಹಿಂದಿನ ಹಿನ್ನೆಲೆ ಹೊಂದಿಕೆಯಾಗುತ್ತಿಲ್ಲ"),
                        T(f"The colour right behind the {en} is slightly different from the screen around it. That is what painting over old text and typing new text leaves behind.",
                          f"{hi} के ठीक पीछे का रंग आस-पास की स्क्रीन से थोड़ा अलग है। पुराने अक्षरों पर पेंट करके नए लिखने से यही निशान बचता है।",
                          f"{kn} ಹಿಂದಿನ ಬಣ್ಣ ಸುತ್ತಲಿನ ಪರದೆಗಿಂತ ಸ್ವಲ್ಪ ಬೇರೆಯಾಗಿದೆ. ಹಳೆಯ ಅಕ್ಷರಗಳ ಮೇಲೆ ಬಣ್ಣ ಹಚ್ಚಿ ಹೊಸದನ್ನು ಬರೆದಾಗ ಇದೇ ಗುರುತು ಉಳಿಯುತ್ತದೆ."),
                        [f"Field: {en}", f"Colour difference: {d:.1f} (genuine screenshots: under 3)"], box))

    # text style outliers among same-size words
    styled = []
    for l in lines:
        for w in l["words"]:
            if len(re.sub(r"\W", "", w["text"])) >= 2:
                st = _ink_and_stroke(arr, w["box"])
                if st:
                    styled.append({"w": w, "ink": st[0], "stroke": st[1]})
    for key in ("amount", "utr"):
        box = fields.get(key)
        if not box:
            continue
        me = _ink_and_stroke(arr, box)
        if not me:
            continue
        bh = box[3] - box[1]
        peers = [s for s in styled if abs((s["w"]["box"][3] - s["w"]["box"][1]) - bh) <= 0.2 * bh
                 and not (s["w"]["box"][0] >= box[0] - 2 and s["w"]["box"][2] <= box[2] + 2 and abs(s["w"]["box"][1] - box[1]) < bh)]
        if len(peers) < 3:
            continue
        # Compare only with text of the same ink colour (values vs grey labels vs links are styled differently on purpose).
        same_ink = [p for p in peers if np.linalg.norm(p["ink"] - me[0]) < 30]
        nearest_ink = min(float(np.linalg.norm(p["ink"] - me[0])) for p in peers)
        dark_peers = [p for p in peers if _lum(p["ink"][None, :])[0] < 90]
        ink_odd = _lum(me[0][None, :])[0] < 90 and len(dark_peers) >= 3 and nearest_ink > 18 and \
            min(float(np.linalg.norm(p["ink"] - me[0])) for p in dark_peers) > 18
        stroke_odd = False
        med = 0.0
        if len(same_ink) >= 3:
            ps = [p["stroke"] for p in same_ink]
            med = statistics.median(ps)
            mad = statistics.median([abs(x - med) for x in ps]) or 0.005
            stroke_odd = abs(me[1] - med) > max(0.05, 5 * mad)
        ink_off = nearest_ink
        if (stroke_odd or ink_odd) and W >= 500:  # stroke widths are noise on tiny images
            en, hi, kn = FIELD[key]
            F.append(_f("TEXT_STYLE_MISMATCH", "high", 30,
                        T(f"The {en} is written in a different style", f"{hi} अलग अंदाज़ में लिखा है", f"{kn} ಬೇರೆ ಶೈಲಿಯಲ್ಲಿ ಬರೆಯಲಾಗಿದೆ"),
                        T(f"Its letter thickness or colour doesn't match other text of the same size on this screen, as if it was typed in separately.",
                          f"इसके अक्षरों की मोटाई या रंग इसी आकार के बाकी टेक्स्ट से मेल नहीं खाता, जैसे इसे अलग से टाइप किया गया हो।",
                          f"ಇದರ ಅಕ್ಷರಗಳ ದಪ್ಪ ಅಥವಾ ಬಣ್ಣ ಇದೇ ಗಾತ್ರದ ಇತರ ಪಠ್ಯಕ್ಕೆ ಹೊಂದುವುದಿಲ್ಲ, ಪ್ರತ್ಯೇಕವಾಗಿ ಟೈಪ್ ಮಾಡಿದಂತೆ."),
                        [f"Stroke ratio {me[1]:.3f} vs {med:.3f} for {len(peers)} similar words", f"Ink colour difference {ink_off:.0f}"], box))

    # error level analysis (meaningful for JPEG files)
    heat = None
    if meta["format"] == "JPEG" and lines:
        ela = _ela(im)
        heat = ela
        def box_ela(b):
            x0, y0, x1, y1 = _clip(b, W, H)
            reg = ela[y0:y1, x0:x1]
            return float(reg.mean()) if reg.size else None
        others = [box_ela(l["box"]) for l in lines if l["box"] not in fields.values()]
        others = [o for o in others if o]
        if len(others) >= 4:
            base = statistics.median(others)
            for key in ("amount", "utr"):
                if key in fields:
                    v = box_ela(fields[key])
                    if v and base > 0.5 and (v / base > 2.4 or v / base < 0.35):
                        en, hi, kn = FIELD[key]
                        F.append(_f("ELA_OUTLIER", "high", 25,
                                    T(f"Compression pattern around the {en} is different", f"{hi} के आस-पास कम्प्रेशन का पैटर्न अलग है", f"{kn} ಸುತ್ತ ಕಂಪ್ರೆಶನ್ ಮಾದರಿ ಬೇರೆಯಾಗಿದೆ"),
                                    T("When part of a JPEG is edited and saved again, that part compresses differently from the rest. This area stands out.",
                                      "JPEG का कोई हिस्सा एडिट करके फिर सेव करने पर वह हिस्सा बाकी से अलग तरह कम्प्रेस होता है। यह हिस्सा अलग दिखता है।",
                                      "JPEG ನ ಒಂದು ಭಾಗವನ್ನು ಎಡಿಟ್ ಮಾಡಿ ಮತ್ತೆ ಉಳಿಸಿದಾಗ ಆ ಭಾಗ ಉಳಿದದ್ದಕ್ಕಿಂತ ಬೇರೆ ರೀತಿ ಕಂಪ್ರೆಸ್ ಆಗುತ್ತದೆ. ಈ ಭಾಗ ಬೇರೆಯಾಗಿ ಕಾಣುತ್ತದೆ."),
                                    [f"Error level {v:.1f} vs {base:.1f} for other text"], fields[key]))

    # content logic
    if HAS_OCR and lines:
        if ex["status"] in ("pending", "failed", "request"):
            word = ex.get("status_word") or ex["status"]
            F.append(_f("NOT_COMPLETED", "critical", 50,
                        T(f"Shows a '{word}' payment, not a completed one", f"यह '{word}' पेमेंट दिखाता है, पूरा हुआ पेमेंट नहीं", f"ಇದು '{word}' ಪಾವತಿ ತೋರಿಸುತ್ತದೆ, ಪೂರ್ಣಗೊಂಡ ಪಾವತಿ ಅಲ್ಲ"),
                        T("Money has not reached you. Pending or failed payments are a common trick: the screenshot looks like proof, but nothing was credited.",
                          "पैसे आप तक नहीं पहुँचे हैं। पेंडिंग या फ़ेल पेमेंट एक आम चाल है: स्क्रीनशॉट सबूत जैसा दिखता है, पर पैसे जमा नहीं हुए।",
                          "ಹಣ ನಿಮಗೆ ತಲುಪಿಲ್ಲ. ಬಾಕಿ ಅಥವಾ ವಿಫಲ ಪಾವತಿ ಸಾಮಾನ್ಯ ತಂತ್ರ: ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಸಾಕ್ಷಿಯಂತೆ ಕಾಣುತ್ತದೆ, ಆದರೆ ಹಣ ಜಮೆಯಾಗಿಲ್ಲ."),
                        [f"Status text: “{word}”"]))
        looks_like_payment = bool(ex["amount"] or ex["utr"] or ex["app"] or ex["status"])
        if not looks_like_payment:
            F.append(_f("NOT_A_RECEIPT", "medium", 10,
                        T("Doesn't look like a payment receipt", "यह पेमेंट की रसीद जैसा नहीं दिखता", "ಇದು ಪಾವತಿ ರಸೀದಿಯಂತೆ ಕಾಣುವುದಿಲ್ಲ"),
                        T("We couldn't find an amount, status or reference number on this image.",
                          "इस तस्वीर में रकम, स्टेटस या रेफ़रेंस नंबर नहीं मिला।",
                          "ಈ ಚಿತ್ರದಲ್ಲಿ ಮೊತ್ತ, ಸ್ಥಿತಿ ಅಥವಾ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಸಿಗಲಿಲ್ಲ."),
                        []))
        elif not ex["utr"]:
            F.append(_f("NO_UTR", "medium", 15,
                        T("No 12-digit UPI reference number visible", "12 अंकों का UPI रेफ़रेंस नंबर नहीं दिखा", "12 ಅಂಕಿಯ UPI ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಕಾಣುತ್ತಿಲ್ಲ"),
                        T("Every completed UPI payment has a 12-digit reference number (UTR). Without it you can't match the payment in your bank statement.",
                          "हर पूरे UPI पेमेंट का 12 अंकों का रेफ़रेंस नंबर (UTR) होता है। इसके बिना आप बैंक स्टेटमेंट में पेमेंट नहीं मिला सकते।",
                          "ಪ್ರತಿ ಪೂರ್ಣಗೊಂಡ UPI ಪಾವತಿಗೆ 12 ಅಂಕಿಯ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ (UTR) ಇರುತ್ತದೆ. ಅದಿಲ್ಲದೆ ಬ್ಯಾಂಕ್ ಸ್ಟೇಟ್‌ಮೆಂಟ್‌ನಲ್ಲಿ ಪಾವತಿ ಹೊಂದಿಸಲು ಆಗುವುದಿಲ್ಲ."),
                        ["Reference label seen but no 12-digit number" if ex["has_utr_label"] else "No reference number label found"]))
        # PhonePe-style transaction ids embed the payment minute (T + YYMMDDHHmm); it must match the time printed.
        if ex.get("txn") and ex["txn"]["ts"] and ex.get("date") and ex["date"]["has_time"]:
            tid = dt.datetime.fromisoformat(ex["txn"]["ts"])
            shown = dt.datetime.fromisoformat(ex["date"]["iso"])
            if abs((tid - shown).total_seconds()) > 180:
                F.append(_f("TXN_TIME_MISMATCH", "high", 35,
                            T("Transaction ID doesn't match the time shown", "ट्रांज़ैक्शन ID दिखाए गए समय से मेल नहीं खाती", "ವಹಿವಾಟು ID ತೋರಿಸಿದ ಸಮಯಕ್ಕೆ ಹೊಂದುವುದಿಲ್ಲ"),
                            T("This app's transaction ID contains the exact date and minute of the payment. It points to a different time than the one printed, so one of them was changed.",
                              "इस ऐप की ट्रांज़ैक्शन ID में पेमेंट की सही तारीख़ और मिनट होते हैं। यह छपे समय से अलग समय बताती है, यानी दोनों में से एक बदला गया है।",
                              "ಈ ಆ್ಯಪ್‌ನ ವಹಿವಾಟು ID ಯಲ್ಲಿ ಪಾವತಿಯ ನಿಖರ ದಿನಾಂಕ ಮತ್ತು ನಿಮಿಷ ಇರುತ್ತದೆ. ಅದು ಮುದ್ರಿತ ಸಮಯಕ್ಕಿಂತ ಬೇರೆ ಸಮಯ ತೋರಿಸುತ್ತದೆ, ಅಂದರೆ ಒಂದನ್ನು ಬದಲಿಸಲಾಗಿದೆ."),
                            [f"Transaction ID {ex['txn']['id']} → {tid.strftime('%d %b %Y, %I:%M %p')}", f"Time shown: {ex['date']['text']}"],
                            ex["txn"]["box"]))
        if ex["date"]:
            d = dt.datetime.fromisoformat(ex["date"]["iso"])
            now = dt.datetime.now(IST)
            if d > now + dt.timedelta(hours=12 if ex["date"]["has_time"] else 36):
                F.append(_f("FUTURE_DATE", "high", 30,
                            T("The payment date is in the future", "पेमेंट की तारीख़ भविष्य की है", "ಪಾವತಿ ದಿನಾಂಕ ಭವಿಷ್ಯದ್ದು"),
                            T("A real receipt can't be dated after today.", "असली रसीद आज के बाद की तारीख़ की नहीं हो सकती।", "ನಿಜವಾದ ರಸೀದಿಗೆ ಇಂದಿನ ನಂತರದ ದಿನಾಂಕ ಇರಲು ಸಾಧ್ಯವಿಲ್ಲ."),
                            [f"Date shown: {ex['date']['text']}"], ex["date"]["box"]))
            elif now - d > dt.timedelta(days=1):
                days = (now - d).days
                F.append(_f("OLD_PAYMENT", "medium", 12,
                            T(f"This payment is {days} days old", f"यह पेमेंट {days} दिन पुराना है", f"ಈ ಪಾವತಿ {days} ದಿನ ಹಳೆಯದು"),
                            T("If they say they just paid, this may be an old screenshot being reused.",
                              "अगर वे कह रहे हैं कि अभी पेमेंट किया, तो यह पुराना स्क्रीनशॉट दोबारा इस्तेमाल हो सकता है।",
                              "ಅವರು ಈಗಷ್ಟೇ ಪಾವತಿಸಿದೆ ಎಂದರೆ, ಇದು ಮರುಬಳಕೆಯಾದ ಹಳೆಯ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಆಗಿರಬಹುದು."),
                            [f"Date shown: {ex['date']['text']}"], ex["date"]["box"]))
        big = [a for a in ex["amounts_all"] if a >= 1]
        if ex["amount"] and len(big) > 1:
            head = ex["amount"]["value"]
            others = [a for a in big if abs(a - head) > 0.009]
            if others and all(abs(o - head) / max(head, 1) > 0.001 for o in others):
                F.append(_f("AMOUNT_MISMATCH", "critical", 45,
                            T("Different amounts appear on the same receipt", "एक ही रसीद पर अलग-अलग रकम है", "ಒಂದೇ ರಸೀದಿಯಲ್ಲಿ ಬೇರೆ ಬೇರೆ ಮೊತ್ತಗಳಿವೆ"),
                            T("The big amount at the top doesn't match another amount on the receipt. Edits often change only one of them.",
                              "ऊपर लिखी बड़ी रकम रसीद की दूसरी रकम से मेल नहीं खाती। एडिट में अक्सर सिर्फ़ एक ही बदली जाती है।",
                              "ಮೇಲಿನ ದೊಡ್ಡ ಮೊತ್ತ ರಸೀದಿಯ ಇನ್ನೊಂದು ಮೊತ್ತಕ್ಕೆ ಹೊಂದುವುದಿಲ್ಲ. ಎಡಿಟ್‌ನಲ್ಲಿ ಸಾಮಾನ್ಯವಾಗಿ ಒಂದನ್ನು ಮಾತ್ರ ಬದಲಿಸಲಾಗುತ್ತದೆ."),
                            [f"Headline: ₹{head:,.2f}", "Also shown: " + ", ".join(f"₹{o:,.2f}" for o in others[:3])], ex["amount"]["box"]))
        if ex.get("zero_amounts") and big:
            z = ex["zero_amounts"][0]
            F.append(_f("AMOUNT_ERASED", "critical", 50,
                        T("One amount on this receipt reads ₹0", "इस रसीद पर एक रकम ₹0 लिखी है", "ಈ ರಸೀದಿಯಲ್ಲಿ ಒಂದು ಮೊತ್ತ ₹0 ಎಂದಿದೆ"),
                        T(f"Another place on the same receipt says ₹{max(big):,.2f}. Real receipts show the same amount everywhere — a digit has been erased or changed.",
                          f"इसी रसीद पर दूसरी जगह ₹{max(big):,.2f} लिखा है। असली रसीद में हर जगह एक ही रकम होती है — कोई अंक मिटाया या बदला गया है।",
                          f"ಇದೇ ರಸೀದಿಯ ಇನ್ನೊಂದು ಕಡೆ ₹{max(big):,.2f} ಇದೆ. ನಿಜವಾದ ರಸೀದಿಯಲ್ಲಿ ಎಲ್ಲೆಡೆ ಒಂದೇ ಮೊತ್ತ ಇರುತ್ತದೆ — ಒಂದು ಅಂಕಿ ಅಳಿಸಲಾಗಿದೆ ಅಥವಾ ಬದಲಿಸಲಾಗಿದೆ."),
                        ["Reads ₹0 here", "Also shown: " + ", ".join(f"₹{a:,.2f}" for a in big[:3])], z["box"]))
        if expected_amount and ex["amount"] and abs(ex["amount"]["value"] - expected_amount) > 0.009:
            F.append(_f("EXPECTED_AMOUNT_MISMATCH", "critical", 45,
                        T(f"Amount is ₹{ex['amount']['value']:,.2f}, not the ₹{expected_amount:,.2f} you expected",
                          f"रकम ₹{ex['amount']['value']:,.2f} है, आपकी उम्मीद के ₹{expected_amount:,.2f} नहीं",
                          f"ಮೊತ್ತ ₹{ex['amount']['value']:,.2f}, ನೀವು ನಿರೀಕ್ಷಿಸಿದ ₹{expected_amount:,.2f} ಅಲ್ಲ"),
                        T("The screenshot shows a different amount from what you are owed.",
                          "स्क्रीनशॉट में आपकी बकाया रकम से अलग रकम दिख रही है।",
                          "ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ನಿಮಗೆ ಬರಬೇಕಾದ ಮೊತ್ತಕ್ಕಿಂತ ಬೇರೆ ಮೊತ್ತ ತೋರಿಸುತ್ತದೆ."),
                        [f"Read: ₹{ex['amount']['value']:,.2f}", f"Expected: ₹{expected_amount:,.2f}"], ex["amount"]["box"]))
    # --- cross-check with other screenshots of the same payment -------------------------------------------
    # Two versions of one receipt means one of them is edited, but not necessarily THIS one. Blame the version
    # that shows its own signs of editing; the clean one is told an edited copy exists.
    own_score = min(100, sum(x["points"] for x in F))
    if any(x["severity"] == "critical" for x in F):
        own_score = max(own_score, 70)
    mine_bad = own_score >= 35
    prev = seen_lookup(ex["utr"]["utr"], sha, ph, ex["amount"]["value"] if ex.get("amount") else None) \
        if (seen_lookup and ex.get("utr") and lines) else None
    fp = {"utr": ex["utr"]["utr"] if ex.get("utr") else None, "txn": ex["txn"]["id"] if ex.get("txn") else None,
          "date": ex["date"]["text"] if ex.get("date") else None, "amount": ex["amount"]["value"] if ex.get("amount") else None,
          "phash": ph}
    sim = similar_lookup(fp, sha) if (similar_lookup and (fp["utr"] or fp["txn"])) else None
    match = sim or prev
    if match:
        other_bad = (match.get("other_score") or 0) >= 35
        ev = sim["evidence"] if sim else [f"Reference: {ex['utr']['utr']}", f"Seen before {prev['count']} time(s)" + (f", with amount ₹{prev['amount']:,.2f}" if prev.get("amount") else "")]
        box = (ex["amount"]["box"] if ex.get("amount") else None) if sim else ex["utr"]["box"]
        if mine_bad:
            if sim:
                F.append(_f("EDITED_COPY", "critical", 50,
                            T("Looks like an edited copy of another receipt", "किसी दूसरी रसीद की एडिट की हुई कॉपी लगती है", "ಇನ್ನೊಂದು ರಸೀದಿಯ ಎಡಿಟ್ ಮಾಡಿದ ನಕಲಿನಂತಿದೆ"),
                            T("We've seen a receipt for the same payment moment with almost the same reference numbers but a different amount, and this one also shows signs of editing.",
                              "हमने उसी समय की एक रसीद देखी है जिसके रेफ़रेंस नंबर लगभग यही हैं, पर रकम अलग है — और इस रसीद में एडिटिंग के निशान भी हैं।",
                              "ಅದೇ ಸಮಯದ, ಬಹುತೇಕ ಇದೇ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆಗಳ ಆದರೆ ಬೇರೆ ಮೊತ್ತದ ರಸೀದಿಯನ್ನು ನಾವು ನೋಡಿದ್ದೇವೆ — ಮತ್ತು ಈ ರಸೀದಿಯಲ್ಲೂ ಎಡಿಟ್ ಗುರುತುಗಳಿವೆ."),
                            ev, box))
            else:
                F.append(_f("UTR_REUSED", "high", 40,
                            T("This reference number was already used in a different screenshot", "यही रेफ़रेंस नंबर किसी दूसरे स्क्रीनशॉट में पहले आ चुका है", "ಇದೇ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಬೇರೆ ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ನಲ್ಲಿ ಈಗಾಗಲೇ ಬಳಕೆಯಾಗಿದೆ"),
                            T("Each UPI payment has its own reference number. The same number on a different image means one of them is fake or recycled — and this one shows signs of editing.",
                              "हर UPI पेमेंट का अपना रेफ़रेंस नंबर होता है। अलग तस्वीर पर वही नंबर मतलब एक नकली या दोबारा इस्तेमाल किया गया है — और इसमें एडिटिंग के निशान हैं।",
                              "ಪ್ರತಿ UPI ಪಾವತಿಗೆ ತನ್ನದೇ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಇರುತ್ತದೆ. ಬೇರೆ ಚಿತ್ರದಲ್ಲಿ ಅದೇ ಸಂಖ್ಯೆ ಇದ್ದರೆ ಒಂದು ನಕಲಿ ಅಥವಾ ಮರುಬಳಕೆ — ಮತ್ತು ಇದರಲ್ಲಿ ಎಡಿಟ್ ಗುರುತುಗಳಿವೆ."),
                            ev, box))
        elif other_bad:
            F.append(_f("ORIGINAL_OF_EDITED", "info", 0,
                        T("An edited copy of this receipt has been checked before", "इस रसीद की एक एडिट की हुई कॉपी पहले जाँची जा चुकी है", "ಈ ರಸೀದಿಯ ಎಡಿಟ್ ಮಾಡಿದ ನಕಲನ್ನು ಹಿಂದೆ ಪರಿಶೀಲಿಸಲಾಗಿದೆ"),
                        T("Someone checked a version of this receipt with a different amount, and that version showed signs of editing. This one shows none, so it looks like the original — still confirm the amount in your bank.",
                          "किसी ने इसी रसीद का अलग रकम वाला रूप जाँचा था, और उसमें एडिटिंग के निशान थे। इसमें कोई निशान नहीं है, तो यह असली लगती है — फिर भी बैंक में रकम देख लें।",
                          "ಯಾರೋ ಈ ರಸೀದಿಯ ಬೇರೆ ಮೊತ್ತದ ಆವೃತ್ತಿಯನ್ನು ಪರಿಶೀಲಿಸಿದ್ದರು, ಅದರಲ್ಲಿ ಎಡಿಟ್ ಗುರುತುಗಳಿದ್ದವು. ಇದರಲ್ಲಿ ಯಾವುದೂ ಇಲ್ಲ, ಹಾಗಾಗಿ ಇದು ಮೂಲದಂತಿದೆ — ಆದರೂ ಬ್ಯಾಂಕ್‌ನಲ್ಲಿ ಮೊತ್ತ ಖಚಿತಪಡಿಸಿ."),
                        ev, None))
        else:
            F.append(_f("TWO_VERSIONS", "high", 35,
                        T("Two different versions of this receipt exist", "इस रसीद के दो अलग रूप मौजूद हैं", "ಈ ರಸೀದಿಯ ಎರಡು ಬೇರೆ ಆವೃತ್ತಿಗಳಿವೆ"),
                        T("Another screenshot of the same payment shows a different amount or reference. Only one can be real, and we can't tell which from the images alone — check your bank app.",
                          "उसी पेमेंट का एक और स्क्रीनशॉट अलग रकम या रेफ़रेंस दिखाता है। असली सिर्फ़ एक हो सकता है, और तस्वीरों से पता नहीं चलता कौन — अपना बैंक ऐप देखें।",
                          "ಅದೇ ಪಾವತಿಯ ಇನ್ನೊಂದು ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಬೇರೆ ಮೊತ್ತ ಅಥವಾ ಉಲ್ಲೇಖ ತೋರಿಸುತ್ತದೆ. ಒಂದೇ ನಿಜವಾಗಿರಬಹುದು, ಚಿತ್ರಗಳಿಂದ ಯಾವುದು ಎಂದು ಹೇಳಲಾಗದು — ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ನೋಡಿ."),
                        ev, box))

    # the strongest check: what the merchant's own bank actually says
    sms = parse_bank_sms(bank_sms) if bank_sms else None
    if sms and (sms["amount"] is not None or sms["utr"]):
        shot_amt = ex["amount"]["value"] if ex.get("amount") else None
        shot_utr = ex["utr"]["utr"] if ex.get("utr") else None
        same_ref = bool(sms["utr"] and shot_utr and sms["utr"] == shot_utr)
        amt_match = sms["amount"] is not None and shot_amt is not None and abs(sms["amount"] - shot_amt) < 0.01
        if sms["utr"] and shot_utr and not same_ref:
            F.append(_f("BANK_DIFFERENT_PAYMENT", "high", 40,
                        T("Your bank message is for a different payment", "आपका बैंक मैसेज किसी दूसरे पेमेंट का है", "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಸಂದೇಶ ಬೇರೆ ಪಾವತಿಯದು"),
                        T("The reference number in your bank SMS doesn't match the one on the screenshot. Look for a credit with the screenshot's reference number; if there is none, you weren't paid.",
                          "आपके बैंक SMS का रेफ़रेंस नंबर स्क्रीनशॉट वाले से मेल नहीं खाता। स्क्रीनशॉट वाले रेफ़रेंस नंबर का क्रेडिट ढूँढें; न मिले तो पैसे नहीं आए।",
                          "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ SMS ನ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ನದಕ್ಕೆ ಹೊಂದುವುದಿಲ್ಲ. ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ನ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆಯ ಜಮೆ ಹುಡುಕಿ; ಇಲ್ಲದಿದ್ದರೆ ಹಣ ಬಂದಿಲ್ಲ."),
                        [f"Bank SMS reference: {sms['utr']}", f"Screenshot reference: {shot_utr}"], ex["utr"]["box"]))
        elif sms["amount"] is not None and shot_amt is not None and not amt_match:
            F.append(_f("BANK_AMOUNT_MISMATCH", "critical", 60,
                        T(f"Your bank received ₹{sms['amount']:,.2f}, but the screenshot shows ₹{shot_amt:,.2f}",
                          f"आपके बैंक में ₹{sms['amount']:,.2f} आए, पर स्क्रीनशॉट ₹{shot_amt:,.2f} दिखाता है",
                          f"ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ಗೆ ₹{sms['amount']:,.2f} ಬಂದಿದೆ, ಆದರೆ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ₹{shot_amt:,.2f} ತೋರಿಸುತ್ತದೆ"),
                        T("The screenshot's amount has been changed. Only the amount in your bank message was actually paid.",
                          "स्क्रीनशॉट की रकम बदली गई है। असल में सिर्फ़ आपके बैंक मैसेज वाली रकम ही आई है।",
                          "ಸ್ಕ್ರೀನ್‌ಶಾಟ್‌ನ ಮೊತ್ತವನ್ನು ಬದಲಿಸಲಾಗಿದೆ. ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಸಂದೇಶದ ಮೊತ್ತ ಮಾತ್ರ ನಿಜವಾಗಿ ಬಂದಿದೆ."),
                        [f"Bank SMS: ₹{sms['amount']:,.2f}" + (f" (ref {sms['utr']})" if sms["utr"] else ""), f"Screenshot: ₹{shot_amt:,.2f}"],
                        ex["amount"]["box"]))
        elif amt_match and (same_ref or not sms["utr"]):
            F.append(_f("BANK_MATCH", "info", 0,
                        T("Matches the bank message you pasted", "आपके बैंक मैसेज से मेल खाता है", "ನೀವು ಅಂಟಿಸಿದ ಬ್ಯಾಂಕ್ ಸಂದೇಶಕ್ಕೆ ಹೊಂದುತ್ತದೆ"),
                        T("The amount" + (" and reference number" if same_ref else "") + " agree with your bank. That is the proof that counts.",
                          "रकम" + (" और रेफ़रेंस नंबर" if same_ref else "") + " आपके बैंक से मेल खाते हैं। असली सबूत यही है।",
                          "ಮೊತ್ತ" + (" ಮತ್ತು ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ" if same_ref else "") + " ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ಗೆ ಹೊಂದುತ್ತವೆ. ನಿಜವಾದ ಸಾಕ್ಷಿ ಇದೇ."),
                        [f"Bank SMS: ₹{sms['amount']:,.2f}" + (f", ref {sms['utr']}" if sms["utr"] else "")]))
        if sms["direction"] == "debit":
            F.append(_f("BANK_SMS_DEBIT", "medium", 10,
                        T("The message you pasted is a debit, not a credit", "आपने जो मैसेज डाला वह डेबिट का है, क्रेडिट का नहीं", "ನೀವು ಅಂಟಿಸಿದ ಸಂದೇಶ ಡೆಬಿಟ್, ಕ್ರೆಡಿಟ್ ಅಲ್ಲ"),
                        T("Paste the message that says money was credited to YOUR account.", "वह मैसेज डालें जिसमें आपके खाते में पैसे जमा होने की बात हो।",
                          "ನಿಮ್ಮ ಖಾತೆಗೆ ಹಣ ಜಮೆಯಾಗಿದೆ ಎನ್ನುವ ಸಂದೇಶವನ್ನು ಅಂಟಿಸಿ."), []))

    # always: the only real proof
    F.append(_f("VERIFY_IN_BANK", "info", 0,
                T("A screenshot is never proof of payment", "स्क्रीनशॉट कभी भी पेमेंट का सबूत नहीं है", "ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಎಂದಿಗೂ ಪಾವತಿಯ ಸಾಕ್ಷಿ ಅಲ್ಲ"),
                T("Before handing over goods, open your own UPI app or bank SMS and check that the money has actually arrived, with the same reference number.",
                  "सामान देने से पहले अपना UPI ऐप या बैंक SMS खोलें और देखें कि पैसे सच में आए हैं, उसी रेफ़रेंस नंबर के साथ।",
                  "ಸಾಮಾನು ಕೊಡುವ ಮೊದಲು ನಿಮ್ಮ UPI ಆ್ಯಪ್ ಅಥವಾ ಬ್ಯಾಂಕ್ SMS ತೆರೆದು ಹಣ ನಿಜವಾಗಿ ಬಂದಿದೆಯೇ, ಅದೇ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆಯೊಂದಿಗೆ, ಎಂದು ನೋಡಿ."),
                [f"Look for reference {ex['utr']['utr']} in your own app" if ex.get("utr") else ""]))

    F.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], -x["points"]))
    score = min(100, sum(x["points"] for x in F))
    if any(x["severity"] == "critical" for x in F):
        score = max(score, 70)
    for threshold, level, headline, advice in SHOT_VERDICTS:
        if score >= threshold:
            break

    return {
        "kind": "shot",
        "id": sha,
        "file": {"name": filename, "size": len(data), "format": meta["format"], "width": W, "height": H, "sha256": sha, "phash": ph},
        "details": {
            "ocr_available": HAS_OCR, "ocr_engine": OCR_ENGINE, "text_read": bool(lines),
            "app": ex.get("app"), "status": ex.get("status"),
            "amount": ex["amount"]["value"] if ex.get("amount") else None,
            "amounts_all": ex.get("amounts_all", []),
            "utr": ex["utr"]["utr"] if ex.get("utr") else None,
            "date": ex["date"]["text"] if ex.get("date") else None,
            "date_iso": ex["date"]["iso"] if ex.get("date") else None,
            "payee": ex["payee"]["text"] if ex.get("payee") else None,
            "expected_amount": expected_amount,
            "text_excerpt": (ex.get("text") or "")[:600],
            "fields_found": sorted(fields),
            "txn_id": ex["txn"]["id"] if ex.get("txn") else None,
            "glyph": {k: glyph[k] for k in ("spread", "profile", "classes")} if glyph else None,
            "bank_sms": {k: sms[k] for k in ("amount", "utr", "direction")} if sms else None,
            "fingerprint": fp,
            "own_score": own_score,
        },
        "verdict": {"score": score, "level": level, "headline": headline, "advice": advice},
        "findings": F,
        "annotated": _annotate(im, F, fields, heat),
        "limitations": [
            "Checks look for common editing mistakes and impossible details. A carefully made fake can pass, and "
            "screenshots forwarded on WhatsApp lose their metadata and are recompressed. Always confirm the money in your own bank or UPI app."
            + ("" if HAS_OCR else " Text checks were skipped because the OCR engine (tesseract) is not installed on the server.")
        ],
    }


SHOT_VERDICTS = [
    (70, "danger", T("Likely fake or edited", "संभवतः नकली या एडिट किया हुआ", "ನಕಲಿ ಅಥವಾ ಎಡಿಟ್ ಮಾಡಿದ್ದು ಇರಬಹುದು"),
     T("Don't hand over goods or money based on this screenshot. Check your own bank or UPI app: if the money isn't there, it wasn't paid.",
       "इस स्क्रीनशॉट के भरोसे सामान या पैसे न दें। अपना बैंक या UPI ऐप देखें: पैसे वहाँ नहीं हैं, तो पेमेंट नहीं हुआ।",
       "ಈ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ನಂಬಿ ಸಾಮಾನು ಅಥವಾ ಹಣ ಕೊಡಬೇಡಿ. ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಅಥವಾ UPI ಆ್ಯಪ್ ನೋಡಿ: ಹಣ ಅಲ್ಲಿ ಇಲ್ಲದಿದ್ದರೆ ಪಾವತಿ ಆಗಿಲ್ಲ.")),
    (35, "suspicious", T("Suspicious — don't trust it yet", "संदिग्ध — अभी भरोसा न करें", "ಸಂಶಯಾಸ್ಪದ — ಇನ್ನೂ ನಂಬಬೇಡಿ"),
     T("Some details don't add up. Confirm the credit in your own bank or UPI app before you continue.",
       "कुछ बातें मेल नहीं खातीं। आगे बढ़ने से पहले अपने बैंक या UPI ऐप में पैसे आने की पुष्टि करें।",
       "ಕೆಲವು ವಿವರಗಳು ಹೊಂದುತ್ತಿಲ್ಲ. ಮುಂದುವರಿಯುವ ಮೊದಲು ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಅಥವಾ UPI ಆ್ಯಪ್‌ನಲ್ಲಿ ಹಣ ಬಂದಿದೆಯೇ ಖಚಿತಪಡಿಸಿ.")),
    (12, "caution", T("Check before you trust it", "भरोसा करने से पहले जाँचें", "ನಂಬುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ"),
     T("Nothing clearly fake, but something is missing or unusual. Match the reference number in your own app.",
       "कुछ साफ़ नकली नहीं, पर कुछ कमी या अजीब बात है। अपने ऐप में रेफ़रेंस नंबर मिलाएँ।",
       "ಸ್ಪಷ್ಟವಾಗಿ ನಕಲಿ ಏನಿಲ್ಲ, ಆದರೆ ಏನೋ ಕಾಣೆಯಾಗಿದೆ ಅಥವಾ ಅಸಾಮಾನ್ಯವಾಗಿದೆ. ನಿಮ್ಮ ಆ್ಯಪ್‌ನಲ್ಲಿ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಹೊಂದಿಸಿ.")),
    (0, "low", T("No signs of editing found", "एडिटिंग के कोई निशान नहीं मिले", "ಎಡಿಟಿಂಗ್ ಗುರುತುಗಳು ಕಂಡುಬಂದಿಲ್ಲ"),
     T("That still isn't proof. The money is only yours once your own bank or UPI app shows it.",
       "फिर भी यह सबूत नहीं है। पैसे तभी आपके हैं जब आपका अपना बैंक या UPI ऐप उन्हें दिखाए।",
       "ಆದರೂ ಇದು ಸಾಕ್ಷಿ ಅಲ್ಲ. ನಿಮ್ಮ ಸ್ವಂತ ಬ್ಯಾಂಕ್ ಅಥವಾ UPI ಆ್ಯಪ್ ತೋರಿಸಿದಾಗ ಮಾತ್ರ ಹಣ ನಿಮ್ಮದು.")),
]


def _annotate(im: Image.Image, findings: list[dict], fields: dict, heat) -> str:
    base = im.copy()
    if heat is not None:
        h = np.clip(heat * 12, 0, 255).astype(np.uint8)
        red = Image.fromarray(np.stack([h, np.zeros_like(h), np.zeros_like(h)], axis=2))
        base = Image.blend(base, red, 0.35)
    d = ImageDraw.Draw(base, "RGBA")
    lw = max(2, im.width // 250)
    flagged = [f for f in findings if f.get("box")]
    for key, box in fields.items():
        if not any(f.get("box") == list(box) for f in flagged):
            d.rectangle(box, outline=(79, 70, 229, 200), width=max(1, lw // 2))
    for f in flagged:
        col = (200, 30, 58, 255) if f["severity"] == "critical" else (217, 72, 15, 255)
        x0, y0, x1, y1 = f["box"]
        d.rectangle((x0 - lw * 2, y0 - lw * 2, x1 + lw * 2, y1 + lw * 2), outline=col, width=lw)
        d.rectangle((x0 - lw * 2, y0 - lw * 2, x1 + lw * 2, y1 + lw * 2), fill=col[:3] + (40,))
    if base.width > 640:
        base = base.resize((640, int(base.height * 640 / base.width)), Image.BILINEAR)
    buf = io.BytesIO()
    base.convert("RGB").save(buf, "JPEG", quality=82)
    return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

