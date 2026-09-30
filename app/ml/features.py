"""Features for the UPI scam model.

One function is used for training AND for live predictions, so the two can never drift apart. It works from the
output of PayGuard's existing UPI parser (qr.analyzer: `details`, including the strict `upi_format` check), the
existing keyword/handle lists, and community history. It deliberately does NOT use the rule engine's score or
verdict: the model has to learn its own mapping from raw signals to risk.
"""
from __future__ import annotations

import math
import re

from ..qr.analyzer import (AUTHORITY_WORDS, BRAND_DOMAINS, KNOWN_PSP_HANDLES, LURE_WORDS, MERCHANT_VPA_HINTS,
                           analyze_payload)

EVERYDAY_WORDS = ("rent", "fees", "fee payment", "tuition", "groceries", "grocery", "dinner", "lunch", "salary", "emi", "bill",
                  "invoice", "order", "gift", "birthday", "wedding", "hospital bill", "school", "college", "petrol", "movie",
                  "trip", "share", "loan return", "maid", "milk", "vegetables", "donation", "deposit for house")
RECEIVE_WORDS = ("receive", "received", "credit", "credited", "refund", "cashback", "cash back", "claim", "get money",
                 "reward", "prize", "winning", "lottery")

# (name, human label shown in explanations)
FEATURES: list[tuple[str, str]] = [
    ("uri_valid", "UPI link is correctly formatted"),
    ("format_problem_count", "Number of UPI format problems"),
    ("action_collect", "It is a collect request (asks you to approve a payment)"),
    ("action_mandate", "It sets up AutoPay / repeated payments"),
    ("vpa_length", "Length of the UPI ID"),
    ("vpa_local_length", "Length of the part before @"),
    ("vpa_local_digit_ratio", "Share of digits in the UPI ID"),
    ("vpa_is_phone_number", "UPI ID is a mobile number"),
    ("vpa_long_digit_run", "UPI ID contains a long random-looking number"),
    ("vpa_handle_known", "UPI handle (@bank) is a known bank/app"),
    ("vpa_brand_or_authority", "UPI ID contains a bank/brand/authority word"),
    ("vpa_merchant_hint", "UPI ID looks like a merchant account"),
    ("has_amount", "Amount is pre-filled"),
    ("amount_log10", "Size of the amount"),
    ("amount_ends_99", "Amount ends in 99 (e.g. 4,999)"),
    ("amount_round_thousand", "Amount is a round thousand"),
    ("has_payee_name", "Payee name is present"),
    ("payee_name_length", "Length of the payee name"),
    ("payee_authority_words", "Payee name claims to be a bank/police/government/support"),
    ("payee_lure_words", "Payee name uses refund/prize/cashback words"),
    ("payee_brand_words", "Payee name mentions a bank or payment brand"),
    ("authority_name_personal_account", "Official-sounding name on a personal (non-merchant) account"),
    ("has_note", "Payment note is present"),
    ("note_lure_words", "Payment note uses scam bait words"),
    ("note_receive_words", "Payment note talks about receiving money"),
    ("note_everyday_words", "Payment note describes an everyday purpose (rent, fees, bill...)"),
    ("note_has_link", "Payment note contains a link"),
    ("note_has_phone", "Payment note contains a phone number"),
    ("merchant_code_present", "Registered merchant code (mc) present"),
    ("transaction_ref_present", "Transaction reference (tr) present"),
    ("signed_qr", "QR is digitally signed"),
    ("recurring_params", "Contains recurring-payment parameters"),
    ("community_reports_log", "People have reported this UPI ID"),
    ("community_got_me", "People said this UPI ID took their money"),
    ("community_disputes", "People said this UPI ID is genuine"),
    ("lookalike_of_reported", "UPI ID looks like a reported scam ID"),
]
FEATURE_NAMES = [n for n, _ in FEATURES]
# yes/no signals: wording for when the signal is ABSENT (used in explanations)
ABSENT = {
    "uri_valid": "UPI link is NOT correctly formatted", "action_collect": "It is a normal payment (not a collect request)",
    "action_mandate": "No AutoPay / repeated payment", "vpa_is_phone_number": "UPI ID is not a mobile number",
    "vpa_long_digit_run": "UPI ID has no long random number", "vpa_handle_known": "UPI handle (@bank) is not a common one",
    "vpa_brand_or_authority": "UPI ID has no bank/brand/authority words", "vpa_merchant_hint": "UPI ID doesn't look like a merchant account",
    "has_amount": "No amount pre-filled", "amount_ends_99": "Amount doesn't end in 99", "amount_round_thousand": "Amount is not a round thousand",
    "has_payee_name": "No payee name", "authority_name_personal_account": "No official-sounding name on a personal account",
    "has_note": "No payment note", "note_everyday_words": "Payment note has no everyday purpose (rent, fees, bill...)",
    "note_has_link": "No link in the note", "note_has_phone": "No phone number in the note",
    "merchant_code_present": "No registered merchant code", "transaction_ref_present": "No transaction reference",
    "signed_qr": "QR is not digitally signed", "recurring_params": "No recurring-payment parameters",
    "lookalike_of_reported": "UPI ID is not a look-alike of a reported ID",
}
BINARY = set(ABSENT)


def describe(name: str, value: float, baseline: float) -> str:
    """Human wording for a signal's value compared with a typical legitimate payment."""
    if name in BINARY:
        return LABELS[name] if value >= 0.5 else ABSENT[name]
    if value > 0 and baseline == 0 and (name.startswith(("community_", "note_", "payee_")) or name.endswith("_count")):
        return LABELS[name]                   # a count that is normally zero: "it has it" is the clear wording
    return f"{LABELS[name]}: {'higher' if value > baseline else 'lower'} than typical"
LABELS = dict(FEATURES)

_BRANDS = tuple(sorted(set(list(BRAND_DOMAINS) + ["sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
                                                   "googlepay", "npci", "bhim", "amazon", "flipkart", "rbi"])))
_VPA_AUTH = ("refund", "kyc", "support", "helpdesk", "help", "care", "customer", "cashback", "reward", "prize", "lottery",
             "govt", "gov", "police", "tax", "officer", "claim", "bonus", "offer")


def _count(text: str, words) -> int:
    t = f" {text.lower()} "
    return sum(1 for w in words if re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", t))


def from_details(details: dict, community: dict | None = None, lookalike: bool = False) -> list[float]:
    """Feature vector (same order as FEATURE_NAMES) for a parsed UPI QR. `details` is qr.analyzer's output."""
    c = community or {}
    fmt = details.get("upi_format") or {"valid": True, "problems": []}
    q = {k.lower(): v for k, v in (details.get("params") or {}).items()}
    action = (details.get("action") or "pay").lower()
    vpa = (details.get("payee_vpa") or "").strip().lower()
    local, _, handle = vpa.partition("@")
    pn = details.get("payee_name") or ""
    tn = details.get("note") or ""
    am = details.get("amount")
    digits = sum(ch.isdigit() for ch in local)
    is_phone = bool(re.fullmatch(r"(\+?91)?[6-9]\d{9}", local))
    merchant_hint = any(h in vpa for h in MERCHANT_VPA_HINTS)
    mc = (details.get("merchant_code") or "").strip()
    merchant_code = bool(mc and mc != "0000")
    authority_pn = _count(pn, AUTHORITY_WORDS)
    brand_pn = _count(pn, _BRANDS)
    is_merchant = merchant_code or bool(details.get("signed")) or merchant_hint
    f = {
        "uri_valid": float(bool(fmt.get("valid"))),
        "format_problem_count": float(len(fmt.get("problems") or [])),
        "action_collect": float(action == "collect"),
        "action_mandate": float(action in ("mandate", "autopay")),
        "vpa_length": float(len(vpa)),
        "vpa_local_length": float(len(local)),
        "vpa_local_digit_ratio": digits / len(local) if local else 0.0,
        "vpa_is_phone_number": float(is_phone),
        "vpa_long_digit_run": float(bool(re.search(r"\d{6,}", local)) and not is_phone),
        "vpa_handle_known": float(handle in KNOWN_PSP_HANDLES),
        "vpa_brand_or_authority": float(_count(local.replace(".", " ").replace("-", " ").replace("_", " "), _BRANDS + _VPA_AUTH) > 0),
        "vpa_merchant_hint": float(merchant_hint),
        "has_amount": float(am is not None),
        "amount_log10": math.log10(am + 1) if am else 0.0,
        "amount_ends_99": float(bool(am) and int(am) % 100 == 99),
        "amount_round_thousand": float(bool(am) and am >= 1000 and am % 1000 == 0),
        "has_payee_name": float(bool(pn.strip())),
        "payee_name_length": float(len(pn.strip())),
        "payee_authority_words": float(authority_pn),
        "payee_lure_words": float(_count(pn, LURE_WORDS)),
        "payee_brand_words": float(brand_pn),
        "authority_name_personal_account": float((authority_pn + brand_pn) > 0 and not is_merchant),
        "has_note": float(bool(tn.strip())),
        "note_lure_words": float(_count(tn, LURE_WORDS)),
        "note_receive_words": float(_count(tn, RECEIVE_WORDS)),
        "note_everyday_words": float(_count(tn, EVERYDAY_WORDS)),
        "note_has_link": float(bool(re.search(r"https?://|www\.|\bbit\.ly\b|\.(xyz|top|club|online|site)\b", tn, re.I))),
        "note_has_phone": float(bool(re.search(r"(?<!\d)[6-9]\d{9}(?!\d)", tn))),
        "merchant_code_present": float(merchant_code),
        "transaction_ref_present": float(bool(details.get("transaction_ref"))),
        "signed_qr": float(bool(details.get("signed"))),
        "recurring_params": float(any(k in q for k in ("recur", "recurvalue", "recurtype", "mn", "validitystart", "validityend"))),
        "community_reports_log": math.log1p(max(0, int(c.get("reports") or 0))),
        "community_got_me": math.log1p(max(0, int(c.get("got_me") or 0))),
        "community_disputes": math.log1p(max(0, int(c.get("disputes") or 0))),
        "lookalike_of_reported": float(bool(lookalike)),
    }
    return [f[n] for n in FEATURE_NAMES]


def from_payload(payload: str, community: dict | None = None, lookalike: bool = False) -> list[float] | None:
    """Training path: run the SAME existing parser the live app uses, then extract. None if not a UPI payload."""
    d = analyze_payload(payload)["details"]
    if d.get("type") != "upi":
        return None
    return from_details(d, community, lookalike)


def from_report(rep: dict) -> list[float] | None:
    """Live path: a finished QR report (after community reports and look-alike matching were applied)."""
    d = rep.get("details") or {}
    if rep.get("kind") != "qr" or d.get("type") != "upi":
        return None
    lookalike = any(f.get("id") == "UPI_MUTATION" for f in rep.get("findings") or [])
    return from_details(d, rep.get("community") or {}, lookalike)
