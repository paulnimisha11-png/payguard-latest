"""Optional: turn a report into a warm, simple message for a parent/grandparent.

Uses the Anthropic API when ANTHROPIC_API_KEY is set; otherwise falls back to
a deterministic template built from the rule texts (always available, works
offline, and is what the core product relies on).
"""
from __future__ import annotations

import os

import httpx

LANG_NAMES = {
    "en": "simple English",
    "hi": "simple Hindi (Devanagari script)",
    "kn": "simple Kannada (Kannada script)",
    "ta": "simple Tamil (Tamil script)",
    "te": "simple Telugu (Telugu script)",
    "mr": "simple Marathi (Devanagari script)",
    "bn": "simple Bengali (Bengali script)",
}
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

FAMILY_INTRO = {
    "en": 'I checked the app file "{name}" with APK X-Ray before installing.',
    "hi": 'इंस्टॉल करने से पहले मैंने ऐप फ़ाइल "{name}" को APK X-Ray से जाँचा।',
    "kn": 'ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವ ಮೊದಲು ನಾನು "{name}" ಆ್ಯಪ್ ಫೈಲ್ ಅನ್ನು APK X-Ray ಮೂಲಕ ಪರಿಶೀಲಿಸಿದೆ.',
    "ta": 'நிறுவும் முன் நான் "{name}" ஆப் கோப்பை APK X-Ray மூலம் சரிபார்த்தேன்.',
    "te": 'ఇన్‌స్టాల్ చేసే ముందు నేను "{name}" యాప్ ఫైల్‌ను APK X-Ray ద్వారా తనిఖీ చేసాను.',
    "mr": 'इन्स्टॉल करण्यापूर्वी मी "{name}" ॲप फाइल APK X-Ray ने तपासली.',
    "bn": 'ইনস্টল করার আগে আমি "{name}" অ্যাপ ফাইলটি APK X-Ray দিয়ে যাচাই করেছি।',
}


def template_message(rep: dict, lang: str = "en") -> str:
    lang = lang if lang in LANG_NAMES else "en"
    v = rep["verdict"]
    name = rep["app"].get("name") or rep["file"].get("name") or "app"
    headline = v["headline"].get(lang) or v["headline"].get("en", "")
    advice = v["advice"].get(lang) or v["advice"].get("en", "")
    lines = [FAMILY_INTRO[lang].format(name=name), "", f"*{headline}* ({v['score']}/100)"]
    for f in rep["findings"][:3]:
        if f["severity"] in ("critical", "high"):
            t_str = f["title"].get(lang) or f["title"].get("en", "")
            lines.append(f"• {t_str}")
    lines += ["", advice]
    return "\n".join(lines)


async def llm_message(rep: dict, lang: str = "en") -> str | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    facts = "\n".join(f"- [{f['severity']}] {f['title']['en']}: {f['detail']['en']}" for f in rep["findings"][:6])
    prompt = (
        f"An app file named '{rep['file']['name']}' (app name '{rep['app']['name']}', package {rep['app']['package']}) "
        f"was scanned before installation. Verdict: {rep['verdict']['headline']['en']} (risk {rep['verdict']['score']}/100).\n"
        f"Findings:\n{facts or '- none'}\n\n"
        f"Write a short WhatsApp message (max 90 words) in {LANG_NAMES[lang]} that a young person can send to their "
        f"elderly parent explaining, without technical words, what this app could do and exactly what to do now. "
        f"Be calm and clear, not scary. If the verdict is danger, mention the 1930 cyber-fraud helpline. "
        f"Do not invent facts beyond the findings. Output only the message."
    )
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": MODEL, "max_tokens": 400, "messages": [{"role": "user", "content": prompt}]},
            )
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json().get("content", [])).strip() or None
    except Exception:
        return None
