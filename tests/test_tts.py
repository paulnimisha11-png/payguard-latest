"""Read-aloud server fallback: eSpeak NG runs locally (no third-party web service)."""
import shutil

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
HAS_ESPEAK = bool(shutil.which("espeak-ng") or shutil.which("espeak"))


def test_tts_requires_text():
    assert client.get("/api/tts?text=").status_code == 400


@pytest.mark.skipif(not HAS_ESPEAK, reason="espeak-ng not installed")
@pytest.mark.parametrize("lang,text", [("hi", "नमस्ते, यह ठगी है"), ("kn", "ಇದು ವಂಚನೆ"), ("ta", "இது மோசடி"), ("en", "This is a scam")])
def test_tts_speaks_indian_languages(lang, text):
    res = client.get("/api/tts", params={"text": text, "lang": lang})
    assert res.status_code == 200, res.text
    assert res.headers["content-type"] == "audio/wav"
    assert res.content.startswith(b"RIFF") and len(res.content) > 1000
    again = client.get("/api/tts", params={"text": text, "lang": lang})   # cached
    assert again.content == res.content


@pytest.mark.skipif(not HAS_ESPEAK, reason="espeak-ng not installed")
def test_tts_text_cannot_become_an_option():
    res = client.get("/api/tts", params={"text": "--version", "lang": "en"})
    assert res.status_code == 200 and res.content.startswith(b"RIFF")   # spoken, not executed as an option


def test_no_calls_to_google_translate():
    import pathlib
    src = pathlib.Path("app/main.py").read_text()
    assert "translate.google" not in src
