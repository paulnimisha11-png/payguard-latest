from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_tts_requires_text():
    res = client.get("/api/tts?text=")
    assert res.status_code == 400


def test_tts_indic_audio():
    res = client.get("/api/tts?text=नमस्ते&lang=hi")
    assert res.status_code == 200
    assert res.headers["content-type"] == "audio/mpeg"
    assert len(res.content) > 100

    # Cache hit test
    cached_res = client.get("/api/tts?text=नमस्ते&lang=hi")
    assert cached_res.status_code == 200
    assert cached_res.content == res.content
