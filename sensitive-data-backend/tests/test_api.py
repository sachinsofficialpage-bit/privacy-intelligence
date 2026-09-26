from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan():
    text = "Email demo@example.com, phone +91 98765 43210, IP 192.168.1.20, password=DemoPass123!"
    response = client.post("/scan", data={"text": text})
    assert response.status_code == 200
    body = response.json()
    assert body["detected_count"] >= 4
    assert body["exposure_score"] > 0
    assert all("start" in item and "end" in item for item in body["findings"])


def test_redact():
    text = "Contact demo@example.com now."
    scan = client.post("/scan", data={"text": text}).json()
    item = scan["findings"][0]
    response = client.post("/redact", json={
        "original_text": text,
        "selected_items": [item],
        "masking_mode": "SMART_MASK",
    })
    assert response.status_code == 200
    assert "demo@example.com" not in response.json()["protected_text"]
