"""Unit tests for health endpoint and capability reporting (§10, §8.4)."""

import os
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "ok"
    assert "version" in data
    assert "ocr_available" in data
    assert isinstance(data["ocr_available"], bool)
    assert "anthropic_key_set" in data
    assert isinstance(data["anthropic_key_set"], bool)
    assert "judge_available" in data
    assert isinstance(data["judge_available"], bool)
    assert "classifier_backend" in data
    assert "degraded_mode" in data
    assert isinstance(data["degraded_mode"], bool)


def test_health_reflects_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-12345")
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["anthropic_key_set"] is True
    assert data["judge_available"] is True
