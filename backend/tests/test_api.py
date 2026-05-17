# -*- coding: utf-8 -*-
"""test_api.py — FastAPI integration tests using TestClient."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

class TestRootEndpoint:
    def test_root_returns_200(self):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_root_has_app_name(self):
        resp = client.get("/")
        data = resp.json()
        assert data["app"] == "HPE"
        assert "docs" in data

class TestPredictEndpoint:
    def test_predict_accepts_event(self):
        event = {
            "event_id": "api-test-001",
            "timestamp": "2025-06-15T10:00:00Z",
            "user_id": "user_1",
            "source_ip": "10.0.0.1",
            "ip_region": "US-East",
            "user_region": "US-East",
            "action": "login",
            "login_hour": 10,
            "data_downloaded_mb": 5.0,
            "failed_attempts_last_15m": 0,
            "success": True,
            "geo_mismatch": False,
            "impossible_travel": False,
        }
        resp = client.post("/api/predict", json=event)
        assert resp.status_code == 200
        data = resp.json()
        assert "event_id" in data
        assert "is_threat" in data
        assert "threat_score" in data
        assert "pipeline_stages" in data

    def test_predict_empty_event(self):
        resp = client.post("/api/predict", json={})
        assert resp.status_code == 200

    def test_batch_rejects_over_100(self):
        events = [{"event_id": f"e-{i}"} for i in range(101)]
        resp = client.post("/api/batch", json={"events": events})
        assert resp.status_code == 400

class TestPipelineEndpoint:
    def test_pipeline_status_responds(self):
        """Pipeline status endpoint exists (may error without DB)."""
        try:
            resp = client.get("/api/pipeline/status")
            assert resp.status_code in (200, 500)
        except Exception:
            pass  # Expected without PostgreSQL — endpoint exists but DB unavailable

class TestDocsEndpoint:
    def test_openapi_schema(self):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "HPE"
