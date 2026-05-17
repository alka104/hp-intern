# -*- coding: utf-8 -*-
"""
test_schemas.py — Unit tests for all Pydantic schemas.
Validates data model creation, field defaults, serialization, and constraints.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestNetworkEvent:
    """Tests for the NetworkEvent schema."""

    def test_valid_event_creation(self):
        from app.schemas import NetworkEvent
        event = NetworkEvent(
            event_id="evt-001",
            timestamp="2025-12-21T09:30:00Z",
            user_id="user_42",
            workspace_id="ws_1",
            source_ip="10.0.0.1",
            ip_region="EU-West",
            user_region="EU-West",
            action="download",
            login_hour=14,
            data_downloaded_mb=500.0,
            failed_attempts_last_15m=3,
            success=True,
            geo_mismatch=False,
            impossible_travel=False,
        )
        assert event.user_id == "user_42"
        assert event.data_downloaded_mb == 500.0
        assert event.login_hour == 14

    def test_defaults_are_safe(self):
        """All fields should have safe defaults (no required fields)."""
        from app.schemas import NetworkEvent
        event = NetworkEvent()
        assert event.event_id == ""
        assert event.success is True
        assert event.geo_mismatch is False
        assert event.data_downloaded_mb == 0.0
        assert event.failed_attempts_last_15m == 0

    def test_serialization_roundtrip(self):
        """Event should survive JSON serialization and deserialization."""
        from app.schemas import NetworkEvent
        event = NetworkEvent(
            event_id="rt-001",
            user_id="user_99",
            source_ip="172.16.0.5",
            action="admin",
            data_downloaded_mb=1024.5,
        )
        json_str = event.model_dump_json()
        restored = NetworkEvent.model_validate_json(json_str)
        assert restored.event_id == "rt-001"
        assert restored.data_downloaded_mb == 1024.5

    def test_anomaly_fields(self):
        """Verify anomaly metadata fields work correctly."""
        from app.schemas import NetworkEvent
        event = NetworkEvent(
            is_injected_anomaly=True,
            anomaly_type="data_exfiltration",
        )
        assert event.is_injected_anomaly is True
        assert event.anomaly_type == "data_exfiltration"


class TestThreatAction:
    """Tests for the ThreatAction enum."""

    def test_all_actions_defined(self):
        from app.schemas import ThreatAction
        actions = [a.value for a in ThreatAction]
        assert "ALLOW" in actions
        assert "MONITOR" in actions
        assert "BLOCK" in actions
        assert "CRITICAL_ALERT" in actions

    def test_action_count(self):
        from app.schemas import ThreatAction
        assert len(ThreatAction) == 4


class TestGeoLocation:
    """Tests for the GeoLocation schema."""

    def test_default_values(self):
        from app.schemas import GeoLocation
        geo = GeoLocation()
        assert geo.lat == 0.0
        assert geo.lng == 0.0
        assert geo.city == "Unknown"

    def test_custom_values(self):
        from app.schemas import GeoLocation
        geo = GeoLocation(lat=12.97, lng=77.59, city="Bangalore")
        assert geo.city == "Bangalore"
        assert geo.lat == 12.97


class TestPredictionResult:
    """Tests for the PredictionResult schema."""

    def test_prediction_result_creation(self):
        from app.schemas import PredictionResult, ThreatAction
        result = PredictionResult(
            event_id="pred-001",
            is_threat=True,
            threat_score=0.92,
            threat_action=ThreatAction.CRITICAL_ALERT,
            xgb_score=0.95,
            lgb_score=0.89,
            ensemble_score=0.92,
            threshold=0.5,
        )
        assert result.is_threat is True
        assert result.threat_action == ThreatAction.CRITICAL_ALERT
        assert result.threat_score == 0.92

    def test_threat_score_bounds(self):
        """Threat score must be between 0 and 1."""
        from app.schemas import PredictionResult, ThreatAction
        result = PredictionResult(
            event_id="bound-test",
            is_threat=False,
            threat_score=0.0,
            threat_action=ThreatAction.ALLOW,
        )
        assert 0.0 <= result.threat_score <= 1.0


class TestPipelineStageResult:
    """Tests for the PipelineStageResult schema."""

    def test_stage_creation(self):
        from app.schemas import PipelineStageResult
        stage = PipelineStageResult(
            stage_name="AI Detection Engine",
            stage_number=5,
            status="threat_detected",
            latency_ms=12.5,
            details={"xgboost_score": 0.95},
            is_real_tool=True,
        )
        assert stage.stage_name == "AI Detection Engine"
        assert stage.is_real_tool is True
        assert stage.latency_ms == 12.5


class TestBatchPredictRequest:
    """Tests for the BatchPredictRequest schema."""

    def test_empty_batch(self):
        from app.schemas import BatchPredictRequest
        batch = BatchPredictRequest(events=[])
        assert len(batch.events) == 0

    def test_batch_with_events(self):
        from app.schemas import BatchPredictRequest, NetworkEvent
        events = [NetworkEvent(event_id=f"batch-{i}") for i in range(5)]
        batch = BatchPredictRequest(events=events)
        assert len(batch.events) == 5


class TestAdminSchemas:
    """Tests for admin-related schemas."""

    def test_admin_alert_defaults(self):
        from app.schemas import AdminAlert
        alert = AdminAlert(
            alert_id="ALR-001",
            event_id="evt-001",
            user_id="user_1",
            threat_score=0.95,
            threat_action="CRITICAL_ALERT",
        )
        assert alert.status == "pending"
        assert alert.admin_notes == ""
        assert alert.rotation_result is None

    def test_approval_request(self):
        from app.schemas import ApprovalRequest
        req = ApprovalRequest(admin_notes="Verified as legitimate threat")
        assert req.admin_notes == "Verified as legitimate threat"

    def test_approval_response(self):
        from app.schemas import ApprovalResponse
        resp = ApprovalResponse(
            success=True,
            alert_id="ALR-001",
            action="approved",
            message="Credentials rotated successfully",
        )
        assert resp.success is True
        assert resp.action == "approved"


class TestHealthResponse:
    """Tests for the HealthResponse schema."""

    def test_healthy_defaults(self):
        from app.schemas import HealthResponse
        health = HealthResponse()
        assert health.status == "healthy"
        assert health.model_loaded is False
        assert health.kafka_connected is False
