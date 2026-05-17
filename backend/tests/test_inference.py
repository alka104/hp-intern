# -*- coding: utf-8 -*-
"""
test_inference.py — Unit tests for the HPE ML inference module.
Validates model loading, feature engineering, and prediction pipeline.
"""

import os
import sys
import pytest
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestInferenceModule:
    """Tests for the inference module without requiring actual model files."""

    def test_import_inference(self):
        """Verify the inference module can be imported."""
        from app import inference
        assert hasattr(inference, 'load_model')
        assert hasattr(inference, 'predict')
        assert hasattr(inference, 'engineer_single_event')
        assert hasattr(inference, 'get_artifacts')

    def test_model_not_loaded_fallback(self):
        """Verify graceful fallback when models are not loaded."""
        from app import inference
        from app.schemas import NetworkEvent

        inference._is_loaded = False

        event = NetworkEvent(
            event_id="test-001",
            timestamp="2025-06-15T09:30:00.000000Z",
            user_id="user_1",
            workspace_id="ws_1",
            source_ip="192.168.1.1",
            ip_region="US-East",
            user_region="US-East",
            action="login",
            login_hour=9,
            data_downloaded_mb=10.0,
            failed_attempts_last_15m=0,
            success=True,
            geo_mismatch=False,
            impossible_travel=False,
        )

        is_threat, score, xgb, lgbm, threshold = inference.predict(event)
        assert is_threat is False
        assert score == 0.0
        assert threshold == 0.5

    def test_get_artifacts_returns_none_when_not_loaded(self):
        """Verify get_artifacts returns None when model not loaded."""
        from app import inference
        inference._is_loaded = False
        assert inference.get_artifacts() is None

    def test_predict_returns_five_values(self):
        """Verify predict returns a 5-tuple."""
        from app import inference
        from app.schemas import NetworkEvent

        inference._is_loaded = False
        event = NetworkEvent(event_id="test-tuple")
        result = inference.predict(event)
        assert isinstance(result, tuple)
        assert len(result) == 5

    def test_user_history_default_structure(self):
        """Verify the default user history dict has expected keys."""
        from app.inference import _user_history
        sample = _user_history["__nonexistent_user__"]
        assert "first_seen_ip" in sample
        assert "prev_ip" in sample
        assert "last_event_time" in sample
        assert "ip_hops_30m" in sample
        assert "admin_actions_15m" in sample
        assert "failed_30m" in sample
        assert "events_1h" in sample
