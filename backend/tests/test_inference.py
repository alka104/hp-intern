# -*- coding: utf-8 -*-
"""
test_inference.py — Unit tests for the HPE ML inference module.
Validates model loading, feature engineering, and prediction pipeline.
"""

import os
import sys
import pytest
import numpy as np

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestInferenceModule:
    """Tests for the inference module without requiring actual model files."""

    def test_import_inference(self):
        """Verify the inference module can be imported."""
        from app import inference
        assert hasattr(inference, 'load_model')
        assert hasattr(inference, 'predict')
        assert hasattr(inference, 'engineer_single_event')

    def test_model_not_loaded_fallback(self):
        """Verify graceful fallback when models are not loaded."""
        from app import inference
        from app.schemas import NetworkEvent
        from datetime import datetime

        # Reset state
        inference._is_loaded = False
        
        event = NetworkEvent(
            event_id="test-001",
            timestamp=datetime.now().isoformat(),
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


class TestSchemas:
    """Tests for the Pydantic schemas."""

    def test_network_event_creation(self):
        """Verify NetworkEvent schema accepts valid data."""
        from app.schemas import NetworkEvent
        from datetime import datetime

        event = NetworkEvent(
            event_id="test-002",
            timestamp=datetime.now().isoformat(),
            user_id="user_2",
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
        assert event.user_id == "user_2"
        assert event.data_downloaded_mb == 500.0


class TestConfig:
    """Tests for the configuration module."""

    def test_config_defaults(self):
        """Verify config defaults are set."""
        from app.config import APP_NAME, APP_VERSION
        assert APP_NAME == "HPE"
        assert APP_VERSION is not None
