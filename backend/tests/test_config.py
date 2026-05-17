# -*- coding: utf-8 -*-
"""test_config.py — Unit tests for config module."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestAppConfig:
    def test_app_name(self):
        from app.config import APP_NAME
        assert APP_NAME == "HPE"

    def test_app_version_exists(self):
        from app.config import APP_VERSION
        assert APP_VERSION is not None and len(APP_VERSION) > 0

    def test_server_location(self):
        from app.config import SERVER_LOCATION
        assert SERVER_LOCATION["city"] == "Bangalore, India"

class TestThreatThresholds:
    def test_threat_levels_exist(self):
        from app.config import THREAT_LEVELS
        assert "ALLOW" in THREAT_LEVELS
        assert "MONITOR" in THREAT_LEVELS
        assert "BLOCK" in THREAT_LEVELS

    def test_thresholds_ordered(self):
        from app.config import THREAT_LEVELS
        assert THREAT_LEVELS["ALLOW"] < THREAT_LEVELS["MONITOR"] < THREAT_LEVELS["BLOCK"]

    def test_thresholds_valid_range(self):
        from app.config import THREAT_LEVELS
        for name, value in THREAT_LEVELS.items():
            assert 0.0 <= value <= 1.0

class TestKafkaTopics:
    def test_topics_defined(self):
        from app.config import KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC
        assert KAFKA_RAW_EVENTS_TOPIC == "hpe-raw-events"
        assert KAFKA_ALERTS_TOPIC == "hpe-alerts"

class TestModelPaths:
    def test_model_path_string(self):
        from app.config import MODEL_PATH
        assert isinstance(MODEL_PATH, str)
        assert "pipeline_artifacts" in MODEL_PATH
