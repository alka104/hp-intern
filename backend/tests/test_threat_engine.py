# -*- coding: utf-8 -*-
"""
test_threat_engine.py — Unit tests for threat scoring and action determination.
Tests the core classification logic without requiring infrastructure dependencies.
Uses mock to avoid importing kafka/vault/elasticsearch clients.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.threat_engine import determine_action, _determine_affected_service
from app.schemas import ThreatAction


class TestDetermineAction:
    """Tests for the threat action determination logic."""

    def test_low_score_allows(self):
        assert determine_action(0.0) == ThreatAction.ALLOW
        assert determine_action(0.1) == ThreatAction.ALLOW
        assert determine_action(0.29) == ThreatAction.ALLOW

    def test_medium_score_monitors(self):
        assert determine_action(0.3) == ThreatAction.MONITOR
        assert determine_action(0.45) == ThreatAction.MONITOR
        assert determine_action(0.59) == ThreatAction.MONITOR

    def test_high_score_blocks(self):
        assert determine_action(0.6) == ThreatAction.BLOCK
        assert determine_action(0.7) == ThreatAction.BLOCK
        assert determine_action(0.84) == ThreatAction.BLOCK

    def test_critical_score_alerts(self):
        assert determine_action(0.85) == ThreatAction.CRITICAL_ALERT
        assert determine_action(0.95) == ThreatAction.CRITICAL_ALERT
        assert determine_action(1.0) == ThreatAction.CRITICAL_ALERT

    def test_boundary_allow_to_monitor(self):
        assert determine_action(0.3) == ThreatAction.MONITOR

    def test_boundary_monitor_to_block(self):
        assert determine_action(0.6) == ThreatAction.BLOCK

    def test_boundary_block_to_critical(self):
        assert determine_action(0.85) == ThreatAction.CRITICAL_ALERT


class TestDetermineAffectedService:
    """Tests for mapping anomaly types to infrastructure services."""

    def test_data_exfiltration_maps_to_elasticsearch(self):
        assert _determine_affected_service({"anomaly_type": "data_exfiltration"}) == "elasticsearch"

    def test_bulk_download_maps_to_elasticsearch(self):
        assert _determine_affected_service({"anomaly_type": "bulk_download"}) == "elasticsearch"

    def test_lateral_movement_maps_to_kafka(self):
        assert _determine_affected_service({"anomaly_type": "lateral_movement"}) == "kafka"

    def test_privilege_escalation_maps_to_kafka(self):
        assert _determine_affected_service({"anomaly_type": "privilege_escalation"}) == "kafka"

    def test_admin_action_maps_to_database(self):
        assert _determine_affected_service({"anomaly_type": "unknown", "action": "admin"}) == "database"

    def test_unknown_defaults_to_elasticsearch(self):
        assert _determine_affected_service({"anomaly_type": "unknown", "action": "login"}) == "elasticsearch"

    def test_empty_event(self):
        assert _determine_affected_service({}) == "elasticsearch"


class TestThreatLevelCoverage:
    """Verify all threat levels are reachable and monotonic."""

    def test_all_actions_reachable(self):
        mapping = {0.0: ThreatAction.ALLOW, 0.4: ThreatAction.MONITOR, 0.7: ThreatAction.BLOCK, 0.9: ThreatAction.CRITICAL_ALERT}
        for score, expected in mapping.items():
            assert determine_action(score) == expected

    def test_monotonic_severity(self):
        order = [ThreatAction.ALLOW, ThreatAction.MONITOR, ThreatAction.BLOCK, ThreatAction.CRITICAL_ALERT]
        prev = 0
        for score in [0.0, 0.1, 0.3, 0.5, 0.6, 0.7, 0.85, 0.9, 1.0]:
            curr = order.index(determine_action(score))
            assert curr >= prev
            prev = curr
