# -*- coding: utf-8 -*-
"""
test_pipeline_stages.py — Unit tests for pipeline stage simulation functions.
Validates that each simulated stage returns valid PipelineStageResult objects.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pipeline_stages import (
    simulate_network_capture,
    simulate_zeek_suricata,
    simulate_elastic_beats,
    simulate_soar_automation,
    simulate_credential_rotation,
    simulate_credential_distribution,
    get_stage_definitions,
    PIPELINE_STAGES,
    _guess_service,
    _classify_event,
)
from app.schemas import PipelineStageResult


class TestStageDefinitions:
    """Tests for pipeline stage metadata."""

    def test_ten_stages_defined(self):
        """Pipeline should have exactly 10 stages."""
        assert len(PIPELINE_STAGES) == 10

    def test_stages_numbered_sequentially(self):
        """Stage numbers should run 1-10."""
        numbers = [s["number"] for s in PIPELINE_STAGES]
        assert numbers == list(range(1, 11))

    def test_get_stage_definitions_returns_list(self):
        result = get_stage_definitions()
        assert isinstance(result, list)
        assert len(result) == 10

    def test_each_stage_has_required_keys(self):
        for stage in PIPELINE_STAGES:
            assert "name" in stage
            assert "number" in stage
            assert "is_real" in stage
            assert "icon" in stage

    def test_real_tools_identified(self):
        """Kafka, AI Engine, Vault, and ELK should be marked as real tools."""
        real_stages = [s for s in PIPELINE_STAGES if s["is_real"]]
        real_names = {s["name"] for s in real_stages}
        assert "Apache Kafka" in real_names
        assert "AI Detection Engine" in real_names
        assert "HashiCorp Vault" in real_names
        assert "ELK Stack / Grafana" in real_names


class TestNetworkCapture:
    """Tests for Stage 1: Network Capture."""

    def test_returns_pipeline_stage_result(self):
        result = simulate_network_capture({"source_ip": "10.0.0.1"})
        assert isinstance(result, PipelineStageResult)

    def test_stage_metadata(self):
        result = simulate_network_capture({})
        assert result.stage_name == "Network/Applications"
        assert result.stage_number == 1
        assert result.status == "captured"
        assert result.is_real_tool is False

    def test_enriched_details(self):
        result = simulate_network_capture({})
        assert "capture_interface" in result.details
        assert "packet_size" in result.details
        assert "tcp_flags" in result.details
        assert "vlan_id" in result.details

    def test_positive_latency(self):
        result = simulate_network_capture({})
        assert result.latency_ms > 0


class TestZeekSuricata:
    """Tests for Stage 2: Zeek/Suricata IDS."""

    def test_returns_pipeline_stage_result(self):
        result = simulate_zeek_suricata({"protocol": "TCP"})
        assert isinstance(result, PipelineStageResult)

    def test_stage_metadata(self):
        result = simulate_zeek_suricata({})
        assert result.stage_name == "Zeek/Suricata"
        assert result.stage_number == 2
        assert result.status == "analyzed"

    def test_zeek_connection_details(self):
        result = simulate_zeek_suricata({})
        assert "zeek_connection" in result.details
        conn = result.details["zeek_connection"]
        assert "uid" in conn
        assert "proto" in conn
        assert "conn_state" in conn

    def test_suspicious_command_generates_alert(self):
        """Suspicious commands should trigger Suricata alerts."""
        result = simulate_zeek_suricata({"command_line": "powershell -enc base64"})
        assert result.details["suspicious_indicators"] is True
        assert len(result.details["suricata_alerts"]) > 0


class TestElasticBeats:
    """Tests for Stage 3: Elastic Beats."""

    def test_returns_pipeline_stage_result(self):
        result = simulate_elastic_beats({})
        assert isinstance(result, PipelineStageResult)

    def test_stage_metadata(self):
        result = simulate_elastic_beats({})
        assert result.stage_name == "Elastic Beats"
        assert result.stage_number == 3
        assert result.status == "normalized"

    def test_ecs_details(self):
        result = simulate_elastic_beats({})
        assert result.details["agent_type"] == "filebeat"
        assert result.details["ecs_version"] == "8.0"
        assert result.details["geo_enriched"] is True


class TestSOARAutomation:
    """Tests for Stage 6: SOAR Automation."""

    def test_threat_triggers_multiple_workflows(self):
        result = simulate_soar_automation({}, is_threat=True, threat_score=0.7)
        assert result.status == "workflows_triggered"
        assert result.details["total_workflows"] >= 4

    def test_no_threat_triggers_baseline(self):
        result = simulate_soar_automation({}, is_threat=False, threat_score=0.1)
        assert result.status == "passed"
        assert result.details["total_workflows"] == 1

    def test_critical_threat_adds_isolation(self):
        """Threat score > 0.9 should trigger network isolation workflow."""
        result = simulate_soar_automation({}, is_threat=True, threat_score=0.95)
        workflow_names = [w["name"] for w in result.details["workflows"]]
        assert "network_isolation" in workflow_names

    def test_incident_id_only_for_threats(self):
        threat_result = simulate_soar_automation({}, is_threat=True, threat_score=0.8)
        safe_result = simulate_soar_automation({}, is_threat=False, threat_score=0.1)
        assert threat_result.details["incident_id"] is not None
        assert safe_result.details["incident_id"] is None


class TestCredentialDistribution:
    """Tests for Stage 9: Credential Distribution."""

    def test_threat_distributes_creds(self):
        result = simulate_credential_distribution(is_threat=True)
        assert result.status == "distributed"
        assert "TLS 1.3" in result.details["encryption"]
        assert result.details["all_targets_updated"] is True

    def test_no_threat_skips_distribution(self):
        result = simulate_credential_distribution(is_threat=False)
        assert result.status == "skipped"


class TestHelperFunctions:
    """Tests for helper utility functions."""

    def test_guess_service_chrome(self):
        assert _guess_service("chrome.exe") == "http"

    def test_guess_service_ssh(self):
        assert _guess_service("ssh") == "ssh"

    def test_guess_service_powershell(self):
        assert _guess_service("powershell.exe") == "smb"

    def test_guess_service_unknown(self):
        assert _guess_service("custom_app") == "unknown"

    def test_classify_event_network(self):
        assert _classify_event("network_connection") == "network"

    def test_classify_event_process(self):
        assert _classify_event("process_start") == "process"

    def test_classify_event_unknown(self):
        assert _classify_event("something_else") == "host"
