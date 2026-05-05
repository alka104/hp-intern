"""
threat_engine.py — Threat scoring, action determination, and full pipeline orchestration.
Combines real tools (Kafka, Elasticsearch, Vault) with simulated stages.
BLOCK/CRITICAL threats require admin approval before credential rotation.
Phase 4: Stage 7 and Stage 8 details updated to accurately reflect:
  - Human-in-the-loop approval flow
  - Infra rotation pending for CRITICAL_ALERT
  - Proportionate response (BLOCK=user only, CRITICAL=user+infra)
"""

import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

from app.config import THREAT_LEVELS
from app.schemas import (
    PredictionResult, PipelineStageResult, ThreatAction, GeoLocation, NetworkEvent
)
from app import inference
from app import kafka_client
from app import elastic_client
from app import vault_client
from app import vault_infra_client
from app import pipeline_stages
from app import admin_store

logger = logging.getLogger("hpe.threat_engine")

# ── Global metrics ─────────────────────────────────────────────────────────────
_metrics = {
    "total_requests": 0,
    "total_threats": 0,
    "total_allowed": 0,
    "total_monitored": 0,
    "total_blocked": 0,
    "total_critical": 0,
    "total_latency_ms": 0.0,
    "attack_types": {},
}


def get_metrics() -> Dict[str, Any]:
    """Get current pipeline metrics."""
    avg_latency = (_metrics["total_latency_ms"] / max(_metrics["total_requests"], 1))
    return {
        **_metrics,
        "avg_latency_ms": round(avg_latency, 2),
        "model_metrics": inference.get_artifacts().get("metrics", {}) if inference.get_artifacts() else {},
        "infra_rotation_count": vault_infra_client.get_infra_rotation_count(),
        "active_infra_leases": len(vault_infra_client.get_active_leases()),
    }


def determine_action(threat_score: float) -> ThreatAction:
    """Determine the appropriate action based on threat score."""
    if threat_score < THREAT_LEVELS["ALLOW"]:
        return ThreatAction.ALLOW
    elif threat_score < THREAT_LEVELS["MONITOR"]:
        return ThreatAction.MONITOR
    elif threat_score < THREAT_LEVELS["BLOCK"]:
        return ThreatAction.BLOCK
    else:
        return ThreatAction.CRITICAL_ALERT


def _determine_affected_service(event_dict: dict) -> str:
    """
    Map the anomaly type to the infrastructure service most at risk.
    Used in Stage 7 details so the frontend dashboard shows which service
    will be rotated when admin approves a CRITICAL_ALERT.
    """
    anomaly = event_dict.get("anomaly_type", "None")
    action = event_dict.get("action", "")

    if anomaly in ["data_exfiltration", "bulk_download"]:
        return "elasticsearch"
    elif anomaly in ["lateral_movement", "privilege_escalation"]:
        return "kafka"
    elif action == "admin":
        return "database"
    else:
        return "elasticsearch"


def process_raw_event(raw_event: dict) -> PredictionResult:
    """
    Called by the Kafka consumer thread.
    Converts a raw dict from Kafka into a NetworkEvent and processes it.
    """
    event_fields = {k: v for k, v in raw_event.items()
                    if k in NetworkEvent.model_fields}
    event = NetworkEvent(**event_fields)
    return process_event(event)


def process_event(event: NetworkEvent) -> PredictionResult:
    """
    Process a single event through the FULL pipeline:
    Network → Zeek/Suricata → Beats → Kafka → AI → SOAR → Vault → Rotation → Dist → ELK
    """
    t0 = time.time()
    event_id = str(uuid.uuid4())[:12]
    event_dict = event.model_dump()
    stages: List[PipelineStageResult] = []

    # ── Stage 1: Network Capture (simulated) ──────────────────────────────────
    stage1 = pipeline_stages.simulate_network_capture(event_dict)
    stages.append(stage1)

    # ── Stage 2: Zeek/Suricata (simulated) ────────────────────────────────────
    stage2 = pipeline_stages.simulate_zeek_suricata(event_dict)
    stages.append(stage2)

    # ── Stage 3: Elastic Beats (simulated) ────────────────────────────────────
    stage3 = pipeline_stages.simulate_elastic_beats(event_dict)
    stages.append(stage3)

    # ── Stage 4: Apache Kafka (REAL) ──────────────────────────────────────────
    kafka_t0 = time.time()
    kafka_latency = (time.time() - kafka_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="Apache Kafka",
        stage_number=4,
        status="consumed",
        latency_ms=round(kafka_latency, 2),
        details={
            "topic": "hpe-raw-events",
            "direction": "consumed",
            "partition": "auto",
        },
        is_real_tool=True,
    ))

    # ── Stage 5: AI Detection Engine (REAL) ───────────────────────────────────
    ai_t0 = time.time()
    try:
        is_threat, ensemble_score, xgb_score, lgb_score, threshold = inference.predict(event)
    except Exception as e:
        logger.error(f"Inference error: {e}")
        is_threat, ensemble_score, xgb_score, lgb_score, threshold = False, 0.0, 0.0, 0.0, 0.5
    ai_latency = (time.time() - ai_t0) * 1000

    threat_action = determine_action(ensemble_score)

    stages.append(PipelineStageResult(
        stage_name="AI Detection Engine",
        stage_number=5,
        status="threat_detected" if is_threat else "clear",
        latency_ms=round(ai_latency, 2),
        details={
            "xgboost_score": round(xgb_score, 6),
            "lightgbm_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "threshold": round(threshold, 6),
            "is_threat": is_threat,
            "action": threat_action.value,
        },
        is_real_tool=True,
    ))

    # ── Stage 6: SOAR Automation (simulated) ──────────────────────────────────
    stage6 = pipeline_stages.simulate_soar_automation(event_dict, is_threat, ensemble_score)
    stages.append(stage6)

    # ── Stage 7: HashiCorp Vault (REAL — Human-in-the-Loop) ───────────────────
    # Phase 4: Stage 7 details now reflect the full rotation plan:
    #   BLOCK       → pending admin approval → user rotation only when approved
    #   CRITICAL    → pending admin approval → user + infra rotation when approved
    #   MONITOR     → logged, no rotation
    #   ALLOW       → no action
    vault_t0 = time.time()
    vault_result = {}

    is_high_severity = is_threat and threat_action in (
        ThreatAction.BLOCK, ThreatAction.CRITICAL_ALERT
    )

    if is_high_severity:
        affected_service = (
            _determine_affected_service(event_dict)
            if threat_action == ThreatAction.CRITICAL_ALERT
            else None
        )
        vault_result = {
            "status": "pending_admin_approval",
            "message": (
                "Credential rotation requires admin approval. "
                f"Threat action: {threat_action.value}."
            ),
            "user": event_dict.get("user_id", "unknown"),
            "threat_score": round(ensemble_score, 6),
            "rotation_plan": {
                "user_rotation": True,
                "infra_rotation": threat_action == ThreatAction.CRITICAL_ALERT,
                "affected_service": affected_service,
                "reason": (
                    "CRITICAL_ALERT: both user and infrastructure credentials "
                    "will be rotated on admin approval"
                    if threat_action == ThreatAction.CRITICAL_ALERT
                    else "BLOCK: user credentials will be rotated on admin approval"
                ),
            },
        }
    elif is_threat and threat_action == ThreatAction.MONITOR:
        vault_result = {
            "status": "monitoring",
            "message": "MONITOR-level threat: logged for observation, no rotation triggered",
            "user": event_dict.get("user_id", "unknown"),
            "threat_score": round(ensemble_score, 6),
        }
    else:
        vault_result = {
            "status": "no_rotation_needed",
            "threat_score": round(ensemble_score, 6),
        }
        admin_store.increment_auto_allowed()

    vault_latency = (time.time() - vault_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="HashiCorp Vault",
        stage_number=7,
        status="pending_approval" if is_high_severity else "no_action",
        latency_ms=round(vault_latency, 2),
        details=vault_result,
        is_real_tool=True,
    ))

    # ── Stage 8: Credential Rotation (deferred — fires when admin approves) ───
    # Phase 4: Stage 8 now distinguishes between:
    #   pending_user_rotation          → BLOCK threat awaiting approval
    #   pending_user_and_infra_rotation → CRITICAL threat awaiting approval
    #   skipped                         → no threat or MONITOR
    if is_high_severity:
        rotation_plan = vault_result.get("rotation_plan", {})
        stage8_status = (
            "pending_user_and_infra_rotation"
            if rotation_plan.get("infra_rotation")
            else "pending_user_rotation"
        )
        stage8_details = {
            "user_rotation": "pending_admin_approval",
            "infra_rotation": (
                f"pending_admin_approval → will rotate '{rotation_plan.get('affected_service')}' service"
                if rotation_plan.get("infra_rotation")
                else "not_required (BLOCK threshold, not CRITICAL)"
            ),
            "vault_auth_method": vault_client.get_auth_method(),
            "vault_infra_connected": vault_infra_client.is_connected(),
            "total_user_rotations_so_far": vault_client.get_rotation_count(),
            "total_infra_rotations_so_far": vault_infra_client.get_infra_rotation_count(),
        }
    else:
        stage8_status = "skipped"
        stage8_details = {
            "reason": "No high-severity threat detected",
            "vault_auth_method": vault_client.get_auth_method(),
        }

    stages.append(PipelineStageResult(
        stage_name="Credential Rotation",
        stage_number=8,
        status=stage8_status,
        latency_ms=0.0,
        details=stage8_details,
        is_real_tool=False,
    ))

    # ── Stage 9: Credentials Distributed (simulated) ──────────────────────────
    stage9 = pipeline_stages.simulate_credential_distribution(is_threat)
    stages.append(stage9)

    # ── Stage 10: ELK Stack / Grafana (REAL — Elasticsearch) ─────────────────
    elk_t0 = time.time()
    es_audit_success = elastic_client.index_audit_log(
        event_id=event_id,
        stage="pipeline_complete",
        action=threat_action.value,
        threat_score=ensemble_score,
        is_threat=is_threat,
        event_data=event_dict,
    )

    if is_threat:
        elastic_client.index_threat(event_id, {
            "event_id": event_id,
            "threat_score": round(ensemble_score, 6),
            "threat_action": threat_action.value,
            "attack_type": event_dict.get("anomaly_type", "unknown"),
            "source_ip": event_dict.get("source_ip", ""),
            "ip_region": event_dict.get("ip_region", ""),
            "user": event_dict.get("user_id", ""),
            "action": event_dict.get("action", ""),
            "xgb_score": round(xgb_score, 6),
            "lgb_score": round(lgb_score, 6),
            "ensemble_score": round(ensemble_score, 6),
            "vault_rotation_triggered": is_high_severity,
            "infra_rotation_pending": (
                is_high_severity and threat_action == ThreatAction.CRITICAL_ALERT
            ),
            "credentials_rotated": False,  # not yet — pending admin approval
        })

        kafka_client.produce_alert({
            "event_id": event_id,
            "threat_score": ensemble_score,
            "action": threat_action.value,
            "user": event_dict.get("user_id", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    elk_latency = (time.time() - elk_t0) * 1000

    stages.append(PipelineStageResult(
        stage_name="ELK Stack / Grafana",
        stage_number=10,
        status="indexed" if es_audit_success else "fallback",
        latency_ms=round(elk_latency, 2),
        details={
            "audit_indexed": es_audit_success,
            "threat_indexed": is_threat,
            "index": "hpe-audit-logs",
        },
        is_real_tool=True,
    ))

    # ── Compute totals ────────────────────────────────────────────────────────
    total_latency = (time.time() - t0) * 1000

    _metrics["total_requests"] += 1
    _metrics["total_latency_ms"] += total_latency
    if is_threat:
        _metrics["total_threats"] += 1
    _action_key_map = {
        ThreatAction.ALLOW:          "total_allowed",
        ThreatAction.MONITOR:        "total_monitored",
        ThreatAction.BLOCK:          "total_blocked",
        ThreatAction.CRITICAL_ALERT: "total_critical",
    }
    action_key = _action_key_map.get(threat_action)
    if action_key:
        _metrics[action_key] += 1
    if is_threat:
        at = event_dict.get("anomaly_type", "unknown")
        _metrics["attack_types"][at] = _metrics["attack_types"].get(at, 0) + 1

    # ── Geo mapping ───────────────────────────────────────────────────────────
    region_geo = {
        "US-East":      {"lat": 40.71,  "lng": -74.01,  "city": "New York"},
        "US-West":      {"lat": 37.77,  "lng": -122.42, "city": "San Francisco"},
        "EU-Central":   {"lat": 50.11,  "lng": 8.68,    "city": "Frankfurt"},
        "Asia-Pacific": {"lat": 1.35,   "lng": 103.82,  "city": "Singapore"},
        "South-America":{"lat": -23.55, "lng": -46.63,  "city": "São Paulo"},
    }
    server_geo = {"lat": 12.97, "lng": 77.59, "city": "Bangalore"}

    ip_region   = event_dict.get("ip_region", "")
    user_region = event_dict.get("user_region", "")
    src_geo = region_geo.get(ip_region, {"lat": 0, "lng": 0, "city": "Unknown"})
    dst_geo = (
        server_geo
        if ip_region == user_region or user_region not in region_geo
        else region_geo.get(user_region, server_geo)
    )

    # ── Create admin alert for BLOCK/CRITICAL (pending approval) ─────────────
    stages_dicts = [s.model_dump() for s in stages]
    alert_id = None

    if is_high_severity:
        admin_alert = admin_store.create_alert(
            event_id=event_id,
            user_id=event_dict.get("user_id", "unknown"),
            threat_score=round(ensemble_score, 6),
            threat_action=threat_action.value,
            xgb_score=round(xgb_score, 6),
            lgb_score=round(lgb_score, 6),
            ensemble_score=round(ensemble_score, 6),
            threshold=round(threshold, 6),
            event_data={
                "user":                     event_dict.get("user_id", ""),
                "source_ip":                event_dict.get("source_ip", ""),
                "ip_region":                event_dict.get("ip_region", ""),
                "action":                   event_dict.get("action", ""),
                "anomaly_type":             event_dict.get("anomaly_type", ""),
                "geo_mismatch":             event_dict.get("geo_mismatch", False),
                "login_hour":               event_dict.get("login_hour", 0),
                "failed_attempts_last_15m": event_dict.get("failed_attempts_last_15m", 0),
                "data_downloaded_mb":       event_dict.get("data_downloaded_mb", 0),
                "impossible_travel":        event_dict.get("impossible_travel", False),
            },
            pipeline_stages=stages_dicts,
            source_geo=src_geo,
            destination_geo=dst_geo,
            total_latency_ms=round(total_latency, 2),
        )
        alert_id = admin_alert["alert_id"]

    return PredictionResult(
        event_id=event_id,
        is_threat=is_threat,
        threat_score=round(ensemble_score, 6),
        threat_action=threat_action,
        xgb_score=round(xgb_score, 6),
        lgb_score=round(lgb_score, 6),
        ensemble_score=round(ensemble_score, 6),
        threshold=round(threshold, 6),
        source_geo=GeoLocation(**src_geo),
        destination_geo=GeoLocation(**dst_geo),
        pipeline_stages=stages,
        total_latency_ms=round(total_latency, 2),
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_summary={
            "user":         event_dict.get("user_id", ""),
            "source_ip":    event_dict.get("source_ip", ""),
            "ip_region":    event_dict.get("ip_region", ""),
            "action":       event_dict.get("action", ""),
            "anomaly_type": event_dict.get("anomaly_type", ""),
            "geo_mismatch": event_dict.get("geo_mismatch", False),
            "alert_id":     alert_id,
        },
    )