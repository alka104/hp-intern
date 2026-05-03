"""
routes/admin.py — Security Admin Dashboard API endpoints.
Provides alert management, approval workflow, and admin audit log.
Phase 2: CRITICAL_ALERT approval triggers BOTH user-level AND
         infrastructure credential rotation.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.schemas import ApprovalRequest, ApprovalResponse
from app import admin_store, vault_client, vault_infra_client
from app.ws_manager import admin_manager

logger = logging.getLogger("hpe.admin")
router = APIRouter(prefix="/api/admin", tags=["admin"])


def _determine_affected_service(event_data: dict) -> str:
    """
    Map the anomaly type in the event to the infrastructure service most at risk.
    Used to decide which service's credentials to rotate on CRITICAL approval.
    """
    anomaly = event_data.get("anomaly_type", "None")
    action = event_data.get("action", "")

    if anomaly in ["data_exfiltration", "bulk_download"]:
        return "elasticsearch"   # attacker likely querying ES directly
    elif anomaly in ["lateral_movement", "privilege_escalation"]:
        return "kafka"           # attacker may be injecting fake events
    elif action == "admin":
        return "database"        # admin action → rotate DB service account
    else:
        return "elasticsearch"   # default: protect the audit trail


@router.get("/alerts")
async def get_alerts(status: str = None, severity: str = None, limit: int = 100):
    """
    List all admin alerts.
    Query params: ?status=pending|approved|rejected&severity=critical|high|medium&limit=100
    """
    alerts = admin_store.get_all_alerts(status=status, severity=severity, limit=limit)
    pending_count = sum(1 for a in admin_store.get_all_alerts(status="pending"))
    return {
        "total": len(alerts),
        "pending_count": pending_count,
        "alerts": alerts,
    }


@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str):
    """Get full forensic details for a single alert."""
    alert = admin_store.get_alert(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found"}
    return alert


@router.post("/alerts/{alert_id}/approve", response_model=ApprovalResponse)
async def approve_alert(alert_id: str, request: ApprovalRequest):
    """
    Approve credential rotation for a threat alert.

    For all approved threats:
      - vault_client.rotate_credentials() rotates the specific user's KV secret

    For CRITICAL_ALERT threats additionally:
      - vault_infra_client.rotate_infrastructure_credentials() revokes the
        current DB service user lease and issues a brand-new dynamic one
    """
    alert = admin_store.approve_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert {alert_id} not found",
        )

    if alert["status"] != "approved":
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="approve",
            message=f"Alert already resolved as: {alert['status']}",
        )

    # ── User-level rotation (always fires on approval) ────────────────────────
    rotation_result = vault_client.rotate_credentials(
        reason=f"admin_approved_threat_score_{alert['threat_score']:.4f}",
        user=alert["user_id"],
        threat_score=alert["threat_score"],
    )

    # ── Infrastructure rotation (only for CRITICAL_ALERT) ─────────────────────
    infra_rotation_result = None
    if alert["threat_action"] == "CRITICAL_ALERT":
        if vault_infra_client.is_connected():
            affected_service = _determine_affected_service(alert.get("event_data", {}))
            infra_rotation_result = vault_infra_client.rotate_infrastructure_credentials(
                service=affected_service,
                reason=f"admin_approved_critical_score_{alert['threat_score']:.4f}",
                threat_score=alert["threat_score"],
            )
            logger.warning(
                f"[ADMIN] Infrastructure credentials rotated for '{affected_service}' "
                f"(alert={alert_id}, success={infra_rotation_result.get('success')})"
            )
        else:
            logger.warning(
                "[ADMIN] Vault infra client not connected — "
                "skipping infrastructure rotation for CRITICAL_ALERT"
            )

    # Attach full rotation result to the alert for audit trail
    combined_result = {
        "user_rotation": rotation_result,
        "infra_rotation": infra_rotation_result,
    }
    admin_store.set_rotation_result(alert_id, combined_result)

    logger.info(
        f"[ADMIN] Approval complete for {alert['user_id']} "
        f"(alert={alert_id}, "
        f"user_vault={rotation_result.get('success')}, "
        f"infra_rotation={'yes' if infra_rotation_result else 'n/a (not CRITICAL)'})"
    )

    # Broadcast to admin WebSocket clients
    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action": "approved",
            "user_id": alert["user_id"],
            "rotation_success": rotation_result.get("success", False),
            "infra_rotation": infra_rotation_result,
        },
    })

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="approved",
        rotation_result=combined_result,
        message=(
            f"User credentials rotated for {alert['user_id']}. "
            + (f"Infrastructure credentials rotated for '{affected_service}'."
               if infra_rotation_result else "")
        ),
    )


@router.post("/alerts/{alert_id}/reject", response_model=ApprovalResponse)
async def reject_alert(alert_id: str, request: ApprovalRequest):
    """Reject an alert as a false positive. No credential rotation."""
    alert = admin_store.reject_alert(alert_id, admin_notes=request.admin_notes)
    if not alert:
        return ApprovalResponse(
            success=False,
            alert_id=alert_id,
            action="reject",
            message=f"Alert {alert_id} not found",
        )

    # Broadcast to admin WebSocket clients
    await admin_manager.broadcast({
        "type": "alert_resolved",
        "data": {
            "alert_id": alert_id,
            "action": "rejected",
            "user_id": alert["user_id"],
        },
    })

    return ApprovalResponse(
        success=True,
        alert_id=alert_id,
        action="rejected",
        message=f"Alert {alert_id} rejected as false positive",
    )


@router.get("/stats")
async def get_admin_stats():
    """Get admin dashboard summary statistics."""
    stats = admin_store.get_stats()
    # Also expose infra rotation count and active leases
    stats["infra_rotation_count"] = vault_infra_client.get_infra_rotation_count()
    stats["active_infra_leases"] = vault_infra_client.get_active_leases()
    return stats


@router.get("/audit-log")
async def get_audit_log(limit: int = 50):
    """Get the history of all admin actions."""
    log = admin_store.get_audit_log(limit=limit)
    return {"total": len(log), "entries": log}


@router.get("/infra-leases")
async def get_infra_leases():
    """
    Get all currently active Vault infrastructure leases.
    Shows which PostgreSQL service users are active, their TTL, and expiry.
    """
    return {
        "active_leases": vault_infra_client.get_active_leases(),
        "total_infra_rotations": vault_infra_client.get_infra_rotation_count(),
    }


# ── Admin WebSocket for real-time alert notifications ──────────────────────────
@router.websocket("/ws")
async def admin_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time admin alert notifications."""
    await websocket.accept()
    admin_manager.add(websocket)

    # Send current stats on connect
    stats = admin_store.get_stats()
    await websocket.send_json({
        "type": "admin_connected",
        "data": stats,
    })

    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        admin_manager.remove(websocket)
    except Exception as e:
        admin_manager.remove(websocket)
        logger.error(f"Admin WebSocket error: {e}")