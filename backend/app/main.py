"""
main.py — FastAPI application entry point for the HPE Threat Detection Pipeline.
Handles startup/shutdown lifecycle, CORS, and route registration.
Phase 2: vault_infra_client connected on startup using the vault hvac client.
"""

import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_NAME, APP_TAGLINE, APP_VERSION, MODEL_PATH
from app import inference, kafka_client, elastic_client, vault_client, vault_infra_client
from app.routes import predict, health, pipeline, simulate, admin
import asyncio
from app.ws_manager import manager as ws_manager, admin_manager
from app.threat_engine import process_raw_event
from app import admin_store

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hpe.main")


# ── Lifespan (startup/shutdown) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle — load models and connect to infrastructure."""
    logger.info(f"{'='*60}")
    logger.info(f"  {APP_NAME} — {APP_TAGLINE}")
    logger.info(f"  Version: {APP_VERSION}")
    logger.info(f"{'='*60}")

    # Load ML model artifacts
    try:
        inference.load_model(MODEL_PATH)
        logger.info("[OK] ML model loaded successfully")
    except Exception as e:
        logger.error(f"[FAIL] ML model loading failed: {e}")

    # Connect to Kafka
    try:
        kafka_connected = kafka_client.connect_kafka()
        if kafka_connected:
            logger.info("[OK] Kafka connected")
        else:
            logger.warning("[WARN] Kafka connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Kafka unavailable: {e}")

    # Connect to Elasticsearch
    try:
        es_connected = elastic_client.connect_elasticsearch()
        if es_connected:
            logger.info("[OK] Elasticsearch connected")
        else:
            logger.warning("[WARN] Elasticsearch connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Elasticsearch unavailable: {e}")

    # Connect to Vault (user-level KV rotation)
    try:
        vault_connected = vault_client.connect_vault()
        if vault_connected:
            logger.info("[OK] HashiCorp Vault connected")
        else:
            logger.warning("[WARN] Vault connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Vault unavailable: {e}")

    # Connect vault_infra_client (Phase 2 — database secrets engine)
    # Reuses the hvac client already authenticated by vault_client
    try:
        if vault_client.is_connected() and vault_client._client is not None:
            infra_connected = vault_infra_client.connect(vault_client._client)
            if infra_connected:
                logger.info("[OK] Vault infrastructure client connected (database secrets engine)")
            else:
                logger.warning("[WARN] Vault infra client failed — infrastructure rotation unavailable")
        else:
            logger.warning("[WARN] Vault not connected — skipping infra client setup")
    except Exception as e:
        logger.warning(f"[WARN] Vault infra client unavailable: {e}")

    # Start Kafka consumer if connected
    result_queue = asyncio.Queue()
    broadcast_task = None

    if kafka_client.is_connected():
        loop = asyncio.get_running_loop()
        kafka_client.start_consumer(
            process_callback=process_raw_event,
            loop=loop,
            result_queue=result_queue,
        )
        logger.info("[OK] Kafka consumer started")

        async def broadcast_results():
            while True:
                try:
                    result = await result_queue.get()
                    result_data = result.model_dump()

                    # Broadcast to simulation dashboard
                    await ws_manager.broadcast({
                        "type": "pipeline_result",
                        "data": {
                            "event": result.event_summary,
                            "prediction": result_data,
                        }
                    })

                    # If this event created an admin alert, notify admin clients
                    alert_id = result.event_summary.get("alert_id")
                    if alert_id:
                        alert = admin_store.get_alert(alert_id)
                        if alert:
                            await admin_manager.broadcast({
                                "type": "new_alert",
                                "data": alert,
                            })
                except Exception as e:
                    logger.error(f"Broadcast error: {e}")

        broadcast_task = asyncio.create_task(broadcast_results())

    logger.info(f"\n  Pipeline ready. Serving on http://0.0.0.0:8000")
    logger.info(f"  Docs:  http://localhost:8000/docs")
    logger.info(f"{'='*60}\n")

    yield  # App runs here

    # Shutdown
    logger.info("Shutting down HPE Pipeline...")
    kafka_client.disconnect_kafka()
    if broadcast_task:
        broadcast_task.cancel()
    elastic_client.disconnect_elasticsearch()
    vault_client.disconnect_vault()
    logger.info("Shutdown complete.")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title=APP_NAME,
    description=f"{APP_TAGLINE} — AI-Powered Network Threat Detection Pipeline",
    version=APP_VERSION,
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(predict.router)
app.include_router(health.router)
app.include_router(pipeline.router)
app.include_router(simulate.router)
app.include_router(admin.router)


@app.get("/")
async def root():
    """Root endpoint with app info."""
    return {
        "app": APP_NAME,
        "tagline": APP_TAGLINE,
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }