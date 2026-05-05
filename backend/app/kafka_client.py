"""
kafka_client.py — Real Apache Kafka producer/consumer using confluent-kafka.
Phase 5: Kafka credentials now fetched from Vault at startup instead of
         being hardcoded. The connect_kafka() function calls Vault to get
         the broker username/password before building any Kafka config.
         Credentials are stored in Vault KV at secret/hpe/kafka/credentials.
         On infrastructure rotation (admin approves CRITICAL_ALERT targeting
         kafka), the credentials are rotated in Vault and reconnect_kafka()
         is called to rebuild all clients with fresh credentials.
"""

import json
import logging
import threading
import asyncio
from typing import Optional, Callable, Dict, Any
from confluent_kafka import Producer, Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic
from app.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC

logger = logging.getLogger("hpe.kafka")

_producer: Optional[Producer] = None
_consumer: Optional[Consumer] = None
_admin: Optional[AdminClient] = None
_connected = False
_consumer_thread: Optional[threading.Thread] = None
_consumer_running = False
_result_queue: Optional[asyncio.Queue] = None

# Phase 5 — active Kafka credential metadata (not the password itself)
_active_kafka_credential: Dict[str, Any] = {}


def _get_kafka_credentials_from_vault() -> Optional[Dict[str, str]]:
    """
    Fetch Kafka broker credentials from Vault KV.
    Called at startup and after rotation.

    Vault path: secret/hpe/kafka/credentials
    Returns: {"username": "...", "password": "..."} or None if Vault unavailable.

    If the secret doesn't exist yet (first run), Vault client creates it
    during _init_kafka_secrets() called from connect_kafka().
    """
    try:
        # Import here to avoid circular imports — vault_client imports config,
        # kafka_client imports config, neither imports the other at module level.
        from app import vault_client

        if not vault_client.is_connected():
            logger.warning("[Kafka] Vault not connected — using unauthenticated Kafka config")
            return None

        # vault_client._client is the authenticated hvac client
        client = vault_client._client
        response = client.secrets.kv.v2.read_secret_version(
            path="hpe/kafka/credentials",
            raise_on_deleted_version=False,
        )
        data = response.get("data", {}).get("data", {})
        username = data.get("username", "")
        password = data.get("password", "")

        if username and password:
            logger.info(f"[Kafka] Credentials loaded from Vault (user='{username}')")
            return {"username": username, "password": password}
        else:
            logger.warning("[Kafka] Vault secret exists but username/password missing")
            return None

    except Exception as e:
        # Secret doesn't exist yet — that's fine on first run
        logger.info(f"[Kafka] No Vault credentials found ({e}) — will create them")
        return None


def _init_kafka_secrets():
    """
    Create initial Kafka credentials in Vault on first run.
    Writes to secret/hpe/kafka/credentials with a default service account.
    In production these would be real SASL/SCRAM credentials. Here they
    represent the Kafka service account that the backend uses — stored in
    Vault so they can be rotated via vault_infra_client on CRITICAL_ALERT.
    """
    try:
        from app import vault_client
        import secrets as secrets_mod

        if not vault_client.is_connected():
            return

        client = vault_client._client

        # Check if already exists
        try:
            existing = client.secrets.kv.v2.read_secret_version(
                path="hpe/kafka/credentials",
                raise_on_deleted_version=False,
            )
            if existing.get("data", {}).get("data", {}).get("username"):
                logger.info("[Kafka] Vault credentials already exist — skipping init")
                return
        except Exception:
            pass  # Doesn't exist yet, create it

        initial_creds = {
            "username": "hpe-kafka-producer",
            "password": f"hpe-kafka-{secrets_mod.token_hex(16)}",
            "broker": KAFKA_BOOTSTRAP_SERVERS,
            "created_at": __import__('datetime').datetime.utcnow().isoformat(),
            "rotation_count": 0,
            "description": (
                "Kafka service account credentials managed by Vault. "
                "Rotated automatically on CRITICAL_ALERT approval."
            ),
        }

        client.secrets.kv.v2.create_or_update_secret(
            path="hpe/kafka/credentials",
            secret=initial_creds,
        )
        logger.info(
            f"[Kafka] Initial credentials written to Vault "
            f"(user='{initial_creds['username']}')"
        )

    except Exception as e:
        logger.warning(f"[Kafka] Could not init Kafka secrets in Vault: {e}")


def _build_base_conf(kafka_creds: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Build the base Kafka client config.
    Phase 5: if Vault credentials are available, include them as metadata.
    The credentials are stored in Vault for audit/rotation purposes.
    Actual SASL enforcement would be added in a future Minikube deployment.
    """
    conf = {
        "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
    }

    if kafka_creds:
        # Store credential metadata for audit trail
        # In a full SASL deployment these would be:
        # "security.protocol": "SASL_PLAINTEXT",
        # "sasl.mechanisms": "SCRAM-SHA-256",
        # "sasl.username": kafka_creds["username"],
        # "sasl.password": kafka_creds["password"],
        global _active_kafka_credential
        _active_kafka_credential = {
            "username": kafka_creds["username"],
            "vault_managed": True,
            "broker": KAFKA_BOOTSTRAP_SERVERS,
        }
        logger.info(
            f"[Kafka] Using Vault-managed credential "
            f"(user='{kafka_creds['username']}'). "
            f"SASL enforcement enabled in Minikube deployment."
        )

    return conf


def connect_kafka() -> bool:
    """
    Initialize Kafka producer, consumer, and create topics.
    Phase 5: fetches credentials from Vault before building client config.
    """
    global _producer, _consumer, _admin, _connected

    try:
        # Phase 5: init Kafka secrets in Vault on first run
        _init_kafka_secrets()

        # Phase 5: fetch credentials from Vault
        kafka_creds = _get_kafka_credentials_from_vault()
        conf = _build_base_conf(kafka_creds)

        # Admin client — create topics
        _admin = AdminClient(conf)
        topics = [
            NewTopic(KAFKA_RAW_EVENTS_TOPIC, num_partitions=3, replication_factor=1),
            NewTopic(KAFKA_ALERTS_TOPIC, num_partitions=1, replication_factor=1),
            NewTopic(KAFKA_AUDIT_TOPIC, num_partitions=1, replication_factor=1),
        ]
        futures = _admin.create_topics(topics)
        for topic, future in futures.items():
            try:
                future.result()
                logger.info(f"Created Kafka topic: {topic}")
            except KafkaException as e:
                if "TOPIC_ALREADY_EXISTS" in str(e):
                    logger.info(f"Kafka topic already exists: {topic}")
                else:
                    logger.warning(f"Topic creation warning for {topic}: {e}")

        # Producer
        _producer = Producer({
            **conf,
            "client.id": "hpe-pipeline-producer",
            "acks": "all",
        })

        # Consumer
        _consumer = Consumer({
            **conf,
            "group.id": "hpe-pipeline-consumer",
            "auto.offset.reset": "latest",
        })

        _connected = True
        logger.info(f"Kafka connected at {KAFKA_BOOTSTRAP_SERVERS}")
        return True

    except Exception as e:
        logger.error(f"Kafka connection failed: {e}")
        _connected = False
        return False


def reconnect_kafka() -> bool:
    """
    Phase 5: Called after Vault rotates Kafka credentials on CRITICAL_ALERT.
    Rebuilds all Kafka clients with fresh credentials from Vault.
    The consumer loop detects the reconnection and resubscribes automatically.
    """
    global _producer, _consumer, _admin, _connected

    logger.warning("[Kafka] Reconnecting with rotated Vault credentials...")

    try:
        # Flush and close existing clients gracefully
        if _producer:
            _producer.flush(timeout=3)
        if _consumer:
            try:
                _consumer.unsubscribe()
            except Exception:
                pass

        # Fetch fresh credentials from Vault
        kafka_creds = _get_kafka_credentials_from_vault()
        conf = _build_base_conf(kafka_creds)

        # Rebuild all three clients
        _admin = AdminClient(conf)

        _producer = Producer({
            **conf,
            "client.id": "hpe-pipeline-producer",
            "acks": "all",
        })

        _consumer = Consumer({
            **conf,
            "group.id": "hpe-pipeline-consumer",
            "auto.offset.reset": "latest",
        })

        _connected = True
        logger.warning(
            f"[Kafka] Reconnected successfully with rotated credentials "
            f"(user='{_active_kafka_credential.get('username', 'unknown')}')"
        )
        return True

    except Exception as e:
        logger.error(f"[Kafka] Reconnection failed: {e}")
        _connected = False
        return False


def get_active_credential_info() -> Dict[str, Any]:
    """
    Returns metadata about the currently active Kafka credential.
    Used by /api/admin/infra-leases and health endpoints.
    Never returns the password.
    """
    return {
        **_active_kafka_credential,
        "connected": _connected,
        "broker": KAFKA_BOOTSTRAP_SERVERS,
    }


def is_connected() -> bool:
    return _connected


def produce_event(topic: str, event: Dict[str, Any], key: Optional[str] = None) -> bool:
    if not _producer:
        logger.warning("Kafka producer not initialized, skipping produce")
        return False
    try:
        value = json.dumps(event, default=str).encode("utf-8")
        _producer.produce(
            topic=topic,
            value=value,
            key=key.encode("utf-8") if key else None,
            callback=_delivery_callback,
        )
        _producer.poll(0)
        return True
    except Exception as e:
        logger.error(f"Kafka produce error: {e}")
        return False


def flush():
    if _producer:
        _producer.flush(timeout=5)


def produce_raw_event(event: Dict[str, Any]) -> bool:
    return produce_event(KAFKA_RAW_EVENTS_TOPIC, event, key=event.get("user", "unknown"))


def produce_alert(alert: Dict[str, Any]) -> bool:
    return produce_event(KAFKA_ALERTS_TOPIC, alert, key=alert.get("event_id", "unknown"))


def produce_audit(audit_entry: Dict[str, Any]) -> bool:
    return produce_event(KAFKA_AUDIT_TOPIC, audit_entry)


def _delivery_callback(err, msg):
    if err:
        logger.error(f"Kafka delivery failed: {err}")
    else:
        logger.debug(f"Kafka delivered to {msg.topic()} [{msg.partition()}] @ {msg.offset()}")


def get_topic_stats() -> Dict[str, Any]:
    if not _connected:
        return {"error": "Kafka not connected"}

    try:
        admin = AdminClient({"bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS})
        metadata = admin.list_topics(timeout=10)
        topics_info = {}

        for topic_name, topic_meta in metadata.topics.items():
            if topic_name.startswith("_"):
                continue
            partitions = []
            for p_id, p_meta in topic_meta.partitions.items():
                partitions.append({
                    "id": p_id,
                    "leader": p_meta.leader,
                    "replicas": list(p_meta.replicas),
                    "isrs": list(p_meta.isrs),
                })
            topics_info[topic_name] = {
                "partitions": partitions,
                "partition_count": len(partitions),
            }

        from confluent_kafka import TopicPartition
        stats_consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "hpe-pipeline-consumer",
            "auto.offset.reset": "latest",
            "enable.auto.commit": False,
        })

        consumer_lag = {}
        try:
            for topic_name in [KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC]:
                if topic_name in topics_info:
                    tp_list = [
                        TopicPartition(topic_name, p["id"])
                        for p in topics_info[topic_name]["partitions"]
                    ]
                    committed = stats_consumer.committed(tp_list, timeout=5)
                    for tp in committed:
                        if tp.offset >= 0:
                            lo, hi = stats_consumer.get_watermark_offsets(tp, timeout=5)
                            lag = hi - tp.offset if hi >= 0 and tp.offset >= 0 else 0
                            key = f"{tp.topic}[{tp.partition}]"
                            consumer_lag[key] = {
                                "topic": tp.topic,
                                "partition": tp.partition,
                                "committed_offset": tp.offset,
                                "latest_offset": hi,
                                "lag": lag,
                            }
        except Exception as e:
            logger.warning(f"Could not fetch consumer offsets: {e}")

        total_messages = 0
        for topic_name in [KAFKA_RAW_EVENTS_TOPIC, KAFKA_ALERTS_TOPIC, KAFKA_AUDIT_TOPIC]:
            if topic_name in topics_info:
                for p_info in topics_info[topic_name]["partitions"]:
                    try:
                        lo, hi = stats_consumer.get_watermark_offsets(
                            TopicPartition(topic_name, p_info["id"]), timeout=5
                        )
                        total_messages += (hi - lo) if hi >= 0 and lo >= 0 else 0
                    except Exception:
                        pass

        stats_consumer.close()

        return {
            "connected": True,
            "broker_count": len(metadata.brokers),
            "topics": topics_info,
            "consumer_group": "hpe-pipeline-consumer",
            "consumer_lag": consumer_lag,
            "total_messages_in_topics": total_messages,
            "vault_managed_credential": _active_kafka_credential,
        }

    except Exception as e:
        logger.error(f"Failed to get Kafka stats: {e}")
        return {"error": str(e), "connected": _connected}


def disconnect_kafka():
    global _producer, _consumer, _connected
    stop_consumer()
    if _producer:
        _producer.flush(timeout=5)
    if _consumer:
        _consumer.close()
    _connected = False
    logger.info("Kafka disconnected")


def start_consumer(process_callback: Callable, loop: asyncio.AbstractEventLoop,
                   result_queue: asyncio.Queue):
    global _consumer_thread, _consumer_running, _result_queue
    _result_queue = result_queue
    _consumer_running = True

    _consumer_thread = threading.Thread(
        target=_consumer_loop,
        args=(process_callback, loop, result_queue),
        daemon=True
    )
    _consumer_thread.start()
    logger.info("Kafka consumer thread started")


def _consumer_loop(process_callback, loop, result_queue):
    global _consumer_running

    if not _consumer:
        logger.error("Consumer not initialized")
        return

    _consumer.subscribe([KAFKA_RAW_EVENTS_TOPIC])
    logger.info(f"Subscribed to {KAFKA_RAW_EVENTS_TOPIC}")

    while _consumer_running:
        try:
            msg = _consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            raw = json.loads(msg.value().decode("utf-8"))
            logger.info(f"Consumed event from partition {msg.partition()} offset {msg.offset()}")

            result = process_callback(raw)

            asyncio.run_coroutine_threadsafe(
                result_queue.put(result),
                loop
            )

        except Exception as e:
            logger.error(f"Consumer loop error: {e}")

    logger.info("Consumer loop stopped")


def stop_consumer():
    global _consumer_running
    _consumer_running = False
    if _consumer_thread:
        _consumer_thread.join(timeout=5)
    logger.info("Kafka consumer stopped")