# -*- coding: utf-8 -*-
"""
conftest.py — Shared pytest fixtures and infrastructure mocks.
Mocks all external infrastructure modules so tests can run without
Kafka, Elasticsearch, Vault, or PostgreSQL installed.
"""
import sys
from unittest.mock import MagicMock

# Mock all infrastructure client libraries before any app imports
_infra_mocks = [
    'confluent_kafka', 'confluent_kafka.admin',
    'elasticsearch',
    'hvac',
    'psycopg2', 'psycopg2.pool', 'psycopg2.extras',
]

for mod in _infra_mocks:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()
