"""Lightweight structured logging utilities for Python web services.

Provides JSON-formatted logging with request correlation IDs,
configurable log levels, and automatic context enrichment.
"""

import logging
import json
import uuid
from datetime import datetime


class StructuredFormatter(logging.Formatter):
    """Format log records as JSON for structured log aggregation."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
        }
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def get_logger(name, level=logging.INFO):
    """Get a structured logger instance.

    Args:
        name: Logger name, typically __name__
        level: Logging level (default: INFO)

    Returns:
        logging.Logger configured with structured JSON output
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def generate_request_id():
    """Generate a unique request correlation ID."""
    return str(uuid.uuid4())[:8]


def log_request(logger, method, path, status_code, duration_ms):
    """Log an HTTP request with standard fields."""
    logger.info(
        "request completed",
        extra={
            "request_id": generate_request_id(),
            "method": method,
            "path": path,
            "status": status_code,
            "duration_ms": duration_ms,
        },
    )
