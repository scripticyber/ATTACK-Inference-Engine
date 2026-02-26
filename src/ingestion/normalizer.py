# src/ingestion/normalizer.py
import logging
from typing import Dict, Any, Optional

from .parsers.sysmon_parser import parse_sysmon_event
from .parsers.zeek_parser import parse_zeek_conn  # can add parse_zeek_dns later

logger = logging.getLogger(__name__)

def normalize_event(raw: Dict[str, Any], source: str = "auto") -> Optional[Dict[str, Any]]:
    """
    Convert raw telemetry event to a unified schema.
    Delegates low-level parsing to source-specific parsers.

    Returns None if parsing fails or event is unsupported.
    """
    if source == "auto":
        if "EventID" in raw or "EventData" in raw:
            source = "sysmon"
        elif "ts" in raw and "uid" in raw:
            source = "zeek"
        else:
            logger.debug("Unknown event source")
            return None

    parsed = None

    if source == "sysmon":
        parsed = parse_sysmon_event(raw)
    elif source == "zeek":
        # For MVP assume conn.log; later detect dns/http/etc.
        parsed = parse_zeek_conn(raw)
    else:
        logger.warning(f"Unsupported source: {source}")
        return None

    if not parsed:
        logger.debug(f"Parser returned None for source {source}")
        return None

    # ── Now map parsed output to unified schema ──
    normalized: Dict[str, Any] = {
        "timestamp": parsed.get("timestamp"),
        "host": parsed.get("host") or parsed.get("computer"),
        "user": parsed.get("user"),
        "event_type": parsed.get("event_type"),
        "event": {
            "category": ["process"] if "process" in parsed else ["network"],
            "kind": "event",
            "type": "start" if parsed.get("event_type") == "process_creation" else "connection",
        },
        "process": parsed.get("process", {}),
        "parent_process": parsed.get("parent_process", {}),
        "network": parsed.get("network", {}),
        "command_line": parsed.get("command_line"),
        "source_ip": parsed.get("source_ip"),
        "dest_ip": parsed.get("dest_ip"),
        "source_port": parsed.get("source_port"),
        "dest_port": parsed.get("dest_port"),
        "proto": parsed.get("proto"),
        "duration": parsed.get("duration"),
        "bytes_in": parsed.get("orig_bytes"),
        "bytes_out": parsed.get("resp_bytes"),
        "original_raw": raw,  # useful for debugging
    }

    # Clean up None values (optional but nice for downstream)
    normalized = {k: v for k, v in normalized.items() if v is not None or isinstance(v, (dict, list))}

    return normalized
