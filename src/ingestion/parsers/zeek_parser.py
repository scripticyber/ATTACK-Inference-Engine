# src/ingestion/parsers/zeek_parser.py
from typing import Dict, Any, Optional


def parse_zeek_conn(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a Zeek conn.log entry (network connection).
    Returns simplified dict or None if missing critical fields.
    """
    required_keys = ["ts", "uid", "id.orig_h", "id.resp_h", "proto"]
    if not all(k in raw for k in required_keys):
        return None

    parsed = {
        "event_type": "network_connection",
        "timestamp": raw.get("ts"),
        "uid": raw.get("uid"),
        "source_ip": raw.get("id.orig_h"),
        "source_port": raw.get("id.orig_p"),
        "dest_ip": raw.get("id.resp_h"),
        "dest_port": raw.get("id.resp_p"),
        "proto": raw.get("proto"),
        "service": raw.get("service", "-"),
        "duration": raw.get("duration", 0.0),
        "orig_bytes": raw.get("orig_bytes", 0),
        "resp_bytes": raw.get("resp_bytes", 0),
        "conn_state": raw.get("conn_state"),
        "history": raw.get("history"),
        "original_raw": raw,
    }

    return parsed


def parse_zeek_dns(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Basic parser for Zeek dns.log (can be extended later).
    """
    if "query" not in raw:
        return None

    parsed = {
        "event_type": "dns_query",
        "timestamp": raw.get("ts"),
        "uid": raw.get("uid"),
        "source_ip": raw.get("id.orig_h"),
        "dest_ip": raw.get("id.resp_h"),
        "query": raw.get("query"),
        "rcode": raw.get("rcode", -1),
        "original_raw": raw,
    }
    return parsed


# You can add more: parse_zeek_http, parse_zeek_files, etc.
