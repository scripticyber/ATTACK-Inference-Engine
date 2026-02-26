import json
from typing import Dict, Any, Optional

def normalize_event(raw: Dict[str, Any], source: str = "auto") -> Optional[Dict[str, Any]]:
    """
    Convert raw Sysmon/Zeek event to a simple unified schema.
    Returns None if invalid/unparseable.
    """
    normalized = {
        "timestamp": None,
        "host": None,
        "user": None,
        "event_type": None,
        "process": {},
        "network": {},
        "command_line": None,
        "parent_process": None,
        "raw": raw,
    }

    if source == "sysmon" or ("EventID" in raw and raw.get("EventID") == 1):
        ed = raw.get("EventData", {})
        normalized.update({
            "timestamp": raw.get("UtcTime") or raw.get("EventTime"),
            "host": raw.get("Computer"),
            "user": ed.get("User"),
            "event_type": "process_creation",
            "process": {
                "image": ed.get("Image"),
                "command_line": ed.get("CommandLine"),
                "pid": ed.get("ProcessId"),
            },
            "parent_process": {
                "image": ed.get("ParentImage"),
                "command_line": ed.get("ParentCommandLine"),
            },
            "command_line": ed.get("CommandLine"),
        })

    elif source == "zeek" or "ts" in raw and "uid" in raw:
        normalized.update({
            "timestamp": raw.get("ts"),
            "host": raw.get("id.orig_h"),
            "event_type": "network_connection",
            "network": {
                "proto": raw.get("proto"),
                "service": raw.get("service"),
                "orig_bytes": raw.get("orig_bytes"),
                "resp_bytes": raw.get("resp_bytes"),
                "duration": raw.get("duration"),
                "dest_ip": raw.get("id.resp_h"),
                "dest_port": raw.get("id.resp_p"),
            },
        })

    else:
        return None

    return normalized
