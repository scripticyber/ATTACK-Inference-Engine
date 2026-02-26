# src/ingestion/parsers/sysmon_parser.py
from typing import Dict, Any, Optional


def parse_sysmon_event(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a single Sysmon event (mainly Event ID 1 - Process Creation for MVP).
    Returns a simplified flat dict or None if not supported.
    """
    event_id = raw.get("EventID") or raw.get("EventData", {}).get("EventID")

    if event_id != 1:
        # For MVP we only handle ProcessCreate; extend later for 3,7,11,13, etc.
        return None

    ed = raw.get("EventData", {})

    parsed = {
        "event_type": "process_creation",
        "timestamp": raw.get("UtcTime") or raw.get("EventTime"),
        "host": raw.get("Computer"),
        "user": ed.get("User"),
        "process": {
            "image": ed.get("Image"),
            "command_line": ed.get("CommandLine"),
            "pid": ed.get("ProcessId"),
            "guid": ed.get("ProcessGuid"),
            "integrity_level": ed.get("IntegrityLevel"),
            "hashes": ed.get("Hashes"),
        },
        "parent_process": {
            "image": ed.get("ParentImage"),
            "command_line": ed.get("ParentCommandLine"),
            "pid": ed.get("ParentProcessId"),
            "guid": ed.get("ParentProcessGuid"),
        },
        "logon": {
            "logon_id": ed.get("LogonId"),
            "logon_guid": ed.get("LogonGuid"),
        },
        "original_raw": raw,  # keep for debugging
    }

    # Clean up empty/none values if desired
    if not parsed["timestamp"]:
        parsed["timestamp"] = raw.get("TimeCreated", {}).get("SystemTime")

    return parsed
