import re
from typing import Dict, Any

def extract_features(normalized: Dict[str, Any]) -> Dict[str, Any]:
    features = {
        "has_suspicious_cmd": False,
        "cmd_entropy": 0.0,           # placeholder
        "is_powershell": False,
        "unusual_parent": False,
        "long_duration_conn": False,
        "unusual_port": False,
    }

    cmd = normalized.get("command_line", "").lower()
    if cmd:
        if any(kw in cmd for kw in ["powershell", "-ep bypass", "iex ", "downloadstring", "invoke-webrequest"]):
            features["is_powershell"] = True
            features["has_suspicious_cmd"] = True

        if "rundll32" in cmd and ("javascript:" in cmd or "http" in cmd):
            features["has_suspicious_cmd"] = True

    net = normalized.get("network", {})
    if net.get("duration", 0) > 60:
        features["long_duration_conn"] = True
    if net.get("dest_port") in [4444, 9001, 8080, 53]:  # example suspicious
        if net.get("dest_port") != 53 or net.get("service") != "dns":
            features["unusual_port"] = True

    return features
