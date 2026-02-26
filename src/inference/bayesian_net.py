from typing import Dict, Any

def update_technique_probabilities(features: Dict[str, Any], config: Dict = None) -> Dict[str, float]:
    """
    MVP: simple heuristic + prior boost.
    Later replace with real pgmpy BayesianNet.
    """
    if config is None:
        config = {}  # load from yaml in real version

    scores = {
        "T1059.001": 0.10,  # base
        "T1218": 0.05,
        "T1071": 0.08,
    }

    if features.get("is_powershell"):
        scores["T1059.001"] += 0.55
    if features.get("has_suspicious_cmd"):
        scores["T1059"] = scores.get("T1059", 0.0) + 0.40
    if features.get("unusual_port") or features.get("long_duration_conn"):
        scores["T1071"] += 0.35

    # Normalize roughly to probabilities (very naive)
    total = sum(scores.values()) + 0.0001
    probs = {k: round(v / total, 4) for k, v in scores.items()}

    return probs
