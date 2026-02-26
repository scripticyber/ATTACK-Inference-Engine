from typing import Dict, Any

def explain_attribution(probs: Dict[str, float], features: Dict[str, Any]) -> str:
    explanation = ["Inference explanation:"]
    for tech, p in sorted(probs.items(), key=lambda x: x[1], reverse=True):
        if p > 0.05:
            explanation.append(f"  • {tech}: {p:.1%} – triggered by features like {list(features.keys())[0]}")
    return "\n".join(explanation) if len(explanation) > 1 else "No strong signals detected."
