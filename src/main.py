import json
import argparse
from pathlib import Path

from ingestion.normalizer import normalize_event
from features.engineer import extract_features
from inference.bayesian_net import update_technique_probabilities
from inference.explain import explain_attribution


def process_file(file_path: Path):
    print(f"\n=== Processing {file_path} ===")
    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                source = "sysmon" if "EventID" in raw or "EventData" in raw else "zeek"
                normalized = normalize_event(raw, source=source)
                if not normalized:
                    print(f"Line {i+1}: skipped (invalid format)")
                    continue

                features = extract_features(normalized)
                probs = update_technique_probabilities(features)
                explanation = explain_attribution(probs, features)

                host = normalized.get("host", "unknown")
                top_tech = max(probs, key=probs.get) if probs else "none"
                top_prob = probs.get(top_tech, 0.0)

                print(f"Host: {host}")
                print(f"Top technique: {top_tech} ({top_prob:.1%})")
                print(explanation)
                print("-" * 60)

            except json.JSONDecodeError:
                print(f"Line {i+1}: invalid JSON")
            except Exception as e:
                print(f"Line {i+1}: error {e}")


def main():
    parser = argparse.ArgumentParser(description="ATT&CK Inference Engine MVP")
    parser.add_argument("--input", default="data/samples", help="Directory with *.jsonl files")
    args = parser.parse_args()

    input_dir = Path(args.input)
    if not input_dir.exists():
        print(f"Input directory not found: {input_dir}")
        return

    for file_path in input_dir.glob("*.jsonl"):
        process_file(file_path)


if __name__ == "__main__":
    main()
