import json
import argparse
from pathlib import Path
import sys

# Use relative imports (since main.py is inside src/)
from .ingestion.normalizer import normalize_event
from .features.engineer import extract_features
from .inference.bayesian_net import update_technique_probabilities
from .inference.explain import explain_attribution


def process_file(file_path: Path):
    print(f"\n=== Processing {file_path} ===")
    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                # Let normalizer handle source detection if possible
                normalized = normalize_event(raw, source="auto")
                if not normalized:
                    print(f"Line {i}: skipped (unsupported or invalid format)")
                    continue

                features = extract_features(normalized)
                probs = update_technique_probabilities(features)
                explanation = explain_attribution(probs, features)

                host = normalized.get("host", normalized.get("source_ip", "unknown"))
                top_tech = max(probs, key=probs.get, default="none") if probs else "none"
                top_prob = probs.get(top_tech, 0.0)

                print(f"Host / Source IP: {host}")
                print(f"Top technique: {top_tech} ({top_prob:.1%})")
                print(explanation)
                print("-" * 70)

            except json.JSONDecodeError:
                print(f"Line {i}: invalid JSON")
            except Exception as e:
                print(f"Line {i}: processing error → {type(e).__name__}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="ATT&CK Inference Engine MVP - Process sample telemetry files"
    )
    parser.add_argument(
        "--input",
        default="data/samples",
        help="Directory containing *.jsonl sample files"
    )
    args = parser.parse_args()

    input_dir = Path(args.input).resolve()
    if not input_dir.exists() or not input_dir.is_dir():
        print(f"Error: Input directory not found or not a directory: {input_dir}", file=sys.stderr)
        sys.exit(1)

    jsonl_files = list(input_dir.glob("*.jsonl"))
    if not jsonl_files:
        print(f"No .jsonl files found in {input_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(jsonl_files)} .jsonl file(s) to process\n")

    for file_path in jsonl_files:
        process_file(file_path)


if __name__ == "__main__":
    main()
