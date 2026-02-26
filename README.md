# ATT&CK Inference Engine (AIE)

**Real-time probabilistic MITRE ATT&CK technique inference from host & network telemetry**

This project aims to build a forensic engine that:
- Ingests Sysmon, Zeek (conn.log, dns.log, etc.), ETW, Windows Event Logs
- Normalizes to a common schema
- Extracts behavioral features
- Uses Bayesian networks + ML classifiers to assign dynamic probability scores to ATT&CK techniques
- Provides explainability (SHAP, evidence paths)
- Outputs to Elasticsearch + basic dashboard views

**Status**: Early MVP – local file-based processing only (no Kafka/Flink yet). Designed to be extensible.

## Features (planned / partial)
- Dynamic (non-signature) technique attribution
- Probabilistic confidence scores that update with new events
- Explainable attributions
- Local-first (runs on laptop), future scalable

## Quick Start (Local)

```bash
git clone https://github.com/scripticyber/ATTACK-Inference-Engine.git
cd ATTACK-Inference-Engine

# Option 1: pip
python3 -m venv .venv
source .venv/bin/activate    # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Option 2: poetry (recommended)
# poetry install

# Run basic pipeline on sample data
python3 src/main.py --input data/samples/
