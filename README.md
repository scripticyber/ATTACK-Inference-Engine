# ATT&CK Inference Engine (AIE)

Real-time forensic inference engine that maps raw telemetry (Sysmon, Zeek, Windows logs) to MITRE ATT&CK techniques with probabilistic confidence scores.

## Goals
- Dynamic, non-signature-based technique attribution
- Probabilistic & explainable inference
- Local-first MVP → scalable architecture

## Current MVP Scope
- Normalize Sysmon + Zeek events
- Extract behavioral features
- Bayesian + ML-based technique probability estimation
- Output to Elasticsearch + basic dashboard

## Quick Start (local)

```bash
git clone https://github.com/YOURUSERNAME/ATTACK-Inference-Engine.git
cd ATTACK-Inference-Engine
docker-compose up -d
poetry install    # or pip install -r requirements.txt
python src/main.py --input data/samples/
