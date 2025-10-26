# AI-driven-Cyber-Deception-Systems
Objective: Build an adaptive honeypot that changes per-session configuration under ML control and demonstrate it increases attacker engagement versus static honeypot.

## Week 3 — Oct 27–Nov 2, 2025 (Data pipeline & feature extraction)

How to run:
1. Start infra: cd infra && ./start.sh
2. (Optional) simulate data: python3 scripts/simulate_attacker.py 200
3. Sessionize: python3 notebooks/extract_sessions.py
4. Extract features: python3 notebooks/feature_extractor.py
5. Open EDA: jupyter notebook notebooks/week3_EDA.ipynb

