# DDoS Feature Engineering Benchmark

This repository contains the source code for the paper **"The Impact of Feature Engineering on Data Quality: A Comparative Study of Extractors for DDoS Detection"**, submitted to SBRC 2026.

## 📌 Overview
We benchmark three feature extractors using the CICDDoS2019 dataset:
1. **CICFlowMeter** (Baseline/Java)
2. **NTLFlowLyzer** (Network/Transport Layer / Python)
3. **ALFlowLyzer** (Application Layer / Python)

## 🚀 Key Features
* **Topological Labeling:** Ground truth correction based on network topology (IP `172.16.0.5`).
* **Hybrid Validation:** Supports both Temporal Generalization (Real) and Statistical Split validation strategies.
* **Sanitization:** Robust handling of `NaN` and `Inf` values produced by modern extractors in volumetric attacks.

## 📂 Structure
* `src/extraction`: Wrappers for running NTLFlowLyzer and ALFlowLyzer.
* `src/preprocessing`: Logic for topological labeling and header injection.
* `src/analysis`: Random Forest benchmark and F1-score calculation.

## 🔧 Usage
1. Install dependencies: `pip install -r requirements.txt`
2. Run extraction (requires `ntlflowlyzer` in PATH).
3. Run analysis: `python src/analysis/run_benchmark.py`
