#!/usr/bin/env python3
"""
Full Pipeline Orchestrator: Extraction → Labeling → Cleanup → Benchmark
========================================================================
Runs the complete pipeline sequentially, deleting interim data after
labeling to keep disk usage within the server's 270GB SSD capacity.

Usage:
    python src/run_pipeline.py [--skip-extraction] [--skip-benchmark]
"""
import subprocess
import sys
import os
import shutil
import argparse
import time

# Pipeline stages: (description, script, interim_dir_to_cleanup)
EXTRACTORS = [
    {
        'name': 'CICFlowMeter',
        'extract': 'src/extraction/cic_wrapper.py',
        'label':   'src/preprocessing/cic_labeler.py',
        'interim': './data/interim/CIC_RAW',
    },
    {
        'name': 'NTLFlowLyzer',
        'extract': 'src/extraction/ntl_wrapper.py',
        'label':   'src/preprocessing/ntl_labeler.py',
        'interim': './data/interim/NTL_RAW',
    },
    {
        'name': 'ALFlowLyzer',
        'extract': 'src/extraction/al_wrapper.py',
        'label':   'src/preprocessing/al_labeler.py',
        'interim': './data/interim/AL_RAW',
    },
]

BENCHMARK_SCRIPT = 'src/analysis/run_balanced_benchmark.py'


def get_dir_size_gb(path):
    """Returns directory size in GB."""
    if not os.path.exists(path):
        return 0.0
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total / (1024 ** 3)


def run_stage(description, script_path):
    """Executes a Python script, streaming output to stdout."""
    print(f"\n{'=' * 60}")
    print(f"🚀 {description}")
    print(f"   Script: {script_path}")
    print(f"{'=' * 60}")
    start = time.time()
    result = subprocess.run(
        [sys.executable, script_path],
        cwd=os.getcwd()
    )
    elapsed = time.time() - start
    if result.returncode != 0:
        print(f"❌ FALHA: {description} (exit code {result.returncode}) [{elapsed:.1f}s]")
        return False
    print(f"✅ CONCLUÍDO: {description} [{elapsed:.1f}s]")
    return True


def cleanup_interim(interim_dir, extractor_name):
    """Removes interim directory to reclaim disk space."""
    if not os.path.exists(interim_dir):
        return
    size_gb = get_dir_size_gb(interim_dir)
    print(f"🗑️  Removendo interim de {extractor_name}: {interim_dir} ({size_gb:.2f} GB)")
    shutil.rmtree(interim_dir)
    print(f"    ✅ {size_gb:.2f} GB liberados.")


def main():
    parser = argparse.ArgumentParser(description='Pipeline Completo: Extração → Rotulagem → Benchmark Balanceado')
    parser.add_argument('--skip-extraction', action='store_true',
                        help='Pular extração e rotulagem (usar dados já processados)')
    parser.add_argument('--skip-benchmark', action='store_true',
                        help='Pular benchmark (apenas extrair e rotular)')
    args = parser.parse_args()

    print("=" * 60)
    print("  PIPELINE COMPLETO — Benchmark Balanceado (50/50 RUS)")
    print("  Disk-aware: interim é apagado após rotulagem")
    print("=" * 60)

    total_start = time.time()

    if not args.skip_extraction:
        for ext in EXTRACTORS:
            # Phase 1: Extraction
            ok = run_stage(f"Extração: {ext['name']}", ext['extract'])
            if not ok:
                print(f"⚠️  Extração de {ext['name']} falhou. Continuando com os demais...")
                continue

            # Phase 2: Labeling
            ok = run_stage(f"Rotulagem: {ext['name']}", ext['label'])
            if not ok:
                print(f"⚠️  Rotulagem de {ext['name']} falhou.")
                continue

            # Phase 3: Cleanup interim
            cleanup_interim(ext['interim'], ext['name'])
    else:
        print("\n⏭️  Extração/Rotulagem ignorada (--skip-extraction)")

    if not args.skip_benchmark:
        # Phase 4: Balanced Benchmark
        run_stage("Benchmark Balanceado (50/50 RUS)", BENCHMARK_SCRIPT)
    else:
        print("\n⏭️  Benchmark ignorado (--skip-benchmark)")

    total_elapsed = time.time() - total_start
    print(f"\n{'=' * 60}")
    print(f"🏁 PIPELINE FINALIZADO [{total_elapsed:.1f}s total]")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
