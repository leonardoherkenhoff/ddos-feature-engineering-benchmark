import os
import glob
import subprocess
from multiprocessing import Pool

"""
ALFlowLyzer Orchestrator
Extracts L7 (Application) features from raw PCAPs (e.g., DNS, HTTP).
Executes extraction in parallel (one file per process).
"""

# --- CONFIGURATION ---
INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/AL_RAW"
NUM_WORKERS = 10
AL_EXEC = "alflowlyzer"

def process_file(args):
    """Worker function to process a single PCAP file via ALFlowLyzer."""
    pcap_path, output_dir = args
    filename = os.path.basename(pcap_path)
    expected_csv = os.path.join(output_dir, filename.replace(".pcap", ".csv"))
    
    if os.path.exists(expected_csv) and os.path.getsize(expected_csv) > 1000:
        return f"⏭️  Skipped: {filename}"

    cmd = [AL_EXEC, "-f", pcap_path, "-o", output_dir + "/"]
    try:
        # Enforce timeout to prevent hangs on malformed packets
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        return f"✅ Success: {filename}"
    except:
        return f"❌ Error: {filename}"

def run_extraction():
    """Main execution loop for parallel L7 feature extraction."""
    print(f"=== ALFlowLyzer Pipeline ===")
    pcaps = glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True)
    
    tasks = []
    for pcap in pcaps:
        # Maintain original directory structure
        rel_path = os.path.relpath(os.path.dirname(pcap), INPUT_DIR)
        target_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(target_dir, exist_ok=True)
        tasks.append((pcap, target_dir))

    with Pool(NUM_WORKERS) as pool:
        for result in pool.imap_unordered(process_file, tasks):
            print(result)

if __name__ == "__main__":
    run_extraction()
