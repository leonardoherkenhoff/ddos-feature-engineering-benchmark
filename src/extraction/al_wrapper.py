import os
import glob
import subprocess
from multiprocessing import Pool

import time
import json

"""
ALFlowLyzer Orchestrator
Extracts L7 (Application) features from raw PCAPs (e.g., DNS, HTTP).
Executes extraction in parallel (one file per process).
"""

# --- CONFIGURATION ---
INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/AL_RAW"
NUM_WORKERS = 10
AL_EXEC = os.environ.get("AL_EXEC", "alflowlyzer")

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
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=600)
        return f"✅ Success: {filename}"
    except subprocess.CalledProcessError as e:
        return f"❌ Error: {filename} - {e.stderr}"
    except Exception as e:
        return f"❌ Error System: {filename} - {e}"

def get_packet_count(pcap_files):
    total = 0
    for pcap in pcap_files:
        try:
            result = subprocess.run(['capinfos', '-c', pcap], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for line in result.stdout.split('\n'):
                if 'Number of packets:' in line:
                    val = line.split(':')[1].strip().replace(',', '')
                    total += int(val)
        except Exception:
            pass
    return total

def run_extraction():
    """Main execution loop for parallel L7 feature extraction."""
    print(f"=== ALFlowLyzer Pipeline ===")
    pcaps = glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True)
    
    start_time = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    monitor_csv = os.path.join(OUTPUT_DIR, "monitor_alflowlyzer.csv")
    monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
    import sys
    monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(os.getpid()), monitor_csv])
    
    print("Counting packets...")
    total_packets = get_packet_count(pcaps)
    print(f"Total packets to process: {total_packets}")
    
    tasks = []
    for pcap in pcaps:
        # Maintain original directory structure
        rel_path = os.path.relpath(os.path.dirname(pcap), INPUT_DIR)
        target_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(target_dir, exist_ok=True)
        tasks.append((pcap, target_dir))

    if tasks:
        with Pool(NUM_WORKERS) as pool:
            for result in pool.imap_unordered(process_file, tasks):
                print(result)

    end_time = time.time()
    elapsed = end_time - start_time
    pps = total_packets / elapsed if elapsed > 0 else 0
    
    monitor_proc.terminate()
    try:
        monitor_proc.wait(timeout=5)
    except:
        monitor_proc.kill()
        
    benchmark_log = os.path.join(OUTPUT_DIR, "benchmark_alflowlyzer.json")
    with open(benchmark_log, 'w') as f:
        json.dump({
            "tool": "ALFlowLyzer", 
            "total_packets": total_packets, 
            "time_seconds": elapsed, 
            "pps": pps,
            "monitor_file": monitor_csv
        }, f, indent=4)
        
    print(f"📊 Benchmark: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

if __name__ == "__main__":
    run_extraction()
