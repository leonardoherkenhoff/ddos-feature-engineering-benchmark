import os
import glob
import subprocess
from multiprocessing import Pool
import sys
import time
import json

INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/AL_RAW"
NUM_WORKERS = 10
AL_EXEC = os.environ.get("AL_EXEC", "alflowlyzer")

def process_file(args):
    """Worker function to process a single PCAP file via ALFlowLyzer."""
    pcap_raw_path, output_dir = args
    pcap_path = os.path.abspath(pcap_raw_path)
    output_dir = os.path.abspath(output_dir)
    filename = os.path.basename(pcap_path)
    expected_csv = os.path.join(output_dir, filename.replace(".pcap", ".csv"))
    json_config = os.path.join(output_dir, filename.replace(".pcap", ".json"))
    
    if os.path.exists(expected_csv) and os.path.getsize(expected_csv) > 1000:
        return f"⏭️  Skipped: {filename}"

    conf = {
        "pcap_file_address": pcap_path,
        "output_file_address": expected_csv,
        "label": "BENIGN",
        "number_of_threads": 4,
        "feature_extractor_min_flows": 0,
        "writer_min_rows": 0
    }
    with open(json_config, 'w') as f:
        json.dump(conf, f)

    cmd = [AL_EXEC, "-c", json_config]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        return f"✅ Success: {filename}"
    except subprocess.CalledProcessError as e:
        return f"❌ Error: {filename} - {e.stderr}"
    except Exception as e:
        return f"❌ Error System: {filename} - {e}"

def get_packet_count(pcap_files):
    import re
    total = 0
    for pcap in pcap_files:
        try:
            result = subprocess.run(['capinfos', '-c', pcap], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            local_count = 0
            for line in result.stdout.split('\n'):
                if 'Number of packets:' in line:
                    val = line.split(':')[1]
                    val_clean = re.sub(r'\D', '', val)
                    if val_clean:
                        local_count = int(val_clean)
                    break
                    
            if local_count == 0 and result.stderr:
                err_match = re.search(r'after reading (\d+) packets', result.stderr)
                if err_match:
                    local_count = int(err_match.group(1))
            total += local_count
        except Exception as e:
            print(f"⚠️ Warning: Failed to parse packet count for {pcap}: {e}")
    return total

def run_extraction():
    print(f"=== ALFlowLyzer Pipeline ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Collect all directories containing at least one PCAP
    pcap_dirs = set()
    for pcap in glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True):
        if "DNS" in pcap:
            pcap_dirs.add(os.path.dirname(pcap))
            
    sys.path.append(os.path.dirname(__file__))
    try:
        from concat_utils import process_directory
    except ImportError:
        def process_directory(d, name): pass
        
    for pcap_dir in sorted(pcap_dirs):
        rel_path = os.path.relpath(pcap_dir, INPUT_DIR)
        attack_name = rel_path.replace(os.path.sep, "_")
        target_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(target_dir, exist_ok=True)
        
        pcaps = glob.glob(os.path.join(pcap_dir, "*.pcap"))
        if not pcaps: continue
        
        print(f"\n🚀 STARTING AL EXTRACTION: {attack_name}...")
        start_time = time.time()
        
        monitor_csv = os.path.join(target_dir, f"monitor_{attack_name}.csv")
        monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
        monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(os.getpid()), monitor_csv])
        
        total_packets = get_packet_count(pcaps)
        
        tasks = [(p, target_dir) for p in pcaps]
        if tasks:
            with Pool(NUM_WORKERS) as pool:
                for result in pool.imap_unordered(process_file, tasks):
                    print(result)

        # Post processing: Concatenate CSVs per Directory
        print(f"Consolidating fragmented CSVs for {attack_name}...")
        process_directory(target_dir, attack_name)

        end_time = time.time()
        elapsed = end_time - start_time
        pps = total_packets / elapsed if elapsed > 0 else 0
        
        monitor_proc.terminate()
        try:
            monitor_proc.wait(timeout=5)
        except:
            monitor_proc.kill()
            
        benchmark_log = os.path.join(target_dir, f"benchmark_{attack_name}.json")
        with open(benchmark_log, 'w') as f:
            json.dump({
                "attack": attack_name,
                "tool": "ALFlowLyzer", 
                "total_packets": total_packets, 
                "time_seconds": elapsed, 
                "pps": pps,
                "monitor_file": monitor_csv
            }, f, indent=4)
            
        print(f"📊 Benchmark: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

if __name__ == "__main__":
    run_extraction()
