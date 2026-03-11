
import os

import glob

import subprocess

import shutil

import json

from multiprocessing import Pool

import time


"""

NTLFlowLyzer Orchestrator

Extracts L3 (Network) and L4 (Transport) features from raw PCAPs.

Implements a chunking strategy to prevent memory overflow during processing.

"""


# --- CONFIGURATION ---

INPUT_DIR = "./data/raw/PCAP"

OUTPUT_DIR = "./data/interim/NTL_RAW"

NUM_WORKERS = 10          

THREADS_PER_WORKER = 4    

CHUNK_SIZE = 50000        # Max packets per chunk to ensure RAM stability

NTL_EXEC = "ntlflowlyzer" 


def get_packet_count(pcap_files):

    total = 0

    for pcap in pcap_files:

        try:

            output = subprocess.check_output(['capinfos', '-c', pcap], text=True)

            for line in output.split('\n'):

                if 'Number of packets:' in line:

                    val = line.split(':')[1].strip().replace(',', '')

                    total += int(val)

        except Exception:

            pass

    return total



def run_cmd(cmd):

    """Executes a shell command silently."""

    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def worker_task(args):

    """Worker function to process a single PCAP chunk via NTLFlowLyzer."""

    pcap_chunk, csv_chunk, json_config = args

    

    # Generate temporary JSON config required by NTLFlowLyzer

    conf = {

        "pcap_file_address": pcap_chunk,

        "output_file_address": csv_chunk,

        "label": "BENIGN", # Dummy label. Replaced in preprocessing phase.

        "number_of_threads": THREADS_PER_WORKER,

        "feature_extractor_min_flows": 0,

        "writer_min_rows": 0

    }

    with open(json_config, 'w') as f:

        json.dump(conf, f)

        

    try:

        subprocess.run([NTL_EXEC, "-c", json_config], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True

    except:

        return False


def process_attack(input_pcap_dir, output_csv_dir, attack_name):

    """Main pipeline: Merge PCAPs -> Split into chunks -> Extract features -> Concatenate."""

    final_csv = os.path.join(output_csv_dir, f"{attack_name}.csv")

    work_dir = os.path.join(output_csv_dir, f"temp_{attack_name}")


    if os.path.exists(final_csv):

        print(f"✅ {attack_name} already exists. Skipping.")

        return


    print(f"\n🚀 STARTING NTL EXTRACTION: {attack_name}...")

    os.makedirs(work_dir, exist_ok=True)

    os.makedirs(output_csv_dir, exist_ok=True)


    # Step 1: Merge raw PCAPs

    merged_pcap = os.path.join(work_dir, "full.pcap")

    pcaps = glob.glob(os.path.join(input_pcap_dir, "*.pcap"))

    if not pcaps: return
    
    start_time = time.time()
    monitor_csv = os.path.join(output_csv_dir, f"monitor_{attack_name}.csv")
    monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
    import sys
    monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(os.getpid()), monitor_csv])
    
    total_packets = get_packet_count(pcaps)

    run_cmd(f"mergecap -F pcap -w '{merged_pcap}' " + " ".join([f"'{p}'" for p in pcaps]))


    # Step 2: Split into safe chunks

    run_cmd(f"editcap -c {CHUNK_SIZE} -F pcap '{merged_pcap}' '{os.path.join(work_dir, 'chunk.pcap')}'")

    chunks = sorted(glob.glob(os.path.join(work_dir, "chunk*.pcap")))


    # Step 3: Parallel extraction

    tasks = [(c, c.replace(".pcap", ".csv"), c.replace(".pcap", ".json")) for c in chunks]

    with Pool(NUM_WORKERS) as pool:

        results = list(pool.imap_unordered(worker_task, tasks))

    

    if results.count(True) < (len(chunks) * 0.99): 

        print(f"   ❌ CRITICAL ERROR: High failure rate during extraction.")

        return


    # Step 4: Merge resulting CSVs

    csv_parts = [f for f in sorted(glob.glob(os.path.join(work_dir, "chunk*.csv"))) if os.path.exists(f)]

    if csv_parts:

        with open(final_csv, 'w') as outfile:

            for csv in csv_parts:

                with open(csv, 'r') as infile:

                    shutil.copyfileobj(infile, outfile)

        print(f"✅ DONE: {final_csv}")

        shutil.rmtree(work_dir, ignore_errors=True)



    # NEW: end profiling

    end_time = time.time()

    elapsed = end_time - start_time
    pps = total_packets / elapsed if elapsed > 0 else 0
    
    monitor_proc.terminate()
    try:
        monitor_proc.wait(timeout=5)
    except:
        monitor_proc.kill()

    benchmark_log = os.path.join(output_csv_dir, f"benchmark_{attack_name}.json")

    with open(benchmark_log, 'w') as f:

        json.dump({

            "attack": attack_name, 

            "total_packets": total_packets, 

            "time_seconds": elapsed, 

            "pps": pps,

            "monitor_file": monitor_csv

        }, f, indent=4)

        

    print(f"📊 Benchmark: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")


if __name__ == "__main__":

    # Example usage logic here

    pass

