import os
import glob
import subprocess
import shutil
import json
from multiprocessing import Pool
import time
import sys

# --- CONFIGURATION ---
NUM_WORKERS = 10          
THREADS_PER_WORKER = 4    
CHUNK_SIZE = 50000        
NTL_EXEC = "ntlflowlyzer" 

def run_cmd(cmd):
    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def worker_task(args):
    pcap_chunk, csv_chunk, json_config = args
    conf = {
        "pcap_file_address": pcap_chunk,
        "output_file_address": csv_chunk,
        "label": "BENIGN",
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

def safe_remove_dir(dir_path):
    for _ in range(5):
        try:
            if os.path.exists(dir_path): shutil.rmtree(dir_path)
            return
        except OSError: time.sleep(2)

def process_attack(input_pcap_dir, output_csv_dir, attack_name):
    final_csv = os.path.join(output_csv_dir, f"{attack_name}.csv")
    work_dir = os.path.join(output_csv_dir, f"temp_{attack_name}")

    if os.path.exists(final_csv) and os.path.getsize(final_csv) > 1000000:
        print(f"✅ {attack_name} already exists. Skipping.")
        return

    print(f"\n🚀 STARTING: {attack_name}...")
    safe_remove_dir(work_dir)
    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(output_csv_dir, exist_ok=True)

    merged_pcap = os.path.join(work_dir, "full.pcap")
    pcaps = glob.glob(os.path.join(input_pcap_dir, "*.pcap"))
    
    if not pcaps: return
    
    print(f"   -> [1/4] Merging {len(pcaps)} files...")
    run_cmd(f"mergecap -F pcap -w '{merged_pcap}' " + " ".join([f"'{p}'" for p in pcaps]))

    print(f"   -> [2/4] Slicing into {CHUNK_SIZE} packet chunks...")
    run_cmd(f"editcap -c {CHUNK_SIZE} -F pcap '{merged_pcap}' '{os.path.join(work_dir, 'chunk.pcap')}'")
    chunks = sorted(glob.glob(os.path.join(work_dir, "chunk*.pcap")))

    print(f"   -> [3/4] Processing ({NUM_WORKERS} Workers)...")
    tasks = []
    for chunk in chunks:
        c_csv = chunk.replace(".pcap", ".csv")
        c_json = chunk.replace(".pcap", ".json")
        tasks.append((chunk, c_csv, c_json))
    
    with Pool(NUM_WORKERS) as pool:
        results = list(pool.imap_unordered(worker_task, tasks))
    
    success_count = results.count(True)
    if success_count < (len(chunks) * 0.99): 
        print(f"   ❌ CRITICAL ERROR: Too many failures.")
        return

    print(f"   -> [4/4] Consolidating final CSV...")
    csv_parts = sorted(glob.glob(os.path.join(work_dir, "chunk*.csv")))
    csv_parts = [f for f in csv_parts if os.path.exists(f)]

    if csv_parts:
        with open(final_csv, 'w') as outfile:
            for csv in csv_parts:
                with open(csv, 'r') as infile:
                    shutil.copyfileobj(infile, outfile)
        print(f"✅ DONE: {final_csv}")
        safe_remove_dir(work_dir)
