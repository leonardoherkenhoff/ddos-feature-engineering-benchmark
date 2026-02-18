import os
import glob
import subprocess
from multiprocessing import Pool

# --- CONFIGURATION ---
NUM_WORKERS = 10
AL_EXEC = "alflowlyzer"

def process_file(args):
    pcap_path, output_dir = args
    filename = os.path.basename(pcap_path)
    expected_csv = os.path.join(output_dir, filename.replace(".pcap", ".csv"))
    
    if os.path.exists(expected_csv) and os.path.getsize(expected_csv) > 1000:
        return f"⏭️  Skipped: {filename}"

    cmd = [AL_EXEC, "-f", pcap_path, "-o", output_dir + "/"]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        return f"✅ Success: {filename}"
    except:
        return f"❌ Error: {filename}"

def run_extraction(input_root, output_root):
    print(f"=== ALFlowLyzer Pipeline (L7 Analysis) ===")
    pcaps = glob.glob(os.path.join(input_root, "**", "*.pcap"), recursive=True)
    
    tasks = []
    for pcap in pcaps:
        rel_path = os.path.relpath(os.path.dirname(pcap), input_root)
        target_dir = os.path.join(output_root, rel_path)
        os.makedirs(target_dir, exist_ok=True)
        tasks.append((pcap, target_dir))

    with Pool(NUM_WORKERS) as pool:
        for result in pool.imap_unordered(process_file, tasks):
            print(result)
