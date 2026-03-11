import os
import glob
import subprocess
import time
import json

"""
CICFlowMeter Orchestrator
Extracts L4 features from raw PCAPs using the baseline Java tool.
"""

INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/CIC_RAW"
CIC_EXEC = os.environ.get("CIC_EXEC", "cicflowmeter") # Fallback to path

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
    print(f"=== CICFlowMeter Pipeline ===")
    pcaps = glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True)
    
    if not pcaps:
        print("No PCAPs found.")
        return

    start_time = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    monitor_csv = os.path.join(OUTPUT_DIR, "monitor_cicflowmeter.csv")
    monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
    import sys
    monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(os.getpid()), monitor_csv])
    
    print("Counting packets...")
    total_packets = get_packet_count(pcaps)
    print(f"Total packets to process: {total_packets}")

    for pcap in pcaps:
        filename = os.path.basename(pcap)
        target_dir = os.path.join(OUTPUT_DIR, os.path.relpath(os.path.dirname(pcap), INPUT_DIR))
        os.makedirs(target_dir, exist_ok=True)
        
        cmd = [CIC_EXEC, pcap, target_dir]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            print(f"✅ Success: {filename}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error processing {filename} (Code {e.returncode}):\n{e.stderr}")
        except Exception as e:
            print(f"❌ Exception processing {filename}: {e}")

    end_time = time.time()
    elapsed = end_time - start_time
    pps = total_packets / elapsed if elapsed > 0 else 0
    
    monitor_proc.terminate()
    try:
        monitor_proc.wait(timeout=5)
    except:
        monitor_proc.kill()
        
    benchmark_log = os.path.join(OUTPUT_DIR, "benchmark_cicflowmeter.json")
    with open(benchmark_log, 'w') as f:
        json.dump({
            "tool": "CICFlowMeter", 
            "total_packets": total_packets, 
            "time_seconds": elapsed, 
            "pps": pps,
            "monitor_file": monitor_csv
        }, f, indent=4)
        
    print(f"📊 Benchmark: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

if __name__ == "__main__":
    run_extraction()
