import os
import glob
import subprocess
import time
import json
import sys

INPUT_DIR = "./data/raw/PCAP"
OUTPUT_DIR = "./data/interim/CIC_RAW"
CIC_EXEC = os.environ.get("CIC_EXEC", "cicflowmeter")

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
    print(f"=== CICFlowMeter Pipeline ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Collect all directories containing at least one PCAP
    pcap_dirs = set()
    for pcap in glob.glob(os.path.join(INPUT_DIR, "**", "*.pcap"), recursive=True):
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
        
        print(f"\n🚀 STARTING CIC EXTRACTION: {attack_name}...")
        start_time = time.time()
        
        monitor_csv = os.path.join(target_dir, f"monitor_{attack_name}.csv")
        monitor_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
        monitor_proc = subprocess.Popen([sys.executable, monitor_script, str(os.getpid()), monitor_csv])
        
        total_packets = get_packet_count(pcaps)
        
        for pcap in pcaps:
            filename = os.path.basename(pcap)
            cmd = [CIC_EXEC, pcap, target_dir]
            
            env = os.environ.copy()
            app_home = os.path.abspath(os.path.join(os.path.dirname(CIC_EXEC), ".."))
            env["JAVA_OPTS"] = env.get("JAVA_OPTS", "") + f" -Djava.library.path={app_home}/lib/native -Xmx12g"

            try:
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
                print(f"✅ Success: {filename}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Error processing {filename} (Code {e.returncode}):\n{e.stderr}")
            except Exception as e:
                print(f"❌ Exception processing {filename}: {e}")

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
                "tool": "CICFlowMeter", 
                "total_packets": total_packets, 
                "time_seconds": elapsed, 
                "pps": pps,
                "monitor_file": monitor_csv
            }, f, indent=4)
            
        print(f"📊 Benchmark: {total_packets} packets | {elapsed:.2f}s | {pps:.2f} pps")

if __name__ == "__main__":
    run_extraction()
