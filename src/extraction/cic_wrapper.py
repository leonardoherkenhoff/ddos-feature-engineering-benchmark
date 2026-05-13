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
    """Counts packets by reading PCAP binary headers directly.
    Independent of capinfos output format, locale, or version."""
    import struct
    PCAP_MAGIC_LE = b'\xd4\xc3\xb2\xa1'
    PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'
    total = 0
    for pcap in pcap_files:
        try:
            with open(pcap, 'rb') as f:
                magic = f.read(4)
                if magic not in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
                    print(f"⚠️ Warning: {pcap} is not a standard PCAP file.")
                    continue
                little_endian = (magic == PCAP_MAGIC_LE)
                f.read(20)  # skip rest of global header
                count = 0
                while True:
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break
                    endian = '<' if little_endian else '>'
                    incl_len = struct.unpack(endian + 'I', hdr[8:12])[0]
                    f.seek(incl_len, 1)
                    count += 1
                total += count
        except Exception as e:
            print(f"⚠️ Warning: Failed to count packets for {pcap}: {e}")
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
            # Smart discovery of jnetpcap native library
            import shutil
            cic_abs_path = shutil.which(CIC_EXEC)
            native_lib_path = None
            if cic_abs_path:
                cic_real_path = os.path.realpath(cic_abs_path)
                search_root = os.path.dirname(cic_real_path)
                for _ in range(5):
                    if os.path.exists(os.path.join(search_root, "jnetpcap", "linux", "jnetpcap-1.4.r1425")):
                        native_lib_path = os.path.join(search_root, "jnetpcap", "linux", "jnetpcap-1.4.r1425")
                        break
                    # Fallback to walk if specific path not found
                    for root, dirs, files in os.walk(search_root):
                        if "libjnetpcap.so" in files:
                            native_lib_path = root
                            break
                        if native_lib_path: break
                    if native_lib_path: break
                    new_root = os.path.dirname(search_root)
                    if new_root == search_root: break
                    search_root = new_root
            
            if not native_lib_path:
                app_home = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(shutil.which(CIC_EXEC) or "")), ".."))
                native_lib_path = os.path.join(app_home, "lib", "native")

            cmd = [CIC_EXEC, pcap, target_dir]
            env = os.environ.copy()
            env["JAVA_OPTS"] = env.get("JAVA_OPTS", "") + f" -Djava.library.path={native_lib_path} -Xmx12g"
            env["LD_LIBRARY_PATH"] = env.get("LD_LIBRARY_PATH", "") + f":{native_lib_path}"

            try:
                result = subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env)
                if result.stderr.strip():
                    jvm_log = os.path.join(target_dir, f"jvm_stderr_{os.path.basename(pcap)}.log")
                    with open(jvm_log, 'w') as jf:
                        jf.write(result.stderr)
                    if any(kw in result.stderr for kw in ['OutOfMemoryError', 'GC overhead', 'heap space']):
                        print(f"⚠️  ALERTA JVM: possível truncagem silenciosa em {filename}! Ver {jvm_log}")
                    else:
                        print(f"⚠️  JVM stderr não-vazio para {filename}. Ver {jvm_log}")
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
