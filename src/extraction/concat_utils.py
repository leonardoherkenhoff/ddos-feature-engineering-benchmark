import os
import glob
import pandas as pd

def concat_csvs(csv_list, output_file):
    if not csv_list: return
    
    first = True
    with open(output_file, 'w') as out:
        for csv in sorted(csv_list):
            try:
                with open(csv, 'r') as infile:
                    header = infile.readline()
                    if first:
                        out.write(header)
                        first = False
                    for line in infile:
                        out.write(line)
            except Exception as e:
                print(f"Warning: Failed to read {csv}: {e}")
                
def cleanup_csvs(csv_list):
    for csv in csv_list:
        try:
            os.remove(csv)
        except:
            pass
            
def process_directory(target_dir, attack_name):
    # Find all CSVs in target_dir that don't match attack_name.csv
    final_csv = os.path.join(target_dir, f"{attack_name}.csv")
    csvs = [f for f in glob.glob(os.path.join(target_dir, "*.csv")) 
            if f != final_csv and not os.path.basename(f).startswith("monitor_") and \
               not os.path.basename(f).startswith(f"benchmark_")]
               
    if not csvs:
        return
        
    concat_csvs(csvs, final_csv)
    cleanup_csvs(csvs)
    print(f"✅ Consolidated {len(csvs)} files into {final_csv}")
