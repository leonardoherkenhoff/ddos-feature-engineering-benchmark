import pandas as pd
import numpy as np
import os
import glob

"""
Topological Labeler & Sanitizer for CICFlowMeter
Cleans column names and applies Ground Truth based strictly on 
the attacker's source IP (Topological rule).
"""

# --- CONFIGURATION ---
INPUT_DIR = "./data/interim/CIC_RAW"
OUTPUT_DIR = "./data/processed/CIC"
ATTACKER_IP = '172.16.0.5'
CHUNK_SIZE = 100_000 

def process_file_auto(file_path):
    """Cleans headers and applies topological labeling in chunks."""
    try:
        filename = os.path.basename(file_path)
        attack_name = filename.replace('.csv', '')
        
        rel_path = os.path.relpath(os.path.dirname(file_path), INPUT_DIR)
        output_dir = os.path.join(OUTPUT_DIR, rel_path)
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, filename)
        if os.path.exists(output_file): os.remove(output_file)
        
        # Read the first chunk to get and clean the columns
        first_chunk = pd.read_csv(file_path, nrows=10)
        clean_cols = [c.strip().lower().replace(' ', '_') for c in first_chunk.columns]
        
        # Identify the source IP column index
        src_col_idx = -1
        for i, col in enumerate(clean_cols):
            if 'src' in col and 'ip' in col:
                src_col_idx = i
                break
                
        if src_col_idx == -1:
            print(f"   [WARNING] Could not find Source IP column in {filename}.")
            return False

        # Add Label to our header list if not already (CIC sometimes has 'Label' at the end)
        has_label = 'label' in clean_cols
        if has_label:
            clean_cols[clean_cols.index('label')] = 'Label'
        else:
            clean_cols.append('Label')
            
        # Write clean header
        with open(output_file, 'w') as f:
            f.write(",".join(clean_cols) + "\n")

        # Process chunks to evaluate IP rules
        # Use on_bad_lines='skip' to avoid breaking on malformed rows
        reader = pd.read_csv(file_path, header=0, chunksize=CHUNK_SIZE, low_memory=False, on_bad_lines='skip')
        for chunk in reader:
            if has_label:
                # Target CIC 'Label' column and override it
                src_ips = chunk.iloc[:, src_col_idx]
                labels = np.where(src_ips == ATTACKER_IP, attack_name, 'BENIGN')
                chunk.iloc[:, clean_cols.index('Label')] = labels
                data_to_save = chunk
            else:
                data_to_save = chunk.copy()
                src_ips = data_to_save.iloc[:, src_col_idx]
                labels = np.where(src_ips == ATTACKER_IP, attack_name, 'BENIGN')
                data_to_save['Label'] = labels
                
            data_to_save.to_csv(output_file, mode='a', header=False, index=False)
            
        return True
    except Exception as e:
        print(f"    ❌ Error processing {file_path}: {e}")
        return False

def main():
    print("=== CICFlowMeter Topological Labeling ===")
    files = sorted(glob.glob(os.path.join(INPUT_DIR, "**", "*.csv"), recursive=True))
    if not files:
        print("No CSV files found in interim directory.")
        return
        
    for f in files:
        if process_file_auto(f):
            print(f"    ✅ Labeled: {os.path.basename(f)}")

if __name__ == "__main__":
    main()
