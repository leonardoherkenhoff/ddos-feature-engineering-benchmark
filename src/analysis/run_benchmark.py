import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import gc
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, f1_score

warnings.simplefilter(action='ignore', category=FutureWarning)

DIRS = {
    'CIC': './data/processed/CIC',
    'NTL': './data/processed/NTL',
    'AL':  './data/processed/AL'
}

OUTPUT_DIR = "./results/figures"
ATTACK_KEYWORDS = ['DNS', 'LDAP', 'MSSQL', 'NetBIOS', 'UDP', 'Syn', 'UDPLag'] 
SAFE_THRESHOLD = 500 * 1024 * 1024 
CHUNK_SIZE = 200_000 
MAX_ROWS_PER_FILE = 2_500_000 

def process_chunk(df_chunk):
    df_chunk.columns = [c.strip().lower().replace(' ', '_') for c in df_chunk.columns]
    possible_labels = [c for c in df_chunk.columns if 'label' in c or 'class' in c]
    if not possible_labels: return None, None
    target_col = possible_labels[-1]
    
    drop_patterns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'ip', 'port', 
                     'timestamp', 'flow_id', 'protocol', 'socket', 'unnamed']
    cols_to_drop = [c for c in df_chunk.columns if any(p in c for p in drop_patterns)]
    cols_to_drop.extend(possible_labels)
    
    X = df_chunk.drop(columns=cols_to_drop, errors='ignore')
    y_raw = df_chunk[target_col]
    
    for col in X.select_dtypes(include=['float64']).columns:
        X[col] = X[col].astype('float32')
    
    X = X.select_dtypes(include=[np.number])
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    
    if isinstance(y_raw, pd.DataFrame): y_raw = y_raw.iloc[:, -1]
    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin
    
    return X, y_bin

def load_dataset(filepath):
    if not os.path.exists(filepath): return None, None
    fsize = os.path.getsize(filepath)
    if fsize < SAFE_THRESHOLD:
        try:
            df = pd.read_csv(filepath)
            return process_chunk(df)
        except: return None, None
    else:
        buffer_X, buffer_y = [], []
        total_rows = 0
        try:
            estimated_rows = (fsize / (1024**3)) * 2_000_000
            sample_rate = min(1.0, MAX_ROWS_PER_FILE / estimated_rows) if estimated_rows > 0 else 0.5
            for chunk in pd.read_csv(filepath, chunksize=CHUNK_SIZE):
                X_c, y_c = process_chunk(chunk)
                if X_c is None: continue
                if sample_rate < 1.0:
                    n = int(len(X_c) * sample_rate)
                    if n > 0:
                        idx = np.random.choice(X_c.index, n, replace=False)
                        X_c, y_c = X_c.loc[idx], y_c.loc[idx]
                buffer_X.append(X_c); buffer_y.append(y_c)
                total_rows += len(X_c)
                if total_rows > MAX_ROWS_PER_FILE: break
            if not buffer_X: return None, None
            return pd.concat(buffer_X, ignore_index=True), pd.concat(buffer_y, ignore_index=True)
        except: return None, None

def find_file(base_dir, day_folder, keyword):
    search_path = os.path.join(base_dir, day_folder) if day_folder else base_dir
    if not os.path.exists(search_path): return None if day_folder else None
    keyword = keyword.lower().replace('drdos_', '')
    for root, _, files in os.walk(search_path):
        for f in files:
            if not f.endswith('.csv') or 'semlabel' in f.lower(): continue
            if keyword == 'udp' and ('lag' in f.lower() or 'portmap' in f.lower()): continue
            if keyword in f.lower(): return os.path.join(root, f)
    return None

def run_analysis():
    print("=== STARTING COMPARATIVE ANALYSIS ===")
    for attack in ATTACK_KEYWORDS:
        print(f"\n>>> Scenario: {attack}")
        for ext_name, ext_root in DIRS.items():
            gc.collect()
            train_path = find_file(ext_root, '01-12', attack)
            if not train_path and ext_name == 'AL': train_path = find_file(ext_root, '', attack)
            if not train_path: continue
            
            test_path = find_file(ext_root, '03-11', attack)
            X_train, y_train = load_dataset(train_path)
            if X_train is None: continue
            
            if test_path:
                rf = RandomForestClassifier(n_estimators=40, n_jobs=4, random_state=42, class_weight='balanced', max_depth=15)
                rf.fit(X_train, y_train)
                train_cols = X_train.columns
                del X_train, y_train; gc.collect()
                
                X_test, y_test = load_dataset(test_path)
                if X_test is None: continue
                for c in (set(train_cols) - set(X_test.columns)): X_test[c] = 0
                X_test = X_test[train_cols]
                y_pred = rf.predict(X_test)
            else:
                if len(y_train.unique()) < 2: continue
                X_train, X_test, y_train, y_test = train_test_split(X_train, y_train, test_size=0.3, random_state=42, stratify=y_train)
                rf = RandomForestClassifier(n_estimators=40, n_jobs=4, random_state=42, class_weight='balanced', max_depth=15)
                rf.fit(X_train, y_train)
                y_pred = rf.predict(X_test)

            f1 = f1_score(y_test, y_pred, average='weighted')
            print(f"    [{ext_name}] F1-Score: {f1:.4f}")
            del rf, X_test, y_test, y_pred; gc.collect()

if __name__ == "__main__":
    run_analysis()
