import pandas as pd
import numpy as np
import os
import gc
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from imblearn.under_sampling import RandomUnderSampler

warnings.simplefilter(action='ignore', category=FutureWarning)

"""
Balanced Sanity Benchmark (50/50 Random Undersampling)
======================================================
Evaluates CICFlowMeter, NTLFlowLyzer, and ALFlowLyzer features under
strictly balanced class distribution to validate genuine discriminative
power of extracted features.

Key differences from run_benchmark.py:
  1. RandomUnderSampler forces 1:1 (Attack:Benign) ratio on BOTH train and test sets.
  2. class_weight='balanced' is REMOVED from the classifier (unnecessary with RUS,
     and its removal is essential for a valid sanity check).
  3. Anti-leakage sanitization uses explicit column lists derived from each
     extractor's actual output schema (not regex guesses).
"""

# --- CONFIGURATION ---
DIRS = {
    'CIC': './data/processed/CIC',
    'NTL': './data/processed/NTL',
    'AL':  './data/processed/AL'
}
OUTPUT_DIR = "./results/balanced"
ATTACK_KEYWORDS = ['DNS', 'LDAP', 'MSSQL', 'NetBIOS', 'NTP', 'SNMP', 'SSDP', 'UDP', 'Syn', 'TFTP', 'UDPLag', 'Portmap']
# ALFlowLyzer only extracts Application Layer (L7) DNS traffic.
# Running it against L3/L4 attack vectors would produce no data.
AL_ATTACK_KEYWORDS = ['DNS']
SAFE_THRESHOLD = 500 * 1024 * 1024  # 500 MB
CHUNK_SIZE = 200_000
MAX_ROWS_PER_FILE = 2_500_000

# --- ANTI-LEAKAGE: Explicit column purge lists per extractor ---
# Derived from: cic_labeler.py, ntl_labeler.py (MASTER_HEADER), al_labeler.py
# These columns are network identifiers that allow the model to memorize
# topology instead of learning behavioral signatures.
LEAKAGE_COLUMNS = {
    'CIC': {
        # CICFlowMeter header names after .strip().lower().replace(' ', '_')
        'flow_id', 'source_ip', 'source_port', 'destination_ip', 'destination_port',
        'src_ip', 'src_port', 'dst_ip', 'dst_port',  # alternate naming
        'timestamp', 'protocol',
    },
    'NTL': {
        # NTLFlowLyzer: first 7 columns from MASTER_HEADER in ntl_labeler.py
        'flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    },
    'AL': {
        # ALFlowLyzer: meta_cols from al_labeler.py (minus 'label' which is the target)
        'flow_id', 'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
    },
}
# Residual safety net: any column containing these substrings is also purged
LEAKAGE_SUBSTRINGS = ['unnamed', 'simillarhttp', 'mac', 'vlan']

os.makedirs(OUTPUT_DIR, exist_ok=True)


def purge_leakage_columns(df, extractor_name):
    """Remove all identifier/metadata columns that cause data leakage.
    
    Uses the explicit per-extractor purge list plus a residual substring filter.
    Returns only behavioral/statistical features.
    """
    cols_normalized = {c.strip().lower().replace(' ', '_'): c for c in df.columns}
    
    # Exact match purge
    known_leakage = LEAKAGE_COLUMNS.get(extractor_name, set())
    cols_to_drop = []
    for norm_name, orig_name in cols_normalized.items():
        if norm_name in known_leakage:
            cols_to_drop.append(orig_name)
        elif any(sub in norm_name for sub in LEAKAGE_SUBSTRINGS):
            cols_to_drop.append(orig_name)
    
    df_clean = df.drop(columns=cols_to_drop, errors='ignore')
    return df_clean


def process_chunk(df_chunk, extractor_name):
    """Sanitizes chunk: removes leakage columns, encodes categoricals, handles NaN/Inf."""
    df_chunk.columns = [c.strip().lower().replace(' ', '_') for c in df_chunk.columns]
    
    # Identify label column
    possible_labels = [c for c in df_chunk.columns if 'label' in c or 'class' in c]
    if not possible_labels:
        return None, None
    target_col = possible_labels[-1]
    
    # Extract target before purging
    y_raw = df_chunk[target_col]
    if isinstance(y_raw, pd.DataFrame):
        y_raw = y_raw.iloc[:, -1]
    
    # Binary encoding: 1 = Attack, 0 = Benign
    y_bin = y_raw.astype(str).str.lower().str.contains('benign').astype(int)
    y_bin = 1 - y_bin
    
    # Drop label columns before feature purge
    df_chunk = df_chunk.drop(columns=possible_labels, errors='ignore')
    
    # Anti-leakage purge
    X = purge_leakage_columns(df_chunk, extractor_name)
    
    # Label-encode any remaining string columns (e.g., ALFlowLyzer L7 behavioral fields)
    for col in X.columns:
        if X[col].dtype == 'object':
            X[col] = X[col].astype(str)
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col])
    
    # Downcasting for RAM efficiency
    for col in X.select_dtypes(include=['float64']).columns:
        X[col] = X[col].astype('float32')
    for col in X.select_dtypes(include=['int64']).columns:
        X[col] = X[col].astype('int32')
    
    # Mathematical sanitization
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    
    return X, y_bin


def load_dataset(filepath, extractor_name):
    """Loads CSV entirely or via reservoir sampling if above SAFE_THRESHOLD."""
    if not os.path.exists(filepath):
        return None, None
    fsize = os.path.getsize(filepath)
    
    if fsize < SAFE_THRESHOLD:
        try:
            df = pd.read_csv(filepath, low_memory=False)
            return process_chunk(df, extractor_name)
        except Exception:
            return None, None
    else:
        buffer_X, buffer_y = [], []
        total_rows = 0
        try:
            estimated_rows = (fsize / (1024**3)) * 2_000_000
            sample_rate = min(1.0, MAX_ROWS_PER_FILE / estimated_rows) if estimated_rows > 0 else 0.5
            for chunk in pd.read_csv(filepath, chunksize=CHUNK_SIZE, low_memory=False):
                X_c, y_c = process_chunk(chunk, extractor_name)
                if X_c is None:
                    continue
                if sample_rate < 1.0:
                    n = int(len(X_c) * sample_rate)
                    if n > 0:
                        idx = np.random.choice(X_c.index, n, replace=False)
                        X_c, y_c = X_c.loc[idx], y_c.loc[idx]
                buffer_X.append(X_c)
                buffer_y.append(y_c)
                total_rows += len(X_c)
                if total_rows > MAX_ROWS_PER_FILE:
                    break
            if not buffer_X:
                return None, None
            return pd.concat(buffer_X, ignore_index=True), pd.concat(buffer_y, ignore_index=True)
        except Exception:
            return None, None


def balance_dataset(X, y):
    """Apply RandomUnderSampler to force 1:1 class ratio."""
    if len(y.unique()) < 2:
        return None, None
    rus = RandomUnderSampler(sampling_strategy='majority', random_state=42)
    X_bal, y_bal = rus.fit_resample(X, y)
    return X_bal, y_bal


def find_file(base_dir, day_folder, keyword):
    """Search helper mapped to CICDDoS2019 directory topology."""
    search_path = os.path.join(base_dir, day_folder) if day_folder else base_dir
    if not os.path.exists(search_path):
        return None
    keyword = keyword.lower().replace('drdos_', '')
    for root, _, files in os.walk(search_path):
        for f in files:
            if not f.endswith('.csv') or 'semlabel' in f.lower():
                continue
            if keyword == 'udp' and 'lag' in f.lower():
                continue
            if keyword in f.lower():
                return os.path.join(root, f)
    return None


def run_balanced_analysis():
    ml_results_db = []
    print("=" * 70)
    print("  BALANCED SANITY BENCHMARK (50/50 Random Undersampling)")
    print("  Extratores: CICFlowMeter | NTLFlowLyzer | ALFlowLyzer")
    print("=" * 70)
    print("Anti-Leakage: Colunas de identificação (IP, Port, Timestamp, FlowID,")
    print("              Protocol) removidas conforme schema de cada extrator.")
    print("Balanceamento: RandomUnderSampler (majority → minority count)")
    print("Classificador: RandomForestClassifier(n_estimators=40, max_depth=15)")
    print("               SEM class_weight='balanced' (redundante com RUS)")
    print("=" * 70)

    for attack in ATTACK_KEYWORDS:
        print(f"\n{'=' * 50}")
        print(f">>> CENÁRIO: {attack}")
        print(f"{'=' * 50}")

        for ext_name, ext_root in DIRS.items():
            # ALFlowLyzer only has data for DNS attack vectors
            if ext_name == 'AL' and attack not in AL_ATTACK_KEYWORDS:
                continue
            gc.collect()

            # --- Locate files ---
            train_path = find_file(ext_root, '01-12', attack)
            if not train_path:
                train_path = find_file(ext_root, '', attack)
            if not train_path:
                print(f"    [{ext_name}] AVISO: CSV base para {attack} não encontrado.")
                continue

            test_path = find_file(ext_root, '03-11', attack)
            if not test_path and ext_name == 'AL':
                test_path = find_file(ext_root, '', attack)

            # --- Load & sanitize ---
            X_train, y_train = load_dataset(train_path, ext_name)
            if X_train is None or len(y_train.unique()) < 2:
                print(f"    [{ext_name}] ERRO: Dados de treino inválidos ou < 2 classes.")
                continue

            # Report purged columns
            print(f"    [{ext_name}] Features após anti-leakage: {X_train.shape[1]} colunas")
            print(f"    [{ext_name}] Distribuição PRÉ-balanceamento: Ataque={int((y_train == 1).sum())} | Benigno={int((y_train == 0).sum())}")

            # --- Balance training set ---
            X_train_bal, y_train_bal = balance_dataset(X_train, y_train)
            if X_train_bal is None:
                print(f"    [{ext_name}] ERRO: Balanceamento falhou (classe única).")
                continue
            print(f"    [{ext_name}] Distribuição PÓS-balanceamento (Treino): Ataque={int((y_train_bal == 1).sum())} | Benigno={int((y_train_bal == 0).sum())}")

            del X_train, y_train
            gc.collect()

            # --- Train RF (NO class_weight) ---
            rf = RandomForestClassifier(
                n_estimators=40, max_depth=15,
                random_state=42, n_jobs=-1
            )

            if test_path and train_path != test_path:
                # STRATEGY 1: Temporal Validation (Day 1 → Day 2)
                strategy = 'Temporal'
                print(f"    [{ext_name}] Validação TEMPORAL (Treino Dia 1 → Teste Dia 2)...")
                rf.fit(X_train_bal, y_train_bal)
                train_cols = X_train_bal.columns
                importances = rf.feature_importances_

                del X_train_bal, y_train_bal
                gc.collect()

                X_test, y_test = load_dataset(test_path, ext_name)
                if X_test is None:
                    print(f"    [{ext_name}] ERRO: Dados de teste inválidos.")
                    continue

                # Balance test set for sanity parity
                X_test_bal, y_test_bal = balance_dataset(X_test, y_test)
                if X_test_bal is None:
                    print(f"    [{ext_name}] ERRO: Balanceamento de teste falhou.")
                    continue

                print(f"    [{ext_name}] Distribuição PÓS-balanceamento (Teste): Ataque={int((y_test_bal == 1).sum())} | Benigno={int((y_test_bal == 0).sum())}")

                # Align columns
                for c in (set(train_cols) - set(X_test_bal.columns)):
                    X_test_bal[c] = 0
                X_test_bal = X_test_bal.reindex(columns=train_cols, fill_value=0)

                y_pred = rf.predict(X_test_bal)
                y_test_final = y_test_bal

            else:
                # STRATEGY 2: Statistical Split (70/30)
                strategy = 'Split'
                print(f"    [{ext_name}] Validação SPLIT (70/30)...")
                X_tr, X_te, y_tr, y_te = train_test_split(
                    X_train_bal, y_train_bal,
                    test_size=0.3, random_state=42, stratify=y_train_bal
                )
                rf.fit(X_tr, y_tr)
                y_pred = rf.predict(X_te)
                y_test_final = y_te
                importances = rf.feature_importances_
                train_cols = X_train_bal.columns

            # --- Metrics ---
            f1 = f1_score(y_test_final, y_pred, average='weighted')
            prec = precision_score(y_test_final, y_pred, average='weighted', zero_division=0)
            rec = recall_score(y_test_final, y_pred, average='weighted', zero_division=0)
            cm = confusion_matrix(y_test_final, y_pred)

            print(f"    ✅ F1={f1:.4f} | Precision={prec:.4f} | Recall={rec:.4f}")
            print(f"    📊 Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

            ml_results_db.append({
                'Extractor': ext_name,
                'Attack': attack,
                'Strategy': strategy,
                'F1-Score': f1,
                'Precision': prec,
                'Recall': rec,
                'TN': cm[0][0],
                'FP': cm[0][1],
                'FN': cm[1][0],
                'TP': cm[1][1],
                'Train_Samples_Balanced': int((y_train_bal if 'y_train_bal' in dir() else y_tr).shape[0]),
                'Features_Count': len(train_cols),
            })

            # --- Top 10 Features ---
            importances_std = np.std([tree.feature_importances_ for tree in rf.estimators_], axis=0)
            indices = np.argsort(importances)[::-1]
            top_10 = []
            for i in range(min(10, len(indices))):
                idx = indices[i]
                feat = train_cols[idx]
                mean_w = importances[idx]
                std_w = importances_std[idx]
                top_10.append(f"{feat} ({mean_w:.3f}±{std_w:.3f})")

            tex_str = ", ".join(top_10).replace('_', '\\_')
            print(f"    📋 LATEX: {attack} & {ext_name} & {strategy} & {prec:.4f} & {rec:.4f} & {f1:.4f} & \\scriptsize{{{tex_str}}} \\\\ \\hline\n")

            del rf, y_pred
            gc.collect()

    # --- Export ---
    df_ml = pd.DataFrame(ml_results_db)
    output_csv = os.path.join(OUTPUT_DIR, 'balanced_ml_metrics.csv')
    df_ml.to_csv(output_csv, index=False, float_format='%.6f')
    print(f"\n[+] Exportação Concluída: {output_csv}")
    print(f"[+] Total de cenários avaliados: {len(ml_results_db)}")


if __name__ == "__main__":
    run_balanced_analysis()
