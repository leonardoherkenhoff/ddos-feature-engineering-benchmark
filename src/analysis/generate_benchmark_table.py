import os
import glob
import json
import pandas as pd

"""
Consolidates benchmark logs (Time, PPS, Overhead) into a LaTeX table
for the SBSeg paper.
"""

def generate_table():
    base_dir = "./data/interim"
    results = []
    
    # Locate all benchmark json files
    benchmark_files = glob.glob(os.path.join(base_dir, "**", "benchmark_*.json"), recursive=True)
    
    for b_file in benchmark_files:
        with open(b_file, 'r') as f:
            data = json.load(f)
            
        tool_name = data.get("tool", "Unknown")
        if tool_name == "Unknown":
            if "ntl" in b_file.lower() or "temp_" in b_file:
                tool_name = "NTLFlowLyzer"
            elif "alflowlyzer" in b_file.lower():
                tool_name = "ALFlowLyzer"
            elif "cic" in b_file.lower():
                tool_name = "CICFlowMeter"
            
        monitor_file = data.get("monitor_file")
        max_ram = 0
        avg_cpu = 0
        std_cpu = 0
        var_cpu = 0
        std_ram = 0
        var_ram = 0
        
        if monitor_file and os.path.exists(monitor_file):
            try:
                m_df = pd.read_csv(monitor_file)
                if not m_df.empty:
                    max_ram = m_df['ram_mb'].max()
                    avg_cpu = m_df['cpu_percent'].mean()
                    std_cpu = m_df['cpu_percent'].std()
                    var_cpu = m_df['cpu_percent'].var()
                    std_ram = m_df['ram_mb'].std()
                    var_ram = m_df['ram_mb'].var()
            except Exception:
                pass
        
        results.append({
            "Extractor": tool_name,
            "Total Packets": data.get("total_packets", 0),
            "Time (s)": round(data.get("time_seconds", 0), 2),
            "Throughput (PPS)": round(data.get("pps", 0), 2),
            "Avg CPU (%)": round(avg_cpu, 2),
            "Std CPU": round(std_cpu if pd.notna(std_cpu) else 0, 2),
            "Var CPU": round(var_cpu if pd.notna(var_cpu) else 0, 2),
            "Max RAM (MB)": round(max_ram, 2),
            "Std RAM": round(std_ram if pd.notna(std_ram) else 0, 2),
            "Var RAM": round(var_ram if pd.notna(var_ram) else 0, 2)
        })

    if not results:
        print("No benchmark data found.")
        return

    df = pd.DataFrame(results)
    # Aggregate if multiple attacks for NTL
    df_agg = df.groupby("Extractor").agg({
        "Total Packets": "sum",
        "Time (s)": "sum",
        "Avg CPU (%)": "mean",
        "Std CPU": "mean",
        "Var CPU": "mean",
        "Max RAM (MB)": "max",
        "Std RAM": "mean",
        "Var RAM": "mean",
    }).reset_index()
    
    df_agg["Throughput (PPS)"] = df_agg["Total Packets"] / df_agg["Time (s)"]
    df_agg["Throughput (PPS)"] = df_agg["Throughput (PPS)"].round(2)
    df_agg["Time (s)"] = df_agg["Time (s)"].round(2)
    df_agg["Avg CPU (%)"] = df_agg["Avg CPU (%)"].round(2)
    df_agg["Std CPU"] = df_agg["Std CPU"].round(2)
    df_agg["Var CPU"] = df_agg["Var CPU"].round(2)
    df_agg["Std RAM"] = df_agg["Std RAM"].round(2)
    df_agg["Var RAM"] = df_agg["Var RAM"].round(2)
    
    print("\n=== Benchmark Consolidation ===")
    print(df_agg.to_string(index=False))
    
    out_file = "./results/figures/benchmark_table.tex"
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w") as f:
        f.write(df_agg.to_latex(index=False, caption="Computational Overhead and Throughput per Extractor", label="tab:overhead"))
    
    # Head to Head NTL vs CIC General Table
    df_head2head = df_agg[df_agg['Extractor'].isin(['CICFlowMeter', 'NTLFlowLyzer'])]
    h2h_file = "./results/figures/head_to_head_cic_ntl.tex"
    with open(h2h_file, "w") as f:
        f.write(df_head2head.to_latex(index=False, caption="General Head to Head Comparison: CICFlowMeter vs NTLFlowLyzer", label="tab:head2head"))

    print(f"\nLaTeX tables saved to ./results/figures/")

if __name__ == "__main__":
    generate_table()
