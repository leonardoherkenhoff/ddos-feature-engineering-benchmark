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
        
        if monitor_file and os.path.exists(monitor_file):
            summary_file = monitor_file.replace('.csv', '_summary.txt')
            if os.path.exists(summary_file):
                with open(summary_file, 'r') as sf:
                    for line in sf:
                        if line.startswith("Max_RAM_MB"):
                            max_ram = float(line.split('=')[1])
                        elif line.startswith("Avg_CPU_Percent"):
                            avg_cpu = float(line.split('=')[1])
        
        results.append({
            "Extractor": tool_name,
            "Total Packets": data.get("total_packets", 0),
            "Time (s)": round(data.get("time_seconds", 0), 2),
            "Throughput (PPS)": round(data.get("pps", 0), 2),
            "Avg CPU (%)": round(avg_cpu, 2),
            "Max RAM (MB)": round(max_ram, 2)
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
        "Max RAM (MB)": "max"
    }).reset_index()
    
    df_agg["Throughput (PPS)"] = df_agg["Total Packets"] / df_agg["Time (s)"]
    df_agg["Throughput (PPS)"] = df_agg["Throughput (PPS)"].round(2)
    df_agg["Time (s)"] = df_agg["Time (s)"].round(2)
    df_agg["Avg CPU (%)"] = df_agg["Avg CPU (%)"].round(2)
    
    print("\n=== Benchmark Consolidation ===")
    print(df_agg.to_string(index=False))
    
    # Generate LaTeX
    latex_table = df_agg.to_latex(index=False, caption="Computational Overhead and Throughput per Extractor", label="tab:overhead")
    
    out_file = "./results/figures/benchmark_table.tex"
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w") as f:
        f.write(latex_table)
    
    print(f"\nLaTeX table saved to {out_file}")

if __name__ == "__main__":
    generate_table()
