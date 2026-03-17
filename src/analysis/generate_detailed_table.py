import os
import glob
import json
import pandas as pd

"""
Generates a per-attack detailed breakdown of benchmark metrics for all extractors.
Outputs: results/figures/benchmark_detailed.csv and benchmark_detailed.tex
"""

def generate_detailed():
    base_dir = "./data/interim"
    results = []

    benchmark_files = glob.glob(os.path.join(base_dir, "**", "benchmark_*.json"), recursive=True)

    for b_file in benchmark_files:
        with open(b_file, 'r') as f:
            data = json.load(f)

        tool_name = data.get("tool", "Unknown")
        if tool_name == "Unknown":
            if "ntl" in b_file.lower():
                tool_name = "NTLFlowLyzer"
            elif "alflowlyzer" in b_file.lower() or "al_raw" in b_file.lower():
                tool_name = "ALFlowLyzer"
            elif "cic" in b_file.lower():
                tool_name = "CICFlowMeter"

        attack_name = data.get("attack", os.path.basename(b_file).replace("benchmark_", "").replace(".json", ""))
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
            if max_ram == 0 or avg_cpu == 0:
                try:
                    m_df = pd.read_csv(monitor_file)
                    if not m_df.empty:
                        max_ram = m_df['ram_mb'].max()
                        avg_cpu = m_df['cpu_percent'].mean()
                except Exception:
                    pass

        results.append({
            "Extractor": tool_name,
            "Attack": attack_name,
            "Packets": data.get("total_packets", 0),
            "Time (s)": round(data.get("time_seconds", 0), 2),
            "Avg CPU (%)": round(avg_cpu, 2),
            "Max RAM (MB)": round(max_ram, 2),
            "Throughput (PPS)": round(data.get("pps", 0), 2),
        })

    if not results:
        print("No benchmark data found.")
        return

    df = pd.DataFrame(results).sort_values(["Extractor", "Attack"])

    out_dir = "./results/figures"
    os.makedirs(out_dir, exist_ok=True)

    csv_out = os.path.join(out_dir, "benchmark_detailed.csv")
    df.to_csv(csv_out, index=False)
    print(f"\n=== Per-Attack Benchmark Breakdown ===")
    print(df.to_string(index=False))

    latex = df.to_latex(
        index=False,
        caption="Per-Attack Computational Overhead and Throughput per Extractor",
        label="tab:overhead_detailed",
        column_format="llrrrrr"
    )
    tex_out = os.path.join(out_dir, "benchmark_detailed.tex")
    with open(tex_out, "w") as f:
        f.write(latex)

    print(f"\nCSV  saved to {csv_out}")
    print(f"LaTeX saved to {tex_out}")

if __name__ == "__main__":
    generate_detailed()
