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
            "Attack": attack_name,
            "Packets": data.get("total_packets", 0),
            "Time (s)": round(data.get("time_seconds", 0), 4),
            "Throughput (PPS)": round(data.get("pps", 0), 4),
            "Avg CPU (%)": round(avg_cpu, 4),
            "Std CPU": round(std_cpu if pd.notna(std_cpu) else 0, 4),
            "Var CPU": round(var_cpu if pd.notna(var_cpu) else 0, 4),
            "Max RAM (MB)": round(max_ram, 4),
            "Std RAM": round(std_ram if pd.notna(std_ram) else 0, 4),
            "Var RAM": round(var_ram if pd.notna(var_ram) else 0, 4)
        })

    if not results:
        print("No benchmark data found.")
        return

    df = pd.DataFrame(results).sort_values(["Extractor", "Attack"])

    out_dir = "./results/figures"
    os.makedirs(out_dir, exist_ok=True)

    def write_dataset(sub_df, prefix, caption):
        if sub_df.empty: return
        csv_out = os.path.join(out_dir, f"{prefix}.csv")
        sub_df.to_csv(csv_out, index=False)
        tex_out = os.path.join(out_dir, f"{prefix}.tex")
        with open(tex_out, "w") as f:
            f.write(sub_df.to_latex(index=False, caption=caption))

    print(f"\n=== Per-Attack Benchmark Breakdown ===")
    print(df.to_string(index=False))
    
    # Gerar Dataset Completo Detalhado
    write_dataset(df, "benchmark_detailed", "Desempenho Sistêmico e Consumo de Infraestrutura Analítico por Extrator")

    # Gerar Dataset Específico: DNS
    df_dns = df[df['Attack'].str.contains('DNS', case=False, na=False)]
    write_dataset(df_dns, "benchmark_dns_only", "Desempenho Sistêmico e Consumo de Infraestrutura por Extrator (Ataque de Exaustão de Camada 7 L7 - Amplificação DNS)")

    # Gerar Dataset Específico: Syn Flood
    df_syn = df[df['Attack'].str.contains('Syn', case=False, na=False)]
    write_dataset(df_syn, "benchmark_syn_only", "Desempenho Sistêmico e Consumo de Infraestrutura por Extrator (Ataque de Camada Oculta - TCP Syn Flood)")
    
    # Head-to-Head Syn Flood (CIC vs NTL only, though AL doesn't parse Syn naturally, this enforces it)
    df_syn_h2h = df_syn[df_syn['Extractor'].isin(['CICFlowMeter', 'NTLFlowLyzer'])]
    write_dataset(df_syn_h2h, "head_to_head_cic_ntl_syn", "Desempenho Sistêmico e Consumo de Infraestrutura por Extrator (Comparativo Direto CIC vs NTL - TCP Syn Flood)")

    print(f"\nCSV and LaTeX saved to {out_dir}")

if __name__ == "__main__":
    generate_detailed()
