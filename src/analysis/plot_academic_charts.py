import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd

# SBSeg Academic Styling
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_context("paper", font_scale=1.5)
# Colorblind friendly palette (Blue / Orange-Redish)
colors_main = ['#0072B2', '#D55E00'] 
colors_secondary = ['#56B4E9', '#E69F00']

# =======================================================
# 1. Flow Collapse & Memory Explosion Chart (Syn Flood)
# =======================================================
def plot_flow_collapse():
    fig, ax1 = plt.subplots(figsize=(8, 6))

    extractors = ['CICFlowMeter', 'NTLFlowLyzer']
    flows = [9.4, 0.416] # In millions
    ram = [9.13, 13.38] # In GB

    x = np.arange(len(extractors))
    width = 0.35

    # Plot Flows (Left Axis)
    ax1.set_xlabel('Extrator', fontweight='bold')
    ax1.set_ylabel('Fluxos Extraídos (Milhões)', color=colors_main[0], fontweight='bold')
    bars1 = ax1.bar(x - width/2, flows, width, label='Fluxos (M)', color=colors_main[0], edgecolor='black')
    ax1.tick_params(axis='y', labelcolor=colors_main[0])
    ax1.set_ylim(0, 11)

    # Plot RAM (Right Axis)
    ax2 = ax1.twinx()  
    ax2.set_ylabel('Pico de RAM Consumida (GB)', color=colors_main[1], fontweight='bold')
    bars2 = ax2.bar(x + width/2, ram, width, label='Max RAM (GB)', color=colors_main[1], edgecolor='black', hatch='//')
    ax2.tick_params(axis='y', labelcolor=colors_main[1])
    ax2.set_ylim(0, 15)

    ax1.set_xticks(x)
    ax1.set_xticklabels(extractors, fontweight='bold')
    
    # Title and Layout
    plt.title('Colapso de Agregação vs. Consumo de Memória\n(TCP Syn Flood - 5M Pacotes)', fontweight='bold', pad=15)
    
    # Combined Legend
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper center', bbox_to_anchor=(0.5, -0.15), fancybox=True, shadow=True, ncol=2)
    
    plt.tight_layout()
    plt.savefig('/home/leo/.gemini/antigravity/playground/obsidian-planck/flow_collapse_v2.pdf', format='pdf', bbox_inches='tight')
    plt.close()

# =======================================================
# 2. Heuristic Blindness Chart (UDP & LDAP Recall Drop)
# =======================================================
def plot_f1_blindness():
    # Constructing DataFrame based on empirical ML results
    data = {
        'Scenario': ['Syn', 'Syn', 'UDP', 'UDP', 'LDAP', 'LDAP'],
        'Extractor': ['CICFlowMeter', 'NTLFlowLyzer', 'CICFlowMeter', 'NTLFlowLyzer', 'CICFlowMeter', 'NTLFlowLyzer'],
        'Recall': [1.00, 0.99, 0.99, 0.81, 0.90, 0.89],
        'Precision': [1.00, 0.99, 0.99, 0.94, 0.99, 0.95]
    }
    df = pd.DataFrame(data)

    fig, ax = plt.subplots(figsize=(9, 6))
    
    # Plotting Recall to highlight Falsos Negativos
    sns.barplot(
        data=df, 
        x='Scenario', y='Recall', hue='Extractor',
        palette=colors_main, edgecolor='black', ax=ax
    )

    # Adding values on top of bars
    for p in ax.patches:
        ax.annotate(f"{p.get_height():.2f}", 
                    (p.get_x() + p.get_width() / 2., p.get_height()), 
                    ha='center', va='center', fontsize=12, fontweight='bold', 
                    color='black', xytext=(0, 10), textcoords='offset points')

    ax.set_ylim(0, 1.1)
    ax.axhline(1.0, color='gray', linestyle='--', linewidth=1)
    
    ax.set_xlabel('Vetor de Ataque', fontweight='bold', fontsize=14)
    ax.set_ylabel('Taxa de Recall', fontweight='bold', fontsize=14)
    plt.title('Cegueira Heurística (Recall): Protocolos Stateful vs Stateless\n', fontweight='bold')
    
    # Move legend outside
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0.)
    
    plt.tight_layout()
    plt.savefig('/home/leo/.gemini/antigravity/playground/obsidian-planck/f1_blindness_v2.pdf', format='pdf', bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    plot_flow_collapse()
    plot_f1_blindness()
    print("Graficos gerados com sucesso como flow_collapse_v2.pdf e f1_blindness_v2.pdf")
