import pandas as pd
import numpy as np
import os

ATTACKER_IP = '172.16.0.5'
CHUNK_SIZE = 100_000 

MASTER_HEADER = [
    "flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "duration", "packets_count", 
    "fwd_packets_count", "bwd_packets_count", "total_payload_bytes", "fwd_total_payload_bytes", "bwd_total_payload_bytes", 
    "payload_bytes_max", "payload_bytes_min", "payload_bytes_mean", "payload_bytes_std", "payload_bytes_variance", 
    "fwd_payload_bytes_max", "fwd_payload_bytes_min", "fwd_payload_bytes_mean", "fwd_payload_bytes_std", 
    "fwd_payload_bytes_variance", "bwd_payload_bytes_max", "bwd_payload_bytes_min", "bwd_payload_bytes_mean", 
    "bwd_payload_bytes_std", "bwd_payload_bytes_variance", "total_header_bytes", "max_header_bytes", "min_header_bytes", 
    "mean_header_bytes", "std_header_bytes", "fwd_total_header_bytes", "fwd_max_header_bytes", "fwd_min_header_bytes", 
    "fwd_mean_header_bytes", "fwd_std_header_bytes", "bwd_total_header_bytes", "bwd_max_header_bytes", 
    "bwd_min_header_bytes", "bwd_mean_header_bytes", "bwd_std_header_bytes", "fwd_avg_segment_size", "bwd_avg_segment_size", 
    "avg_segment_size", "fwd_init_win_bytes", "bwd_init_win_bytes", "active_min", "active_max", "active_mean", "active_std", 
    "idle_min", "idle_max", "idle_mean", "idle_std", "bytes_rate", "fwd_bytes_rate", "bwd_bytes_rate", "packets_rate", 
    "bwd_packets_rate", "fwd_packets_rate", "down_up_rate", "avg_fwd_bytes_per_bulk", "avg_fwd_packets_per_bulk", 
    "avg_fwd_bulk_rate", "avg_bwd_bytes_per_bulk", "avg_bwd_packets_bulk_rate", "avg_bwd_bulk_rate", "fwd_bulk_state_count", 
    "fwd_bulk_total_size", "fwd_bulk_per_packet", "fwd_bulk_duration", "bwd_bulk_state_count", "bwd_bulk_total_size", 
    "bwd_bulk_per_packet", "bwd_bulk_duration", "fin_flag_counts", "psh_flag_counts", "urg_flag_counts", "ece_flag_counts", 
    "syn_flag_counts", "ack_flag_counts", "cwr_flag_counts", "rst_flag_counts", "fwd_fin_flag_counts", "fwd_psh_flag_counts", 
    "fwd_urg_flag_counts", "fwd_ece_flag_counts", "fwd_syn_flag_counts", "fwd_ack_flag_counts", "fwd_cwr_flag_counts", 
    "fwd_rst_flag_counts", "bwd_fin_flag_counts", "bwd_psh_flag_counts", "bwd_urg_flag_counts", "bwd_ece_flag_counts", 
    "bwd_syn_flag_counts", "bwd_ack_flag_counts", "bwd_cwr_flag_counts", "bwd_rst_flag_counts", "fin_flag_percentage_in_total", 
    "psh_flag_percentage_in_total", "urg_flag_percentage_in_total", "ece_flag_percentage_in_total", "syn_flag_percentage_in_total", 
    "ack_flag_percentage_in_total", "cwr_flag_percentage_in_total", "rst_flag_percentage_in_total", "fwd_fin_flag_percentage_in_total", 
    "fwd_psh_flag_percentage_in_total", "fwd_urg_flag_percentage_in_total", "fwd_ece_flag_percentage_in_total", 
    "fwd_syn_flag_percentage_in_total", "fwd_ack_flag_percentage_in_total", "fwd_cwr_flag_percentage_in_total", 
    "fwd_rst_flag_percentage_in_total", "bwd_fin_flag_percentage_in_total", "bwd_psh_flag_percentage_in_total", 
    "bwd_urg_flag_percentage_in_total", "bwd_ece_flag_percentage_in_total", "bwd_syn_flag_percentage_in_total", 
    "bwd_ack_flag_percentage_in_total", "bwd_cwr_flag_percentage_in_total", "bwd_rst_flag_percentage_in_total", 
    "fwd_fin_flag_percentage_in_fwd_packets", "fwd_psh_flag_percentage_in_fwd_packets", "fwd_urg_flag_percentage_in_fwd_packets", 
    "fwd_ece_flag_percentage_in_fwd_packets", "fwd_syn_flag_percentage_in_fwd_packets", "fwd_ack_flag_percentage_in_fwd_packets", 
    "fwd_cwr_flag_percentage_in_fwd_packets", "fwd_rst_flag_percentage_in_fwd_packets", "bwd_fin_flag_percentage_in_bwd_packets", 
    "bwd_psh_flag_percentage_in_bwd_packets", "bwd_urg_flag_percentage_in_bwd_packets", "bwd_ece_flag_percentage_in_bwd_packets", 
    "bwd_syn_flag_percentage_in_bwd_packets", "bwd_ack_flag_percentage_in_bwd_packets", "bwd_cwr_flag_percentage_in_bwd_packets", 
    "bwd_rst_flag_percentage_in_bwd_packets", "packets_iat_mean", "packet_iat_std", "packet_iat_max", "packet_iat_min", 
    "packet_iat_total", "fwd_packets_iat_mean", "fwd_packets_iat_std", "fwd_packets_iat_max", "fwd_packets_iat_min", 
    "fwd_packets_iat_total", "bwd_packets_iat_mean", "bwd_packets_iat_std", "bwd_packets_iat_max", "bwd_packets_iat_min", 
    "bwd_packets_iat_total", "subflow_fwd_packets", "subflow_bwd_packets", "subflow_fwd_bytes", "subflow_bwd_bytes", 
    "delta_start", "handshake_duration", "handshake_state", "packets_delta_time_min", "packets_delta_time_max", 
    "packets_delta_time_mean", "packets_delta_time_mode", "packets_delta_time_variance", "packets_delta_time_std", 
    "packets_delta_time_median", "packets_delta_time_skewness", "packets_delta_time_cov", "bwd_packets_delta_time_min", 
    "bwd_packets_delta_time_max", "bwd_packets_delta_time_mean", "bwd_packets_delta_time_mode", "bwd_packets_delta_time_variance", 
    "bwd_packets_delta_time_std", "bwd_packets_delta_time_median", "bwd_packets_delta_time_skewness", "bwd_packets_delta_time_cov", 
    "fwd_packets_delta_time_min", "fwd_packets_delta_time_max", "fwd_packets_delta_time_mean", "fwd_packets_delta_time_mode", 
    "fwd_packets_delta_time_variance", "fwd_packets_delta_time_std", "fwd_packets_delta_time_median", "fwd_packets_delta_time_skewness", 
    "fwd_packets_delta_time_cov", "packets_delta_len_min", "packets_delta_len_max", "packets_delta_len_mean", "packets_delta_len_mode", 
    "packets_delta_len_variance", "packets_delta_len_std", "packets_delta_len_median", "packets_delta_len_skewness", 
    "packets_delta_len_cov", "bwd_packets_delta_len_min", "bwd_packets_delta_len_max", "bwd_packets_delta_len_mean", 
    "bwd_packets_delta_len_mode", "bwd_packets_delta_len_variance", "bwd_packets_delta_len_std", "bwd_packets_delta_len_median", 
    "bwd_packets_delta_len_skewness", "bwd_packets_delta_len_cov", "fwd_packets_delta_len_min", "fwd_packets_delta_len_max", 
    "fwd_packets_delta_len_mean", "fwd_packets_delta_len_mode", "fwd_packets_delta_len_variance", "fwd_packets_delta_len_std", 
    "fwd_packets_delta_len_median", "fwd_packets_delta_len_skewness", "fwd_packets_delta_len_cov", "header_bytes_delta_len_min", 
    "header_bytes_delta_len_max", "header_bytes_delta_len_mean", "header_bytes_delta_len_mode", "header_bytes_delta_len_variance", 
    "header_bytes_delta_len_std", "header_bytes_delta_len_median", "header_bytes_delta_len_skewness", "header_bytes_delta_len_cov", 
    "bwd_header_bytes_delta_len_min", "bwd_header_bytes_delta_len_max", "bwd_header_bytes_delta_len_mean", 
    "bwd_header_bytes_delta_len_mode", "bwd_header_bytes_delta_len_variance", "bwd_header_bytes_delta_len_std", 
    "bwd_header_bytes_delta_len_median", "bwd_header_bytes_delta_len_skewness", "bwd_header_bytes_delta_len_cov", 
    "fwd_header_bytes_delta_len_min", "fwd_header_bytes_delta_len_max", "fwd_header_bytes_delta_len_mean", 
    "fwd_header_bytes_delta_len_mode", "fwd_header_bytes_delta_len_variance", "fwd_header_bytes_delta_len_std", 
    "fwd_header_bytes_delta_len_median", "fwd_header_bytes_delta_len_skewness", "fwd_header_bytes_delta_len_cov", 
    "payload_bytes_delta_len_min", "payload_bytes_delta_len_max", "payload_bytes_delta_len_mean", "payload_bytes_delta_len_mode", 
    "payload_bytes_delta_len_variance", "payload_bytes_delta_len_std", "payload_bytes_delta_len_median", 
    "payload_bytes_delta_len_skewness", "payload_bytes_delta_len_cov", "bwd_payload_bytes_delta_len_min", 
    "bwd_payload_bytes_delta_len_max", "bwd_payload_bytes_delta_len_mean", "bwd_payload_bytes_delta_len_mode", 
    "bwd_payload_bytes_delta_len_variance", "bwd_payload_bytes_delta_len_std", "bwd_payload_bytes_delta_len_median", 
    "bwd_payload_bytes_delta_len_skewness", "bwd_payload_bytes_delta_len_cov", "fwd_payload_bytes_delta_len_min", 
    "fwd_payload_bytes_delta_len_max", "fwd_payload_bytes_delta_len_mean", "fwd_payload_bytes_delta_len_mode", 
    "fwd_payload_bytes_delta_len_variance", "fwd_payload_bytes_delta_len_std", "fwd_payload_bytes_delta_len_median", 
    "fwd_payload_bytes_delta_len_skewness", "fwd_payload_bytes_delta_len_cov"
]

def process_file_auto(file_path, output_dir):
    try:
        filename = os.path.basename(file_path)
        attack_name = filename.replace('_semLabel.csv', '')
        output_file = os.path.join(output_dir, f"{attack_name}.csv")
        
        if os.path.exists(output_file): os.remove(output_file)
        
        with open(file_path, 'r') as f:
            line = f.readline()
            if not line: return False
            cols_in_file = len(line.strip().split(','))
        
        n_features = cols_in_file - 1
        final_header = MASTER_HEADER[:n_features] + ["Label"]
        
        with open(output_file, 'w') as f: f.write(",".join(final_header) + "\n")

        reader = pd.read_csv(file_path, header=None, chunksize=CHUNK_SIZE, low_memory=False)
        for chunk in reader:
            data = chunk.iloc[:, :-1]
            if data.shape[1] != n_features: continue

            # TOPOLOGICAL LABELING
            src_ips = data.iloc[:, 2]
            labels = np.where(src_ips == ATTACKER_IP, attack_name, 'BENIGN')
            data['Label'] = labels
            
            data.to_csv(output_file, mode='a', header=False, index=False)
        return True
    except: return False
