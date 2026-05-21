import csv
import os
import time

CSV_FILE = "results.csv"

def log_to_csv(algo_name, operation, file_size_mb, exec_time, cpu_percent, energy):

    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)

        # Write header only once
        if not file_exists:
            writer.writerow([
                "Timestamp",
                "Algorithm",
                "Operation",
                "File Size (MB)",
                "Execution Time (s)",
                "CPU Usage (%)",
                "Energy (J)"
            ])

        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            algo_name,
            operation,
            round(float(file_size_mb), 6) if file_size_mb != "N/A" else "N/A",
            round(exec_time, 6),
            round(cpu_percent, 2),
            round(energy, 6)
        ])
