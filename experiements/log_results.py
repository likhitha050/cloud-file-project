import csv
import os

CSV_FILE = "results.csv"

def log_to_csv(algo_name, operation, file_size_mb, exec_time, cpu_percent, energy):
    file_exists = os.path.isfile(CSV_FILE)

    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "Algorithm",
                "Operation",
                "File Size (MB)",
                "Execution Time (s)",
                "CPU Usage (%)",
                "Energy (J)"
            ])

        writer.writerow([
            algo_name,
            operation,
            file_size_mb,
            exec_time,
            cpu_percent,
            energy
        ])
