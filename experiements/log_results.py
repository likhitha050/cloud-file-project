import csv
import os
import time

# ==========================================
# CSV FILE CONFIG
# ==========================================
CSV_FILE = "results.csv"


# ==========================================
# LOG FUNCTION
# ==========================================
def log_to_csv(
    algo_name,
    operation,
    file_size_mb,
    exec_time,
    cpu_percent,
    ram_usage_mb,
    energy
):

    # Check if CSV already exists
    file_exists = os.path.isfile(CSV_FILE)

    # Open CSV file
    with open(CSV_FILE, mode="a", newline="") as file:

        writer = csv.writer(file)

        # ==========================================
        # WRITE HEADER ONLY ONCE
        # ==========================================
        if not file_exists:

            writer.writerow([
                "Timestamp",
                "Algorithm",
                "Operation",
                "File Size (MB)",
                "Execution Time (s)",
                "CPU Usage (%)",
                "RAM Usage (MB)",
                "Energy (J)"
            ])

        # ==========================================
        # HANDLE FILE SIZE SAFELY
        # ==========================================
        try:

            if file_size_mb != "N/A":
                file_size_mb = round(float(file_size_mb), 6)

        except:
            file_size_mb = "N/A"

        # ==========================================
        # WRITE DATA ROW
        # ==========================================
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            algo_name,
            operation,
            file_size_mb,
            round(exec_time, 6),
            round(cpu_percent, 2),
            round(ram_usage_mb, 2),
            round(energy, 6)
        ])

    print("Metrics saved to results.csv")
