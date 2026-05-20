import time
import psutil
import os
from functools import wraps
from ..experiments.log_results import log_to_csv
MAX_POWER_WATTS = 15.0
IDLE_POWER_WATTS = 5.0

def calculate_energy(cpu_percent, exec_time):
    """Estimates energy in Joules based on CPU% and Time."""
    average_power = IDLE_POWER_WATTS + (MAX_POWER_WATTS - IDLE_POWER_WATTS) * (cpu_percent / 100.0)
    energy_joules = average_power * exec_time
    return energy_joules

def measure_performance(algo_name, operation):
    """A decorator that wraps any function to measure Time, CPU, Energy, and File Size."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            
            # --- FIXED FILE SIZE DETECTION ---
            file_size_mb = "N/A"
            
            file_path = args[0] if args else None
            
            # If it's a string, check if it actually exists on the hard drive
            if file_path and isinstance(file_path, str):
                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        file_bytes = os.path.getsize(file_path)
                        # Added 4 decimal places so tiny files still show a size!
                        file_size_mb = f"{file_bytes / (1024 * 1024):.4f}"
                except Exception:
                    pass # Ignore if it's not a file (like an OTP secret)

            # Prime the CPU monitor
            psutil.cpu_percent(interval=None)
            
            # Start timer
            start_time = time.perf_counter()

            # Execute the actual algorithm
            result = func(*args, **kwargs)

            # Stop timer and get CPU usage
            end_time = time.perf_counter()
            cpu_percent = psutil.cpu_percent(interval=None)

            # Calculate Metrics
            exec_time = end_time - start_time
            energy = calculate_energy(cpu_percent, exec_time)

            # Output the formatted log
            print(f"{algo_name} | {operation} | Size: {file_size_mb} MB | Time: {exec_time:.6f}s | CPU: {cpu_percent}% | Energy: {energy:.6f} J")

            # Save to CSV
            log_to_csv(algo_name, operation, file_size_mb, exec_time, cpu_percent, energy)

            return result
        return wrapper
    return decorator
