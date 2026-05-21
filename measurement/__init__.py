import time
import psutil
import os
from functools import wraps
from experiements.log_results import log_to_csv

MAX_POWER_WATTS = 15.0
IDLE_POWER_WATTS = 5.0


def calculate_energy(cpu_percent, exec_time):
    """
    Estimates energy in Joules based on CPU usage and execution time.
    """

    average_power = (
        IDLE_POWER_WATTS +
        (MAX_POWER_WATTS - IDLE_POWER_WATTS)
        * (cpu_percent / 100.0)
    )

    energy_joules = average_power * exec_time

    return energy_joules


def measure_performance(algo_name, operation):
    """
    Decorator to measure:
    - Execution Time
    - CPU Usage
    - Energy Consumption
    - File Size
    """

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):

            # ----------------------------------
            # FILE SIZE DETECTION
            # ----------------------------------
            file_size_mb = "N/A"

            file_path = args[0] if args else None

            if file_path and isinstance(file_path, str):

                try:
                    if os.path.exists(file_path) and os.path.isfile(file_path):

                        file_bytes = os.path.getsize(file_path)

                        file_size_mb = (
                            f"{file_bytes / (1024 * 1024):.4f}"
                        )

                except Exception:
                    pass

            # ----------------------------------
            # PROCESS MONITORING
            # ----------------------------------
            process = psutil.Process(os.getpid())

            # CPU times before execution
            cpu_before = process.cpu_times()

            # RAM before execution
            memory_before = process.memory_info().rss / (1024 * 1024)

            # Start timer
            start_time = time.perf_counter()

            # ----------------------------------
            # EXECUTE FUNCTION
            # ----------------------------------
            result = func(*args, **kwargs)

            # End timer
            end_time = time.perf_counter()

            # CPU times after execution
            cpu_after = process.cpu_times()

            # RAM after execution
            memory_after = process.memory_info().rss / (1024 * 1024)

            # ----------------------------------
            # CALCULATE METRICS
            # ----------------------------------
            exec_time = end_time - start_time

            cpu_time_used = (
                (cpu_after.user - cpu_before.user) +
                (cpu_after.system - cpu_before.system)
            )

            cpu_percent = (
                (cpu_time_used / exec_time) * 100
                if exec_time > 0 else 0
            )

            avg_memory_mb = (
                memory_before + memory_after
            ) / 2

            energy = calculate_energy(
                cpu_percent,
                exec_time
            )

            # ----------------------------------
            # PRINT RESULTS
            # ----------------------------------
            print(
                f"{algo_name} | "
                f"{operation} | "
                f"Size: {file_size_mb} MB | "
                f"Time: {exec_time:.6f}s | "
                f"CPU: {cpu_percent:.2f}% | "
                f"RAM: {avg_memory_mb:.2f} MB | "
                f"Energy: {energy:.6f} J"
            )

            # ----------------------------------
            # SAVE TO CSV
            # ----------------------------------
            log_to_csv(
                algo_name,
                operation,
                file_size_mb,
                exec_time,
                cpu_percent,
                energy
            )

            return result

        return wrapper

    return decorator
