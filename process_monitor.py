import psutil
import platform
import time
import config
import log_writer
import response
from collections import deque

# Track suspicious events to prevent false positives
event_history = deque(maxlen=50)
process_monitor_initialized = False

def get_os():
    """Detect the current operating system."""
    return platform.system()

def detect_suspicious_processes():
    global process_monitor_initialized

    os_name = get_os()

    if not process_monitor_initialized:
        log_writer.log_and_print("SYSTEM", f"Running process monitor on {os_name}")
        process_monitor_initialized = True

    for process in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'ppid']):
        try:
            pname = process.info.get('name', '').lower() if process.info.get('name') else "unknown"
            ppath = process.info.get('exe') or "unknown"
            parent_pid = process.info.get('ppid')
            cpu_usage = process.info.get('cpu_percent', 0)
            mem_usage = (process.info.get('memory_info').rss / (1024 * 1024)) if process.info.get('memory_info') else 0  # MB

            if not ppath or pname in config.WHITELIST_PROCESSES:
                continue

            # === BLACKLISTED PROCESS ===
            if pname in config.BLACKLIST_PROCESSES:
                log_writer.log_and_print("BLACKLIST", f"Blacklisted process detected: {pname} (PID: {process.info['pid']})")
                response.terminate_process(process.info['pid'], pname)
                continue

            # === GRAYLISTED PROCESS ===
            if pname in config.GRAYLIST_PROCESSES:
                log_writer.log_and_print("GRAYLIST", f"Graylisted process detected: {pname} (PID: {process.info['pid']})")
                response.terminate_process(process.info['pid'], pname)
                continue

            # === SUSPICIOUS PATH ===
            if any(path in ppath for path in config.SUSPICIOUS_PATHS):
                log_writer.log_and_print("GRAYLIST", f"Process from suspicious path: {ppath} ({pname})")

            # === HIGH RESOURCE USAGE ===
            if cpu_usage > config.HIGH_CPU_THRESHOLD or mem_usage > config.HIGH_MEMORY_THRESHOLD:
                log_writer.log_and_print("GRAYLIST", f"High resource usage: {pname} - CPU: {cpu_usage}%, RAM: {mem_usage:.2f}MB")

            # === SUSPICIOUS PARENT-CHILD ===
            if parent_pid:
                try:
                    parent_name = psutil.Process(parent_pid).name().lower()
                    if parent_name in config.SUSPICIOUS_PARENTS and pname in config.SUSPICIOUS_PARENTS[parent_name]:
                        log_writer.log_and_print("GRAYLIST", f"Suspicious parent-child: {parent_name} → {pname}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            continue

def track_event(event):
    """Store suspicious events and detect abnormal patterns."""
    global event_history
    current_time = time.time()
    event_history.append((event, current_time))
    event_history = deque([(e, t) for e, t in event_history if current_time - t < config.THRESHOLDS["time_window"]])

def count_suspicious_events(event_name):
    """Count occurrences of a specific event in history."""
    return sum(1 for e, _ in event_history if event_name in e)

if __name__ == "__main__":
    print("[+] EDR is now monitoring processes. Press CTRL+C to stop.")
    try:
        detect_suspicious_processes()
        while True:
            detect_suspicious_processes()
            time.sleep(config.SCAN_INTERVAL)
    except KeyboardInterrupt:
        log_writer.log_and_print("SYSTEM", "EDR stopped by user. Exiting cleanly.")
