import os
import datetime

# Log file path
LOG_FILE = "edr_logs.log"

def log_and_print(event_type, message):
    """ Logs an event to file and prints it to the console """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{event_type}] {message}"

    # Print to console
    print(log_entry)

    # Append to log file with UTF-8 encoding for cross-platform support
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(log_entry + "\n")
