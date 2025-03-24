import time
import threading
import log_writer
import process_monitor
import log_monitor
import utils
import config
import json
import shutil

def display_banner():
    """Displays a simple banner for the EDR system."""
    print("""
    =======================================
       EDR - Endpoint Detection & Response
    =======================================
    """)

def check_requirements():
    """Checks system requirements before starting."""
    utils.check_python_version()
    if not utils.is_admin():
        log_writer.log_and_print("WARNING", "⚠️  Run this script as Administrator/Root for full functionality.")

def start_process_monitor():
    """Starts process monitoring in a separate thread."""
    while True:
        process_monitor.detect_suspicious_processes()
        time.sleep(10)

def start_log_monitor():
    """Starts log monitoring in a separate thread."""
    while True:
        log_monitor.monitor_logs()
        time.sleep(10)

# ============================
# CONFIG MANAGEMENT FUNCTIONS
# ============================

def backup_config():
    """Creates a backup of config.py before modifying it."""
    shutil.copy("config.py", "config_backup.py")

def load_config():
    """Loads the config file dynamically."""
    import importlib
    importlib.reload(config)

def display_config_menu():
    """Displays the config management menu."""
    while True:
        print("\n--- Config Management ---")
        print("[1] View Current Configuration")
        print("[2] Modify Whitelist/Blacklist")
        print("[3] Modify Thresholds")
        print("[4] Modify Suspicious Paths")
        print("[5] Modify Windows Event IDs")
        print("[6] Restore Config from Backup")
        print("[7] Back to Main Menu")

        choice = input("\n[?] Select an option: ").strip()

        if choice == "1":
            view_config()
        elif choice == "2":
            modify_process_lists()
        elif choice == "3":
            modify_thresholds()
        elif choice == "4":
            modify_suspicious_paths()
        elif choice == "5":
            modify_windows_events()
        elif choice == "6":
            restore_config()
        elif choice == "7":
            break
        else:
            print("[!] Invalid choice. Please select again.")

def view_config():
    """Displays the current config values."""
    print("\nCurrent Configuration:")
    print(f"Whitelist: {config.WHITELIST_PROCESSES}")
    print(f"Blacklist: {config.BLACKLIST_PROCESSES}")
    print(f"Thresholds: {config.THRESHOLDS}")
    print(f"Suspicious Paths: {config.SUSPICIOUS_PATHS}")
    print(f"Windows Events: {config.WINDOWS_EVENTS}")

def modify_process_lists():
    """Allows the user to modify the whitelist/blacklist."""
    print("\n--- Modify Process Lists ---")
    print("[1] Add to Whitelist")
    print("[2] Remove from Whitelist")
    print("[3] Add to Blacklist")
    print("[4] Remove from Blacklist")
    
    choice = input("\n[?] Select an option: ").strip()

    if choice in ["1", "2", "3", "4"]:
        process_name = input("Enter process name: ").strip()
        if choice == "1":
            config.WHITELIST_PROCESSES.append(process_name)
        elif choice == "2" and process_name in config.WHITELIST_PROCESSES:
            config.WHITELIST_PROCESSES.remove(process_name)
        elif choice == "3":
            config.BLACKLIST_PROCESSES.append(process_name)
        elif choice == "4" and process_name in config.BLACKLIST_PROCESSES:
            config.BLACKLIST_PROCESSES.remove(process_name)
        save_config()
    else:
        print("[!] Invalid choice.")

def modify_thresholds():
    """Allows the user to modify thresholds."""
    print("\n--- Modify Thresholds ---")
    for key, value in config.THRESHOLDS.items():
        new_value = input(f"{key} (Current: {value}): ")
        if new_value.isdigit():
            config.THRESHOLDS[key] = int(new_value)
    save_config()

def modify_suspicious_paths():
    """Allows the user to modify suspicious paths."""
    print("\n--- Modify Suspicious Paths ---")
    print("[1] Add Path")
    print("[2] Remove Path")
    
    choice = input("\n[?] Select an option: ").strip()
    path = input("Enter path: ").strip()

    if choice == "1":
        config.SUSPICIOUS_PATHS.append(path)
    elif choice == "2" and path in config.SUSPICIOUS_PATHS:
        config.SUSPICIOUS_PATHS.remove(path)
    else:
        print("[!] Invalid choice or path does not exist.")

    save_config()

def modify_windows_events():
    """Allows the user to modify Windows Event IDs."""
    print("\n--- Modify Windows Event IDs ---")
    print("[1] Add Event")
    print("[2] Remove Event")
    
    choice = input("\n[?] Select an option: ").strip()
    event_id = input("Enter event ID: ").strip()

    if choice == "1":
        description = input("Enter event description: ").strip()
        config.WINDOWS_EVENTS[event_id] = description
    elif choice == "2" and event_id in config.WINDOWS_EVENTS:
        del config.WINDOWS_EVENTS[event_id]
    else:
        print("[!] Invalid choice or event does not exist.")

    save_config()

def restore_config():
    """Restores config from backup."""
    shutil.copy("config_backup.py", "config.py")
    load_config()
    print("[+] Configuration restored successfully.")

def save_config():
    """Saves changes to config.py."""
    backup_config()
    with open("config.py", "w") as f:
        f.write(f"WHITELIST_PROCESSES = {json.dumps(config.WHITELIST_PROCESSES, indent=4)}\n")
        f.write(f"BLACKLIST_PROCESSES = {json.dumps(config.BLACKLIST_PROCESSES, indent=4)}\n")
        f.write(f"THRESHOLDS = {json.dumps(config.THRESHOLDS, indent=4)}\n")
        f.write(f"SUSPICIOUS_PATHS = {json.dumps(config.SUSPICIOUS_PATHS, indent=4)}\n")
        f.write(f"WINDOWS_EVENTS = {json.dumps(config.WINDOWS_EVENTS, indent=4)}\n")
    load_config()
    print("[+] Configuration updated successfully.")

# ============================
# MAIN MENU
# ============================

def main_menu():
    """Displays the main menu for the EDR system."""
    while True:
        print("\n[1] Start Process Monitoring")
        print("[2] Start Log Monitoring")
        print("[3] Start Both (Recommended)")
        print("[4] Manage Configurations")
        print("[5] Exit")

        choice = input("\n[?] Select an option: ").strip()

        if choice == "1":
            log_writer.log_and_print("SYSTEM", "Starting Process Monitoring...")
            start_process_monitor()
        elif choice == "2":
            log_writer.log_and_print("SYSTEM", "Starting Log Monitoring...")
            start_log_monitor()
        elif choice == "3":
            log_writer.log_and_print("SYSTEM", "Starting Full EDR System...")
            threading.Thread(target=start_process_monitor, daemon=True).start()
            threading.Thread(target=start_log_monitor, daemon=True).start()
            while True:
                time.sleep(1)
        elif choice == "4":
            display_config_menu()  # This is the new function we added
        elif choice == "5":
            log_writer.log_and_print("SYSTEM", "Exiting EDR System...")
            break
        else:
            print("[!] Invalid choice. Please select again.")

if __name__ == "__main__":
    utils.clear_screen()
    display_banner()
    check_requirements()
    main_menu()
