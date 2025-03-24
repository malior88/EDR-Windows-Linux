import config
import json
import shutil
import importlib

CONFIG_FILE = "config.py"
BACKUP_FILE = "config_backup.py"

def backup_config():
    """Creates a backup of config.py before modifying it."""
    shutil.copy(CONFIG_FILE, BACKUP_FILE)

def load_config():
    """Reloads the config file dynamically."""
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
    shutil.copy(BACKUP_FILE, CONFIG_FILE)
    load_config()
    print("[+] Configuration restored successfully.")

def save_config():
    """Saves changes to config.py."""
    backup_config()
    with open(CONFIG_FILE, "w") as f:
        f.write(f"WHITELIST_PROCESSES = {json.dumps(config.WHITELIST_PROCESSES, indent=4)}\n")
        f.write(f"BLACKLIST_PROCESSES = {json.dumps(config.BLACKLIST_PROCESSES, indent=4)}\n")
        f.write(f"THRESHOLDS = {json.dumps(config.THRESHOLDS, indent=4)}\n")
        f.write(f"SUSPICIOUS_PATHS = {json.dumps(config.SUSPICIOUS_PATHS, indent=4)}\n")
        f.write(f"WINDOWS_EVENTS = {json.dumps(config.WINDOWS_EVENTS, indent=4)}\n")
    load_config()
    print("[+] Configuration updated successfully.")
