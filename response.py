import platform
import subprocess
import log_writer
import config

def get_os():
    return platform.system()

def ask_user_confirmation(action, target):
    while True:
        user_input = input(f"[?] {action} - {target} detected. Do you want to proceed? (y/n): ").strip().lower()
        if user_input in ('y', 'n'):
            return user_input == 'y'
        print("Please enter 'y' or 'n'")

def terminate_process(pid, pname=None):
    """Terminates a suspicious process. Skips prompt if in blacklist and AUTO_MODE=True"""
    pname = pname or "unknown"
    if config.AUTO_MODE and pname in config.BLACKLIST_PROCESSES:
        _kill_process(pid)
        log_writer.log_and_print("RESPONSE", f"[AUTO] Terminated blacklisted process: {pname} (PID {pid})")
        return

    if config.AUTO_MODE and pname in config.GRAYLIST_PROCESSES:
        if ask_user_confirmation("Terminate GRAYLIST process", f"{pname} (PID {pid})"):
            _kill_process(pid)
            log_writer.log_and_print("RESPONSE", f"Terminated graylisted process: {pname} (PID {pid})")
        else:
            log_writer.log_and_print("USER_DECISION", f"User chose NOT to terminate: {pname} (PID {pid})")

def _kill_process(pid):
    try:
        if get_os() == "Windows":
            subprocess.call(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.call(["kill", "-9", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log_writer.log_and_print("ERROR", f"Failed to terminate process {pid}: {str(e)}")

def lock_user(user):
    if config.AUTO_MODE:
        if ask_user_confirmation("Lock User", f"User {user}"):
            _lock(user)
        else:
            log_writer.log_and_print("USER_DECISION", f"User chose NOT to lock user: {user}")
    else:
        _lock(user)

def _lock(user):
    try:
        if get_os() == "Windows":
            subprocess.call(["net", "user", user, "/active:no"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.call(["passwd", "-l", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_writer.log_and_print("RESPONSE", f"Locked user account: {user}")
    except Exception as e:
        log_writer.log_and_print("ERROR", f"Failed to lock user {user}: {str(e)}")

def disable_service(service_name):
    if ask_user_confirmation("Disable Service", f"Service {service_name}"):
        try:
            if get_os() == "Windows":
                subprocess.call(["sc", "config", service_name, "start= disabled"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.call(["systemctl", "disable", "--now", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_writer.log_and_print("RESPONSE", f"Disabled service: {service_name}")
        except Exception as e:
            log_writer.log_and_print("ERROR", f"Failed to disable service {service_name}: {str(e)}")
    else:
        log_writer.log_and_print("USER_DECISION", f"User chose NOT to disable service: {service_name}")

def quarantine_file(file_path):
    if ask_user_confirmation("Quarantine File", f"File {file_path}"):
        quarantine_folder = "C:\\Quarantine" if get_os() == "Windows" else "/var/quarantine"
        try:
            subprocess.call(["mkdir", "-p", quarantine_folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(["mv", file_path, quarantine_folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            log_writer.log_and_print("RESPONSE", f"Quarantined file: {file_path}")
        except Exception as e:
            log_writer.log_and_print("ERROR", f"Failed to quarantine file {file_path}: {str(e)}")
    else:
        log_writer.log_and_print("USER_DECISION", f"User chose NOT to quarantine file: {file_path}")
