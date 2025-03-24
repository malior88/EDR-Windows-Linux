import subprocess
import platform
import time
import config
import log_writer
import response
import re
from collections import deque

event_history = deque(maxlen=50)
privilege_escalation_reported = set()
user_creation_reported = set()
user_lock_decisions = set()
already_reported_lines = deque(maxlen=500)
reported_windows_pids = set()

def get_os():
    """Detect the current operating system."""
    return platform.system()

def monitor_logs():
    """Monitor logs for suspicious activity based on OS."""
    os_name = get_os()
    
    if os_name == "Windows":
        monitor_windows_logs()
    elif os_name == "Linux":
        monitor_linux_logs()

def monitor_windows_logs():
    suspicious_events = {
        "4720": "New user account created",
        "4672": "Special privileges assigned to new logon",
        "4688": "New process created",
        "1102": "Security log cleared",
        "7045": "New service installed",
    }

    try:
        command = 'wevtutil qe Security /c:50 /rd:true /f:text'
        output = subprocess.check_output(command, shell=True, text=True, errors="ignore")
        entries = output.split("\n\n")

        event_detected = False

        for entry in entries:
            event_id_match = re.search(r"Event ID:\s+(\d+)", entry)
            if not event_id_match:
                continue
            event_id = event_id_match.group(1)

            if event_id not in suspicious_events:
                continue

            description = suspicious_events[event_id]
            user_match = re.search(r"Account Name:\s+([^\r\n]+)", entry)
            pid_match = re.search(r"New Process ID:\s+(\d+)", entry)

            user = user_match.group(1).strip() if user_match else "Unknown"
            pid = pid_match.group(1) if pid_match else None

            if event_id == "4688":
                image_match = re.search(r"New Process Name:\s+([^\r\n]+)", entry)
                if not image_match:
                    continue  
                image_path = image_match.group(1).strip().lower()
                proc_name = image_path.split("\\")[-1]
                if proc_name not in config.GRAYLIST_PROCESSES:
                    continue
                if pid and pid in reported_windows_pids:
                    continue
                if pid:
                    reported_windows_pids.add(pid)
                log_writer.log_and_print("GRAYLIST", f"[Windows Log] {description} | User: {user} | Process: {proc_name}")
                track_event(description)
                event_detected = True
                continue

            if entry in already_reported_lines:
                continue
            already_reported_lines.append(entry)

            log_writer.log_and_print("GRAYLIST", f"[Windows Log] {description} | User: {user}")
            track_event(description)
            event_detected = True

            # 🟡 משתמש חדש – תשאל לפני נעילה
            if event_id == "4720" and user not in user_lock_decisions:
                user_lock_decisions.add(user)
                if not response.ask_user_confirmation("New user created", f"Did you initiate creation of user '{user}'?"):
                    log_writer.log_and_print("BLACKLIST", f"Unauthorized user creation detected | User: {user}")
                    response.lock_user(user)

        if event_detected:
            log_writer.log_and_print("SYSTEM", "[+] Monitoring Windows Event Logs...")

    except subprocess.CalledProcessError as e:
        log_writer.log_and_print("ERROR", f"Failed to read Windows logs: {str(e)}")

def monitor_linux_logs():
    suspicious_patterns = {
        r"Failed password for (?:invalid user )?(\S+)": "Failed SSH login attempt",
        r"Accepted password for (\S+)": "Successful SSH login",
        r"sudo: pam_unix.*?by (\S+)": "Privilege escalation attempt detected",
        r"useradd.*? (\S+)": "New user created - Check legitimacy",
        r"passwd: password changed for (\S+)": "Password change detected"
    }

    try:
        command = "tail -n 100 /var/log/auth.log || tail -n 100 /var/log/secure"
        output = subprocess.check_output(command, shell=True, text=True, errors="ignore")

        event_detected = False

        for line in output.splitlines():
            if line in already_reported_lines:
                continue
            already_reported_lines.append(line)

            for pattern, description in suspicious_patterns.items():
                match = re.search(pattern, line)
                if match:
                    user = match.group(1) if match.groups() else "Unknown"

                    if "Privilege escalation attempt detected" in description:
                        if user in privilege_escalation_reported:
                            continue
                        privilege_escalation_reported.add(user)

                    if "New user created" in description:
                        if user in user_creation_reported:
                            continue
                        user_creation_reported.add(user)

                    log_writer.log_and_print("GRAYLIST", f"[Linux Log] {description} | User: {user}")
                    track_event(description)
                    event_detected = True

                    if "Failed SSH login attempt" in description and count_suspicious_events("Failed SSH login") >= config.THRESHOLDS["failed_logins"]:
                        if user not in user_lock_decisions:
                            user_lock_decisions.add(user)
                            log_writer.log_and_print("BLACKLIST", f"Multiple failed SSH logins detected | User: {user}")
                            response.lock_user(user)

                    # 🟡 משתמש חדש – תשאל לפני נעילה
                    if "New user created" in description:
                        if user not in user_lock_decisions:
                            user_lock_decisions.add(user)
                            if not response.ask_user_confirmation("New user created", f"Did you initiate creation of user '{user}'?"):
                                log_writer.log_and_print("BLACKLIST", f"Unauthorized user creation detected | User: {user}")
                                response.lock_user(user)

        if event_detected:
            log_writer.log_and_print("SYSTEM", "[+] Monitoring Linux Syslogs...")

    except subprocess.CalledProcessError as e:
        log_writer.log_and_print("ERROR", f"Failed to read Linux logs: {str(e)}")

def track_event(event):
    """Store suspicious events and detect abnormal patterns."""
    global event_history
    current_time = time.time()
    event_history.append((event, current_time))
    event_history = deque([(e, t) for e, t in event_history if current_time - t < config.THRESHOLDS["time_window"]], maxlen=50)

def count_suspicious_events(event_name):
    """Count occurrences of a specific event in history."""
    return sum(1 for e, _ in event_history if event_name in e)
