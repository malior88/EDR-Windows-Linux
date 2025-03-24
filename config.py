# ========================================
# CONFIGURATION FILE FOR EDR (Endpoint Detection & Response)
# ========================================

# Process whitelist (processes that should not be considered suspicious)
WHITELIST_PROCESSES = [
    "system.exe", "smss.exe", "wininit.exe", "csrss.exe", "lsass.exe",
    "services.exe", "winlogon.exe", "explorer.exe", "taskmgr.exe",
    "svchost.exe", "spoolsv.exe", "dwm.exe", "audiodg.exe",
    "fontdrvhost.exe", "logonui.exe", "msiexec.exe", "taskhost.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "teams.exe", "zoom.exe", "skype.exe",
    "mstsc.exe", "vpnclient.exe", "putty.exe", "wlanext.exe", "dns.exe",
    "sqlservr.exe", "mysqld.exe", "postgres.exe", "mongod.exe",
    "notepad.exe", "vscode.exe", "java.exe", "javaw.exe", "python.exe",
    "wget.exe", "curl.exe", "xfdesktop", "cmd.exe", "powershell.exe", 
]

# Process graylist (processes that are suspicious but not blacklisted)
GRAYLIST_PROCESSES = [
    "wscript.exe", "cscript.exe",
    "schtasks.exe", "taskhost.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe"
]

# Process blacklist (processes that are known to be malicious)
BLACKLIST_PROCESSES = [
    "mimikatz.exe", "nc", "netcat", "nc.exe", "netcat.exe", "nmap.exe",
    "meterpreter.exe", "msfvenom.exe", "lsass_dump.exe",
    "ransomware.exe", "trojan.exe", "infostealer.exe", "malware"
]

# Suspicious paths (directories that are usually associated with malicious activity)
SUSPICIOUS_PATHS = [
    "C:\\Users\\Public\\", "C:\\Windows\\Temp\\", "C:\\Users\\Downloads\\",
    "C:\\Users\\AppData\\Local\\Temp\\", "/tmp", "/var/tmp", "/etc"
]

# Suspicious parent-child process relationships
SUSPICIOUS_PARENTS = {
    "winword.exe": ["cmd.exe", "powershell.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
    "cmd.exe": ["powershell.exe"],
    "bash": ["python3"]
}

# Windows event IDs and their descriptions
WINDOWS_EVENTS = {
    "4688": "New Process Created - Suspicious if running from Temp/AppData",
    "1": "Sysmon Process Creation",
    "7036": "Service Started/Stopped",
    "4697": "New Service Installed",
    "7045": "New Service Installed (Sysmon)",
    "400": "WMI Activity",
    "4624": "Successful Logon",
    "4625": "Failed Logon Attempt",
    "4672": "Special Privileges Assigned",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4728": "User Added to Group",
    "4732": "User Added to Privileged Group",
    "4768": "TGT Request (Kerberos)",
    "4769": "Kerberos Service Ticket Request",
    "4663": "File Access",
    "4656": "Handle Request on File",
    "4660": "File Deleted",
    "11": "File Creation on USB",
    "4740": "Account Locked Out",
    "4776": "Credential Validation",
    "4765": "SID History Added",
    "1102": "Security Log Cleared",
    "4723": "Password Reset Attempt",
    "4726": "User Account Deleted"
}

# Thresholds for detecting suspicious activity
THRESHOLDS = {
    "failed_logins": 2,  # Number of failed logins to trigger a suspicious event
    "suspicious_processes": 1,  # Number of suspicious processes to trigger a warning
    "suspicious_events": 1,  # Number of suspicious events to trigger a warning
    "time_window": 30  # Time window (in seconds) for counting suspicious events
}

# High resource usage thresholds
HIGH_CPU_THRESHOLD = 70  # Threshold for CPU usage percentage
HIGH_MEMORY_THRESHOLD = 300  # Threshold for memory usage in MB
SCAN_INTERVAL = 5  # Time interval for scanning processes (in seconds)

# List of kernel processes to ignore
IGNORE_KERNEL_PROCESSES = [
    "kthreadd", "kworker", "migration", "idle", "rcu", "kauditd",
    "ksoftirqd", "ksmd", "khugepaged", "kcompactd", "oom_reaper"
]

# Patterns for extracting user-related information from logs
USER_EXTRACTION_PATTERNS = [
    r"user (\S+)",
    r"Failed password for (invalid user )?(\S+)",
    r"Accepted password for (\S+)",
    r"User (\S+) from",
    r"Account (\S+) locked due to",
    r"Password change detected for user (\S+)"
]

# Auto mode setting (whether to automatically react to suspicious events)
AUTO_MODE = True
