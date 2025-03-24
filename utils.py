import os
import psutil
import sys
import platform
import ctypes

# Function to clear the screen
def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

# Function to check if a process is suspicious based on its name or path
def is_suspicious_process(proc):
    suspicious_names = ['malware', 'hacktool']
    suspicious_paths = ['/tmp', '/dev/shm', 'C:\\Temp', 'C:\\Users\\Public']

    try:
        if proc.name().lower() in suspicious_names:
            return True
        if any(path.lower() in proc.exe().lower() for path in suspicious_paths):
            return True
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        pass
    return False

# Function to check if a user is unauthorized based on a list of authorized users
def is_unauthorized_user(user):
    authorized_users = ['root', 'user1', 'user2', 'Administrator']
    return user not in authorized_users

# Function to check if a process is consuming excessive CPU or memory
def is_high_resource_usage(proc):
    high_cpu_threshold = 80  # CPU usage > 80% is considered high
    high_memory_threshold = 200  # Memory usage > 200MB is considered high

    try:
        cpu_usage = proc.cpu_percent(interval=1)
        memory_usage = proc.memory_info().rss / (1024 * 1024)  # Convert to MB

        return cpu_usage > high_cpu_threshold or memory_usage > high_memory_threshold
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False

# Function to check for suspicious paths
def check_suspicious_paths(proc):
    suspicious_paths = ['/tmp', '/dev/shm', 'C:\\Temp', 'C:\\Users\\Public']
    try:
        return any(path.lower() in proc.exe().lower() for path in suspicious_paths)
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False

# Function to check if the Python version is compatible (>= 3.6)
def check_python_version():
    if sys.version_info < (3, 6):
        print("Python 3.6 or higher is required. Please upgrade your Python version.")
        sys.exit(1)
    else:
        print(f"Python version is {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} - Compatible")

# Cross-platform admin check
def is_admin():
    if platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0
