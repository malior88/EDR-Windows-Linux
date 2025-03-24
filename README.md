# EDR - Endpoint Detection and Response

This repository presents a cross-platform EDR (Endpoint Detection and Response) system built in Python. It is designed to monitor system activity in real time, detect suspicious behavior, and automatically respond to potential threats on both Linux and Windows environments.

## Features

- Detects privilege escalation attempts
- Detects unauthorized user creation
- Identifies suspicious processes and file paths
- Detects high CPU usage patterns
- Monitors SSH brute-force attacks (Linux)
- Reacts in real-time by locking users or terminating processes

## Highlights

- Cross-platform support (Linux & Windows)
- Customizable thresholds and detection rules
- Editable whitelist, blacklist, and suspicious paths
- Modular code structure for easy extension and integration

## Project Structure

- `main.py` – Launches the EDR and user interface
- `process_monitor.py` – Monitors system processes and resource usage
- `log_monitor.py` – Analyzes system logs for signs of compromise
- `response.py` – Applies automated responses to threats
- `config.py` – Stores user-defined settings and thresholds
- `log_writer.py` – Manages structured logging
- `utils.py` – Helper functions

## License

This project is released under the MIT License.
