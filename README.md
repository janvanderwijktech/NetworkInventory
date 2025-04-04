# Network Inventory

This is a Python-based network scanner with a graphical user interface (GUI) that scans a specified IPv4 subnet, displays discovered devices in real time, and stores device information in an SQLite database. The application is highly configurable through a `settings.ini` file and supports additional features such as sound notifications, executing custom commands when new devices are discovered, and exporting the device list to a CSV file.

## Features

- **Network Scanning:**  
  Periodically scans a defined IPv4 subnet using ICMP ping and retrieves device information (IP, hostname, and MAC vendor).

- **Database Storage:**  
  New devices are stored in an SQLite database, allowing for historical tracking of discovered devices.

- **Live GUI:**  
  The application uses Tkinter to display device data in a resizable, scrollable table.

- **Progress & Countdown:**  
  Displays a live progress percentage during scans and a countdown timer until the next scan.

- **Sound Notifications:**  
  Plays a configurable WAV file as a notification when a scan is completed. The user can toggle the sound on or off via the GUI.

- **Custom Command Execution:**  
  Executes user-defined commands (e.g., sending notifications via Pushover) when a new host is discovered. Custom commands can use variables such as `%HOST%`, `%IP%`, and `%MAC%`.

- **CSV Export:**  
  Provides an option to export the current device list to a CSV file and open it in the system’s default text editor.

## Requirements

- **Python 3.x**
- The following Python modules (most are included in the standard library):
  - `configparser`
  - `sqlite3`
  - `ipaddress`
  - `subprocess`
  - `re`
  - `socket`
  - `requests` (install with `pip install requests`)
  - `threading`
  - `time`
  - `tkinter` (may require additional installation on some systems)
  - `winsound` (Windows only)
  - `csv`, `tempfile`, `os`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/network-scanner.git
