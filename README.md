# OctelTracer

OctelTracer is a Python-based network monitoring and security tool designed to track suspicious IP activity and provide real-time alerts. This project is especially useful for those seeking to monitor potential intrusions, unauthorized access attempts, or suspicious scanning activity on their network.

## Features

- **Real-time IP Tracking**: Monitors incoming traffic and logs IP activity.
- **Alert System**: Sends system notifications for specific events, such as unauthorized IP access or network scanning attempts.
- **Blacklist & Whitelist Management**: Customize IPs to ignore (whitelist) or block (blacklist) from tracking.
- **Detailed Statistics**: Provides insights on total alerts, common methods of intrusion, and targeted ports.
- **Log Viewer**: Allows for viewing historical IP activity logs.
  
## Installation

1. **Clone the Repository**:

   ```shell
   git clone https://github.com/Octellic/OctelTracer.git
   cd OctelTracer
   ```

2. **Install Requirements**:

   ```shell
   pip install -r requirements.txt
   ```

3. **Run OctelTracer**:

   ```shell
   python tracer.py
   ```

## Usage

Upon running the script, you'll be presented with a menu allowing you to:

- **View Logs**: Shows all recorded IP activity.
- **Manage Blacklist**: Add or remove IPs that should be blocked.
- **Manage Whitelist**: Add or remove IPs that should be ignored by OctelTracer.
- **View Stats**: Displays statistics on alert counts, commonly targeted ports, and intrusion methods.

## Requirements

- **Python 3.8 or higher**
- Required Libraries (see `requirements.txt`):
  - `rich`: For console styling
  - `plyer`: For system notifications
  - `scapy`: For packet sniffing
  - `ipwhois`: For IP lookups

## Example Output

OctelTracer logs IPs and provides actionable information on detected network activities.

Example log entry:

```
Date: 2024-11-10
IP Address: 192.168.1.10
Method: Port Scan
Port: 22
ISP: Example ISP
Location: City, Country
```

## Contributing

Feel free to open issues or pull requests to improve OctelTracer. Contributions are always welcome!

---

**Disclaimer**: OctelTracer is intended for educational and security purposes on networks you have permission to monitor. Unauthorized use on other networks may be illegal.
```
