import threading
import time
import json
import os
from rich.console import Console
from rich.prompt import Prompt
from plyer import notification
from ipwhois import IPWhois
from socket import gethostbyaddr, gaierror
from collections import defaultdict
from scapy.all import sniff, IP, ICMP, TCP

# File Logging Configuration
log_filename = 'network_activity.json'

# Ensure the log file exists
if not os.path.exists(log_filename):
    with open(log_filename, 'w') as f:
        json.dump([], f)  # Initialize with an empty list if file doesn't exist

# Dictionary to track suspicious activity
activity_log = defaultdict(list)
ip_log = set()
whitelist = set()
blacklist = set()

# Tracking alert statistics
ip_alert_count = defaultdict(int)
port_alert_count = defaultdict(int)
method_alert_count = defaultdict(int)

# Thresholds for detection
PING_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
ALERT_TIME_WINDOW = 60  # seconds

# List of private IP ranges
PRIVATE_IP_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255')
]

# Check if an IP is private
def is_private_ip(ip):
    for network_start, network_end in PRIVATE_IP_RANGES:
        if network_start <= ip <= network_end:
            return True
    return False

# Fetch WHOIS information using IPWhois
def fetch_whois_data(ip):
    try:
        ipwhois = IPWhois(ip)
        whois_data = ipwhois.lookup_rdap()
        isp = whois_data.get('network', {}).get('name', 'N/A')
        country = whois_data.get('country', 'N/A')
        city = whois_data.get('city', 'N/A')
        loc = whois_data.get('location', 'N/A')
        try:
            hostname = gethostbyaddr(ip)[0]
        except (gaierror, Exception):
            hostname = 'N/A'
        is_bot = 'Yes' if 'bot' in isp.lower() else 'No'
        return isp, city, country, loc, is_bot, hostname
    except Exception as e:
        return 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'

# Send notifications
def send_notification(ip, port, method):
    isp, city, country, loc, is_bot, hostname = fetch_whois_data(ip)
    message = (f"Suspicious Network Activity from IP: {ip}\n"
               f"Port: {port}\n"
               f"Method: {method}\n"
               f"ISP: {isp}\n"
               f"Location: {city}, {country} ({loc})\n"
               f"Bot Rating: {is_bot}\n"
               f"Hostname: {hostname}")
    notification.notify(
        title="Suspicious Network Activity Detected",
        message=message,
        timeout=10
    )

def detect_ping(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        src_ip = packet[IP].src
        if src_ip in blacklist:
            return  # Skip blacklisted IPs
        activity_log[src_ip].append(time.time())
        if len(activity_log[src_ip]) > PING_THRESHOLD:
            if src_ip not in ip_log and not is_private_ip(src_ip):
                log_activity(src_ip, 'ping')
                send_notification(src_ip, 'N/A', 'Ping')
                ip_log.add(src_ip)
            activity_log[src_ip].clear()

def detect_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if src_ip in blacklist:
            return  # Skip blacklisted IPs
        activity_log[src_ip].append(dst_port)
        if len(activity_log[src_ip]) > PORT_SCAN_THRESHOLD:
            if src_ip not in ip_log and not is_private_ip(src_ip):
                log_activity(src_ip, dst_port)
                send_notification(src_ip, dst_port, 'Port Scan')
                ip_log.add(src_ip)
            activity_log[src_ip].clear()

def packet_handler(packet):
    if packet.haslayer(IP):
        detect_ping(packet)
        detect_port_scan(packet)

def clear_old_entries():
    while True:
        current_time = time.time()
        for ip, timestamps in list(activity_log.items()):
            activity_log[ip] = [t for t in timestamps if current_time - t < ALERT_TIME_WINDOW]
            if not activity_log[ip]:
                del activity_log[ip]
        time.sleep(ALERT_TIME_WINDOW)

# Log activity to a JSON file
def log_activity(ip, activity_type):
    isp, city, country, loc, is_bot, hostname = fetch_whois_data(ip)  # Fetch WHOIS info
    log_entry = {
        'ip': ip,
        'activity': activity_type,
        'timestamp': time.time(),
        'whitelisted': ip in whitelist,
        'blacklisted': ip in blacklist,
        'isp': isp,
        'city': city,
        'country': country,
        'location': loc,
        'is_bot': is_bot,
        'hostname': hostname
    }
    with open(log_filename, 'r+') as f:
        logs = json.load(f)
        logs.append(log_entry)
        f.seek(0)
        json.dump(logs, f, indent=4)

    # Update alert counters for stats
    ip_alert_count[ip] += 1
    method_alert_count[activity_type] += 1
    if isinstance(activity_type, int):  # Port scan method
        port_alert_count[activity_type] += 1

# Display Branding in Purple
def display_brand():
    brand_name = """
 _____     _       _ _____                     
|     |___| |_ ___| |_   _|___ ___ ___ ___ ___ 
|  |  |  _|  _| -_| | | | |  _| .'|  _| -_|  _|
|_____|___|_| |___|_| |_| |_| |__,|___|___|_|  
"""
    return brand_name

# Main CLI Menu using rich
def menu():
    console = Console()
    console.clear()

    # Print the brand name in purple
    console.print(display_brand(), style="bold magenta")

    # Add taskbar options here to navigate
    console.print("\n[1] View Logs", style="bold green")
    console.print("[2] Manage Blacklist", style="bold red")
    console.print("[3] Manage Whitelist", style="bold blue")
    console.print("[4] View Stats", style="bold yellow")
    console.print("[5] Quit", style="bold red")

    choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")

    if choice == "1":
        view_logs(console)
    elif choice == "2":
        manage_blacklist(console)
    elif choice == "3":
        manage_whitelist(console)
    elif choice == "4":
        view_stats(console)
    elif choice == "5":
        return

# View Logs function
def view_logs(console):
    console.clear()
    console.print(display_brand(), style="bold magenta")
    console.print("\n[Activity Logs]\n", style="bold yellow")

    with open(log_filename, 'r') as f:
        logs = json.load(f)

    if not logs:
        console.print("[red]No logs available.[/red]")
    else:
        for entry in logs[-5:]:  # Display the last 5 logs
            console.print(f"[IP: {entry['ip']}] Activity: {entry['activity']} "
                          f"Timestamp: {entry['timestamp']} "
                          f"Whitelisted: {entry['whitelisted']} Blacklisted: {entry['blacklisted']} "
                          f"ISP: {entry['isp']} Location: {entry['city']}, {entry['country']} "
                          f"Bot: {entry['is_bot']} Hostname: {entry['hostname']}",
                          style="bold cyan")

    Prompt.ask("Press [Enter] to go back")
    menu()  # After viewing logs, go back to the main menu

# View Stats: Top IPs, Ports etc.
def view_stats(console):
    console.clear()
    console.print(display_brand(), style="bold magenta")
    console.print("\n[Statistics]\n", style="bold yellow")

    try:
        # Display Stats
        total_ip_alerts = sum(ip_alert_count.values())
        console.print(f"Total IP Alerts: {total_ip_alerts}")

        # Check if method_alert_count is not empty before finding the most common method
        if method_alert_count:
            most_common_method = max(method_alert_count, key=method_alert_count.get)
            console.print(f"Most Common Method: {most_common_method}")
        else:
            console.print("Most Common Method: No data available", style="red")

        # Display the most common port
        if port_alert_count:
            most_common_port = max(port_alert_count, key=port_alert_count.get)
            console.print(f"Most Common Port: {most_common_port}")
        else:
            console.print("Most Common Port: No data available", style="red")

        # Prompt to go back
        Prompt.ask("Press [Enter] to go back")
        menu()

    except Exception as e:
        console.print(f"Error displaying statistics: {e}", style="bold red")


    except Exception as e:
        # If there is an error, print an error message
        console.print(f"[bold red]Error displaying statistics: {e}[/bold red]")
def manage_whitelist(console):
    console.clear()
    console.print(display_brand(), style="bold magenta")
    console.print("\n[Whitelist Management]\n", style="bold yellow")

    # Show current whitelist
    console.print("Current Whitelist:", style="bold green")
    if whitelist:
        for ip in whitelist:
            console.print(f" - {ip}")
    else:
        console.print("No IPs currently whitelisted.", style="red")

    # Manage Whitelist
    action = Prompt.ask("Choose an action: [1] Add IP [2] Remove IP [3] Back", choices=["1", "2", "3"])

    if action == "1":
        ip_to_add = Prompt.ask("Enter IP to whitelist:")
        whitelist.append(ip_to_add)  # Add IP to the whitelist
        console.print(f"IP {ip_to_add} added to the whitelist.", style="bold green")

    elif action == "2":
        ip_to_remove = Prompt.ask("Enter IP to remove from whitelist:")
        if ip_to_remove in whitelist:
            whitelist.remove(ip_to_remove)  # Remove IP from the whitelist
            console.print(f"IP {ip_to_remove} removed from the whitelist.", style="bold green")
        else:
            console.print(f"IP {ip_to_remove} not found in the whitelist.", style="red")

    # Go back to menu
    Prompt.ask("Press [Enter] to go back")
    menu()

def manage_blacklist(console):
    console.clear()
    console.print(display_brand(), style="bold magenta")
    console.print("\n[Blacklist Management]\n", style="bold yellow")

    # Show current blacklist
    console.print("Current Blacklist:", style="bold red")
    if blacklist:
        for ip in blacklist:
            console.print(f" - {ip}")
    else:
        console.print("No IPs currently blacklisted.", style="green")

    # Manage Blacklist
    action = Prompt.ask("Choose an action: [1] Add IP [2] Remove IP [3] Back", choices=["1", "2", "3"])

    if action == "1":
        ip_to_add = Prompt.ask("Enter IP to blacklist:")
        blacklist.append(ip_to_add)  # Add IP to the blacklist
        console.print(f"IP {ip_to_add} added to the blacklist.", style="bold red")

    elif action == "2":
        ip_to_remove = Prompt.ask("Enter IP to remove from blacklist:")
        if ip_to_remove in blacklist:
            blacklist.remove(ip_to_remove)  # Remove IP from the blacklist
            console.print(f"IP {ip_to_remove} removed from the blacklist.", style="bold red")
        else:
            console.print(f"IP {ip_to_remove} not found in the blacklist.", style="green")

    # Go back to menu
    Prompt.ask("Press [Enter] to go back")
    menu()


# Main program
if __name__ == "__main__":
    # Start the background task for clearing old entries
    threading.Thread(target=clear_old_entries, daemon=True).start()

    # Start packet sniffing in the background
    sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_handler, store=0))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start the menu
    menu()
