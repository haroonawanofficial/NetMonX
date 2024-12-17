from scapy.all import fragment, send, IP, TCP, UDP, ICMP, Raw, GRE
from netaddr import IPNetwork
import argparse
import random
import click
import logging
import time
import os
import json
from datetime import datetime
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import ARP
from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, IPField, BitField

# Manually define MPLS
class MPLS(Packet):
    name = "MPLS"
    fields_desc = [
        BitField("label", 3, 20),  # MPLS Label
        BitField("tc", 0, 3),      # Traffic Class
        BitField("s", 1, 1),       # Bottom of Stack
        ByteField("ttl", 64)       # Time To Live
    ]

# Bind MPLS to IP
bind_layers(MPLS, IP)

# Manually define the IGMP class if not available
class IGMP(Packet):
    name = "IGMP"
    fields_desc = [
        ByteField("type", 0x11),       # IGMP Type: Membership Query/Report
        ByteField("mrcode", 0),        # Max Response Code
        ShortField("checksum", 0),     # Checksum
        IPField("group", "0.0.0.0")    # Group Address
    ]

# Bind IGMP to IP protocol 2
bind_layers(IP, IGMP, proto=2)



# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Global storage for detected MAC addresses
mac_db = defaultdict(dict)
MAC_DATABASE_FILE = "mac_database.json"

# Load MAC database if it exists
if os.path.exists(MAC_DATABASE_FILE):
    with open(MAC_DATABASE_FILE, 'r') as f:
        mac_db.update(json.load(f))

@click.group()
def cli():
    """NetMonX - Advanced Network Monitoring and Pentesting CLI Tool"""
    pass

# Network Monitoring Commands
@cli.group()
def monitor():
    """Commands related to network monitoring"""
    pass

@monitor.command()
@click.option('--mac', is_flag=True, help="Monitor MAC addresses in real-time")
@click.option('--wireless', is_flag=True, help="Monitor wireless MAC addresses")
@click.option('--record-new', is_flag=True, help="Record new MAC addresses to database")
def start(mac, wireless, record_new):
    """Start real-time monitoring"""
    if mac:
        logging.info("Starting real-time MAC address monitoring...")
        monitor_mac_addresses(record_new)
    if wireless:
        logging.info("Starting real-time Wireless MAC monitoring...")
        monitor_wireless_mac_addresses(record_new)

def monitor_mac_addresses(record_new):
    """Monitor MAC addresses in real-time using Scapy"""
    def process_packet(pkt):
        if pkt.haslayer(ARP):
            mac = pkt[ARP].hwsrc
            ip = pkt[ARP].psrc
            timestamp = str(datetime.now())
            if mac not in mac_db:
                logging.info(f"New MAC address detected: {mac} with IP: {ip}")
                if record_new:
                    mac_db[mac]['ip'] = ip
                    mac_db[mac]['first_seen'] = timestamp
                    mac_db[mac]['last_seen'] = timestamp
                    save_mac_database()
            else:
                mac_db[mac]['last_seen'] = timestamp
                logging.info(f"MAC address {mac} detected again. Last seen updated.")

    sniff(prn=process_packet, filter="arp", store=0)

def monitor_wireless_mac_addresses(record_new):
    """Monitor Wireless MAC addresses in real-time using Scapy"""
    def process_packet(pkt):
        if pkt.haslayer(Dot11):
            mac = pkt.addr2
            timestamp = str(datetime.now())
            if mac and mac not in mac_db:
                logging.info(f"New wireless MAC address detected: {mac}")
                if record_new:
                    mac_db[mac]['first_seen'] = timestamp
                    mac_db[mac]['last_seen'] = timestamp
                    save_mac_database()
            elif mac:
                mac_db[mac]['last_seen'] = timestamp
                logging.info(f"Wireless MAC address {mac} detected again. Last seen updated.")
    
    sniff(prn=process_packet, iface="wlan0", store=0)

def save_mac_database():
    """Save the MAC database to a file"""
    with open(MAC_DATABASE_FILE, 'w') as f:
        json.dump(mac_db, f, indent=4)
    logging.info("MAC database saved successfully.")

# Security Commands
@cli.group()
def security():
    """Commands related to network security"""
    pass

@security.command()
@click.option('--rogue-detection', is_flag=True, help="Enable rogue device detection")
@click.option('--stealth', is_flag=True, help="Enable stealth mode for monitoring")
@click.option('--anomaly-detection', is_flag=True, help="Enable anomaly detection based on MAC behavior")
def protect(rogue_detection, stealth, anomaly_detection):
    """Enable security features"""
    if rogue_detection:
        logging.info("Rogue device detection enabled...")
        detect_rogue_devices()
    if stealth:
        logging.info("Stealth mode enabled...")
        # Implementation of stealth monitoring logic here
    if anomaly_detection:
        logging.info("Anomaly detection enabled...")
        detect_mac_anomalies()

import time

def detect_rogue_devices():
    """Continuously detect rogue devices on the network."""
    logging.info("Scanning for rogue devices. Press Ctrl+C to stop...")

    try:
        while True:
            # Sniff ARP packets to detect new devices
            def process_packet(pkt):
                if pkt.haslayer(ARP):
                    mac = pkt[ARP].hwsrc
                    ip = pkt[ARP].psrc
                    timestamp = str(datetime.now())
                    if mac not in mac_db:
                        logging.warning(f"Rogue device detected: MAC {mac} with IP {ip}")
                        mac_db[mac] = {'ip': ip, 'first_seen': timestamp, 'last_seen': timestamp}
                        save_mac_database()
                    else:
                        logging.info(f"Known device detected: MAC {mac} with IP {ip}")
                        mac_db[mac]['last_seen'] = timestamp
                        save_mac_database()
            
            # Sniff for ARP packets (adjust filter for specific traffic if needed)
            sniff(prn=process_packet, filter="arp", store=0, timeout=5)
            
            time.sleep(1)  # Pause briefly to avoid resource overload

    except KeyboardInterrupt:
        logging.info("Rogue device detection stopped by user.")


def detect_mac_anomalies():
    """Detect anomalies in MAC behavior"""
    logging.info("Detecting anomalies in MAC behavior...")
    for mac, details in mac_db.items():
        # Example anomaly: if a MAC address is seen on multiple IPs frequently
        if 'ip' in details and details['ip'] != details.get('last_ip'):
            logging.warning(f"Anomaly detected: MAC {mac} has changed IP from {details.get('last_ip')} to {details['ip']}.")
        details['last_ip'] = details.get('ip')
    save_mac_database()

# Stealth Scanning Techniques
@cli.group()
def scan():
    """Commands related to advanced and stealthy network scanning"""
    pass

@scan.command()
@click.option('--ip-range', required=True, help="IP range or target IP to scan")
@click.option('--technique', required=True, type=click.Choice(['inverse', 'bad-tcp', 'covert', 'ack-tunneling', 'tcp-timestamp', 'syn-ack', 'randomized-ttl']), help="Scanning technique to use")
@click.option('--randomize', is_flag=True, help="Randomize the scan to blend in with legitimate traffic")
@click.option('--legit-traffic', is_flag=True, help="Include legitimate traffic patterns during the scan")
@click.option('--stealth', is_flag=True, help="Perform scan with enhanced stealth techniques")
@click.option('--spoof-ip', default=None, help="Spoof the source IP address for the scan")
@click.option('--fragment', is_flag=True, help="Enable packet fragmentation to bypass certain filters")
def start(ip_range, technique, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Start an advanced stealth scan using a specific technique with optional IP spoofing"""
    logging.info(f"Starting {technique} scan on IP range: {ip_range}")
    logging.info(f"Spoofing IP: {spoof_ip if spoof_ip else 'None'}")

    if technique == "inverse":
        inverse_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "bad-tcp":
        bad_tcp_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "covert":
        covert_channel_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "ack-tunneling":
        ack_tunneling_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "tcp-timestamp":
        tcp_timestamp_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "syn-ack":
        syn_ack_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)
    elif technique == "randomized-ttl":
        randomized_ttl_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment)

#Defin Custom Ports
def inverse_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform an inverse scan where responses from closed ports are more revealing"""
    logging.info("Performing inverse scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/TCP(dport=random.randint(1, 65535), flags="SA")
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible closed port or firewalled.")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == "RA":
                logging.info(f"{ip} has a closed port, but inverse scan detected it.")

def bad_tcp_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform a scan using deliberately malformed TCP packets to evade detection"""
    logging.info("Performing bad TCP checksum scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/TCP(dport=random.randint(1, 65535), chksum=0xFFFF)
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible malformed TCP handling.")
        elif response.haslayer(TCP):
            logging.info(f"Malformed TCP packet to {ip} received a response.")

def covert_channel_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform a covert channel scan using non-standard or disguised protocols"""
    logging.info("Performing covert channel scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/UDP(dport=random.randint(1, 65535))/b"CovertData"
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible filtering or closed.")
        elif response.haslayer(UDP):
            logging.info(f"Response received from port {response.sport} - Covert channel scan detected a response.")

def ack_tunneling_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform an ACK tunneling scan to evade detection by firewalls"""
    logging.info("Performing ACK tunneling scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/TCP(dport=random.randint(1, 65535), flags="A")
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, firewall might be filtering.")
        elif response.haslayer(TCP):
            logging.info(f"ACK tunneling scan received a response from {ip}.")

def tcp_timestamp_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform a TCP timestamp option manipulation scan to detect anomalies"""
    logging.info("Performing TCP timestamp option manipulation scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/TCP(dport=random.randint(1, 65535), options=[('Timestamp', (12345, 0))])
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible filtering or blocking.")
        elif response.haslayer(TCP):
            logging.info(f"TCP timestamp scan detected a response from {ip}.")

def syn_ack_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform a SYN+ACK scan to detect open and closed ports"""
    logging.info("Performing SYN+ACK scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, dst=str(ip))/TCP(dport=random.randint(1, 65535), flags="SA")
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible filtering or firewalled.")
        elif response.haslayer(TCP):
            logging.info(f"SYN+ACK scan detected a response from {ip}.")

def randomized_ttl_scan(ip_range, randomize, legit_traffic, stealth, spoof_ip, fragment):
    """Perform a scan with randomized TTL values to avoid detection"""
    logging.info("Performing randomized TTL scan...")
    
    for ip in IPNetwork(ip_range):
        packet = IP(src=spoof_ip if spoof_ip else None, ttl=random.randint(1, 128))/TCP(dport=random.randint(1, 65535), flags="S")
        if fragment:
            packet = fragment_packet(packet)
        if legit_traffic:
            generate_legit_traffic(str(ip))
        if randomize:
            time.sleep(random.uniform(0.5, 2.0))
        if stealth:
            packet = enhance_stealth(packet)
        response = sr1(packet, timeout=1, verbose=False)
        if response is None:
            logging.info(f"No response from {ip}, possible TTL-based filtering.")
        elif response.haslayer(TCP):
            logging.info(f"Randomized TTL scan detected a response from {ip}.")

def enhance_stealth(packet):
    """Enhance the stealth of a packet by modifying headers and timing"""
    packet[IP].id = random.randint(0, 65535)
    packet[IP].flags = "DF"
    packet[TCP].seq = random.randint(0, 4294967295)
    packet[TCP].ack = random.randint(0, 4294967295)
    packet[IP].ttl = random.randint(64, 128)
    return packet

def fragment_packet(packet):
    """Fragment the packet to bypass certain types of filtering and detection"""
    return [packet[i:i+8] for i in range(0, len(packet), 8)]

def generate_legit_traffic(target_ip):
    """Generate legitimate traffic to blend in with the network activity"""
    packet_types = [TCP, UDP, ICMP]
    for _ in range(random.randint(1, 3)):
        pkt_type = random.choice(packet_types)
        if pkt_type == TCP:
            packet = IP(dst=target_ip)/TCP(dport=80)
        elif pkt_type == UDP:
            packet = IP(dst=target_ip)/UDP(dport=53)
        else:
            packet = IP(dst=target_ip)/ICMP()
        send(packet, verbose=False)
        logging.info(f"Legitimate {pkt_type.__name__} packet sent to {target_ip}")

# Alerts & Notifications Commands
@cli.group()
def alerts():
    """Commands related to alerts and notifications"""
    pass

@alerts.command()
@click.option('--email', help="Email address for alerts")
@click.option('--sms', help="Phone number for SMS alerts")
def configure(email, sms):
    """Configure alert notifications"""
    if email:
        logging.info(f"Configuring email alerts to {email}...")
        # Implementation of email alert configuration
    if sms:
        logging.info(f"Configuring SMS alerts to {sms}...")
        # Implementation of SMS alert configuration

# Reporting Commands
@cli.group()
def report():
    """Commands related to generating reports"""
    pass

@report.command()
@click.option('--start-date', required=True, help="Start date for the report (YYYY-MM-DD)")
@click.option('--end-date', required=True, help="End date for the report (YYYY-MM-DD)")
@click.option('--output', default="report.txt", help="Output file for the report")
def generate(start_date, end_date, output):
    """Generate network reports"""
    logging.info(f"Generating report from {start_date} to {end_date}...")
    generate_report(start_date, end_date, output)

def generate_report(start_date, end_date, output):
    """Generate a report based on monitoring and attack data"""
    # Sample data for demonstration
    report_data = {
        'start_date': start_date,
        'end_date': end_date,
        'attacks': [
            {'type': 'MAC Spoofing', 'timestamp': str(datetime.now())},
            {'type': 'Deauth Attack', 'timestamp': str(datetime.now())}
        ],
        'network_activity': [
            {'ip': '192.168.1.10', 'mac': 'AA:BB:CC:DD:EE:FF', 'timestamp': str(datetime.now())}
        ]
    }
    with open(output, 'w') as f:
        f.write(json.dumps(report_data, indent=4))
    logging.info("Report generated successfully!")

# Device Identification Commands
@cli.group()
def device():
    """Commands related to device identification"""
    pass

@device.command()
@click.option('--mac', required=True, help="MAC address to identify")
def identify(mac):
    """Identify device based on MAC address"""
    logging.info(f"Identifying device with MAC address {mac}...")
    if mac in mac_db:
        details = mac_db[mac]
        logging.info(f"Device details: IP: {details.get('ip')}, First Seen: {details.get('first_seen')}, Last Seen: {details.get('last_seen')}")
    else:
        logging.warning(f"No records found for MAC address {mac}")

# Database Integration Commands
@cli.group()
def db():
    """Commands related to database integration"""
    pass

@db.command()
@click.option('--init', is_flag=True, help="Initialize database")
@click.option('--add-data', is_flag=True, help="Add monitoring data to database")
def manage(init, add_data):
    """Manage database operations"""
    if init:
        logging.info("Initializing database...")
        if os.path.exists(MAC_DATABASE_FILE):
            os.remove(MAC_DATABASE_FILE)
        logging.info("MAC database initialized.")
    if add_data:
        logging.info("Adding monitoring data to database...")
        save_mac_database()

# Advanced Features Commands
@cli.group()
def advanced():
    """Commands related to advanced network features"""
    pass

@advanced.command()
@click.option('--dpi', is_flag=True, help="Enable Deep Packet Inspection")
@click.option('--anomaly-detection', is_flag=True, help="Enable anomaly detection")
def features(dpi, anomaly_detection):
    """Enable advanced network features"""
    if dpi:
        logging.info("Deep Packet Inspection enabled...")
        perform_dpi()
    if anomaly_detection:
        logging.info("Anomaly detection enabled...")
        detect_mac_anomalies()

def perform_dpi(interface="eth0"):
    """Perform Deep Packet Inspection"""
    logging.info("Performing Deep Packet Inspection on interface %s...", interface)

    def inspect_packet(packet):
        try:
            # Extract packet layers and payload
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                logging.info(f"Packet from {packet[IP].src} to {packet[IP].dst}: {payload}")

                # Simple example checks
                if b"malicious" in payload:
                    logging.warning("Malicious content detected in packet from %s to %s", packet[IP].src, packet[IP].dst)

                if b"GET" in payload and packet.haslayer(TCP) and packet[TCP].dport == 80:
                    logging.info("HTTP GET request detected from %s", packet[IP].src)
            
            # Inspect DNS queries
            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
                dns_query = packet[DNSQR].qname.decode()
                logging.info("DNS query for %s from %s", dns_query, packet[IP].src)

        except Exception as e:
            logging.error("Error processing packet: %s", str(e))

    # Sniffing packets on the specified interface
    sniff(iface=interface, prn=inspect_packet, store=0)

# Evasion Techniques

@cli.command()
@click.option('--function', required=True, type=click.Choice(['confuse_channel', 'smuggle_data', 'tunnel_data', 'wrap_protocol', 'fragment_data', 'steganography', 'disguise_traffic']), help="Function to execute")
@click.option('--source-ip', help="Source IP address")
@click.option('--target-ip', help="Target IP address")
@click.option('--interface', help="Network Interface for Channel Switching")
def evade(function, source_ip, target_ip, interface):
    """Network Operations for Evasion Techniques"""
    if function == 'confuse_channel':
        confuse_channel(interface)
    elif function == 'smuggle_data':
        smuggle_data(source_ip, target_ip)
    elif function == 'tunnel_data':
        tunnel_data(source_ip, target_ip)
    elif function == 'wrap_protocol':
        wrap_protocol(source_ip, target_ip, "example.com")
    elif function == 'fragment_data':
        fragment_data(source_ip, target_ip, "This is a fragmented payload")
    elif function == 'steganography':
        steganography(source_ip, target_ip)
    elif function == 'disguise_traffic':
        disguise_traffic(source_ip, target_ip)

def confuse_channel(interface):
    """
    Confuse network monitoring by dynamically switching wireless channels.
    """
    channels = [1, 6, 11]  # Common Wi-Fi channels
    while True:
        new_channel = random.choice(channels)
        os.system(f"iwconfig {interface} channel {new_channel}")
        print(f"Switched to channel {new_channel}")
        time.sleep(10)  # Switch channel every 10 seconds

LOG_FILE = "smuggle_data_log.txt"

def log_packet(action, packet, response=None):
    """Log packets sent and responses received to a file."""
    with open(LOG_FILE, "a") as log:
        log.write(f"{datetime.now()} - {action}\n")
        log.write(f"Packet: {packet.summary()}\n")
        if response:
            log.write(f"Response: {response.summary()}\n")
        log.write("\n")

def generate_random_payload(size=32):
    """Generate a randomized payload with alphanumeric characters and noise."""
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?/`~"
    return ''.join(random.choice(characters) for _ in range(size))

def smuggle_data(source_ip, target_ip):
    """Advanced ICMP data smuggling with dynamic payloads and adaptive behavior."""
    print("[*] Starting advanced ICMP data smuggling...")
    for i in range(20):
        payload_size = random.randint(20, 120)
        noise = generate_random_payload(payload_size)
        ttl = random.randint(40, 128)

        pkt = IP(src=source_ip, dst=target_ip, ttl=ttl, id=random.randint(1, 65535)) / \
              ICMP(type=8, code=0) / Raw(load=noise)

        if random.choice([True, False]):
            pkt = fragment(pkt, fragsize=random.randint(8, 16))  # Fragmentation
            print("[!] Sending fragmented packet...")

        response = sr1(pkt, timeout=1, verbose=False)
        log_packet("Smuggle Data Packet", pkt, response)
        print(f"[+] Sent ICMP packet {i+1} with TTL={ttl} and Payload Size={payload_size}")

        time.sleep(random.uniform(0.1, 2.0))

def tunnel_data(source_ip, target_ip):
    """Tunnel data inside DNS queries to simulate protocol tunneling."""
    print("[*] Starting DNS tunneling...")
    for i in range(10):
        payload = generate_random_payload(random.randint(10, 30))
        dns_query = IP(src=source_ip, dst=target_ip) / \
                    UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{payload}.example.com"))

        response = sr1(dns_query, timeout=2, verbose=False)
        log_packet("Tunnel Data Packet", dns_query, response)
        print(f"[+] Sent DNS query with payload: {payload}")

        time.sleep(random.uniform(0.5, 2.5))

    print("[*] DNS tunneling completed.")
def wrap_protocol(source_ip, target_ip, payload):
    """
    Wrap data within a legitimate HTTP request to evade detection.
    """
    packet = IP(src=source_ip, dst=target_ip) / TCP(dport=80) / Raw(load=f"GET / HTTP/1.1\r\nHost: {payload}\r\n\r\n")
    send(packet)
    print("HTTP request sent with disguised payload.")

def fragment_data(source_ip, target_ip, payload):
    """Fragment data into multiple IP fragments to bypass reassembly detection."""
    print("[*] Sending fragmented packets...")
    for i in range(0, len(payload), 10):
        frag = payload[i:i + 10] + generate_random_payload(5)  # Add random noise
        pkt = IP(src=source_ip, dst=target_ip, flags="MF", frag=i // 10) / \
              UDP(dport=4444) / Raw(load=frag)

        send(pkt, verbose=False)
        log_packet("Fragment Data Packet", pkt)
        print(f"[+] Sent fragmented packet {i // 10 + 1} with payload chunk: {frag}")

        time.sleep(random.uniform(0.2, 1.0))


def steganography(source_ip, target_ip):
    """
    Embed hidden data within TCP packet flags.
    """
    hidden_msg = "secret"
    flags = ['F', 'S', 'R', 'P', 'A', 'U']  # TCP flags
    for flag in flags:
        pkt = IP(src=source_ip, dst=target_ip) / TCP(flags=flag) / Raw(load=hidden_msg)
        send(pkt)
    print("Steganography data sent via TCP flags.")

def disguise_traffic(source_ip, target_ip):
    """
    Disguise traffic to confuse monitoring systems by using unusual protocols,
    malformed packets, fragmented headers, and randomized payloads.
    """
    print("[*] Starting advanced traffic disguise with unusual protocols...")

    # List of unusual protocols
    unusual_protocols = [
        "GRE", "ESP", "AH", "IP-in-IP", "IGMP", "EIGRP", "PIM", "L2TP", "MPLS"
    ]

    for i in range(50):  # Send 50 randomized packets
        # Generate random payload with varying size and noise
        payload = generate_random_payload(random.randint(50, 200))
        ttl = random.randint(5, 64)  # Randomize TTL for more suspicion
        proto = random.choice(unusual_protocols)
        pkt = IP(src=source_ip, dst=target_ip, ttl=ttl, id=random.randint(1, 65535))

        # Use unusual protocols with random headers
        if proto == "GRE":  # Generic Routing Encapsulation
            pkt /= GRE(proto=random.randint(0, 255)) / Raw(load=payload)
        elif proto == "ESP":  # Encapsulating Security Payload
            pkt /= IP(proto=50) / Raw(load=payload)
        elif proto == "AH":  # Authentication Header
            pkt /= IP(proto=51) / Raw(load=payload)
        elif proto == "IP-in-IP":  # IP encapsulated within IP
            pkt /= IP(proto=4) / IP(src=random_ip(), dst=random_ip()) / Raw(load=payload)
        elif proto == "IGMP":  # Internet Group Management Protocol
            pkt /= IGMP(type=random.choice([0x11, 0x12, 0x16]), mrcode=random.randint(0, 255)) / Raw(load=payload)
        elif proto == "EIGRP":  # Cisco's Enhanced Interior Gateway Routing Protocol
            pkt /= IP(proto=88) / Raw(load=payload)
        elif proto == "PIM":  # Protocol Independent Multicast
            pkt /= IP(proto=103) / Raw(load=payload)
        elif proto == "L2TP":  # Layer 2 Tunneling Protocol
            pkt /= UDP(dport=1701) / Raw(load=payload)
        elif proto == "MPLS":  # Multi-Protocol Label Switching
            pkt /= MPLS(label=random.randint(1, 1048575), s=1) / Raw(load=payload)

        # Handle packet fragmentation
        if random.choice([True, False]):
            fragments = fragment(pkt, fragsize=random.randint(8, 32))  # Irregular fragmentation
            print(f"[!] Sending fragmented {proto} packet...")
            for frag in fragments:
                send(frag, verbose=False)
                log_packet(f"Fragmented {proto} Traffic Packet", frag)
        else:
            send(pkt, verbose=False)
            log_packet(f"Disguised {proto} Traffic Packet", pkt)

        print(f"[+] Sent {proto} packet {i+1} with TTL={ttl} and payload size={len(payload)}")
        time.sleep(random.uniform(0.05, 1.0))  # Adaptive delay for extra stealth

    print("[*] Advanced traffic disguise completed.")

def random_ip():
    """Generate a random IP address."""
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


if __name__ == '__main__':
    cli()
