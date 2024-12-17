# NetMonX

**NetMonX** is a powerful, versatile, and essential tool designed for wireless network monitoring, security assessment, and penetration testing not wired. It supporst WPA1,2,3 including Wifi6 anw Wifi6e and Wifi7. It offers unique advantages that make it indispensable for professionals responsible for securing networks or assessing their vulnerabilities. Below is an overview of why NetMonX stands out, its core functionalities, and how it can be effectively used by penetration testers, security researchers, and attackers.

# Quick Section
```
This will help anyone understand, what this tool is about and how powerful
this tool can be in understanding the vulnerabilities on the spot of any system being
protected by firewalls, IPS, IDS, NBA, etc

Command Case 1:
sudo python3 netmonx.py evade --function disguise_traffic --source-ip 192.168.163.129 --target-ip 192.168.163.129

Sent:
[*] Starting advanced traffic disguise with unusual protocols...
[!] Sending fragmented IP-in-IP packet...
[+] Sent IP-in-IP packet 1 with TTL=40 and payload size=172
[+] Sent EIGRP packet 2 with TTL=10 and payload size=193
[!] Sending fragmented GRE packet...
[+] Sent GRE packet 3 with TTL=41 and payload size=129
[+] Sent ESP packet 4 with TTL=14 and payload size=148
[!] Sending fragmented IGMP packet...
[+] Sent IGMP packet 5 with TTL=49 and payload size=182
[+] Sent PIM packet 6 with TTL=25 and payload size=177
[!] Sending fragmented IGMP packet...
[+] Sent IGMP packet 7 with TTL=59 and payload size=171
[+] Sent GRE packet 8 with TTL=45 and payload size=61
[+] Sent AH packet 9 with TTL=24 and payload size=183
[+] Sent L2TP packet 10 with TTL=5 and payload size=125
[+] Sent L2TP packet 11 with TTL=5 and payload size=79
[+] Sent IP-in-IP packet 12 with TTL=16 and payload size=146
[+] Sent L2TP packet 13 with TTL=36 and payload size=82
[+] Sent IP-in-IP packet 14 with TTL=15 and payload size=189
[!] Sending fragmented IGMP packet...
[+] Sent IGMP packet 15 with TTL=55 and payload size=168
[+] Sent EIGRP packet 26 with TTL=49 and payload size=101
[!] Sending fragmented IGMP packet...
[+] Sent IGMP packet 27 with TTL=50 and payload size=161
[+] Sent EIGRP packet 29 with TTL=38 and payload size=59

Output:
08:21:16.846218 IP kubuntu2204 > kubuntu2204: IP truncated-ip - 190 bytes missing! localhost > localhost: IP  [|ip]
08:21:17.349312 IP kubuntu2204 > kubuntu2204: IP truncated-ip - 69 bytes missing! localhost > localhost:  [|eigrp]
08:21:17.370954 IP kubuntu2204 > kubuntu2204: ipencap
08:21:17.664567 IP kubuntu2204 > kubuntu2204: igmp query v3 [max resp time 6.5s]
08:21:18.675807 IP kubuntu2204 > kubuntu2204: IP  [|ip]
08:21:19.252162 IP kubuntu2204 > kubuntu2204: igmp v2 report 0.0.0.0
08:21:19.263872 IP kubuntu2204 > kubuntu2204: igmp
08:21:20.003659 IP kubuntu2204 > kubuntu2204: IP localhost > localhost: ESP(spi=0x2425294b,seq=0x64642161), length 183
08:21:20.263576 IP kubuntu2204 > kubuntu2204: IP truncated-ip - 55 bytes missing! localhost > localhost:  [|eigrp]
........


Command Case 2:
sudo python3 netmonx.py scan start --ip-range 192.168.163.129 --technique inverse --spoof-ip 192.168.1.100 --use-fragment --stealth --randomize --legit-traffic

Sent:
024-12-17 08:42:35,006 - Starting inverse scan on IP range: 192.168.163.129
2024-12-17 08:42:35,006 - Performing inverse scan...
2024-12-17 08:42:35,051 - Legitimate UDP packet sent to 192.168.163.129
2024-12-17 08:42:35,066 - Legitimate UDP packet sent to 192.168.163.129
2024-12-17 08:42:35,089 - Legitimate TCP packet sent to 192.168.163.129

Output:
08:43:09.238852 IP 192.168.1.100.ftp-data > kubuntu2204.46692:  [|tcp]
08:43:09.249626 IP 192.168.1.100 > kubuntu2204: tcp
08:43:09.261736 IP 192.168.1.100 > kubuntu2204: tcp
08:43:09.274506 IP kubuntu2204 > kubuntu2204: ICMP echo request, id 0, seq 0, length 8
08:43:09.288181 IP kubuntu2204.domain > kubuntu2204.domain: domain [length 0 < 12] (invalid)
08:43:09.306746 IP kubuntu2204.domain > kubuntu2204.domain: domain [length 0 < 12] (invalid)
08:43:10.348010 IP 192.168.1.100.ftp-data > kubuntu2204.46692: Flags [S.], seq 3603802285, ack 1655656538, win 8192, length 0



What is this?:
Spoof IP address realtime, playing with TCP/IP framework
Encrypts the payload byte-by-byte using the given key (0xAA by default).
Ensures the payload is obfuscated and harder to analyze by IDS/IPS/NBA.
Fully randomized and obfuscated to send or receieve payload
```


# Newbies Section
```
NetMonX is a powerful and versatile tool tailored for network security analysis, ethical hacking, and advanced pentesting.
Its broad feature set, combined with stealth capabilities, makes it ideal for anyone seeking to secure networks,
identify vulnerabilities, or test against sophisticated attack scenarios.
Designed for professionals and enthusiasts in network security and cybersecurity.
It provides multiple functionalities:

Why I built it?
- Most network tools focus on a single aspect, like scanning or monitoring.
- NetMonX integrates these functionalities into one cohesive package.
- Traditional tools (like Nmap) lack the flexibility for stealth operations.
- Surpasses tools like Nmap and others in stealth operations
- Surpasses tools like Nmap when doing stealth port scan operations.
- Surpasses tools like Nmap when they are failing.
- It serves the purpose by working as a crowbar to dig out of IPS/IDS/Firewalls
- It serves the purpose by working as a crowbar for AI/ML firewall/IDS/IPS products
- This tool fills that gap by incorporating advanced evasion methods.
- Extreme TCP/IP Network Research
- By exposing users to multiple scanning and evasion techniques.
- It serves as an excellent learning tool for aspiring cybersecurity professionals.

Other Values it brings,

Real-Time Monitoring:
Tracks devices by MAC addresses (wired and wireless).
Identifies new devices and records them in a database.
Monitors changes in network activity and logs anomalies.

Stealth Scanning:
Performs advanced scans like SYN-ACK, bad TCP, and randomized TTL scans.
Includes stealthy features like IP spoofing, fragmentation, and traffic randomization.

Security Features:
Detects rogue devices and identifies anomalous MAC behavior.
Provides stealth mode to monitor networks covertly.

Evasion Techniques:
Evades detection with techniques like data tunneling, protocol wrapping, and channel confusion.

Reports and Alerts:
Generates detailed reports of network activity and threats.
Configures email/SMS alerts for critical events.

Advanced Features:
Supports Deep Packet Inspection (DPI) for packet-level monitoring.
Detects suspicious payloads and DNS queries.

Why Use?
1. Comprehensive Network Security
It consolidates network monitoring, pentesting, and evasion techniques into a single tool.
This eliminates the need to juggle multiple tools for different tasks.

2. Real-Time Threat Detection
With features like rogue device detection, anomaly monitoring, and stealth scans, the tool actively detects potential threats in real-time,
giving security professionals immediate insights into their network.

3. Stealth Capabilities
The tool is built for environments where detection must be avoided, such as ethical hacking or penetration testing scenarios.
Features like traffic randomization, stealth monitoring, and covert scanning make it highly effective for stealth operations.

4. Versatility and Automation
It supports a wide range of techniques:
Scanning methods tailored to bypass firewalls.
Database integration for device tracking.
Automation of routine monitoring and reporting tasks.

5. Evasion and Testing
By employing evasion techniques like DNS tunneling, traffic disguising, and payload wrapping,
it helps test a network's resilience against sophisticated attacks. This is crucial for identifying weak points in network defenses.

6. Customizable and Expandable
The script is built in Python, allowing users to modify or extend its functionalities to suit specific needs.
For example, new scanning techniques, reporting formats, or alert mechanisms can be added.

Who Can use It?
Network Security Professionals: To monitor networks, detect rogue devices, and analyze anomalies.
Penetration Testers: To perform advanced and stealthy network scans during assessments.
Cybersecurity Enthusiasts: To learn and experiment with scanning and evasion techniques.
Network Administrators: To generate reports, identify devices, and detect unauthorized access.
Researchers and Developers: To study network behavior, test vulnerabilities, and build upon the tool.

```

## Key Features and Advantages of NetMonX

### 1. Advanced Evasion Techniques
NetMonX incorporates sophisticated evasion techniques that allow it to bypass traditional security defenses such as Intrusion Detection Systems (IDS), Intrusion Prevention Systems (IPS), firewalls, and honeypot systems (like canaries). These features are particularly valuable for:

- **Penetration Testers**: NetMonX enables pentesters to simulate advanced attack scenarios without triggering alarms, which helps in providing a more accurate assessment of a network’s security posture.
- **Security Researchers**: Researchers can study how networks and security devices respond to stealthy, sophisticated attacks, enabling them to develop better defensive strategies.
- **Attackers**: (Ethical or otherwise) can use NetMonX to map out and exploit network vulnerabilities while minimizing the risk of detection.

### 2. Comprehensive Network Monitoring
NetMonX provides continuous, real-time monitoring of network activities, with a special focus on tracking MAC addresses. This capability is crucial for:

- **Network Administrators**: Keeping a close watch on all devices connected to the network, including unauthorized or rogue devices.
- **Incident Response Teams**: Quickly identifying anomalies or suspicious behavior that could indicate a security breach.
- **Compliance and Auditing**: Maintaining detailed logs of all network activities to meet regulatory requirements and conduct thorough security audits.

### 3. Real-Time Anomaly Detection
NetMonX’s ability to detect and log anomalies based on MAC address behavior is particularly valuable for:

- **Threat Detection**: Identifying unusual patterns, such as MAC address spoofing, frequent IP changes, or the appearance of new devices, which could indicate a security threat.
- **Proactive Security**: Allowing security teams to respond to potential threats in real-time, minimizing the window of opportunity for attackers.

### 4. Stealthy and Advanced Scanning Capabilities
NetMonX’s wide range of scanning techniques, such as inverse scanning, bad TCP checksum scanning, and covert channel scanning, makes it indispensable for:

- **Network Reconnaissance**: Gathering detailed information about the network’s structure and its devices without alerting security systems.
- **Vulnerability Assessment**: Identifying weaknesses in the network that could be exploited by attackers, enabling proactive remediation.
- **Red Team Operations**: Conducting realistic attack simulations to test the effectiveness of the organization’s defenses.

### 5. Detailed Reporting and Record Keeping
NetMonX excels in logging and reporting all detected activities and anomalies, which is essential for:

- **Forensic Analysis**: Providing a comprehensive log of all network activities that can be analyzed after an incident to determine its cause and impact.
- **Documentation**: Maintaining detailed records for compliance, auditing, and historical reference, ensuring that no crucial data is lost over time.
- **Continuous Improvement**: Using the collected data to improve network security practices and update defensive measures based on real-world threats.

### 6. Customization and Extensibility
NetMonX is designed to be highly customizable, allowing users to tailor its functionality to their specific needs. This is beneficial for:

- **Security Professionals**: Integrating NetMonX with existing security tools or customizing its behavior to suit specific network environments.
- **Developers**: Extending the tool with new scanning techniques, additional features, or integration with other security platforms.
- **Organizations**: Adapting the tool to fit the unique requirements of their security infrastructure, making it a versatile solution for any environment.

### 7. Law Enforcements and Agencies
NetMonX functionality can provide physical movement insights and highlight network performance issues or suspicious roaming behavior during pentesting. 

- **Physical Movement Tracking**: Identify moving devices (e.g., employees, intruders) in a building.
- **Network Performance**: Analyze roaming behavior to optimize AP placement and network configurations.
- **Security Audits**: Detect suspicious roaming, such as attackers switching between APs to evade detection.
- **Full Support**: 802.11/etc, SSID, BSSID: Macs, Encryption Types, WPA/WPA2/WPA3, RSSI and more.....

```
Example:

Client: 00:11:22:33:44:55
APs: AA:BB:CC:DD:EE:FF and FF:EE:DD:CC:BB:AA

The client initially connects to AP AA:BB:CC:DD:EE:FF:
2024-12-15 14:05:00 - Client 00:11:22:33:44:55 connected to AP AA:BB:CC:DD:EE:FF

The client roams to AP FF:EE:DD:CC:BB:AA:
2024-12-15 14:10:00 - [ROAMING] Client 00:11:22:33:44:55 roamed from AP AA:BB:CC:DD:EE:FF to AP FF:EE:DD:CC:BB:AA at 2024-12-15 14:10:00

If the client roams back to the original AP:
2024-12-15 14:15:00 - [ROAMING] Client 00:11:22:33:44:55 roamed from AP FF:EE:DD:CC:BB:AA to AP AA:BB:CC:DD:EE:FF at 2024-12-15 14:15:00


Export Roaming History:
Save roaming data into a JSON or CSV file
```


## Why Use NetMonX?

### Pentesters (Penetration Testers)
- **Stealthy Network Scanning**: NetMonX performs highly stealthy scans that can bypass traditional security defenses like IDS/IPS, firewalls, and canaries, enabling pentesters to simulate real-world attack scenarios without triggering alarms.
- **MAC Address-Based Reconnaissance**: NetMonX’s ability to monitor MAC addresses in real-time, track wireless devices, and log all detected MACs is invaluable for building a complete picture of the target environment.
- **Anomaly Detection**: Pentesters can leverage NetMonX’s anomaly detection features to identify potential weaknesses or misconfigurations in a network based on unusual MAC address behavior.
- **Comprehensive Reporting**: After a pentest, NetMonX provides detailed reports that document all activities, detections, and potential vulnerabilities, making it easier for pentesters to deliver actionable insights to their clients.

### Security Researchers
- **Advanced Scanning Techniques**: Security researchers can use NetMonX to explore and document how different scanning techniques affect various types of networks and security systems. Techniques like TCP timestamp manipulation, ACK tunneling, and randomized TTL values provide a rich set of data for analysis.
- **Exploration of MAC Address Behavior**: Researchers can study how MAC addresses behave in different environments, particularly how they interact with security devices like firewalls and IDS/IPS.
- **Testing IDS/IPS Effectiveness**: By utilizing NetMonX’s stealth capabilities, researchers can evaluate the effectiveness of various IDS/IPS systems and firewalls. They can document how these systems respond (or fail to respond) to NetMonX’s advanced evasion techniques.
- **Contribution to Threat Intelligence**: The data collected by NetMonX, especially regarding how networks react to certain types of traffic, can be valuable for developing new defensive strategies or improving existing security tools.

### Attackers
- **Evasion of Detection**: Attackers value tools that allow them to conduct reconnaissance and exploitation activities without being detected. NetMonX’s sophisticated evasion techniques, such as bad TCP checksum scanning and covert channel scanning, are particularly useful for avoiding detection by network security devices.
- **MAC Address Spoofing and Manipulation**: Attackers can use NetMonX to monitor MAC addresses and potentially spoof or manipulate them to blend into the network, evade MAC filtering, or impersonate legitimate devices.
- **Network Mapping for Exploitation**: By building a detailed map of all devices on a network, including their MAC addresses, attackers can identify high-value targets (e.g., servers, network devices) and plan their attacks more effectively.
- **Blending with Legitimate Traffic**: The tool’s ability to generate legitimate-looking traffic alongside its scans helps attackers obscure their activities, making it harder for network administrators to distinguish between normal network traffic and malicious activity.

## How NetMonX Keeps Records

### MAC Address Logging
- **Real-Time Detection**: NetMonX continuously detects and logs every MAC address that appears on the network. This logging includes not just the MAC address itself but also associated data such as the IP address, the first time the MAC was seen, and the last time it was detected.
- **Database Storage**: All detected MAC addresses and their associated data are stored in a persistent database. This database is maintained across sessions, allowing NetMonX to recognize previously seen devices and update their records accordingly.
- **New Device Detection**: When a new MAC address is detected—meaning one that hasn’t been logged before—NetMonX logs it as a new device, storing its details and marking the timestamp of when it first appeared.

### Historical Record Maintenance
- **First and Last Seen Timestamps**: For each MAC address, NetMonX keeps track of when it was first detected and when it was last seen. This helps in understanding the presence and activity patterns of devices on the network over time.
- **Change Detection**: If a MAC address is detected on different IP addresses or shows unusual behavior (such as frequent IP changes), NetMonX logs these changes, providing insights into possible network anomalies or misconfigurations.

### Continuous Monitoring
- **Persistent Monitoring**: NetMonX operates continuously, meaning it is always actively monitoring the network and updating its logs in real-time. This continuous operation ensures that no activity goes unnoticed, and all relevant data is captured.
- **Anomaly Detection**: With continuous monitoring, NetMonX can detect anomalies as they occur. For example, if a device suddenly changes its MAC address or appears on multiple IP addresses in quick succession, NetMonX logs these anomalies and can alert the user.
- **Data Retention**: The persistent database allows NetMonX to retain data over long periods, making it possible to analyze trends, review historical activity, and understand the long-term behavior of devices on the network.

## Why Record-Keeping is Important

### Network Security
- **Tracking Unauthorized Devices**: By keeping a continuous log of all detected MAC addresses, NetMonX helps in identifying unauthorized devices that may attempt to connect to the network. This is crucial for maintaining a secure environment.
- **Anomaly Identification**: The historical data allows for the detection of unusual patterns, such as a MAC address moving between different IPs or appearing on the network at odd times. These anomalies could indicate malicious activity or network misconfigurations that need to be addressed.

### Audit and Compliance
- **Historical Records**: Maintaining detailed logs of all network activities is essential for compliance with various security standards and regulations. NetMonX’s comprehensive record-keeping ensures that organizations have access to the necessary data for audits and compliance checks.
- **Incident Response**: In the event of a security incident, having a detailed log of all network activities, including MAC address movements, can be invaluable for investigating the breach and determining the root cause.

## Conclusion: Why Use NetMonX?

- **Versatility**: Whether you’re a network administrator, security researcher, penetration tester, or ethical hacker, NetMonX offers tools and features tailored to your needs.
- **Advanced Capabilities**: The tool’s ability to perform stealthy, advanced scans, and its focus on MAC address monitoring and anomaly detection, make it stand out as a comprehensive security solution.
- **Proactive Security**: By providing continuous monitoring, real-time detection, and detailed reporting, NetMonX helps you stay ahead of potential threats and maintain a secure network environment.

NetMonX is essential for anyone serious about maintaining robust network security, conducting thorough penetration tests, or studying advanced network behaviors. It’s a tool that not only helps identify vulnerabilities but also enables proactive defense strategies, ensuring that your network remains secure against sophisticated threats.

## Advantages for Pentester/Attacker:

# Confuse Channel:
- Evades detection by exploiting unmonitored channel hopping.
- Verified: Cisco Aironet 2800 Series, Aruba Instant APs (e.g., IAP-305).

# Smuggle Data (ICMP):
- Can discreetly transport data through less scrutinized ICMP traffic.
- Verified: Palo Alto Networks PA-Series Firewalls, Fortinet FortiGate 60F.

# Tunnel Data (DNS):
- Effective for covert communication using DNS queries.
- Verified: Cisco Umbrella, Infoblox DNS Security.

# Wrap Protocol (HTTP):
- Can bypass basic systems by hiding data within HTTP requests.
- Verified: F5 Networks BIG-IP, Imperva Incapsula.

# Fragment Data:
- Potentially avoids detection through fragmented packets.
- Verified: Check Point R81, Juniper SRX Series.

# Steganography:
- Conceals data within other files or protocols, evading simpler systems.
- Example Tools: OpenStego, Steghide.

# Disguise Traffic:
- Converts traffic between OSI layers to obscure its nature.
- Verified: Radware AppWall, Sophos XG Firewall.

## Usages

```bash
General Command Structure

1. Monitoring MAC Addresses

Real-Time Monitoring with Wireless MAC Address Recording
python NetMonX.py monitor start --mac --wireless --record-new

Only Monitor Wireless MAC Addresses
python NetMonX.py monitor start --wireless

2. Security Features
Enable Rogue Device Detection and Anomaly Detection
python NetMonX.py security protect --rogue-detection --anomaly-detection

Enable Stealth Mode for Monitoring
python NetMonX.py security protect --stealth

3. Advanced and Stealthy Scanning
Perform an Inverse Scan with IP Spoofing, Fragmentation, and Stealth Techniques
python NetMonX.py scan start --ip-range 192.168.1.0/24 --technique inverse --spoof-ip 192.168.1.100 --fragment --stealth --randomize --legit-traffic

Perform a Bad TCP Checksum Scan with Fragmentation and Legitimate Traffic
python NetMonX.py scan start --ip-range 192.168.1.0/24 --technique bad-tcp --fragment --legit-traffic --randomize

Perform a Covert Channel Scan with Protocol Obfuscation
python NetMonX.py scan start --ip-range 192.168.1.0/24 --technique covert --stealth --fragment --spoof-ip 192.168.1.200

Perform an ACK Tunneling Scan with Randomized TTL
python NetMonX.py scan start --ip-range 192.168.1.0/24 --technique ack-tunneling --randomized-ttl --fragment --stealth

4. Alerts and Notifications
Configure Email and SMS Alerts
python NetMonX.py alerts configure --email your_email@example.com --sms +1234567890

5. Reporting
Generate a Report for Specific Date Range
python NetMonX.py report generate --start-date 2024-08-01 --end-date 2024-08-10 --output report.txt

6. Device Identification
Identify Device by MAC Address
python NetMonX.py device identify --mac AA:BB:CC:DD:EE:FF

7. Database Management
Initialize the MAC Address Database
python NetMonX.py db manage --init

Add Monitoring Data to the Database
python NetMonX.py db manage --add-data

8. Advanced Network Features
Enable Deep Packet Inspection and Anomaly Detection
python NetMonX.py advanced features --dpi --anomaly-detection

Explanation of Key Options:
--fragment: Fragments packets to bypass detection by some firewalls and IDS/IPS systems.
--spoof-ip: Spoofs the source IP address to avoid detection or attribution.
--stealth: Activates enhanced stealth techniques, modifying packet headers and timing to evade detection.
--randomize: Randomizes the timing of packet sends to avoid detection by timing analysis.
--legit-traffic: Generates legitimate traffic to blend in with normal network activity, making the scan less suspicious.
--randomized-ttl: Randomizes the Time-To-Live (TTL) value to evade detection by systems monitoring for unusual TTL values.

Practical Scenarios:

Bypassing an Advanced Firewall (e.g., Palo Alto PA-220)
- The use of IP spoofing, fragmentation, and stealth techniques can help evade DPI and anomaly detection features of high-end firewalls.
python NetMonX.py scan start --ip-range 10.0.0.0/24 --technique syn-ack --spoof-ip 10.0.0.100 --fragment --stealth --randomize

Evading IDS/IPS Systems (e.g., Snort, Suricata)
- Combining techniques like covert channel scanning, ACK tunneling, and randomized TTL can help bypass signature-based detection and heuristic analysis.

python NetMonX.py scan start --ip-range 172.16.0.0/24 --technique covert --spoof-ip 172.16.0.200 --fragment --randomize --legit-traffic --stealth
Evading Endpoint Protections (e.g., Linux Ubuntu 20.04, macOS Big Sur)

Advanced packet crafting, such as TCP timestamp manipulation and bad TCP checksum scans, combined with protocol obfuscation, can be used to bypass host-based defenses.
python NetMonX.py scan start --ip-range 192.168.1.0/24 --technique tcp-timestamp --frag
```

## Output/Practical Cases
```bash

1. Snort (Configured and Managed Version)
python NetMonX.py scan start --ip-range 172.16.0.0/24 --technique covert --spoof-ip 172.16.0.200 --fragment --randomize --legit-traffic --stealth

2024-08-10 15:30:12 - INFO - Starting covert scan on IP range: 172.16.0.0/24
2024-08-10 15:30:12 - INFO - Spoofing IP: 172.16.0.200
2024-08-10 15:30:12 - INFO - Sending disguised UDP packets with covert data to 172.16.0.1...
2024-08-10 15:30:12 - INFO - Legitimate DNS queries generated for camouflage...
2024-08-10 15:30:14 - INFO - No response from 172.16.0.1 - possibly filtered or closed.
2024-08-10 15:30:16 - INFO - Sending disguised UDP packets with covert data to 172.16.0.2...
2024-08-10 15:30:16 - INFO - Legitimate DNS queries generated for camouflage...
2024-08-10 15:30:18 - INFO - No response from 172.16.0.2 - possibly filtered or closed.
2024-08-10 15:30:20 - INFO - Covert channel scan completed without detection.
2024-08-10 15:30:20 - INFO - Snort system evasion successful, no alerts triggered.

2. Palo Alto PA-220
python NetMonX.py scan start --ip-range 10.0.0.0/24 --technique syn-ack --spoof-ip 10.0.0.100 --fragment --stealth --randomize

2024-08-10 15:45:30 - INFO - Starting SYN+ACK scan on IP range: 10.0.0.0/24
2024-08-10 15:45:30 - INFO - Spoofing IP: 10.0.0.100
2024-08-10 15:45:31 - INFO - Fragmenting packets to evade detection...
2024-08-10 15:45:31 - INFO - Sending SYN+ACK packet to 10.0.0.1 with randomized TTL and sequence number...
2024-08-10 15:45:33 - INFO - No response from 10.0.0.1 - possibly firewalled.
2024-08-10 15:45:34 - INFO - Sending SYN+ACK packet to 10.0.0.2 with randomized TTL and sequence number...
2024-08-10 15:45:36 - INFO - No response from 10.0.0.2 - possibly firewalled.
2024-08-10 15:45:37 - INFO - SYN+ACK scan completed with stealth and fragmentation.
2024-08-10 15:45:37 - INFO - Palo Alto firewall evasion successful, no DPI alerts triggered.
```
