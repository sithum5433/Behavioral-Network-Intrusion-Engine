# 🛡️ DeepSight: Behavioral Network Intrusion Engine

DeepSight is an advanced, custom-built Behavioral Network Intrusion Detection Engine developed in Python. Moving beyond traditional signature-based firewalls, DeepSight actively monitors live network traffic, learns normal flow states, and detects behavioral anomalies in real-time. 

When a critical threat is detected, it interfaces directly with the OS-level firewall (`iptables`) to automatically quarantine the malicious node.

---

## 🚀 Key Features

*   **Stateful Flow Analysis:** Tracks inbound and outbound packet counts and port access patterns per IP address.
*   **Shannon Entropy Scoring:** Mathematically analyzes raw IP payloads to detect highly encrypted data, identifying potential Command & Control (C2) tunnels or data exfiltration.
*   **Port Scan Detection:** Identifies aggressive reconnaissance scanning across multiple ports.
*   **Traffic Flood / DoS Detection:** Monitors packet velocity and flags abnormal spikes in traffic.
*   **Automated OS-Level Quarantine:** Instantly blocks malicious IP addresses using Linux `iptables` without requiring manual intervention.
*   **Interactive CLI & Threat Reconnaissance:** A multi-threaded architecture allows the sniffer to run in the background while providing a foreground CLI to list blocked IPs, unblock nodes, and investigate threats (Reverse DNS, Geolocation, and ISP lookups).

---

## 🛠️ Prerequisites

DeepSight requires a Linux environment (Kali Linux recommended) with root privileges to access raw network sockets and modify firewall rules.

*   **OS:** Linux (Debian/Ubuntu/Kali)
*   **Python:** Python 3.x
*   **Libraries:** `scapy`

---

## ⚙️ Installation

1. Clone the repository

2. sudo apt-get update
sudo apt-get install python3-scapy

💻 Usage
Due to the nature of raw socket sniffing and firewall manipulation, DeepSight must be run with sudo or as the root user.
sudo python3 deepsight.py


help	------->      Displays the list of available commands.




<img width="1920" height="1080" alt="Screenshot_2026-07-17_10_17_03" src="https://github.com/user-attachments/assets/96871654-0e97-4103-be64-79942bee35e1" />



