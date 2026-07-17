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




## ✨ Latest Upgrades: Human-in-the-Loop (HITL) Architecture

To address real-world Security Operations Center (SOC) challenges such as false positives (e.g., accidentally blocking Google or GitHub due to high HTTPS encryption entropy) and alert fatigue, DeepSight has been upgraded with a **Human-in-the-Loop** decision model:

*   **Auto-Investigation Engine:** Suspicious IPs are no longer just flagged. The engine automatically fetches Geolocation, ISP, and Reverse DNS (Hostname) data in the background to provide immediate context to the security analyst.
*   **Pending Threat Queue:** Instead of blindly blocking traffic, alerts are placed in a pending queue. The system presents the gathered intelligence and waits for an admin's final decision.
*   **ID-Based Target Resolution:** Streamlined the CLI workflow for faster response times. Analysts can now quarantine or whitelist threats using auto-generated alert IDs (e.g., typing `block 1` instead of `block 150.171.110.98`).
*   **Smart Whitelisting:** Quickly bypass trusted IP addresses (`ignore <id>`) to refine the engine's accuracy and prevent future interruptions to essential services.


<img width="1920" height="1080" alt="Screenshot_2026-07-17_10_35_53" src="https://github.com/user-attachments/assets/28e93b25-acd7-49c6-955b-3a1c119c7b0d" />



