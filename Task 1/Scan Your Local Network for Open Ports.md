
# 🔒 Port Scanning and Network Security Basics

## Objective: Learn to discover open ports on devices in your local network to understand network exposure. 
## Tools:  Nmap (free), Wireshark (optional).

---

## 1. What is an Open Port?
An **open port** is a network port that is actively accepting connections or data packets. It is associated with a specific service or application on a device, such as a web server (port 80) or SSH server (port 22). Open ports can be entry points for legitimate services or potential attack vectors if left unsecured.

---

## 2. How Does Nmap Perform a TCP SYN Scan?
Nmap performs a **TCP SYN scan** (`-sS`) by sending SYN packets to target ports and analyzing the responses:
- **SYN-ACK** → Port is **open**.
- **RST** → Port is **closed**.
- **No response/filtered** → Port is **filtered** (by a firewall).

This scan is stealthy because it doesn't complete the TCP handshake, making it less likely to be logged.

---

## 3. What Risks Are Associated With Open Ports?
- **Unauthorized access** to services (e.g., open SSH or RDP).
- **Exploitation** of known vulnerabilities in exposed applications.
- **Denial of Service (DoS)** via unprotected services.
- **Information leakage** from banners or service details.
- **Network mapping** by attackers to identify targets.

---

## 4. Difference Between TCP and UDP Scanning
| Feature       | TCP Scan                         | UDP Scan                           |
|---------------|----------------------------------|------------------------------------|
| Protocol      | Connection-oriented              | Connectionless                     |
| Reliability   | High                            | Lower                              |
| Speed         | Faster (with SYN scan)          | Slower due to retransmissions      |
| Detection     | Easier to detect (logs)         | Harder to detect                   |
| Use Case      | Common for service discovery     | Used for discovering DNS, SNMP, etc. |

---

## 5. How Can Open Ports Be Secured?
- **Disable unused services/ports**.
- **Use firewalls** to block external access.
- **Implement access control lists (ACLs)**.
- **Enable intrusion detection/prevention systems (IDS/IPS)**.
- **Regularly update software** to patch vulnerabilities.
- **Use port-knocking or VPNs** for sensitive services.

---

## 6. What is a Firewall's Role Regarding Ports?
A **firewall** monitors and controls incoming and outgoing traffic based on predetermined security rules. Regarding ports, it can:
- Block or allow traffic to specific ports.
- Limit port access by IP address or time.
- Detect and block suspicious port scanning activity.
- Log attempts to access closed or unauthorized ports.

---

## 7. What is a Port Scan and Why Do Attackers Perform It?
A **port scan** is the process of sending packets to ports on a host to determine which ones are open, closed, or filtered. **Attackers** perform port scans to:
- Discover **available services**.
- **Identify vulnerabilities** or misconfigurations.
- **Map network infrastructure**.
- **Plan further attacks** such as exploitation or brute-force.

---

## 8. How Does Wireshark Complement Port Scanning?
**Wireshark** is a network protocol analyzer that captures and inspects network packets in real-time. It complements port scanning by:
- **Visualizing SYN packets** sent during a scan.
- Identifying **unusual responses or activity**.
- **Verifying scan results** through actual traffic logs.
- **Learning about services** communicating on the network.

---

