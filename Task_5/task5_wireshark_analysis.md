# Task 5 – Capture and Analyze Network Traffic Using Wireshark

## Objective
Capture live network packets using Wireshark, identify basic protocols, and analyze traffic types.

---

## Step-by-Step Process

1. **Install Wireshark**  
   Download from [https://www.wireshark.org](https://www.wireshark.org) and install.

2. **Start Packet Capture**  
   - Open Wireshark  
   - Select your **active network interface** (usually Wi-Fi or Ethernet)  
   - Click **Start Capturing**.

3. **Generate Traffic**  
   - Browse websites, ping servers, or stream videos to produce network activity.

4. **Stop Capture**  
   - After ~1 minute, click **Stop**.

5. **Filter Packets**  
   - Example filters:  
     - HTTP traffic: `http`  
     - DNS traffic: `dns`  
     - TCP traffic: `tcp`

6. **Identify Protocols**  
   - Minimum 3 protocols: HTTP, DNS, TCP.

7. **Export Capture**  
   - File → Export Specified Packets → `.pcap` format.

---

## Findings (Example)

| Protocol | Purpose | Example Packet Details |
|----------|---------|------------------------|
| **HTTP** | Web data transfer | GET /index.html from example.com |
| **DNS**  | Domain name resolution | Query for google.com → IP address |
| **TCP**  | Reliable transport | TCP handshake SYN → SYN-ACK → ACK |

---

## Interview Questions & Answers

1. **What is Wireshark used for?**  
   Wireshark is a network protocol analyzer used to capture and inspect packets in real time.

2. **What is a packet?**  
   A packet is a small unit of data transmitted over a network containing headers and payload.

3. **How to filter packets in Wireshark?**  
   Use the filter bar (e.g., `http`, `dns`, `tcp.port == 80`).

4. **Difference between TCP and UDP?**  
   - TCP: Connection-oriented, reliable, error-checked.  
   - UDP: Connectionless, faster, no guarantee of delivery.

5. **What is a DNS query packet?**  
   A request sent to a DNS server to resolve a domain name into an IP address.

6. **How can packet capture help in troubleshooting?**  
   It helps identify latency, packet loss, misconfigurations, and security issues.

7. **What is a protocol?**  
   A set of rules for communication between network devices.

8. **Can Wireshark decrypt encrypted traffic?**  
   It can decrypt some encrypted traffic if keys or certificates are available; otherwise, the payload remains unreadable.

---

