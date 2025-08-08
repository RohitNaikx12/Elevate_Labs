
# Task 4: Setup and Use a Firewall on Windows/Linux

## Objective
Configure and test basic firewall rules to allow or block traffic.

## Tools
- **Windows Firewall**  
- **UFW (Uncomplicated Firewall)** on Linux

---

## Steps Performed

1. **Opened firewall configuration tool**  
   - On Windows: Used Windows Defender Firewall with Advanced Security  
   - On Linux: Used `ufw` via terminal

2. **Listed current firewall rules**  
   ```bash
   sudo ufw status numbered
   ```  
   or via Windows Firewall inbound/outbound rule list.

3. **Added a rule to block inbound traffic on port 23 (Telnet)**  
   ```bash
   sudo ufw deny 23
   ```  
   On Windows, created a new inbound rule blocking TCP port 23.

4. **Tested the rule**  
   - Attempted to connect using `telnet localhost 23` → Connection blocked.

5. **Allowed SSH (port 22) on Linux**  
   ```bash
   sudo ufw allow 22/tcp
   ```

6. **Removed the test block rule**  
   ```bash
   sudo ufw delete deny 23
   ```

7. **Documented commands and GUI steps** (as above).

8. **Summary of how firewall filters traffic**  
   - Firewalls inspect network packets and allow/block them based on pre-defined rules.  
   - They operate at different layers (network/transport) to control traffic flow.

---

## Interview Questions and Answers

1. **What is a firewall?**  
   A firewall is a network security device or software that monitors and filters incoming and outgoing network traffic based on security rules.

2. **Difference between stateful and stateless firewall?**  
   - **Stateful**: Tracks the state of active connections and makes decisions based on the connection state and rules.  
   - **Stateless**: Makes decisions solely based on the individual packet's header without tracking connection state.

3. **What are inbound and outbound rules?**  
   - **Inbound rules**: Control traffic coming **into** your device/network.  
   - **Outbound rules**: Control traffic **leaving** your device/network.

4. **How does UFW simplify firewall management?**  
   UFW provides an easy-to-use command-line interface for managing iptables rules without needing deep networking knowledge.

5. **Why block port 23 (Telnet)?**  
   Telnet is insecure as it transmits data, including passwords, in plaintext, making it vulnerable to interception.

6. **What are common firewall mistakes?**  
   - Allowing unnecessary open ports  
   - Misconfigured rules blocking essential services  
   - Not updating firewall rules as network needs change

7. **How does a firewall improve network security?**  
   It prevents unauthorized access, blocks malicious traffic, and reduces the attack surface of a system/network.

8. **What is NAT in firewalls?**  
   Network Address Translation hides internal IP addresses by mapping them to a public IP, adding privacy and security.

---

## Deliverables
- **Screenshot**: (Include firewall status and applied rules)
- **Configuration file**: Saved list of firewall rules

---

**Key Concepts**: Firewall configuration, network traffic filtering, ports, UFW, Windows Firewall
