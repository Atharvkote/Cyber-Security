Here are essential **Nmap** commands for basic scanning during a penetration test:  

### **Basic Host Discovery**
1. **Ping Scan (Check if a host is online)**
   ```bash
   nmap -sn 192.168.1.1
   ```
   - Does not perform port scanning, only checks if the host is alive.

2. **Scan an IP Range or Subnet**
   ```bash
   nmap -sn 192.168.1.0/24
   ```
   - Scans an entire subnet for live hosts.

### **Port Scanning**
3. **Default Scan (Detects open ports & running services)**
   ```bash
   nmap 192.168.1.1
   ```
   - Performs a SYN scan on the most common 1,000 ports.

4. **Scan a Specific Port**
   ```bash
   nmap -p 21 192.168.1.1
   ```
   - Checks if **port 21 (FTP)** is open.

5. **Scan Multiple Ports**
   ```bash
   nmap -p 21,22,80 192.168.1.1
   ```
   - Scans ports 21 (FTP), 22 (SSH), and 80 (HTTP).

6. **Scan All 65,535 Ports**
   ```bash
   nmap -p- 192.168.1.1
   ```
   - Scans all TCP ports.

### **Service and Version Detection**
7. **Detect Running Services and Versions**
   ```bash
   nmap -sV 192.168.1.1
   ```
   - Identifies services running on open ports and attempts to detect their versions.

8. **Operating System Detection**
   ```bash
   nmap -O 192.168.1.1
   ```
   - Tries to determine the operating system of the target.

9. **Aggressive Scan (OS, services, scripts, and traceroute)**
   ```bash
   nmap -A 192.168.1.1
   ```
   - Combines OS detection, version detection, script scanning, and traceroute.

### **Advanced Scanning**
10. **Scan Hosts Without Ping (For Stealth)**
    ```bash
    nmap -Pn 192.168.1.1
    ```
    - Bypasses ICMP ping checks and directly scans ports.

11. **Stealth Scan (Avoids Detection)**
    ```bash
    nmap -sS 192.168.1.1
    ```
    - Uses SYN scan to avoid detection by firewalls.

12. **UDP Scan (For Services Like DNS, SNMP)**
    ```bash
    nmap -sU -p 53,161 192.168.1.1
    ```
    - Checks for open UDP ports (like 53 for DNS, 161 for SNMP).

### **Scan for FTP Vulnerabilities**
13. **Check for Anonymous FTP Login**
    ```bash
    nmap --script ftp-anon -p 21 192.168.1.1
    ```
    - Checks if anonymous login is enabled on the FTP server.

14. **Check for FTP Backdoors**
    ```bash
    nmap --script ftp-vsftpd-backdoor -p 21 192.168.1.1
    ```
    - Tests for Vsftpd 2.3.4 backdoor vulnerability.

15. **Brute Force FTP Login**
    ```bash
    nmap --script ftp-brute -p 21 192.168.1.1
    ```
    - Attempts to brute force FTP login credentials.

Would you like me to add these commands to your **README** file? 🚀