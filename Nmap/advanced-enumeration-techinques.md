# Nmap 

## Introduction

Nmap (Network Mapper) is a powerful open-source tool used for network discovery, port scanning, service enumeration, and vulnerability detection. It is widely used by system administrators and penetration testers to audit network security.

---

## Common Nmap Options and Their Descriptions

| Option              | Description                                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| `-sS`               | TCP SYN scan (stealth scan). Sends SYN packets without completing the handshake, making it less detectable. |
| `-sT`               | TCP connect scan. Completes the full 3-way handshake. Easier to detect by firewalls and IDS.                |
| `-sU`               | UDP scan. Useful for detecting services like DNS, SNMP, NTP. Slower than TCP scans.                         |
| `-sF`               | TCP FIN scan. Sends FIN flag to detect open ports (stealthy against some firewalls).                        |
| `-sN`               | TCP NULL scan. Sends packet with no flags set to probe for open ports.                                      |
| `-sX`               | Xmas scan. Sends packet with FIN, URG, and PSH flags set. Used to identify open ports.                      |
| `-p-`               | Scans all 65,535 ports.                                                                                     |
| `-p <range>`        | Scan specific ports or ranges (e.g., `-p 20-100,443`).                                                      |
| `-v`                | Verbose output (use `-vv` for even more detailed output).                                                   |
| `-O`                | OS detection. Attempts to identify the target’s operating system.                                           |
| `-A`                | Aggressive scan. Includes OS detection, version detection, script scanning, and traceroute.                 |
| `-T<0-5>`           | Timing template (0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane).                         |
| `-f`                | Packet fragmentation (used for firewall evasion). Splits packets into smaller fragments.                    |
| `-D RND:<n>`        | Use random decoys to obfuscate the real scan source. Example: `-D RND:10`.                                  |
| `--traceroute`      | Performs traceroute to determine the path to the target.                                                    |
| `-sV`               | Version detection. Identifies running services and versions.                                                |
| `--script=<script>` | Runs NSE (Nmap Scripting Engine) scripts for vulnerability detection and enumeration.                       |

---

## Nmap Output Formats

* Normal output: `-oN filename.txt`
* XML output: `-oX filename.xml`
* Grepable output: `-oG filename.txt`
* All formats: `-oA basename`

---

## Example Scans with Outputs

### 1. TCP SYN Scan

```bash
nmap -sS 192.168.1.10
```

**Output (sample):**

```
Starting Nmap 7.93 at 2025-08-18 16:30 IST
Nmap scan report for 192.168.1.10
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Explanation: Shows open SSH and HTTP ports using stealth SYN scan.

---

### 2. Full Port Scan

```bash
nmap -p- 192.168.1.10
```

Scans all 65,535 ports. Useful for comprehensive discovery.

---

### 3. OS and Version Detection

```bash
nmap -sV -O --osscan-guess -p 1-1000 192.168.1.10
```

**Output (sample):**

```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 4.7p1
80/tcp   open  http    Apache httpd 2.2.8
Device type: general purpose
Running: Linux 2.6.X
OS details: Linux 2.6.9 - 2.6.33
```

---

### 4. Detecting Firewalls and IDS

```bash
nmap -sS -D RND:10 -f -T2 192.168.1.10
```

* `-D RND:10`: Adds 10 random decoy IPs.
* `-f`: Fragmented packets to bypass firewalls.
* `-T2`: Slows scan to avoid triggering IDS.

---

### 5. Firewall Evasion with Fragmentation

```bash
nmap -f 192.168.1.10
```

Sends fragmented packets, making detection harder.

---

### 6. Traceroute

```bash
nmap --traceroute -T2 192.168.1.10
```

Shows the path packets take to reach the target.

---

### 7. Aggressive Scan

```bash
nmap -A 192.168.1.10
```

Performs OS detection, version detection, script scanning, and traceroute in one scan.

---

### 8. Vulnerability Scans

* Heartbleed vulnerability on port 443:

```bash
nmap -p 443 --script ssl-heartbleed -v 192.168.1.10
```

* EternalBlue (MS17-010) SMB vulnerability on port 445:

```bash
nmap -p 445 --script smb-vuln-ms17-010 -v 192.168.1.10
```

---

### 9. Banner Grabbing

```bash
nmap -sV --script=banner 192.168.1.10
```

Retrieves service banners to identify running software.

---

### 10. Web Server Enumeration

```bash
nmap -p 80 --script=http-enum 192.168.1.10
```

Finds hidden files, directories, and applications on the web server.

---

## Enumeration Techniques with Nmap Scripts

1. **NetBIOS Enumeration (Ports 137-139, 445)**

```bash
nmap -p 137-139,445 --script nbstat 192.168.1.10
```

Reveals domain name, host name, and shared folders.

---

2. **SNMP Enumeration (UDP Ports 161,162)**

```bash
nmap -sU -p 161,162 --script snmp-info 192.168.1.10
```

Provides SNMP system information such as device details.

---

3. **LDAP Enumeration (Port 389)**

```bash
nmap -sT -p 389 --script ldap-search 192.168.1.10
```

Retrieves group information, user accounts, and email addresses.

---

4. **NTP Enumeration (UDP Port 123)**

```bash
nmap -sU -p 123 --script ntp-info 192.168.1.10
```

Finds NTP server details such as time and software version.

---

5. **SMTP Enumeration (Ports 25, 465)**

```bash
nmap -sT -p 25,465 --script smtp-enum-users 192.168.1.10
```

Enumerates valid email addresses and user accounts.

---

6. **DNS Enumeration (Port 53, TCP/UDP)**

```bash
nmap -sT -sU -p 53 --script=dns-recursion,dns-zone-transfer 192.168.1.10
```

Performs subdomain enumeration, zone transfers, and DNS information gathering.

---

## Conclusion

Nmap is not only a port scanner but a complete network reconnaissance tool. Its ability to perform stealth scans, evade firewalls, identify operating systems, enumerate services, and detect vulnerabilities makes it indispensable for penetration testing and security auditing.

