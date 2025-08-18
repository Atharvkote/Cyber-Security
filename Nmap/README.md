<p align="center">
    <img height="350"  src="../.git-config/Nmap.png" alt="img">
</p>

#  Nmap - Scanning, Enumeration, Firewall Evasion, and Outputs

Nmap (Network Mapper) is the most popular tool for **network discovery, enumeration, vulnerability detection, and firewall/IDS evasion**.
This guide covers **scan types, options, scripts, evasion techniques, and detailed outputs**.


##  Basic Nmap Syntax

```bash
nmap [Scan Type(s)] [Options] <target>
```

Examples:

```bash
nmap -sS -p- 192.168.1.1
nmap -A -T4 10.10.10.5
nmap -sU -p 53 192.168.56.101
```

---

##  Scan Options Explained (with Output Examples)

| Option           | Description                                                                                                           | Example                          | Sample Output                                                                     |                      
| ---------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------------- |
| **-sS**          | TCP SYN scan (stealth scan). Sends SYN packet, waits for SYN/ACK (open) or RST (closed). Does not complete handshake. | `nmap -sS 192.168.1.1`           | `PORT   STATE SERVICE 22/tcp open  ssh 80/tcp open  http`                         |                      |
| **-sT**          | TCP Connect scan. Completes the 3-way handshake (less stealthy).                                                      | `nmap -sT 192.168.1.1`           | `PORT   STATE SERVICE 21/tcp open  ftp 23/tcp open  telnet`                       |                      |
| **-sU**          | UDP scan. Detects services like DNS, SNMP, NTP.                                                                       | `nmap -sU -p 53,161 192.168.1.1` |  `PORT   STATE SERVICE 53/udp open domain 161/udp open filtered snmp` |
| **-sF**          | TCP FIN scan. Sends FIN flag only. Useful against stateless firewalls.                                                | `nmap -sF 192.168.1.1`           | `PORT   STATE SERVICE 139/tcp closed netbios-ssn 445/tcp open   microsoft-ds`     |                      |
| **-sN**          | TCP NULL scan. Sends packet with **no flags**. Detects open ports on non-RFC-compliant stacks.                        | `nmap -sN 192.168.1.1`           | `PORT   STATE SERVICE 80/tcp open  http`                                          |                      |
| **-sX**          | Xmas scan. Sends FIN+URG+PSH flags (lights up like a “Christmas tree”).                                               | `nmap -sX 192.168.1.1`           | `PORT   STATE SERVICE 25/tcp open  smtp`                                          |                      |
| **-p-**          | Scan **all 65,535 ports**.                                                                                            | `nmap -sS -p- 192.168.1.1`       | `Scanned 65535 ports, 10 open found`                                              |                      |
| **-p <range>**   | Scan specific ports or ranges.                                                                                        | `nmap -p 20-80,443 192.168.1.1`  | `21/tcp open ftp 22/tcp open ssh 80/tcp open http 443/tcp open https`             |                      |
| **-v**           | Verbose output. `-vv` = extra details.                                                                                | `nmap -sS -v 192.168.1.1`        | `Initiating SYN Stealth Scan... Discovered open port 22/tcp on 192.168.1.1`       |                      |
| **-O**           | OS detection (TCP/IP fingerprinting).                                                                                 | `nmap -O 192.168.1.1`            | `Running: Linux 3.X OS details: Linux 3.2 - 3.16`                                 |                      |
| **-A**           | Aggressive scan: includes OS detection, version detection, script scanning, traceroute.                               | `nmap -A 192.168.1.1`            | `PORT 22/tcp open ssh OpenSSH 7.2p2 OS: Linux Kernel 4.4 Traceroute: Hops: 3`     |                      |
| **-T<0-5>**      | Timing template. <br>0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane.                                | `nmap -sS -T4 192.168.1.1`       | `Scanning completed in 12.43s (fast)`                                             |                      |
| **-f**           | Fragment packets (firewall evasion).                                                                                  | `nmap -sS -f 192.168.1.1`        | `Packets fragmented, evading simple firewalls`                                    |                      |
| **-D RND:10**    | Use 10 random **decoys** to hide source.                                                                              | `nmap -sS -D RND:10 192.168.1.1` | `Nmap scan report for target ... Source disguised with decoys`                    |                      |
| **--traceroute** | Show route packets take to reach host.                                                                                | `nmap --traceroute 192.168.1.1`  | `TRACEROUTE (using port 22/tcp) Hop 1: 192.168.1.1 Hop 2: 10.0.0.1 Hop 3: Target` |                      |

---

## Output Formats

| Command              | Description                                        |
| -------------------- | -------------------------------------------------- |
| `-oN filename.txt`   | Save output in **normal text** format.             |
| `-oX filename.xml`   | Save output in **XML format** (import into tools). |
| `-oG filename.gnmap` | Save in **grepable format** (for scripting).       |
| `-oA prefix`         | Save in **all formats** at once.                   |

Example:

```bash
nmap -sV -O -p 1-1000 -oA fullscan 192.168.1.1
```

Creates:

* `fullscan.nmap`
* `fullscan.xml`
* `fullscan.gnmap`

-
## Firewall & IDS/IPS Evasion Techniques

### Fragmented Packets

```bash
nmap -sS -f 192.168.1.1
```

Breaks packets into smaller fragments to bypass firewalls that inspect headers.

### Decoy Scans

```bash
nmap -sS -D RND:10 192.168.1.1
```

Launches scan with **decoys** to hide true attacker IP.

### Slow Scans (Avoid IDS detection)

```bash
nmap -sS -T2 192.168.1.1
```

Reduces packet rate to avoid detection.


## NSE (Nmap Scripting Engine) Examples

###  Service Enumeration

* **Banner grabbing**

```bash
nmap -sV --script=banner 192.168.1.1
```

* **Web server info**

```bash
nmap -p 80 --script=http-enum 192.168.1.1
```

###  Vulnerability Scans

* **Heartbleed**

```bash
nmap -p 443 --script ssl-heartbleed -v 192.168.1.1
```

* **EternalBlue (MS17-010)**

```bash
nmap -p 445 --script smb-vuln-ms17-010 -v 192.168.1.1
```


##  Enumeration Techniques

1. **NetBIOS (137-139,445)**

```bash
nmap -p 137-139,445 --script nbstat 192.168.1.1
```

 Gets hostname, domain, shared folders.


2. **SNMP (161,162/UDP)**

```bash
nmap -sU -p 161,162 --script snmp-info 192.168.1.1
```

 Reveals SNMP system info.

---

3. **LDAP (389/TCP)**

```bash
nmap -sT -p 389 --script ldap-search 192.168.1.1
```

 Extracts users, groups, emails.



4. **NTP (123/UDP)**

```bash
nmap -sU -p 123 --script ntp-info 192.168.1.1
```

 Server version & details.


5. **SMTP (25,465/TCP)**

```bash
nmap -sT -p 25,465 --script smtp-enum-users 192.168.1.1
```

Finds valid email users.

6. **DNS (53/TCP+UDP)**

```bash
nmap -sT -sU -p 53 --script=dns-recursion,dns-zone-transfer 192.168.1.1
```

 Subdomains, internal IPs.

##  Real-World Example: Metasploitable2 Scan

```bash
nmap -sS -A -p- -T4 192.168.56.101
```

**Output (trimmed):**

```plaintext
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 4.7
23/tcp   open  telnet
25/tcp   open  smtp    Postfix smtpd
80/tcp   open  http    Apache httpd 2.2.8
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql   MySQL 5.0.51a
```

 Shows multiple **known-vulnerable services** (FTP backdoor, old SSH, MySQL, etc.).


##  Summary Table (Cheat Sheet)

| Option            | Use Case                                 |
| ----------------- | ---------------------------------------- |
| `-sS`             | Stealthy SYN scan                        |
| `-sT`             | Full connect scan                        |
| `-sU`             | UDP service discovery                    |
| `-sF / -sN / -sX` | Firewall/IDS evasion                     |
| `-p-`             | Scan all ports                           |
| `-O`              | OS detection                             |
| `-A`              | Aggressive scan (OS + version + scripts) |
| `-T0` → `-T5`     | Scan speed/stealth balance               |
| `-f`              | Fragment packets to evade firewalls      |
| `-D`              | Hide source with decoys                  |
| `--traceroute`    | Map route to target                      |
| `-oA`             | Save output in all formats               |
