<p align="center">
    <img src="../.git-config/Nmap.png" alt="Nmap Logo" height="120">
</p>

# Nmap Complete Guide – From Basics to Advanced

This README is a **complete guide to Nmap**, covering everything from basic scans to advanced evasion, NSE scripting, and real-world labs (Metasploitable2).  
It is structured for both **beginners and advanced penetration testers**.


## Table of Contents

- [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet)
- [Introduction](#introduction)
- [Basic Scan Types](#basic-scan-types)
- [Port Scanning Options](#port-scanning-options)
- [Service and Version Detection](#service-and-version-detection)
- [OS Detection](#os-detection)
- [Timing & Performance](#timing--performance)
- [Firewall & IDS Evasion](#firewall--ids-evasion)
- [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
- [Output Formats](#output-formats)
- [Enumeration Techniques](#enumeration-techniques)
- [Mermaid Diagram – Nmap Scan Flow](#mermaid-diagram--nmap-scan-flow)
- [Real-World Lab Walkthrough (Metasploitable2)](#real-world-lab-walkthrough-metasploitable2)
- [Best Practices & Common Mistakes](#best-practices--common-mistakes)
- [References](#references)


## Quick Reference Cheat Sheet

| Goal | Command |
|--|---|
| Ping Scan (discover live hosts) | `nmap -sn 192.168.1.0/24` |
| Scan single target | `nmap 192.168.1.10` |
| Scan range of IPs | `nmap 192.168.1.1-50` |
| TCP SYN (stealth) scan | `nmap -sS 192.168.1.10` |
| UDP scan | `nmap -sU 192.168.1.10` |
| Service version detection | `nmap -sV 192.168.1.10` |
| Aggressive scan (OS, version, scripts, traceroute) | `nmap -A 192.168.1.10` |
| Save output to file | `nmap -oN result.txt 192.168.1.10` |
| Run vuln scripts | `nmap --script vuln 192.168.1.10` |


## Introduction

Nmap (**Network Mapper**) is a free and open-source tool for:
- Network discovery
- Port scanning
- Service/version detection
- OS fingerprinting
- Vulnerability scanning (via NSE)

It is used by:
- Network administrators (auditing security, checking firewalls)
- Penetration testers (finding open services & weak points)
- Hackers/CTF players (enumeration in attack chains)



## Basic Scan Types

| Option | Description            | Example                 |
| --- | --- | --- |
| `-sS`  | TCP SYN (stealth scan) | `nmap -sS 192.168.1.10` |
| `-sT`  | TCP connect scan       | `nmap -sT 192.168.1.10` |
| `-sU`  | UDP scan               | `nmap -sU 192.168.1.10` |
| `-sF`  | FIN scan               | `nmap -sF 192.168.1.10` |
| `-sX`  | Xmas scan              | `nmap -sX 192.168.1.10` |
| `-sN`  | Null scan              | `nmap -sN 192.168.1.10` |

## Port Scanning Options

Port scanning is the **core function of Nmap**, used to identify which services (applications) are listening on a target system. Different scanning modes give flexibility depending on whether you want **speed, stealth, or completeness**.

### 1. Scan All 65,535 Ports

```bash
nmap -p- 192.168.1.10
```

* Scans **every TCP port** (1–65535).
* Useful when looking for **non-standard services** (e.g., SSH on port 2222, custom web apps).
* Slower than default scans, especially on large networks.
* Common for **penetration tests** where attackers can’t assume services are only on standard ports.



### 2. Scan Specific Ports

```bash
nmap -p 21,22,80,443 192.168.1.10
```

* Targets **only the ports listed**.
* Faster, because it skips irrelevant ports.
* Example use cases:

  * Check if **SSH (22)** or **FTP (21)** is open.
  * Verify if **web services (80/443)** are running.
* Useful for **focused troubleshooting** or **compliance checks**.



### 3. Top 1000 Ports (Default)

```bash
nmap 192.168.1.10
```

* Nmap’s **default scan behavior**.
* Scans the **most common 1000 ports** (based on frequency data collected by Nmap project).
* Balances **speed and coverage**.
* Good for **initial reconnaissance** to get a quick overview of a target.



### 4. Aggressive Scan (Comprehensive)

```bash
nmap -A 192.168.1.10
```

* Performs a **detailed scan**, including:

  * OS detection
  * Service version detection
  * Default NSE scripts
  * Traceroute
* Very **informative**, but:

  * Slower than other scans
  * **Noisy** (easy to detect by firewalls/IDS)
* Best for **in-depth analysis** after initial reconnaissance.
Perfect — just like we did for **Port Scanning Options**, let’s expand **Service & Version Detection** into a **numbered set of 3 options** (normal, specific intensity, and aggressive). Here’s the improved version:


## Service and Version Detection

Port scanning tells you *which ports are open*, but **service detection** tells you *what’s actually running* on those ports (e.g., Apache vs. Nginx, OpenSSH vs. Dropbear). This helps identify **software, versions, and potential vulnerabilities**.


### 1. Basic Service Detection

```bash
nmap -sV 192.168.1.10
```

* Detects **applications** behind open ports.
* Example:

  * Port 22 → `OpenSSH 8.2`
  * Port 80 → `Apache httpd 2.4.49`
* Very useful for **enumeration** during penetration tests.


### 2. Custom Version Intensity

```bash
nmap -sV --version-intensity 5 192.168.1.10
```

* Controls **how deep Nmap probes** for version info (scale: `0–9`).

  * `0` → Lightest (fewer probes, faster, less accurate).
  * `5` → Balanced (default).
  * `9` → Most aggressive (tries all probes, slower).
* Helpful when you want to **fine-tune speed vs. accuracy**.


### 3. Aggressive Version Detection

```bash
nmap -sV --version-intensity 9 192.168.1.10
```

* Uses the **highest probe intensity**.
* Provides **very accurate detection** of obscure services.
* Drawbacks:

  * **Slower**
  * **Noisy** (easier for firewalls/IDS to detect)
* Best for **deep analysis** when stealth is not required.
Got it 👍 Let’s rewrite both **OS Detection** and **Timing & Performance** in the same **3-option structured style** (like we did for Ports and Services). This keeps everything uniform and easy to revise.


##  OS Detection

OS detection attempts to **guess the target’s operating system** based on TCP/IP stack fingerprints. Accuracy depends on open ports, network conditions, and fingerprint database.


### 1. Basic OS Detection

```bash
nmap -O 192.168.1.10
```

* Tries to identify the **operating system** (Linux, Windows, BSD, etc.).
* Accuracy increases when **multiple open ports** are found.


### 2. With Version & Traceroute (Aggressive)

```bash
nmap -A 192.168.1.10
```

* Combines multiple features:

  * **OS detection (-O)**
  * **Version detection (-sV)**
  * **NSE default scripts (-sC)**
  * **Traceroute (--traceroute)**
* Great for **in-depth enumeration**, but noisy.


### 3. Verbose OS Fingerprinting

```bash
nmap -O --osscan-guess 192.168.1.10
```

* If Nmap is unsure, it **makes an educated guess** about the OS.
* Useful when standard detection fails.
* May result in **false positives**.


##  Timing & Performance

Nmap timing controls let you balance **speed vs. stealth**. Templates range from `-T0` (paranoid) to `-T5` (insane).


### 1. Slow & Stealthy Scan

```bash
nmap -T1 192.168.1.10
```

* Very slow, but avoids triggering IDS/IPS.
* Best when **stealth is critical**.


### 2. Default Balanced Scan

```bash
nmap -T3 192.168.1.10
```

* The **default template**.
* Balances **speed and accuracy**.
* Good for general scans.


### 3. Fast & Aggressive Scan

```bash
nmap -T5 192.168.1.10
```

* Extremely fast but **very noisy**.
* Likely to trigger **firewalls & IDS alerts**.
* Best when **speed matters more than stealth**.


| Timing Template | Speed      | Stealth            |
| --------------- | ---------- | ------------------ |
| `-T0`           | Paranoid   | Very stealthy      |
| `-T1`           | Sneaky     | Stealthy           |
| `-T3`           | Default    | Balanced           |
| `-T4`           | Aggressive | Fast, less stealth |
| `-T5`           | Insane     | Fast but noisy     |



## Nmap Scripting Engine (NSE)

The **Nmap Scripting Engine (NSE)** allows Nmap to go beyond simple port scanning. It uses **Lua scripts** to automate tasks like service enumeration, vulnerability detection, and brute forcing.

### Categories of NSE Scripts

* **default** → Runs commonly useful scripts (service detection, version info).
* **safe** → Scripts that won’t crash or harm the target.
* **intrusive** → May affect the target (e.g., brute-force, DoS-like behavior).
* **vuln** → Looks for known vulnerabilities.
* **auth** → Checks authentication methods (e.g., weak creds).
* **discovery** → Gathers info about networks/services.
* **exploit** → Attempts to actively exploit vulnerabilities.

### Examples

* Run **default scripts** (like banner grabbing, OS detection):

```bash
nmap -sC 192.168.1.10
```

* Run **vulnerability detection** scripts:

```bash
nmap --script vuln 192.168.1.10
```

* Run scripts from **multiple categories**:

```bash
nmap --script "default,safe" 192.168.1.10
```

* Run a **specific script**, e.g., to fetch website titles:

```bash
nmap --script http-title -p 80 192.168.1.10
```


## Output Formats

When scanning, storing results properly is important for later analysis and reporting. Nmap supports multiple output formats:

| Format       | Command                              | Use Case                                                                              |
| -- | -- | - |
| **Normal**   | `nmap -oN result.txt 192.168.1.10`   | Human-readable summary.                                                               |
| **XML**      | `nmap -oX result.xml 192.168.1.10`   | For parsing with tools (like Metasploit, Nessus, or custom scripts).                  |
| **Grepable** | `nmap -oG result.gnmap 192.168.1.10` | Useful for quickly extracting IPs/ports with grep/awk.                                |
| **All**      | `nmap -oA result 192.168.1.10`       | Saves in **all three formats** at once (`result.nmap`, `result.xml`, `result.gnmap`). |

### Example Workflow:

1. Run scan with all outputs:

   ```bash
   nmap -sV -oA scan_results 192.168.1.0/24
   ```
2. Use `grep` on `.gnmap` to filter open ports:

   ```bash
   grep "80/open" scan_results.gnmap
   ```
3. Import `.xml` into security tools for visualization/reporting.

## Enumeration Techniques in Nmap

Enumeration is the process of **extracting detailed information about services, users, shares, and configurations** from a target system after identifying open ports. These techniques are essential in penetration testing and red teaming because they provide the **blueprint of the network** before exploitation.


## 1. NetBIOS Enumeration (137–139, 445/TCP)

**Purpose:**
NetBIOS (Network Basic Input/Output System) provides network communication services for Windows systems. It is used for **file sharing, printer sharing, and name resolution**. Attackers use NetBIOS enumeration to gather details about **hostnames, domains, shares, and logged-in users**.

**Common Ports:**

* 137 (NetBIOS Name Service)
* 138 (NetBIOS Datagram Service)
* 139 (NetBIOS Session Service)
* 445 (Direct SMB over TCP)

**What You Can Discover:**

* Hostname and domain
* Workgroup/Domain information
* Shared folders & drives
* Logged-in users
* Potential weak SMB configurations

**Nmap Command:**

```bash
nmap -p 137-139,445 --script nbstat 192.168.1.1
```


## 2. SNMP Enumeration (161/162 UDP)

**Purpose:**
SNMP (Simple Network Management Protocol) is used for managing devices like **routers, switches, servers, and printers**. If misconfigured with default community strings (`public` or `private`), attackers can retrieve **sensitive system information**.

**Common Ports:**

* 161/UDP (SNMP queries)
* 162/UDP (SNMP traps)

**What You Can Discover:**

* System details (hostname, OS, uptime)
* Network interfaces
* Running processes
* Routing tables
* Community strings (often left as default!)
* Hardware details (CPU, memory, disk usage)

**Nmap Command:**

```bash
nmap -sU -p 161,162 --script snmp-info 192.168.1.1
```


## 3. LDAP Enumeration (389/TCP)

**Purpose:**
LDAP (Lightweight Directory Access Protocol) is used in **Active Directory (AD)** environments to query directory services. Attackers use LDAP enumeration to gather information about **users, groups, computers, and policies**.

**Common Ports:**

* 389 (LDAP plaintext)
* 636 (LDAP over SSL - LDAPS)
* 3268 (Global Catalog for AD)
* 3269 (Global Catalog over SSL)

**What You Can Discover:**

* User accounts and groups
* Email addresses
* Password policies
* Domain structure
* Computer objects

**Nmap Command:**

```bash
nmap -sT -p 389 --script ldap-search 192.168.1.1
```


## 4. NTP Enumeration (123/UDP)

**Purpose:**
NTP (Network Time Protocol) synchronizes time across network devices. Misconfigured NTP servers can leak **internal details about network devices**.

**Common Port:**

* 123/UDP

**What You Can Discover:**

* System time (useful for Kerberos attacks in AD)
* NTP server details
* Peers & upstream servers
* OS and device information (sometimes revealed in responses)

**Nmap Command:**

```bash
nmap -sU -p 123 --script ntp-info 192.168.1.1
```


## 5. SMTP Enumeration (25, 465, 587/TCP)

**Purpose:**
SMTP (Simple Mail Transfer Protocol) is used for email delivery. Many mail servers allow **user enumeration** through poorly configured responses.

**Common Ports:**

* 25 (SMTP plaintext)
* 465 (SMTPS - deprecated)
* 587 (SMTP with TLS)

**What You Can Discover:**

* Valid email addresses
* Usernames (for later brute-force/credential attacks)
* Mail server banner (software version)

**Techniques Used:**

* **VRFY** → Verify if a user exists.
* **EXPN** → Expand mailing lists.
* **RCPT TO** → Test for valid users.

**Nmap Command:**

```bash
nmap -sT -p 25,465 --script smtp-enum-users 192.168.1.1
```


## 6. DNS Enumeration (53/TCP & UDP)

**Purpose:**
DNS (Domain Name System) resolves domain names to IP addresses. Attackers use DNS enumeration to gather information about a **target organization’s infrastructure**.

**Common Ports:**

* 53/TCP
* 53/UDP

**What You Can Discover:**

* Subdomains (`www`, `mail`, `ftp`, etc.)
* Internal IP addresses
* Zone transfers (if misconfigured)
* Caching servers and recursive queries
* Email & mail exchange servers (MX records)

**Nmap Command:**

```bash
nmap -sT -sU -p 53 --script=dns-recursion,dns-zone-transfer 192.168.1.1
```


## Summary Table

| Service         | Ports       | Info Gathered                      | Risk                                    |
|  | -- | - |  |
| **NetBIOS/SMB** | 137-139,445 | Hostnames, shares, users           | High (data leakage, SMB exploits)       |
| **SNMP**        | 161/162 UDP | System info, processes, interfaces | High (default community strings common) |
| **LDAP**        | 389/636     | Users, groups, domain policies     | Critical (AD enumeration)               |
| **NTP**         | 123/UDP     | System time, peers, OS hints       | Medium                                  |
| **SMTP**        | 25,465,587  | Valid users, server banner         | Medium (phishing/brute force)           |
| **DNS**         | 53/TCP+UDP  | Subdomains, zone transfers, IPs    | High (network mapping)                  |


## **Real-World Lab Walkthrough (Metasploitable)**

**Target:** Metasploitable2 (IP: `192.168.56.101`)

### Step 1 – Host discovery

```bash
nmap -sn 192.168.56.0/24
```

### Step 2 – Port scan

```bash
nmap -sS -p- 192.168.56.101
```

### Step 3 – Service detection

```bash
nmap -sV 192.168.56.101
```

### Step 4 – Run vuln scripts

```bash
nmap --script vuln 192.168.56.101
```


## Best Practices & Common Mistakes

### Best Practices

* Use `-sS` (SYN scan) for stealth and speed.
* Always save results (`-oA`) for later analysis.
* Use NSE scripts to automate enumeration.
* Start with `-T3` (default) before moving to aggressive timing.
* Verify results manually; don’t rely only on Nmap.

### Common Mistakes

* Running `-A` blindly (too noisy, may crash weak services).
* Forgetting UDP (`-sU`) — many services (DNS, SNMP) use UDP.
* Misinterpreting `filtered` ports (means firewall, not closed).
* Scanning without permission (illegal, may trigger IDS).
* Assuming “closed” = “safe” (could change anytime).


## References

* [Nmap Official Guide](https://nmap.org/book/)
* [Nmap Cheat Sheet](https://nmap.org/book/man.html)
* [SANS Penetration Testing with Nmap](https://pen-testing.sans.org/tools/nmap/)


```
That's Nmap For You!
```
