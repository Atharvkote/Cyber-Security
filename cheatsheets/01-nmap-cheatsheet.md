#  NMAP CHEATSHEET

### (All-important commands in table + description format)


# 1. Basic Scan Commands

| Command                  | Description                                    |
| ------------------------ | ---------------------------------------------- |
| `nmap <target>`          | Default scan (top 1000 TCP ports).             |
| `nmap 192.168.1.0/24`    | Scan an entire subnet.                         |
| `nmap host1 host2 host3` | Scan multiple hosts.                           |
| `nmap -iL targets.txt`   | Load targets from a file.                      |
| `nmap -Pn <target>`      | Disable host discovery (treat host as online). |


# 2. Host Discovery (Ping Scanning)

| Command                       | Description                          |
| ----------------------------- | ------------------------------------ |
| `nmap -sn 192.168.1.0/24`     | Ping sweep (find live hosts).        |
| `nmap -PR -sn 192.168.1.0/24` | ARP discovery (fast, local network). |
| `nmap -PE -sn <target>`       | ICMP echo request discovery.         |
| `nmap -PP -sn <target>`       | ICMP timestamp ping.                 |
| `nmap -PS22,80 <target>`      | TCP SYN ping on specific ports.      |
| `nmap -PA22,80 <target>`      | TCP ACK ping.                        |
| `nmap -PU53 <target>`         | UDP ping.                            |
| `nmap -PO <target>`           | IP protocol ping.                    |


# 3. Scan Types (TCP/UDP)

| Command             | Description                        |
| ------------------- | ---------------------------------- |
| `nmap -sS <target>` | TCP SYN (stealth) scan.            |
| `nmap -sT <target>` | TCP Connect scan (no raw sockets). |
| `nmap -sU <target>` | UDP scan.                          |
| `nmap -sA <target>` | ACK scan (firewall rule mapping).  |
| `nmap -sW <target>` | Window scan.                       |
| `nmap -sM <target>` | Maimon scan.                       |
| `nmap -sN <target>` | Null scan.                         |
| `nmap -sF <target>` | FIN scan.                          |
| `nmap -sX <target>` | Xmas scan.                         |
| `nmap -sY <target>` | SCTP INIT scan.                    |
| `nmap -sZ <target>` | SCTP COOKIE-ECHO scan.             |
| `nmap -sO <target>` | IP protocol scan.                  |


# 4. Port Specification & Scan Options

| Command                         | Description                |
| ------------------------------- | -------------------------- |
| `nmap -p 80 <target>`           | Scan specific port.        |
| `nmap -p 1-1000 <target>`       | Scan a port range.         |
| `nmap -p- <target>`             | Scan all 65535 TCP ports.  |
| `nmap -F <target>`              | Fast scan (top 100 ports). |
| `nmap --top-ports 200 <target>` | Scan N top ports.          |
| `nmap --exclude-ports 22,80`    | Don’t scan listed ports.   |
| `nmap --open <target>`          | Show only open ports.      |


# 5. Service & Version Detection

| Command                          | Description                |
| -------------------------------- | -------------------------- |
| `nmap -sV <target>`              | Service/version detection. |
| `nmap -sV --version-light`       | Faster/light detection.    |
| `nmap -sV --version-all`         | Try all probes.            |
| `nmap --version-intensity <0-9>` | Control probe depth.       |


# 6. OS Detection & Traceroute

| Command                           | Description                          |
| --------------------------------- | ------------------------------------ |
| `nmap -O <target>`                | OS detection.                        |
| `nmap -O --osscan-guess <target>` | Guess OS when unsure.                |
| `nmap -A <target>`                | OS + version + traceroute + scripts. |
| `nmap --traceroute <target>`      | Trace network path.                  |


# 7. Timing & Performance

| Command           | Description                         |
| ----------------- | ----------------------------------- |
| `-T0`             | Paranoid (extremely slow).          |
| `-T1`             | Sneaky (stealthy).                  |
| `-T2`             | Polite.                             |
| `-T3`             | Normal (default).                   |
| `-T4`             | Aggressive (fast, noisy).           |
| `-T5`             | Insane (very fast, very noisy).     |
| `--min-rate 100`  | Send at least X packets per second. |
| `--max-rate 1000` | Limit packet rate.                  |
| `--scan-delay 1s` | Delay between probes.               |
| `--max-retries 3` | Limit retries.                      |


# 8. Firewall / IDS Evasion

| Command                          | Description                                        |
| -------------------------------- | -------------------------------------------------- |
| `nmap -f <target>`               | Fragment packets.                                  |
| `nmap --mtu 16 <target>`         | Set MTU to fragment packets.                       |
| `nmap -D RND:10 <target>`        | Decoy scanning.                                    |
| `nmap -S <spoofed-IP> <target>`  | Spoof source IP.                                   |
| `nmap --spoof-mac <vendor>`      | Spoof MAC address.                                 |
| `nmap --data-length 50 <target>` | Append random data for evasion.                    |
| `nmap --badsum <target>`         | Send bad checksums (firewalls accept, host drops). |
| `nmap --source-port 53 <target>` | Spoof source port (DNS/other trusted ports).       |

# 9. NSE (Nmap Scripting Engine)

## Running scripts

| Command                                   | Description                   |
| ----------------------------------------- | ----------------------------- |
| `nmap -sC <target>`                       | Default scripts (safe).       |
| `nmap --script vuln <target>`             | Vulnerability scripts.        |
| `nmap --script default <target>`          | Default scripts only.         |
| `nmap --script safe <target>`             | Safe scripts.                 |
| `nmap --script intrusive <target>`        | Aggressive/intrusive scripts. |
| `nmap --script auth <target>`             | Authentication scripts.       |
| `nmap --script discovery <target>`        | Enumeration scripts.          |
| `nmap --script exploit <target>`          | Exploit scripts.              |
| `nmap --script "default,vuln" <target>`   | Run multiple categories.      |
| `nmap --script http-title -p 80 <target>` | Run single script.            |


## NSE arguments

| Command                                    | Description                 |
| ------------------------------------------ | --------------------------- |
| `--script-args 'user=admin,pass=password'` | Script arguments.           |
| `--script-args-file args.txt`              | Load script args from file. |


# 10. Script Categories (Full Coverage)

| Category  | Description                         |
| --------- | ----------------------------------- |
| auth      | Authentication & credential checks  |
| broadcast | Network discovery broadcast scripts |
| brute     | Brute-force authentication          |
| default   | Safe useful scripts                 |
| discovery | Information gathering               |
| exploit   | Exploit vulnerabilities             |
| external  | External web lookups                |
| fuzzer    | Fuzzing for input issues            |
| intrusive | High-risk scripts                   |
| malware   | Malware detection                   |
| safe      | Safe, non-intrusive                 |
| version   | Used for version detection          |
| vuln      | Vulnerability identification        |


# 11. IPv6 Scanning

| Command                                    | Description            |
| ------------------------------------------ | ---------------------- |
| `nmap -6 <target>`                         | IPv6 scan.             |
| `nmap -6 -sT <target>`                     | IPv6 TCP scan.         |
| `nmap -6 -sU <target>`                     | IPv6 UDP scan.         |
| `nmap -6 --script ipv6-node-info <target>` | IPv6 info enumeration. |


# 12. Output & Reporting

| Command                        | Description                        |
| ------------------------------ | ---------------------------------- |
| `nmap -oN file.nmap <target>`  | Normal output.                     |
| `nmap -oX file.xml <target>`   | XML output.                        |
| `nmap -oG file.gnmap <target>` | Grepable output.                   |
| `nmap -oA base <target>`       | All formats (.nmap, .xml, .gnmap). |
| `nmap -v <target>`             | Verbose.                           |
| `nmap -vv <target>`            | Extra verbose.                     |


# 13. Packet Manipulation (Advanced)

| Command                | Description                |
| ---------------------- | -------------------------- |
| `--data-length 64`     | Append random data.        |
| `--data-string "text"` | Insert custom payload.     |
| `--ttl <value>`        | Set TTL value.             |
| `--ip-options <opt>`   | Add custom IP options.     |
| `--badsum`             | Send bad checksum packets. |


# 14. Debugging + Trace Options

| Command                 | Description                             |
| ----------------------- | --------------------------------------- |
| `nmap -v`               | Verbose.                                |
| `nmap -vv`              | Extra verbose.                          |
| `nmap --packet-trace`   | Show all packets sent/received.         |
| `nmap --reason`         | Explain why a port is in a given state. |
| `nmap --stats-every 5s` | Show progress updates.                  |
| `nmap -d`               | Debug mode.                             |
| `nmap -d2`              | More debugging.                         |
| `nmap -d9`              | Maximum debugging.                      |


# 15. Post-Scan Processing

| Command                                         | Description          |
| ----------------------------------------------- | -------------------- |
| `grep "open" scan.gnmap`                        | Find open ports.     |
| `awk '/Nmap scan report/{print $NF}' scan.nmap` | Extract host list.   |
| `xsltproc scan.xml -o scan.html`                | Convert XML to HTML. |

