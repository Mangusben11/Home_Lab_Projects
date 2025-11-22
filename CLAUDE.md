# CLAUDE.md - Home Lab Projects Context File

> **Purpose**: This file serves as persistent memory for Claude Code sessions, providing context about the project structure, learning objectives, and conventions for Windows security education.

---

## Project Overview

**Student:** Benjamina
**Institution:** DVC Computer Science
**Focus:** Windows Security, Ethical Hacking, and Penetration Testing
**Environment:** WSL2 on Windows with VMware virtualization lab
**Project Start:** November 2024

This repository is a structured learning environment for developing cybersecurity skills with emphasis on:
- Windows system administration and security hardening
- Active Directory attack and defense techniques
- Ethical penetration testing methodology
- Blue team detection and response capabilities

---

## Lab Environment

### Host System
- **OS:** Windows with WSL2 (Linux 6.6.87.2-microsoft-standard-WSL2)
- **Hypervisor:** VMware Workstation
- **Working Directory:** `/mnt/c/Users/Ben/Desktop/cs_research.clude/Home_Lab_Projects`

### Virtual Machines

| Machine | OS | Role | Domain Status | Purpose |
|---------|-----|------|---------------|---------|
| Kali Linux | Kali Linux | Attacker | N/A | Primary penetration testing platform |
| Windows Server 2022 | Windows Server | Domain Controller | AD ACTIVATED | Active Directory Domain Controller - central authentication |
| Windows 11 | Windows 11 | Domain Client | JOINED | Modern Windows client - AD attacks, lateral movement |
| Ubuntu Linux | Ubuntu Desktop | Domain Client | JOINED | Linux AD integration, cross-platform attacks |
| Ubuntu Server | Ubuntu Server | Domain Client | JOINED | Server-side Linux AD integration |
| Linux Mint | Linux Mint | Standalone/TBD | NOT JOINED (?) | Reverse engineering, potential future domain member |

### Network Configuration
- **Network Type:** VMware Workstation virtual network (VMnet10 - Lab Network)
- **Network Segment:** 192.168.10.0/24
- Lab networks should be isolated (Host-Only or NAT with no internet for targets)
- Attacker machine may have NAT for tool updates
- All domain-joined machines communicate with Windows Server 2022 DC

#### IP Address Assignments
| IP Address | Hostname | Role | Notes |
|------------|----------|------|-------|
| 192.168.10.10 | WIN-LUAK1VFNJ8D | Domain Controller | Windows Server 2022, lab.local DC |
| 192.168.10.11 | (TBD) | Domain Client | Windows 11, domain-joined |
| 192.168.10.40 | (TBD) | Linux Client | Ubuntu, SSH open |
| 192.168.10.50 | kali | Attacker | Kali Linux, static IP |

#### Kali Network Commands
```bash
# Set static IP (temporary)
sudo ip addr add 192.168.10.50/24 dev eth0

# Make IP persistent with nmcli
nmcli con mod "Wired connection 1" ipv4.addresses 192.168.10.50/24
nmcli con mod "Wired connection 1" ipv4.gateway 192.168.10.1
nmcli con mod "Wired connection 1" ipv4.method manual
nmcli con up "Wired connection 1"

# Configure DNS to use Domain Controller
echo "nameserver 192.168.10.10" | sudo tee /etc/resolv.conf
```

### Active Directory Configuration
- **Domain Controller:** Windows Server 2022
- **Domain Name:** lab.local
- **DC Hostname:** WIN-LUAK1VFNJ8D
- **Domain Status:** ACTIVE AND OPERATIONAL
- **Domain-Joined Clients:** Windows 11, Ubuntu Linux, Ubuntu Server
- **Pending:** Linux Mint (status to be confirmed)

#### Domain Controller Services (Verified)
| Port | Service | Status |
|------|---------|--------|
| 53 | DNS | Active |
| 88 | Kerberos | Active |
| 389 | LDAP | Active |
| 445 | SMB | Active (Signing Required) |
| 3268 | Global Catalog | Active |

**Security Note:** SMB signing is required on the DC, which prevents SMB relay attacks.

---

## Learning Roadmap Summary

### Current Phase: Active Directory Attack and Defense (READY FOR ADVANCED EXERCISES)

**Phase 1 - Foundations (IN PROGRESS)**
- [ ] Networking fundamentals (TCP/IP, OSI, common ports)
- [ ] Linux command line proficiency
- [ ] Python scripting for automation
- [ ] PowerShell for Windows environments

**Phase 2 - Core Skills (READY TO START)**
- [ ] Reconnaissance and OSINT
- [ ] Scanning and enumeration (Nmap, enum4linux)
- [ ] Vulnerability assessment
- [ ] Basic exploitation with Metasploit

**Phase 3 - Windows/AD Specialization (LAB READY - HIGH PRIORITY)**
- [x] Active Directory lab setup and configuration
- [x] Domain Controller deployment (Windows Server 2022)
- [x] Domain client joining (Windows 11, Ubuntu, Ubuntu Server)
- [ ] Active Directory enumeration and attacks
- [ ] Windows privilege escalation
- [ ] Credential harvesting and lateral movement
- [ ] Kerberos attacks (Kerberoasting, AS-REP Roasting)
- [ ] Cross-platform AD attacks (Linux to Windows)

**Phase 4 - Defense Integration**
- [ ] SIEM concepts and log analysis
- [ ] Windows Event ID monitoring
- [ ] Group Policy hardening
- [ ] Incident response procedures

### Certification Path
1. CompTIA Security+ (entry-level validation)
2. eJPT (practical penetration testing)
3. OSCP (industry standard, career accelerator)

---

## Directory Structure

```
Home_Lab_Projects/
|
|-- CLAUDE.md                       # THIS FILE - Project context for AI sessions
|-- README.md                       # Human-readable project overview
|-- ETHICAL_HACKING_ROADMAP.md      # Complete learning path checklist
|
|-- Active_Directory/               # AD attack and defense labs
|   |-- README.md                   # AD lab guidance and resources
|   |-- Enumeration/                # BloodHound, PowerView exercises
|   |-- Attacks/                    # Kerberoasting, Pass-the-Hash, etc.
|   |-- Defense/                    # AD hardening, detection rules
|
|-- Windows_Security/               # Windows hardening and administration
|   |-- README.md                   # Windows security learning path
|   |-- GPO_Configurations/         # Group Policy templates
|   |-- Security_Baselines/         # CIS benchmarks, hardening guides
|   |-- Event_Logging/              # Important Event IDs, Sysmon configs
|
|-- Penetration_Testing/            # General pentest methodology
|   |-- README.md                   # Pentest methodology overview
|   |-- Reconnaissance/             # OSINT, scanning techniques
|   |-- Exploitation/               # Exploit exercises and notes
|   |-- Post_Exploitation/          # Privilege escalation, persistence
|
|-- Defense_Blue_Team/              # Defensive security exercises
|   |-- README.md                   # Blue team learning resources
|   |-- Detection_Rules/            # SIEM rules, Sigma rules
|   |-- Hardening_Guides/           # System hardening documentation
|   |-- Threat_Hunting/             # Proactive hunting playbooks
|
|-- Tools_and_Scripts/              # Custom automation and tools
|   |-- README.md                   # Tool documentation standards
|   |-- Python/                     # Python security scripts
|   |-- PowerShell/                 # PowerShell tools and modules
|   |-- Bash/                       # Bash automation scripts
|
|-- CTF_Writeups/                   # Challenge solutions
|   |-- README.md                   # Writeup format and guidelines
|   |-- HackTheBox/                 # HTB machine writeups
|   |-- TryHackMe/                  # THM room writeups
|   |-- VulnHub/                    # VulnHub VM writeups
|
|-- Lab_Journal/                    # Session documentation
|   |-- SESSION_LOG_TEMPLATE.md     # Template for lab sessions
|   |-- YYYY-MM-DD_session.md       # Individual session logs
|
|-- Documentation_Templates/        # Professional report formats
|   |-- PENTEST_REPORT_TEMPLATE.md  # Penetration test report
|   |-- INCIDENT_RESPONSE_TEMPLATE.md # IR report format
```

---

## Conventions and Standards

### File Naming
- Use `UPPERCASE_WITH_UNDERSCORES.md` for templates and key documents
- Use `lowercase-with-dashes.md` for notes and writeups
- Use `YYYY-MM-DD_description.md` for dated session logs
- Screenshots: `screenshot_YYYYMMDD_description.png`

### Documentation Standards
- Every lab exercise must include the **defense perspective**
- Document exact commands used (copy-paste reproducible)
- Include timestamps for session logs
- Reference MITRE ATT&CK technique IDs where applicable

### Code and Script Standards
- Include header comments with: purpose, author, date, usage
- Add defensive detection notes for any offensive scripts
- Test in isolated lab only - never against unauthorized systems

### Commit Messages (if using git)
- Format: `[category] Brief description`
- Categories: `[lab]`, `[docs]`, `[scripts]`, `[ctf]`, `[notes]`
- Example: `[lab] Add Kerberoasting exercise to AD folder`

---

## Quick Reference Commands

### Lab Management (VMware)
```bash
# Start VMware from command line (Windows)
vmrun start "/path/to/vm.vmx"

# List running VMs
vmrun list

# Snapshot management
vmrun snapshot "/path/to/vm.vmx" "clean_state"
vmrun revertToSnapshot "/path/to/vm.vmx" "clean_state"
```

### Kali Linux Essentials
```bash
# Update and upgrade
sudo apt update && sudo apt upgrade -y

# Start Metasploit database
sudo msfdb init && msfconsole

# Quick Nmap scans
nmap -sC -sV -oA scan_output <target>      # Standard scripts + versions
nmap -p- --min-rate=1000 <target>          # All ports fast scan
nmap -sU -top-ports 100 <target>           # UDP top ports

# Service enumeration
enum4linux -a <target>                      # SMB enumeration
smbclient -L //<target>/ -N                 # List SMB shares
```

### Windows Commands (Target/Defense)
```powershell
# System information
systeminfo
whoami /all
net user
net localgroup administrators

# Active Directory enumeration
Get-ADUser -Filter * | Select-Object Name, SamAccountName
Get-ADGroup -Filter * | Select-Object Name
Get-ADComputer -Filter * | Select-Object Name, DNSHostName

# Security event logs
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 10
```

### Session Workflow
```bash
# 1. Create new session log
cp Lab_Journal/SESSION_LOG_TEMPLATE.md Lab_Journal/$(date +%Y-%m-%d)_session.md

# 2. Snapshot VMs before testing
# 3. Document as you work
# 4. Revert snapshots after testing
# 5. File notes in appropriate category folder
```

---

## Key Windows Event IDs to Monitor

| Event ID | Description | Attack Relevance |
|----------|-------------|------------------|
| 4624 | Successful logon | Track authentication |
| 4625 | Failed logon | Brute force detection |
| 4648 | Explicit credential logon | Pass-the-Hash indicator |
| 4672 | Special privileges assigned | Admin logon tracking |
| 4688 | Process creation | Command execution audit |
| 4697 | Service installed | Persistence mechanism |
| 4698 | Scheduled task created | Persistence mechanism |
| 4720 | User account created | Account manipulation |
| 4732 | Member added to local group | Privilege escalation |
| 7045 | Service installed (System log) | Persistence mechanism |

---

## MITRE ATT&CK Quick Reference

### Common Techniques to Study
- **T1078** - Valid Accounts (credential theft)
- **T1087** - Account Discovery
- **T1098** - Account Manipulation
- **T1110** - Brute Force
- **T1133** - External Remote Services
- **T1136** - Create Account
- **T1187** - Forced Authentication (LLMNR/NBT-NS)
- **T1547** - Boot or Logon Autostart Execution
- **T1548** - Abuse Elevation Control Mechanism
- **T1558** - Steal or Forge Kerberos Tickets

---

## Learning Resources

### Primary Platforms
- **TryHackMe:** https://tryhackme.com (guided paths, beginner-friendly)
- **HackTheBox:** https://www.hackthebox.com (CTF-style, intermediate+)
- **PortSwigger Academy:** https://portswigger.net/web-security (web security)
- **HackTheBox Academy:** https://academy.hackthebox.com (structured courses)

### Windows-Specific
- **WADComs:** https://wadcoms.github.io (Windows/AD command reference)
- **LOLBAS:** https://lolbas-project.github.io (Living Off The Land Binaries)
- **AD Attack Cheat Sheet:** https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings

### Reference Frameworks
- **MITRE ATT&CK:** https://attack.mitre.org
- **OWASP:** https://owasp.org
- **NIST CSF:** https://www.nist.gov/cyberframework

---

## Session Continuity Notes

> **For Claude Code sessions:** Use this section to track ongoing work and next steps.

### Current Focus Area
- Phase 3: Active Directory Attack and Defense
- Priority: AD enumeration and exploitation techniques
- Lab Status: FULLY OPERATIONAL

### Recent Progress
- [2024-11] - Initial project structure created
- [2024-11] - Active Directory ACTIVATED on Windows Server 2022
- [2024-11] - Windows 11 successfully JOINED to domain
- [2024-11] - Ubuntu Linux successfully JOINED to domain
- [2024-11] - Ubuntu Server successfully JOINED to domain
- [2024-11-21] - Lab environment documentation updated
- [2025-11-21] - Kali Linux network configuration completed (VMnet10, 192.168.10.50)
- [2025-11-21] - Full network discovery completed - all lab machines identified
- [2025-11-21] - Domain Controller scan completed - services enumerated
- [2025-11-21] - Domain name confirmed: lab.local

### Completed Milestones
- [x] VMware Workstation virtual network configured
- [x] Kali Linux attack machine deployed
- [x] Windows Server 2022 Domain Controller operational
- [x] Active Directory Domain Services activated
- [x] Windows 11 domain-joined
- [x] Ubuntu Linux domain-joined (cross-platform integration)
- [x] Ubuntu Server domain-joined
- [x] Kali Linux moved to VMnet10 (lab network)
- [x] Kali static IP configured (192.168.10.50/24)
- [x] Network discovery - all lab machines mapped
- [x] Domain Controller port scan and service enumeration

### Next Session Tasks (Recommended Priority Order)
1. [ ] Fix Kali DNS: `echo "nameserver 192.168.10.10" | sudo tee /etc/resolv.conf`
2. [ ] Make Kali IP persistent with nmcli commands (see Network Configuration section)
3. [ ] Enumerate domain users via LDAP (ldapsearch or ldapdomaindump)
4. [ ] Run crackmapexec for SMB enumeration: `crackmapexec smb 192.168.10.0/24`
5. [ ] Run enum4linux-ng against DC: `enum4linux-ng 192.168.10.10`
6. [ ] Set up BloodHound for attack path mapping
7. [ ] Consider accessing Windows 11 with domain admin creds (alternative to reimaging)
8. [ ] Test cross-platform attacks: Linux-to-Windows lateral movement
9. [ ] Set up Windows Event logging on DC for defense monitoring
10. [ ] (Optional) Join Linux Mint to domain for additional practice

### Open Questions/Blockers
- [x] Document domain name and IP addressing scheme (COMPLETED: lab.local, 192.168.10.0/24)
- [ ] Confirm Linux Mint domain join status
- [ ] Identify Windows 11 hostname (currently unknown, IP: 192.168.10.11)
- [ ] Identify Ubuntu hostname (currently unknown, IP: 192.168.10.40)
- [ ] Create test user accounts with varying privilege levels for attack practice

---

## Ethical Framework Reminder

**All activities in this repository are for educational purposes in controlled lab environments.**

- Only target systems you own or have explicit written authorization to test
- Home labs and intentionally vulnerable VMs are your training ground
- Never apply techniques against production or unauthorized systems
- Understanding attacks enables better defense - this is the defender's advantage
- Document everything for learning and portfolio purposes

---

## Immediate Learning Opportunities (With Current Lab)

Your AD environment is ready for hands-on attack and defense exercises. Here are exercises you can start TODAY:

### Beginner AD Exercises
1. **AD Enumeration with PowerView** - Run from Windows 11 to map domain structure
2. **BloodHound Collection** - Visualize attack paths in your domain
3. **Basic Nmap Scanning** - Identify all services on domain machines from Kali

### Intermediate AD Exercises
4. **Kerberoasting** - Extract and crack service account tickets
5. **AS-REP Roasting** - Target accounts without Kerberos pre-authentication
6. **LLMNR/NBT-NS Poisoning** - Capture credentials with Responder

### Advanced AD Exercises
7. **Pass-the-Hash** - Lateral movement using NTLM hashes
8. **Pass-the-Ticket** - Kerberos ticket-based lateral movement
9. **DCSync Attack** - Simulate domain controller replication (requires DA)

### Defense Exercises
10. **Enable Advanced Audit Policies** - Configure Windows Event logging on DC
11. **Monitor for Attack Signatures** - Set up detection for the attacks above
12. **Implement Tiered Admin Model** - Protect privileged accounts

---

*Last Updated: 2025-11-21*
*This file should be updated as the project evolves and new context is established.*
