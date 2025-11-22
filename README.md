# Windows Security & Active Directory Lab

A comprehensive home lab environment for learning Windows security, Active Directory attacks and defenses, and ethical penetration testing. This repository documents my journey into cybersecurity through hands-on practice.

## About This Project

**Author:** Benjamina
**Institution:** DVC Computer Science
**Focus Areas:** Windows Security, Active Directory, Ethical Hacking
**Started:** November 2024

This repository serves as both a **learning journal** and **professional portfolio** demonstrating practical cybersecurity skills through documented lab exercises.

---

## Lab Environment

### Network Architecture

```
                    [VMnet10 - Isolated Lab Network]
                         192.168.10.0/24
                               |
        +----------------------+----------------------+
        |                      |                      |
   [Domain Controller]    [Windows Client]      [Linux Clients]
   WIN-LUAK1VFNJ8D        Windows 11            Ubuntu Desktop
   192.168.10.10          192.168.10.11         192.168.10.40
   Windows Server 2022    Domain-joined          Domain-joined
   lab.local DC                |                      |
        |                      |                      |
        +----------------------+----------------------+
                               |
                        [Kali Linux]
                        192.168.10.50
                        Attack Machine
```

### Virtual Machines

| Machine | OS | Role | Purpose |
|---------|-----|------|---------|
| WIN-LUAK1VFNJ8D | Windows Server 2022 | Domain Controller | AD DS, DNS, Kerberos |
| Win11 Client | Windows 11 | Domain Workstation | AD attacks, lateral movement |
| Ubuntu Desktop | Ubuntu Linux | Domain Client | Cross-platform AD integration |
| Ubuntu Server | Ubuntu Server | Domain Client | Server-side Linux AD |
| Kali Linux | Kali Linux | Attacker | Penetration testing platform |
| Linux Mint | Linux Mint | Standalone | Reverse engineering (optional) |

### Domain Configuration

- **Domain Name:** lab.local
- **Domain Controller:** WIN-LUAK1VFNJ8D (192.168.10.10)
- **Network:** VMnet10 (Host-Only/Isolated)

---

## Repository Structure

```
Home_Lab_Projects/
|
|-- Active_Directory/           # AD attack and defense labs
|   |-- Enumeration/            # BloodHound, PowerView, ldapsearch
|   |-- Attacks/                # Kerberoasting, Pass-the-Hash, etc.
|   |-- Defense/                # Hardening, detection rules
|
|-- Windows_Security/           # Windows hardening and administration
|   |-- GPO_Configurations/     # Group Policy templates
|   |-- Security_Baselines/     # CIS benchmarks
|   |-- Event_Logging/          # Important Event IDs, Sysmon
|
|-- Penetration_Testing/        # General pentest methodology
|   |-- Reconnaissance/         # OSINT, scanning techniques
|   |-- Exploitation/           # Exploit exercises
|   |-- Post_Exploitation/      # Privilege escalation, persistence
|
|-- Defense_Blue_Team/          # Defensive security exercises
|   |-- Detection_Rules/        # SIEM/Sigma rules
|   |-- Hardening_Guides/       # System hardening docs
|   |-- Threat_Hunting/         # Proactive hunting playbooks
|
|-- Tools_and_Scripts/          # Custom automation
|   |-- Python/                 # Python security scripts
|   |-- PowerShell/             # PowerShell tools
|   |-- Bash/                   # Bash automation
|
|-- CTF_Writeups/               # Capture The Flag solutions
|   |-- HackTheBox/             # HTB machine writeups
|   |-- TryHackMe/              # THM room writeups
|
|-- Lab_Journal/                # Session documentation
|   |-- SESSION_YYYY-MM-DD.md   # Individual session logs
|
|-- Documentation_Templates/    # Professional report formats
    |-- PENTEST_REPORT_TEMPLATE.md
    |-- INCIDENT_RESPONSE_TEMPLATE.md
```

---

## Learning Path

### Current Focus: Active Directory Attack and Defense

#### Completed
- [x] Lab environment setup (VMware Workstation)
- [x] Windows Server 2022 Domain Controller deployment
- [x] Active Directory Domain Services configuration
- [x] Domain client joining (Windows 11, Ubuntu)
- [x] Kali Linux attack machine configuration
- [x] Network discovery and DC enumeration

#### In Progress
- [ ] LDAP enumeration techniques
- [ ] BloodHound attack path analysis
- [ ] Kerberos attack techniques

#### Planned
- [ ] Credential harvesting and lateral movement
- [ ] Windows Event ID monitoring for attack detection
- [ ] SIEM rule development

---

## Skills Demonstrated

### Offensive Security
- Network reconnaissance and enumeration
- Active Directory attack methodology
- Windows exploitation techniques
- Credential attacks (Kerberoasting, AS-REP Roasting)
- Lateral movement techniques

### Defensive Security
- Windows Event log analysis
- Attack detection and alerting
- Security hardening (GPO, baselines)
- Incident response documentation

### Technical Skills
- VMware virtualization
- Windows Server administration
- Active Directory management
- Linux system administration
- Python and PowerShell scripting

---

## Tools and Technologies

### Attack Tools
- Kali Linux
- Nmap, Masscan
- CrackMapExec
- BloodHound/SharpHound
- Impacket Suite
- Metasploit Framework
- Responder
- Mimikatz (understanding for defense)

### Defense Tools
- Windows Event Viewer
- Sysmon
- Sigma Rules
- Windows Defender

### Platforms
- VMware Workstation
- Windows Server 2022
- Windows 11
- Ubuntu Linux
- Active Directory Domain Services

---

## Documentation Standards

All exercises follow professional documentation practices:

1. **Objective** - What is being learned or tested
2. **Steps** - Exact commands and procedures (reproducible)
3. **Results** - Outputs and screenshots
4. **Defense Perspective** - How to detect/prevent the attack
5. **MITRE ATT&CK Mapping** - Technique IDs where applicable

---

## Ethical Statement

**All activities in this repository are conducted in isolated, personally-owned lab environments for educational purposes only.**

- Only systems I own or have explicit authorization to test
- No techniques applied against production or unauthorized systems
- Understanding attacks enables better defense
- Knowledge shared responsibly for learning purposes

---

## Certification Path

Working toward industry certifications:

1. **CompTIA Security+** - Foundational security knowledge
2. **eJPT** - Entry-level penetration testing
3. **OSCP** - Advanced penetration testing (goal)

---

## Resources

### Learning Platforms
- [TryHackMe](https://tryhackme.com) - Guided learning paths
- [HackTheBox](https://www.hackthebox.com) - CTF-style challenges
- [HackTheBox Academy](https://academy.hackthebox.com) - Structured courses
- [PortSwigger Academy](https://portswigger.net/web-security) - Web security

### References
- [MITRE ATT&CK](https://attack.mitre.org) - Attack framework
- [WADComs](https://wadcoms.github.io) - Windows/AD command reference
- [LOLBAS](https://lolbas-project.github.io) - Living Off The Land Binaries
- [AD Attack Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)

---

## Connect

This repository represents my journey into cybersecurity. I welcome connections with other learners and professionals in the field.

---

*Last Updated: November 2025*
