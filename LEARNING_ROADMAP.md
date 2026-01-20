# SEC_LAB Learning Roadmap

A structured progression from foundational skills to career-ready expertise in Intrusion Detection, Digital Forensics, and Ethical Hacking.

---

## Phase 1: Foundations (Current)

> Build the infrastructure and understand how systems work before attacking or defending them.

### 1.1 Lab Infrastructure
- [x] Network segmentation (VMnet8 + isolated analysis network)
- [x] Wazuh SIEM deployment
- [x] Domain Controller setup (lab.local)
- [x] Domain client enrollment (Windows 11, Ubuntu)
- [ ] Baseline documentation

### 1.2 Core Skills to Develop
| Skill | How You'll Practice | Lab Asset |
|-------|---------------------|-----------|
| Windows Server Administration | Configure AD, GPOs, DNS | DC01 |
| Linux Administration | Manage Ubuntu, read logs | Ubuntu Client, Wazuh Manager |
| Networking Fundamentals | Packet capture, traffic analysis | All VMs + Wireshark |
| Log Analysis | Query Wazuh, correlate events | Wazuh Manager |

### 1.3 Exercises
- [ ] Create domain users and groups with different privilege levels
- [ ] Configure Group Policy for security baselines
- [ ] Capture and analyze normal network traffic (establish baseline)
- [ ] Document authentication flow in AD environment

---

## Phase 2: Intrusion Detection

> Learn to see attacks through the defender's lens.

### 2.1 Skills to Develop
| Skill | Description | Industry Relevance |
|-------|-------------|-------------------|
| SIEM Operation | Write queries, create dashboards | SOC Analyst, Detection Engineer |
| Alert Triage | Distinguish true/false positives | SOC Analyst |
| Detection Engineering | Write custom rules for known attacks | Detection Engineer |
| Threat Hunting | Proactively search for IOCs | Threat Hunter |

### 2.2 Exercises
| Exercise | Attack (Kali) | Detection (Wazuh) | Status |
|----------|---------------|-------------------|--------|
| Port Scan Detection | nmap scans | Detect scan patterns | [ ] |
| Brute Force Detection | hydra/medusa | Failed login correlation | [x] |
| Suspicious Process | Reverse shell | Process creation alerts | [ ] |
| Lateral Movement | psexec/wmiexec | Remote execution detection | [ ] |
| Persistence Detection | Scheduled tasks, registry | Persistence mechanism alerts | [ ] |
| Credential Dumping | mimikatz | LSASS access detection | [ ] |

### 2.3 Deliverables for Portfolio
- [ ] Custom Wazuh detection rules with documentation
- [ ] Alert triage playbook (decision tree for common alerts)
- [ ] Attack detection writeup: "How I detected X attack using Y technique"

---

## Phase 3: Ethical Hacking

> Learn offensive techniques to understand what you're defending against.

### 3.1 Skills to Develop
| Skill | Description | Industry Relevance |
|-------|-------------|-------------------|
| Reconnaissance | Network mapping, service enumeration | Penetration Tester |
| Vulnerability Assessment | Identify weaknesses | Vulnerability Analyst |
| Exploitation | Gain initial access | Penetration Tester |
| Post-Exploitation | Privilege escalation, lateral movement | Red Team |
| Active Directory Attacks | Kerberoasting, Pass-the-Hash, DCSync | Red Team |

### 3.2 Exercises
| Exercise | Target | Technique | Status |
|----------|--------|-----------|--------|
| Service Enumeration | Metasploitable2 | nmap, banner grabbing | [ ] |
| Web App Exploitation | Metasploitable2 | SQLi, command injection | [ ] |
| Linux Privilege Escalation | Metasploitable2 | SUID, sudo misconfig | [ ] |
| AD Enumeration | lab.local | BloodHound, PowerView | [ ] |
| Kerberoasting | lab.local | Request service tickets, crack offline | [ ] |
| Pass-the-Hash | lab.local | Harvest and reuse NTLM hashes | [ ] |
| Golden Ticket | lab.local | Forge Kerberos tickets | [ ] |

### 3.3 Deliverables for Portfolio
- [ ] Penetration test report: Metasploitable2
- [ ] AD attack chain writeup with mitigations
- [ ] Custom exploitation scripts with comments

---

## Phase 4: Digital Forensics

> Investigate incidents and extract evidence.

### 4.1 Skills to Develop
| Skill | Description | Industry Relevance |
|-------|-------------|-------------------|
| Disk Forensics | Image acquisition, file recovery | Forensic Analyst |
| Memory Forensics | Analyze RAM dumps for malware | Incident Responder |
| Malware Analysis | Static and dynamic analysis | Malware Analyst |
| Timeline Analysis | Reconstruct incident sequence | Forensic Analyst |
| Evidence Handling | Chain of custody, documentation | All forensic roles |

### 4.2 Exercises
| Exercise | Asset | Tools | Status |
|----------|-------|-------|--------|
| Disk Imaging | Ubuntu Client | dd, FTK Imager | [ ] |
| File System Analysis | Disk image | Autopsy, Sleuth Kit | [ ] |
| Memory Acquisition | Windows 11 | WinPMEM, DumpIt | [ ] |
| Memory Analysis | Memory dump | Volatility 3 | [ ] |
| Malware Triage | FLARE VM | PEStudio, YARA | [ ] |
| Dynamic Malware Analysis | FLARE VM | Process Monitor, Wireshark | [ ] |
| Incident Timeline | Compromised VM | Plaso, log2timeline | [ ] |

### 4.3 Deliverables for Portfolio
- [ ] Forensic investigation report (simulated incident)
- [ ] Malware analysis report with IOCs
- [ ] Incident timeline reconstruction

---

## Phase 5: Integration

> Combine all domains - attack, detect, investigate.

### 5.1 Purple Team Exercises
| Scenario | Red Team Action | Blue Team Response | Forensic Analysis |
|----------|-----------------|--------------------| ------------------|
| Ransomware Simulation | Deploy simulated ransomware | Detect and alert | Analyze artifacts |
| Data Exfiltration | Steal sensitive files | Detect abnormal traffic | Trace exfil path |
| APT Simulation | Multi-stage attack chain | Detect each phase | Full incident report |

### 5.2 Capstone Project Ideas
- **Full Incident Response**: Attack a system, detect it, contain it, investigate it, report it
- **Detection Engineering**: Create a detection for a real-world CVE, document false positive tuning
- **Threat Hunt**: Given IOCs from a real threat report, hunt for them in your environment

---

## Skills Matrix (Interview Reference)

| Category | Skill | Proficiency | Evidence |
|----------|-------|-------------|----------|
| **Infrastructure** | Windows Server/AD | | |
| | Linux Administration | | |
| | Network Configuration | | |
| **Detection** | SIEM (Wazuh) | | |
| | Log Analysis | | |
| | Detection Rule Writing | | |
| **Offensive** | Network Reconnaissance | | |
| | Web App Exploitation | | |
| | AD Attacks | | |
| **Forensics** | Disk Imaging | | |
| | Memory Analysis | | |
| | Malware Analysis | | |

*Update proficiency (Learning/Familiar/Proficient/Expert) and link to evidence as you progress.*

---

## Progress Log

| Date | Activity | Phase | Notes |
|------|----------|-------|-------|
| 2026-01-16 | Created lab network, DC01 deployed | Phase 1 | |
| 2026-01-16 | Windows 11 VM installed (WS01) | Phase 1 | 8GB RAM, 4 cores, 80GB disk |
| 2026-01-17 | WS01 joined to lab.local domain | Phase 1 | Fixed DC01 static IP (was DHCP), configured DNS |
| 2026-01-17 | Wazuh agents confirmed on WS01 + Ubuntu | Phase 1 | Upgraded Wazuh to 4.14.2, all services running |
| 2026-01-20 | Completed Brute Force Detection exercise | Phase 2 | First portfolio piece - CrackMapExec attack, Wazuh detection, writeup created |

---

## Resources

### Intrusion Detection
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)

### Ethical Hacking
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Digital Forensics
- [SANS DFIR Cheat Sheets](https://www.sans.org/posters/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [Autopsy](https://www.autopsy.com/)
