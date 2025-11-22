# CTF Writeups - Challenge Solutions and Learning

This directory contains writeups from Capture The Flag challenges and vulnerable machine exercises.

---

## Learning Objectives

By completing and documenting CTF challenges, you will:
- Apply security concepts in practical scenarios
- Develop systematic problem-solving approaches
- Build a portfolio demonstrating hands-on skills
- Learn from diverse vulnerability types

---

## Directory Structure

```
CTF_Writeups/
|-- README.md                   # This file
|-- HackTheBox/                 # HackTheBox machine writeups
|   |-- Easy/
|   |-- Medium/
|   |-- Hard/
|
|-- TryHackMe/                  # TryHackMe room writeups
|   |-- Learning_Paths/
|   |-- Challenges/
|
|-- VulnHub/                    # VulnHub VM writeups
|
|-- Other_CTFs/                 # Competition writeups
|   |-- picoCTF/
|   |-- HTB_CTF/
```

---

## Writeup Template

Use this format for consistent, professional writeups:

```markdown
# [Machine/Challenge Name]

## Overview
| Attribute | Value |
|-----------|-------|
| Platform | HackTheBox / TryHackMe / VulnHub |
| Difficulty | Easy / Medium / Hard |
| OS | Windows / Linux |
| Date Completed | YYYY-MM-DD |
| Time Spent | X hours |
| Key Skills | [Skills practiced] |

## Summary
[2-3 sentence overview of the box and main vulnerabilities]

## Reconnaissance

### Port Scan
```
[Nmap output]
```

### Service Enumeration
[Details of enumeration performed]

## Exploitation

### Initial Foothold
[How you gained initial access]

### User Flag
[Path to user access]

## Privilege Escalation
[How you escalated to root/admin]

### Root Flag
[Path to root access]

## Lessons Learned
1. [Key takeaway 1]
2. [Key takeaway 2]

## Defense Perspective
- How to detect this attack:
- How to prevent this vulnerability:

## References
- [Relevant links]

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | [Technique] | T1xxx |
| Privilege Escalation | [Technique] | T1xxx |
```

---

## Recommended Learning Progression

### Beginner Path (Start Here)
**TryHackMe Rooms:**
1. Tutorial
2. OpenVPN
3. Linux Fundamentals (1, 2, 3)
4. Windows Fundamentals (1, 2, 3)
5. Intro to Networking
6. Nmap
7. Network Services (1, 2)
8. Metasploit Introduction

**First Machines:**
- TryHackMe: Basic Pentesting
- TryHackMe: Kenobi
- HackTheBox: Lame (retired)
- VulnHub: Kioptrix Level 1

### Intermediate Path
**TryHackMe:**
- Buffer Overflow Prep
- Active Directory Basics
- Attacking Kerberos
- Windows PrivEsc
- Linux PrivEsc

**HackTheBox (Easy-Medium):**
- Active
- Forest
- Cascade
- Resolute

### Advanced Path
**HackTheBox Pro Labs:**
- Offshore (AD-focused)
- RastaLabs (Red team)
- Cybernetics

**Certifications:**
- OSCP exam machines
- HTB Dante/Zephyr

---

## Writeup Best Practices

### DO:
- Include exact commands used (reproducible)
- Add screenshots at key moments
- Explain your thought process
- Document dead ends and what you learned
- Include the defense perspective
- Map techniques to MITRE ATT&CK
- Credit resources and tools used

### DO NOT:
- Share writeups for active/unretired machines (violates ToS)
- Include actual flags in public writeups
- Skip the enumeration documentation
- Forget the defensive recommendations

---

## Screenshot Guidelines

Capture screenshots for:
1. Initial nmap scan results
2. Key vulnerability discovery
3. Successful exploitation
4. Proof of access (flags, whoami output)
5. Privilege escalation success

**Naming Convention:**
```
[machine]_[step]_[description].png

Examples:
lame_01_nmap_scan.png
lame_02_smb_vuln.png
lame_03_shell_access.png
lame_04_root_flag.png
```

---

## Platforms and Resources

### CTF Platforms
| Platform | URL | Notes |
|----------|-----|-------|
| HackTheBox | hackthebox.com | Industry standard, retired boxes for writeups |
| TryHackMe | tryhackme.com | Guided learning, beginner-friendly |
| VulnHub | vulnhub.com | Downloadable VMs |
| PicoCTF | picoctf.org | Beginner CTF challenges |
| OverTheWire | overthewire.org | Linux/networking wargames |

### Writeup References
- https://0xdf.gitlab.io - Excellent HTB writeups
- https://ippsec.rocks - Video writeups searchable by technique
- https://book.hacktricks.xyz - Methodology reference

### Learning Support
- HTB Discord
- TryHackMe Discord
- r/hackthebox
- r/tryhackme

---

## Portfolio Value

CTF writeups demonstrate to employers:
- **Technical depth:** Understanding of attacks and defenses
- **Communication:** Ability to document and explain
- **Persistence:** Completing challenging problems
- **Methodology:** Systematic approach to security

**Tips for Portfolio:**
1. Publish writeups on personal blog/GitHub
2. Include only retired/allowed machines
3. Focus on unique approaches or insights
4. Keep writeups updated and well-formatted

---

## Progress Tracking

| Platform | Easy | Medium | Hard | Insane |
|----------|------|--------|------|--------|
| HackTheBox | 0 | 0 | 0 | 0 |
| TryHackMe | 0 | 0 | 0 | - |
| VulnHub | 0 | 0 | 0 | 0 |

**Update this table as you complete machines!**

---

*Only publish writeups for retired/allowed machines. Always include the defense perspective.*
