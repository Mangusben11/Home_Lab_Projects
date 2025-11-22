# [Machine/Challenge Name]

## Overview

| Attribute | Value |
|-----------|-------|
| **Platform** | HackTheBox / TryHackMe / VulnHub |
| **Difficulty** | Easy / Medium / Hard / Insane |
| **Operating System** | Windows / Linux |
| **IP Address** | X.X.X.X |
| **Date Completed** | YYYY-MM-DD |
| **Time Spent** | X hours X minutes |
| **Key Skills** | [e.g., SMB enumeration, Kerberoasting, Linux privesc] |

---

## Summary

[2-3 sentences describing the machine and the main attack path. What made this box interesting or challenging?]

---

## Reconnaissance

### Initial Port Scan

```bash
# Command used
nmap -sC -sV -oA nmap/initial <target_ip>
```

**Results:**
```
[Paste nmap output here]
```

### Service Enumeration

#### Port XX - [Service Name]
[Details of enumeration for this service]

```bash
# Commands used
```

#### Port XX - [Service Name]
[Details of enumeration for this service]

---

## Vulnerability Identification

### Vulnerability 1: [Name]
- **Description:** [What is the vulnerability?]
- **CVE:** [If applicable]
- **CVSS:** [If known]
- **Discovery Method:** [How did you find it?]

---

## Exploitation

### Initial Foothold

**Attack Vector:** [Brief description]

**Steps:**
1. [Step 1]
   ```bash
   [Command]
   ```

2. [Step 2]
   ```bash
   [Command]
   ```

**Result:**
```
[Output showing shell access]
$ whoami
user
```

### User Flag

```
[flag location]
user.txt: [redact in public writeups]
```

---

## Privilege Escalation

### Enumeration

**Local Enumeration:**
```bash
# Commands run for enumeration
sudo -l
find / -perm -4000 2>/dev/null
```

**Findings:**
[What did you discover that led to privesc?]

### Exploitation

**Technique:** [e.g., SUID binary abuse, kernel exploit, misconfigured sudo]

**Steps:**
1. [Step 1]
   ```bash
   [Command]
   ```

2. [Step 2]
   ```bash
   [Command]
   ```

**Result:**
```
$ whoami
root
```

### Root Flag

```
[flag location]
root.txt: [redact in public writeups]
```

---

## Alternative Paths

[Were there other ways to exploit this machine?]

---

## Lessons Learned

### Technical Skills
1. [What new technique did you learn?]
2. [What tool usage improved?]
3. [What concept became clearer?]

### Methodology
1. [What would you do differently?]
2. [What enumeration step was key?]

---

## Defense Perspective

### Detection Opportunities
- **Log Sources:** [What logs would show this attack?]
- **Event IDs:** [Relevant Windows Event IDs]
- **Signatures:** [What patterns could be detected?]

### Prevention Recommendations
1. [How to prevent the initial foothold]
2. [How to prevent privilege escalation]
3. [General hardening recommendations]

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|--------|-----------|-----|-------|
| Reconnaissance | [Technique] | T1xxx | [Details] |
| Initial Access | [Technique] | T1xxx | [Details] |
| Execution | [Technique] | T1xxx | [Details] |
| Privilege Escalation | [Technique] | T1xxx | [Details] |

---

## Tools Used

| Tool | Purpose | Link |
|------|---------|------|
| Nmap | Port scanning | https://nmap.org |
| [Tool] | [Purpose] | [Link] |

---

## References

- [Link to relevant resource]
- [CVE details if applicable]
- [Helpful writeup or guide]

---

## Screenshots

| Step | Screenshot |
|------|------------|
| Initial scan | `screenshots/01_nmap.png` |
| Vulnerability | `screenshots/02_vuln.png` |
| User shell | `screenshots/03_user.png` |
| Root shell | `screenshots/04_root.png` |

---

*Completed: YYYY-MM-DD | Writeup by: Benjamina*
