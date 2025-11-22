# Active Directory - Attack and Defense Labs

This directory contains exercises, notes, and resources for learning Active Directory security from both offensive and defensive perspectives.

---

## Learning Objectives

By completing exercises in this section, you will be able to:
- Enumerate Active Directory environments using various tools
- Understand and execute common AD attack techniques
- Implement defensive measures and detection rules
- Identify misconfigurations that lead to domain compromise

---

## Directory Structure

```
Active_Directory/
|-- README.md               # This file
|-- Enumeration/            # AD enumeration techniques
|   |-- bloodhound/         # BloodHound data and analysis
|   |-- powerview/          # PowerView scripts and output
|   |-- ldap_queries/       # Custom LDAP enumeration
|
|-- Attacks/                # Offensive techniques
|   |-- kerberoasting/      # Service ticket attacks
|   |-- asrep_roasting/     # AS-REP roasting exercises
|   |-- pass_the_hash/      # PTH/PTT techniques
|   |-- delegation/         # Delegation abuse
|   |-- dcsync/             # DCSync attack exercises
|
|-- Defense/                # Defensive countermeasures
|   |-- detection_rules/    # SIEM and Sigma rules
|   |-- hardening/          # AD hardening guides
|   |-- monitoring/         # What to watch for
```

---

## Lab Prerequisites

### Environment Requirements
- Windows Server 2022 configured as Domain Controller
- At least one Windows 11 client joined to domain
- Kali Linux with AD tools installed

### Tool Installation (Kali)
```bash
# BloodHound and dependencies
sudo apt install bloodhound neo4j
pip3 install bloodhound

# Impacket suite
pip3 install impacket

# CrackMapExec
pip3 install crackmapexec

# Kerbrute for user enumeration
# Download from: https://github.com/ropnop/kerbrute/releases
```

### Windows Tools
- PowerView: https://github.com/PowerShellMafia/PowerSploit
- Rubeus: https://github.com/GhostPack/Rubeus
- Mimikatz: https://github.com/gentilkiwi/mimikatz

---

## Attack Techniques Overview

### Enumeration Phase
| Technique | Tool | MITRE ATT&CK |
|-----------|------|--------------|
| User enumeration | Kerbrute, enum4linux | T1087.002 |
| Group enumeration | PowerView, BloodHound | T1069.002 |
| Trust enumeration | PowerView | T1482 |
| ACL analysis | BloodHound | T1069 |

### Credential Attacks
| Attack | Description | Defense |
|--------|-------------|---------|
| Kerberoasting | Request TGS for SPNs, crack offline | Managed Service Accounts, strong passwords |
| AS-REP Roasting | Attack accounts without preauth | Enable Kerberos preauth |
| Password Spraying | Try common passwords across users | Account lockout, monitoring |
| DCSync | Replicate credentials from DC | Limit replication rights |

### Lateral Movement
| Technique | Tools | Detection |
|-----------|-------|-----------|
| Pass-the-Hash | Mimikatz, CrackMapExec | Event ID 4624 type 3, 4648 |
| Pass-the-Ticket | Rubeus, Mimikatz | Event ID 4768, 4769 anomalies |
| Overpass-the-Hash | Rubeus | Unusual TGT requests |

---

## Defensive Priorities

### Critical Security Settings
1. **Disable LLMNR and NBT-NS** - Prevents credential capture
2. **Enable Kerberos Pre-authentication** - Stops AS-REP roasting
3. **Limit DCSync Rights** - Only DCs should have replication permissions
4. **Use Group Managed Service Accounts** - Automatic password rotation
5. **Implement LAPS** - Randomize local admin passwords

### Detection Rules to Implement
- Kerberoasting: High volume TGS requests from single source
- DCSync: Non-DC requesting directory replication
- Golden Ticket: TGT with unusual lifetime
- Pass-the-Hash: NTLM authentication to multiple hosts rapidly

---

## Exercises

### Exercise 1: AD Enumeration with BloodHound
**Difficulty:** Beginner
**Time:** 2 hours

1. Start neo4j database and BloodHound
2. Run SharpHound collector on domain
3. Import data and analyze attack paths
4. Document shortest path to Domain Admin

### Exercise 2: Kerberoasting
**Difficulty:** Intermediate
**Time:** 1-2 hours

1. Enumerate SPNs in the domain
2. Request service tickets
3. Extract tickets and crack with hashcat
4. Document detection opportunities

### Exercise 3: Full Domain Compromise Chain
**Difficulty:** Advanced
**Time:** 4+ hours

1. Start from initial foothold
2. Enumerate and identify attack path
3. Execute attack chain to Domain Admin
4. Document each step with evidence
5. Write defensive recommendations

---

## Resources

### Learning Platforms
- **HackTheBox Pro Labs:** Offshore, RastaLabs, Cybernetics
- **TryHackMe:** Active Directory learning path
- **PentesterAcademy:** Windows Red Team Lab

### Reference Materials
- https://adsecurity.org - Sean Metcalf's AD security blog
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
- https://orange-cyberdefense.github.io/ocd-mindmaps/ - AD attack mindmaps

### Intentionally Vulnerable Labs
- **YOURDOMAINCONTROLLER:** https://yourdomaincontroller.com
- **DVAD (Damn Vulnerable AD):** https://github.com/WazeHell/vulnerable-AD
- **GOAD (Game of AD):** https://github.com/Orange-Cyberdefense/GOAD

---

*Document all exercises using the session log template. Always include the defense perspective.*
