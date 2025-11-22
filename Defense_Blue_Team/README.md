# Defense / Blue Team - Detection and Response

This directory contains resources for learning defensive security, threat detection, incident response, and security operations.

---

## Learning Objectives

By completing exercises in this section, you will be able to:
- Develop and tune detection rules for common attacks
- Analyze security logs to identify malicious activity
- Perform incident response and forensic analysis
- Implement security hardening measures
- Conduct proactive threat hunting

---

## Directory Structure

```
Defense_Blue_Team/
|-- README.md                   # This file
|-- Detection_Rules/            # SIEM and detection rules
|   |-- sigma/                  # Sigma rule format
|   |-- splunk/                 # Splunk queries
|   |-- elastic/                # Elastic/ELK queries
|
|-- Hardening_Guides/           # System hardening
|   |-- windows/                # Windows hardening
|   |-- linux/                  # Linux hardening
|   |-- network/                # Network security
|
|-- Threat_Hunting/             # Proactive hunting
|   |-- playbooks/              # Hunting playbooks
|   |-- ioc_lists/              # Indicator repositories
|
|-- Incident_Response/          # IR procedures
|   |-- playbooks/              # IR playbooks
|   |-- forensics/              # Forensic techniques
|
|-- Exercises/                  # Hands-on labs
```

---

## Detection Engineering

### Sigma Rules

Sigma is a generic signature format for SIEM systems. Write once, convert to any SIEM.

**Example Sigma Rule - Mimikatz Detection:**
```yaml
title: Mimikatz Usage Detection
status: experimental
description: Detects Mimikatz execution patterns
author: Benjamina
date: 2024/11/21
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'lsadump::dcsync'
        - Image|endswith: '\mimikatz.exe'
        - OriginalFileName: 'mimikatz.exe'
    condition: selection
falsepositives:
    - Legitimate security testing
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

**Sigma Resources:**
- Sigma Repository: https://github.com/SigmaHQ/sigma
- Sigma Converter: https://uncoder.io

### Key Detection Patterns

| Attack | Data Source | Detection Logic |
|--------|-------------|-----------------|
| Kerberoasting | Event ID 4769 | High volume TGS requests, RC4 encryption |
| Pass-the-Hash | Event ID 4624 | Type 3 logon with NTLM, source != destination |
| DCSync | Event ID 4662 | Replication rights used by non-DC |
| Credential Dumping | Sysmon 10 | LSASS access from non-system process |
| Lateral Movement | Event ID 4648 | Explicit credential usage pattern |

---

## Log Analysis

### Windows Event Log Queries

**PowerShell Log Analysis:**
```powershell
# Failed logon attempts (brute force detection)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
} -MaxEvents 100 |
Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='Source';E={$_.Properties[19].Value}}

# Successful logons
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
} | Where-Object {$_.Properties[8].Value -in @(2,3,10)}

# New process creation with command line
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
} | Select-Object TimeCreated,
    @{N='Process';E={$_.Properties[5].Value}},
    @{N='CommandLine';E={$_.Properties[8].Value}}

# Service installations
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7045
}
```

### Sysmon Analysis
```powershell
# Process creation (Event ID 1)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 1} |
    Select-Object TimeCreated, Message

# Network connections (Event ID 3)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object {$_.Id -eq 3} |
    Select-Object TimeCreated, Message
```

---

## Incident Response Framework

### NIST Incident Response Phases

```
1. Preparation
   - IR plan development
   - Tool deployment
   - Team training

2. Detection & Analysis
   - Alert triage
   - Log analysis
   - Scope determination

3. Containment
   - Short-term: Isolate affected systems
   - Long-term: Rebuild/patch systems

4. Eradication
   - Remove malware
   - Close attack vectors
   - Patch vulnerabilities

5. Recovery
   - Restore systems
   - Verify functionality
   - Monitor for reinfection

6. Lessons Learned
   - Post-incident review
   - Documentation
   - Process improvement
```

### Quick Triage Commands

**Windows:**
```powershell
# Running processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 20

# Network connections
Get-NetTCPConnection | Where-Object State -eq 'Established'

# Scheduled tasks
Get-ScheduledTask | Where-Object State -eq 'Ready'

# Services
Get-Service | Where-Object Status -eq 'Running'

# Recent file modifications
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}

# Autoruns equivalent
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Linux:**
```bash
# Running processes
ps auxf

# Network connections
netstat -tulpn
ss -tulpn

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Recent file modifications
find / -mtime -1 -type f 2>/dev/null

# User accounts
cat /etc/passwd
cat /etc/shadow
last
```

---

## Threat Hunting

### Hunting Hypothesis Examples

1. **Hypothesis:** Attackers are using PowerShell for malicious activity
   - **Data:** Event ID 4104 (Script Block Logging)
   - **Hunt:** Look for encoded commands, download cradles, AMSI bypass

2. **Hypothesis:** Lateral movement via PsExec is occurring
   - **Data:** Event ID 7045, Sysmon Event 1
   - **Hunt:** New services named "PSEXESVC", pipes named "psexec"

3. **Hypothesis:** Credential theft from LSASS is happening
   - **Data:** Sysmon Event 10
   - **Hunt:** Non-system processes accessing LSASS memory

### Threat Hunting Process

```
1. Form Hypothesis
   - Based on threat intel
   - Based on known TTPs
   - Based on environment knowledge

2. Investigate
   - Query relevant data sources
   - Analyze results
   - Pivot on interesting findings

3. Pattern Recognition
   - Identify anomalies
   - Correlate across data sources
   - Timeline analysis

4. Document & Respond
   - Document findings
   - Create detections for future
   - Remediate if threats found
```

---

## Exercises

### Exercise 1: Detection Rule Development
**Difficulty:** Beginner
**Time:** 2 hours

1. Choose an attack technique from MITRE ATT&CK
2. Research detection methods
3. Write a Sigma rule
4. Test against lab data
5. Document false positive handling

### Exercise 2: Log Analysis Challenge
**Difficulty:** Intermediate
**Time:** 3 hours

1. Import provided Windows event logs
2. Identify suspicious activity
3. Build timeline of events
4. Determine attack technique used
5. Write incident summary

### Exercise 3: Incident Response Simulation
**Difficulty:** Advanced
**Time:** 4+ hours

1. Respond to simulated compromise
2. Perform triage and scoping
3. Identify IOCs
4. Document containment actions
5. Write full IR report

---

## Resources

### Detection Repositories
- **Sigma Rules:** https://github.com/SigmaHQ/sigma
- **Elastic Detection Rules:** https://github.com/elastic/detection-rules
- **Splunk Security Content:** https://github.com/splunk/security_content

### Blue Team Platforms
- **Blue Team Labs Online:** https://blueteamlabs.online
- **CyberDefenders:** https://cyberdefenders.org
- **LetsDefend:** https://letsdefend.io

### Threat Intelligence
- **MITRE ATT&CK:** https://attack.mitre.org
- **AlienVault OTX:** https://otx.alienvault.com
- **VirusTotal:** https://www.virustotal.com

### Forensic Tools
- **Autopsy:** https://www.autopsy.com
- **Volatility:** https://www.volatilityfoundation.org
- **KAPE:** https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape

---

*For every attack technique learned, document the corresponding detection method.*
