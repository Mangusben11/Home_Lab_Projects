# Tools and Scripts - Custom Automation

This directory contains custom scripts, tool configurations, and automation for security testing and defense.

---

## Learning Objectives

By developing scripts in this section, you will be able to:
- Automate repetitive security tasks
- Create custom tools for specific use cases
- Understand how security tools work internally
- Build a portfolio of practical code samples

---

## Directory Structure

```
Tools_and_Scripts/
|-- README.md                   # This file
|-- Python/                     # Python security scripts
|   |-- reconnaissance/         # Recon automation
|   |-- exploitation/           # Exploit helpers
|   |-- defense/                # Blue team scripts
|
|-- PowerShell/                 # PowerShell modules and scripts
|   |-- enumeration/            # AD and Windows enumeration
|   |-- hardening/              # Security configuration
|   |-- monitoring/             # Log analysis
|
|-- Bash/                       # Bash automation
|   |-- scanning/               # Network scanning helpers
|   |-- setup/                  # Environment setup
|
|-- Configs/                    # Tool configurations
|   |-- nmap/                   # Nmap scripts and timing
|   |-- burp/                   # Burp Suite configs
|   |-- sysmon/                 # Sysmon configurations
```

---

## Script Documentation Standards

Every script should include a header with:

**Python Example:**
```python
#!/usr/bin/env python3
"""
Script Name: port_scanner.py
Purpose: Simple TCP port scanner for learning
Author: Benjamina
Date: 2024-11-21
Version: 1.0

Usage:
    python3 port_scanner.py -t <target> -p <ports>

Dependencies:
    - socket (standard library)

Defensive Note:
    This activity generates network traffic that can be detected by:
    - IDS/IPS systems looking for port scan patterns
    - Firewall logs showing connection attempts
    - Netflow analysis showing unusual traffic

EDUCATIONAL USE ONLY - Only use on systems you own or have authorization to test.
"""

import argparse
import socket

def main():
    # Script implementation
    pass

if __name__ == "__main__":
    main()
```

**PowerShell Example:**
```powershell
<#
.SYNOPSIS
    Enumerates local security settings for baseline comparison

.DESCRIPTION
    Collects security-relevant configuration from Windows systems
    for hardening assessment and documentation.

.AUTHOR
    Benjamina

.DATE
    2024-11-21

.NOTES
    Defensive Detection:
    - This script uses WMI queries that may trigger EDR alerts
    - Event ID 4688 will log script execution

    EDUCATIONAL USE ONLY
#>

function Get-SecurityBaseline {
    # Implementation
}
```

**Bash Example:**
```bash
#!/bin/bash
#
# Script: quick_enum.sh
# Purpose: Rapid enumeration wrapper for CTF scenarios
# Author: Benjamina
# Date: 2024-11-21
#
# Usage: ./quick_enum.sh <target_ip>
#
# Defensive Note:
#   Generates significant network traffic
#   Will appear in target's firewall logs
#
# EDUCATIONAL USE ONLY

TARGET=$1
# Implementation
```

---

## Useful Script Ideas

### Reconnaissance
- [ ] Subdomain enumerator
- [ ] Port scan result parser
- [ ] Web directory brute forcer
- [ ] Screenshot automation for web hosts
- [ ] Certificate transparency log parser

### Enumeration
- [ ] SMB share enumerator
- [ ] AD user/group collector
- [ ] Service account finder
- [ ] Password policy checker
- [ ] DNS zone transfer tester

### Exploitation Helpers
- [ ] Reverse shell generator
- [ ] Payload encoder
- [ ] Credential sprayer
- [ ] Hash extractor/formatter

### Post-Exploitation
- [ ] Windows enumeration script
- [ ] Linux enumeration script
- [ ] Credential search tool
- [ ] Network pivot helper

### Defense/Blue Team
- [ ] Log parser for specific events
- [ ] IOC scanner
- [ ] Baseline comparison tool
- [ ] Alert correlation script
- [ ] Sigma rule tester

---

## Python Security Libraries

```bash
# Core networking
pip install scapy
pip install python-nmap
pip install requests

# Web security
pip install beautifulsoup4
pip install selenium

# Cryptography
pip install pycryptodome
pip install passlib

# Exploitation frameworks
pip install impacket
pip install pwntools

# Parsing and analysis
pip install python-whois
pip install dnspython
```

---

## PowerShell Security Modules

```powershell
# Active Directory module (requires RSAT)
Import-Module ActiveDirectory

# PowerSploit (offensive)
# https://github.com/PowerShellMafia/PowerSploit

# PowerView for AD enumeration
Import-Module .\PowerView.ps1

# PSReadline for better shell
Install-Module PSReadLine -Force
```

---

## Tool Configuration Files

### Nmap Timing Templates
```
# Save as ~/.nmap/timing.conf
# Stealth scanning
-T2 --scan-delay 1s --max-retries 2

# Balanced
-T3 --max-retries 3

# Aggressive (CTF/Lab)
-T4 --min-rate=1000

# Maximum speed (noisy)
-T5 --min-rate=5000
```

### Sysmon Configuration
Recommended configs to store:
- SwiftOnSecurity: https://github.com/SwiftOnSecurity/sysmon-config
- Olaf Hartong modular: https://github.com/olafhartong/sysmon-modular

---

## Version Control Practices

**For this directory:**
1. Never commit actual credentials or tokens
2. Use `.example` files for config templates
3. Include `.gitignore` for sensitive files:

```gitignore
# Credentials
*.key
*.pem
credentials.txt
passwords.txt

# Output files
*.raw
*.pcap
loot/

# Temporary files
*.tmp
*.log
__pycache__/
```

---

## Testing Your Scripts

Always test scripts in your lab environment:
1. Set up isolated network
2. Snapshot target VMs before testing
3. Monitor with Wireshark/tcpdump
4. Check defensive tools detection
5. Document results

---

## Career Portfolio Notes

Scripts developed here can be showcased in job applications:
- Clean, documented code demonstrates professionalism
- Defensive notes show security awareness
- Working tools prove practical skills

**GitHub Portfolio Tips:**
- Create public repo with sanitized scripts
- Write clear README for each tool
- Include sample output (sanitized)
- Add license (MIT recommended for portfolio)

---

*All scripts should include defensive detection notes - understanding both sides makes better security professionals.*
