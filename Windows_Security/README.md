# Windows Security - Hardening and Administration

This directory contains resources for learning Windows system administration, security configuration, and hardening techniques.

---

## Learning Objectives

By completing exercises in this section, you will be able to:
- Understand Windows architecture (Registry, Services, Security Principals)
- Configure Group Policy for security hardening
- Implement security baselines and benchmarks
- Monitor Windows systems through Event Logging
- Configure and manage Windows Defender

---

## Directory Structure

```
Windows_Security/
|-- README.md                   # This file
|-- GPO_Configurations/         # Group Policy templates and exports
|   |-- security_baseline.xml   # Exported baseline GPO
|   |-- audit_policy.xml        # Audit policy configuration
|
|-- Security_Baselines/         # Industry standard baselines
|   |-- CIS_Benchmarks/         # CIS Windows hardening
|   |-- STIG/                   # DoD STIG configurations
|   |-- Microsoft_Baseline/     # Microsoft security baseline
|
|-- Event_Logging/              # Logging configuration
|   |-- sysmon_config.xml       # Sysmon configuration
|   |-- important_events.md     # Key Event IDs reference
|   |-- log_forwarding/         # WEF configuration
|
|-- Exercises/                  # Hands-on labs
|   |-- 01_user_management/
|   |-- 02_permissions/
|   |-- 03_gpo_hardening/
```

---

## Windows Architecture Fundamentals

### Key Components to Understand

| Component | Description | Security Relevance |
|-----------|-------------|-------------------|
| Registry | Hierarchical database for settings | Persistence, configuration attacks |
| Services | Background processes | Privilege escalation via misconfig |
| SAM Database | Local user credentials | Credential theft target |
| LSASS | Authentication process | Mimikatz target |
| WMI | Management infrastructure | Lateral movement vector |
| PowerShell | Scripting engine | Living-off-the-land attacks |

### Security Principals
- **Users:** Individual accounts
- **Groups:** Collections of users/computers
- **Computers:** Machine accounts in AD
- **Service Accounts:** Accounts for services
- **SIDs:** Security Identifiers (unique identifiers)

---

## Group Policy Security Settings

### Critical GPO Settings to Configure

**Account Policies:**
```
Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies
- Password Policy: 14+ characters, complexity, 24 password history
- Account Lockout: 5 attempts, 30 minute lockout, 30 minute reset
```

**Audit Policy:**
```
Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy
- Logon/Logoff: Success and Failure
- Object Access: Success and Failure
- Privilege Use: Success and Failure
- Process Creation: Success
```

**Security Options:**
```
Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
- Network access: Do not allow anonymous enumeration of SAM accounts
- Network security: LAN Manager authentication level: Send NTLMv2 only
- User Account Control: All settings enabled
```

### PowerShell Commands for GPO
```powershell
# View current GPO settings
gpresult /r
gpresult /h gpo_report.html

# Force GPO update
gpupdate /force

# View security policy
secedit /export /cfg security_export.cfg
```

---

## Security Baselines

### CIS Benchmarks
Download from: https://www.cisecurity.org/cis-benchmarks
- Windows 10 Enterprise
- Windows 11 Enterprise
- Windows Server 2022

### Microsoft Security Baseline
Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319
- Includes GPO templates
- LGPO tool for local policy

### DISA STIGs
Download from: https://public.cyber.mil/stigs/
- Department of Defense standards
- Very restrictive, good for reference

---

## Event Logging Configuration

### Enable Command Line Logging
```
Computer Configuration > Administrative Templates > System > Audit Process Creation
- Include command line in process creation events: Enabled
```

### Sysmon Deployment
```powershell
# Download Sysmon
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with configuration
sysmon64.exe -accepteula -i sysmonconfig.xml

# Recommended configs:
# https://github.com/SwiftOnSecurity/sysmon-config
# https://github.com/olafhartong/sysmon-modular
```

### Critical Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4648 | Security | Explicit credentials (runas) |
| 4672 | Security | Special privileges assigned |
| 4688 | Security | Process created |
| 4697 | Security | Service installed |
| 4698/4699 | Security | Scheduled task created/deleted |
| 4720 | Security | User account created |
| 4732 | Security | Member added to local group |
| 7045 | System | Service installed |
| 1 | Sysmon | Process creation with hash |
| 3 | Sysmon | Network connection |
| 11 | Sysmon | File created |

---

## Windows Defender Configuration

### PowerShell Management
```powershell
# Check status
Get-MpComputerStatus

# Update definitions
Update-MpSignature

# Run quick scan
Start-MpScan -ScanType QuickScan

# Configure exclusions (for lab only!)
Add-MpPreference -ExclusionPath "C:\Tools"

# Enable all protection features
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableScriptScanning $false

# View threat detections
Get-MpThreatDetection
```

### Attack Surface Reduction Rules
```powershell
# Enable ASR rules (use with caution in lab)
Add-MpPreference -AttackSurfaceReductionRules_Ids <rule-guid> -AttackSurfaceReductionRules_Actions Enabled

# Key rules:
# Block Office from creating child processes
# Block credential stealing from LSASS
# Block process creations from WMI
```

---

## Exercises

### Exercise 1: User and Permission Management
**Difficulty:** Beginner
**Time:** 1 hour

1. Create local users and groups
2. Configure NTFS permissions
3. Test access with different accounts
4. Document permission inheritance

### Exercise 2: Security Baseline Implementation
**Difficulty:** Intermediate
**Time:** 2-3 hours

1. Download CIS Benchmark for your Windows version
2. Create a GPO implementing key settings
3. Apply and test the GPO
4. Document deviations and justifications

### Exercise 3: Event Log Analysis
**Difficulty:** Intermediate
**Time:** 2 hours

1. Enable advanced audit policy
2. Deploy Sysmon with SwiftOnSecurity config
3. Generate test events (logons, process creation)
4. Query and analyze events with PowerShell

### Exercise 4: Defender Evasion Understanding
**Difficulty:** Advanced
**Time:** 3+ hours

1. Research common evasion techniques
2. Test detection capabilities in lab
3. Document what gets detected vs bypassed
4. Write detection rules for gaps

---

## Resources

### Microsoft Documentation
- https://docs.microsoft.com/en-us/windows/security/
- https://docs.microsoft.com/en-us/windows-server/security/
- https://docs.microsoft.com/en-us/sysinternals/

### Security Guides
- https://adsecurity.org - AD and Windows security
- https://posts.specterops.io - SpecterOps blog
- https://www.yourdomaincontroller.com/learning - Windows security learning

### Tools
- **Sysinternals Suite:** Process Monitor, Autoruns, TCPView
- **Sysmon:** Advanced logging
- **LGPO:** Local Group Policy Object utility
- **PolicyAnalyzer:** Compare GPO settings

---

*Always document your configurations and test in isolated lab environments first.*
