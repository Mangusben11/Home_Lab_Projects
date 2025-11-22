# Windows Event IDs - Security Reference

Quick reference for security-relevant Windows Event IDs. Essential for threat detection and incident response.

---

## Account Logon Events (Security Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4624** | Successful logon | Track all authentication |
| **4625** | Failed logon | Brute force, password spray detection |
| **4634** | Logoff | Session tracking |
| **4647** | User initiated logoff | Session tracking |
| **4648** | Logon with explicit credentials | Runas, PTH indicator |
| **4672** | Special privileges assigned | Admin logon tracking |
| **4768** | Kerberos TGT requested | AS-REP roasting detection |
| **4769** | Kerberos service ticket requested | Kerberoasting detection |
| **4771** | Kerberos pre-auth failed | Password spray detection |
| **4776** | NTLM authentication | Pass-the-Hash detection |

### Logon Type Reference (Event 4624/4625)

| Type | Description | Notes |
|------|-------------|-------|
| 2 | Interactive | Local keyboard logon |
| 3 | Network | SMB, network share access |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | RunAs with /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain creds |

---

## Account Management Events (Security Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4720** | User account created | Persistence detection |
| **4722** | User account enabled | Account manipulation |
| **4723** | Password change attempt | Credential events |
| **4724** | Password reset attempt | Admin activity tracking |
| **4725** | User account disabled | Account lifecycle |
| **4726** | User account deleted | Account manipulation |
| **4728** | Member added to global group | Privilege escalation |
| **4732** | Member added to local group | Local admin addition |
| **4735** | Local group changed | Group manipulation |
| **4738** | User account changed | Account modification |
| **4740** | Account locked out | Brute force indicator |
| **4756** | Member added to universal group | AD group changes |
| **4767** | Account unlocked | Admin activity |

---

## Process Events (Security Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4688** | Process created | Command execution audit |
| **4689** | Process terminated | Process lifecycle |

**Important:** Enable command line logging via GPO:
```
Computer Configuration > Administrative Templates > System > Audit Process Creation
> Include command line in process creation events: Enabled
```

---

## Object Access Events (Security Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4656** | Handle requested to object | File/registry access |
| **4657** | Registry value modified | Registry persistence |
| **4658** | Handle closed | Object access tracking |
| **4660** | Object deleted | File deletion tracking |
| **4663** | Object access attempt | File access audit |
| **4670** | Permissions changed | ACL modification |

---

## Privilege Use Events (Security Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4673** | Privileged service called | Sensitive privilege use |
| **4674** | Operation on privileged object | Privilege abuse |
| **4703** | Token rights adjusted | Token manipulation |

---

## System Events

### Security Log
| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4616** | System time changed | Anti-forensics detection |
| **4657** | Registry value modified | Persistence detection |
| **4697** | Service installed | Service persistence |
| **4698** | Scheduled task created | Task scheduler persistence |
| **4699** | Scheduled task deleted | Cleanup detection |
| **4700** | Scheduled task enabled | Task manipulation |
| **4701** | Scheduled task disabled | Task manipulation |
| **4702** | Scheduled task updated | Task modification |
| **4719** | Audit policy changed | Security bypass attempt |
| **4739** | Domain policy changed | AD security changes |

### System Log
| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **7034** | Service crashed | Exploitation indicator |
| **7035** | Service control sent | Service manipulation |
| **7036** | Service state changed | Service lifecycle |
| **7040** | Service start type changed | Persistence |
| **7045** | Service installed | Service persistence |

---

## PowerShell Events (PowerShell Operational Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **4103** | Module logging | PowerShell command details |
| **4104** | Script block logging | Full script content |
| **4105** | Script block start | Execution tracking |
| **4106** | Script block end | Execution tracking |

**Enable via GPO:**
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
> Turn on Module Logging: Enabled
> Turn on Script Block Logging: Enabled
```

---

## Sysmon Events (Sysmon Operational Log)

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| **1** | Process creation | Process with hash, command line |
| **2** | File creation time changed | Timestomping detection |
| **3** | Network connection | Outbound connections |
| **5** | Process terminated | Process lifecycle |
| **6** | Driver loaded | Rootkit detection |
| **7** | Image loaded | DLL injection detection |
| **8** | CreateRemoteThread | Process injection |
| **9** | RawAccessRead | Direct disk read |
| **10** | ProcessAccess | LSASS access detection |
| **11** | FileCreate | File creation tracking |
| **12** | Registry key/value created/deleted | Registry persistence |
| **13** | Registry value set | Registry modification |
| **15** | FileCreateStreamHash | ADS detection |
| **17** | Pipe created | Named pipe creation |
| **18** | Pipe connected | Named pipe connection |
| **22** | DNS query | DNS logging |
| **23** | File delete | File deletion with hash |

---

## Detection Queries

### PowerShell - Failed Logons (Brute Force)
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddHours(-24)
} | Group-Object {$_.Properties[5].Value} |
Where-Object Count -gt 10 |
Sort-Object Count -Descending
```

### PowerShell - Admin Logons
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4672
    StartTime=(Get-Date).AddDays(-1)
} | Select-Object TimeCreated,
    @{N='User';E={$_.Properties[1].Value}}
```

### PowerShell - New Services
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7045
    StartTime=(Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message
```

### PowerShell - Scheduled Tasks Created
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4698
    StartTime=(Get-Date).AddDays(-7)
}
```

---

## Quick Reference Card

### Critical Events to Always Monitor
1. **4625** - Failed logons (brute force)
2. **4624 Type 10** - RDP logons
3. **4648** - Explicit credential use (PTH)
4. **4720** - New user accounts
5. **4732** - Local admin group changes
6. **7045** - New services installed
7. **4698** - Scheduled tasks created
8. **4688** - Process creation (with command line)
9. **Sysmon 1** - Process creation with hash
10. **Sysmon 10** - LSASS access

---

## Resources

- Microsoft Security Auditing: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/
- SANS Windows Logging Cheat Sheet: https://www.sans.org/posters/windows-forensic-analysis/
- Ultimate Windows Security: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

---

*Keep this reference handy during log analysis and detection engineering.*
