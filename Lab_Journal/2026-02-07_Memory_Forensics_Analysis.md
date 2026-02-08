# Lab Journal - Memory Forensics Analysis with Volatility 3

**Date:** 2026-02-07
**Phase:** Phase 4 - Digital Forensics
**Exercise:** Memory Analysis (Volatility 3)
**Target:** WS01 (Windows 11, 10.0.0.16)
**Analysis Platform:** Kali Linux (10.0.0.10)

---

## Objective

Analyze a memory dump captured from WS01 after simulated malicious activity to identify indicators of compromise using Volatility 3.

## Setup

- **Memory dump:** `memdump.raw` (9 GB, captured with WinPMEM)
- **Capture time:** 2026-02-04 17:59:03 UTC
- **Tool:** Volatility 3 Framework v2.28.0 (`/home/kali/volatility3/vol.py`)
- **OS identified:** Windows 11 (NT 10.0, build 26100), 64-bit, 4 processors

## Plugins Used

| Plugin | Purpose | Key Findings |
|--------|---------|-------------|
| `windows.info` | Identify OS version | Windows 11 build 26100, 64-bit |
| `windows.pslist` | List all processes | 130+ processes, suspicious PowerShell chain identified |
| `windows.pstree` | Parent-child relationships | Confirmed explorer -> powershell -> powershell -> calc chain |
| `windows.cmdline` | Process command-line arguments | Decoded Base64 encoded PowerShell payload |
| `windows.malfind` | Detect injected code (RWX memory) | Hits on PowerShell processes and Defender (false positive) |
| `windows.netscan` | Network connections | Empty results (Win11 compatibility issue) |

## Findings

### 1. Malicious Process Chain

```
explorer.exe (PID 6392, started 16:17:04)
  └── powershell.exe (PID 13108, started 17:49:46)    <- Interactive session
        └── powershell.exe (PID 13240, started 17:55:34)  <- Encoded command
              └── calc.exe (PID 9600, started 17:55:35, EXITED 17:55:35)  <- PoC payload
```

### 2. Encoded PowerShell Command

**Raw argument:**
```
powershell.exe -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA7ACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwAwADAA
```

**Decoded (Base64 -> UTF-16LE):**
```powershell
Start-Process calc.exe; Start-Sleep -Seconds 300
```

This is a classic attacker proof-of-concept pattern: launch a visible application (calc) to prove code execution, then sleep to keep the process alive.

### 3. Malfind Results (RWX Memory Regions)

| Process | PID | Verdict |
|---------|-----|---------|
| `MsMpEng.exe` | 3296 | **False positive** - Windows Defender JIT engine |
| `OneDrive.exe` | 8980 | **False positive** - .NET application behavior |
| `powershell.exe` | 13108 | **True positive** - Malicious interactive session |
| `powershell.exe` | 13240 | **True positive** - Encoded command executor |
| `powershell.exe` | 10740 | **Expected** - Used for memory acquisition |
| `RuntimeBroker.exe` | 11592 | **False positive** - Normal UWP broker |
| `LockApp.exe` | 11908 | **False positive** - Normal Windows component |

### 4. Other Observations

- **GetHelp.exe (PID 10064):** 183 threads, launched via Settings network diagnostics - legitimate
- **winpmem_mini_x (PID 12352):** Memory acquisition tool, spawned by powershell.exe (PID 10740) - expected
- **wazuh-agent.exe (PID 3308):** Running as expected, monitoring the endpoint
- **netscan returned empty:** Known limitation with Windows 11 memory structures in Volatility 3

## Attack Timeline

| Time (UTC) | Event | Evidence Source |
|------------|-------|----------------|
| 16:16:37 | System boot | `windows.info` SystemTime |
| 16:17:04 | User login (explorer.exe starts) | `windows.pslist` |
| 17:49:46 | Interactive PowerShell session opened | `windows.cmdline` PID 13108 |
| 17:55:34 | Encoded PowerShell command executed | `windows.cmdline` PID 13240 |
| 17:55:35 | calc.exe spawned and exited (PoC) | `windows.pslist` PID 9600 |
| 17:57:37 | Memory acquisition PowerShell opened | `windows.pslist` PID 10740 |
| 17:59:03 | Memory dump captured with WinPMEM | `windows.pslist` PID 12352 |

## Lessons Learned

1. **First-time Volatility 3 cache build takes significant time** - ~10 minutes for 6,138 symbol files on Kali VM. Subsequent runs are much faster.
2. **`windows.netscan` may return empty on Windows 11** - Consider using `windows.netstat` or checking for network artifacts via other means.
3. **`-EncodedCommand` is a key indicator** - Base64 encoded PowerShell is heavily used by attackers to obfuscate payloads.
4. **Malfind produces false positives** - Defender (MsMpEng.exe), .NET apps, and UWP brokers commonly have RWX memory. Context matters.
5. **Process trees reveal attack chains** - The parent-child relationship (explorer -> powershell -> powershell -> calc) is a clear indicator of hands-on-keyboard activity.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|-----------|----|---------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Encoded PowerShell command |
| Obfuscated Files or Information | T1027 | Base64 encoded command |
| Execution via API | T1106 | Start-Process cmdlet |

---

*Tools: Volatility 3 v2.28.0, WinPMEM*
*Next: Document portfolio writeup*
