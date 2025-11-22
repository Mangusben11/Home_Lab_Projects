# Incident Response Report

## Document Control
| Field | Value |
|-------|-------|
| **Incident ID** | IR-YYYY-XXX |
| **Date Detected** | YYYY-MM-DD HH:MM |
| **Date Reported** | YYYY-MM-DD HH:MM |
| **Severity** | Critical/High/Medium/Low |
| **Status** | Open/Contained/Eradicated/Closed |
| **Handler** | Benjamina |

---

## 1. Incident Summary

### 1.1 Overview
[Brief description of what happened]

### 1.2 Classification
- **Type:** [Malware/Unauthorized Access/Data Breach/DoS/Phishing/Other]
- **Attack Vector:** [How the attack occurred]
- **MITRE ATT&CK Tactics:** [T1XXX - Technique Name]

### 1.3 Impact Assessment
| Impact Area | Level | Description |
|-------------|-------|-------------|
| Confidentiality | High/Medium/Low/None | [Details] |
| Integrity | High/Medium/Low/None | [Details] |
| Availability | High/Medium/Low/None | [Details] |

---

## 2. Timeline of Events

| Date/Time | Event | Source |
|-----------|-------|--------|
| YYYY-MM-DD HH:MM | [Event description] | [Log source] |
| YYYY-MM-DD HH:MM | [Event description] | [Log source] |

---

## 3. Detection

### 3.1 How Was It Detected?
[Alert, user report, routine monitoring, etc.]

### 3.2 Detection Indicators
**Indicators of Compromise (IOCs):**
| Type | Value | Context |
|------|-------|---------|
| IP Address | X.X.X.X | [Description] |
| Hash (MD5) | [hash] | [Description] |
| Domain | [domain] | [Description] |
| File Path | [path] | [Description] |

### 3.3 Relevant Log Entries
**Windows Event IDs Observed:**
- Event ID XXXX: [Description]

```
[Relevant log snippet]
```

---

## 4. Affected Assets

| Asset | IP/Hostname | Role | Impact |
|-------|-------------|------|--------|
| [Name] | [IP] | [Server/Workstation/etc.] | [Compromised/At Risk/Clean] |

---

## 5. Analysis

### 5.1 Attack Vector Analysis
[How did the attacker gain access?]

### 5.2 Attacker Actions
[What did the attacker do once inside?]

### 5.3 Root Cause
[What underlying weakness allowed this incident?]

---

## 6. Response Actions

### 6.1 Containment
| Action | Date/Time | Performed By | Result |
|--------|-----------|--------------|--------|
| [Action taken] | [When] | [Who] | [Outcome] |

### 6.2 Eradication
| Action | Date/Time | Performed By | Result |
|--------|-----------|--------------|--------|
| [Action taken] | [When] | [Who] | [Outcome] |

### 6.3 Recovery
| Action | Date/Time | Performed By | Result |
|--------|-----------|--------------|--------|
| [Action taken] | [When] | [Who] | [Outcome] |

---

## 7. Lessons Learned

### 7.1 What Went Well
- [Positive aspect of response]

### 7.2 What Could Be Improved
- [Area for improvement]

### 7.3 Preventive Recommendations
| Recommendation | Priority | Owner | Due Date |
|----------------|----------|-------|----------|
| [Recommendation] | High/Medium/Low | [Person] | [Date] |

---

## 8. Evidence Preservation

| Evidence Item | Location | Hash (SHA256) | Chain of Custody |
|---------------|----------|---------------|------------------|
| [Item] | [Path/Storage] | [Hash] | [Who handled it] |

---

## Appendix: Supporting Documentation
- [Memory dumps]
- [Disk images]
- [Network captures]
- [Screenshots]

---
*Report generated for educational/lab purposes - Simulated incident response exercise*
