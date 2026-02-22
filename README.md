# SEC_LAB — Security Home Lab

An Active Directory home lab for hands-on training in intrusion detection, ethical hacking, and digital forensics. This repository documents my journey from building infrastructure to detecting real attack techniques and investigating incidents.

## Repository Structure

```
├── Portfolio Documents/    # Completed technical writeups (start here!)
├── Lab_Journal/            # Ongoing progress notes and observations
├── Lab_Screenshots/        # Visual documentation of lab activities
├── LEARNING_ROADMAP.md     # Structured progression plan
└── README.md
```

## Featured Projects

### Detecting SMB Brute Force Attacks with Wazuh SIEM
Executed a credential stuffing attack using CrackMapExec, then built custom Wazuh detection rules to identify the attack pattern through failed login correlation.

Skills demonstrated: SIEM operation, detection engineering, log analysis, attack simulation

### Memory Forensics: Detecting Encoded PowerShell Execution
Simulated a malicious encoded PowerShell payload on a domain workstation, captured a 9GB memory dump with WinPMEM, and analyzed it using Volatility 3 to decode the payload and reconstruct the attack.

Skills demonstrated: Memory acquisition, Volatility 3, process analysis, PowerShell forensics

---

## Network Configuration

### VMnet8 (10.0.0.0/24)

Domain: lab.local  
DHCP Range: 10.0.0.10 - 10.0.0.254

| VM                  | IP           | Role                          | Domain     |
|---------------------|--------------|-------------------------------|------------|
| DC01 (Win Server 2022) | 10.0.0.5  | Domain Controller             | lab.local  |
| Kali Linux          | 10.0.0.10    | Attack box                    | -          |
| Metasploitable2     | 10.0.0.11    | Vulnerable target             | -          |
| Ubuntu Client       | 10.0.0.12    | Monitored endpoint            | lab.local  |
| Wazuh Manager       | 10.0.0.13    | SIEM/Detection                | -          |
| WS01 (Windows 11)   | DHCP         | Domain workstation            | lab.local  |

### Isolated Network (172.16.0.0/24)

| VM       | IP            | Role             |
|----------|---------------|------------------|
| FLARE VM | 172.16.0.128  | Malware analysis |

---

## Learning Roadmap

I'm following a structured five-phase approach. See [LEARNING_ROADMAP.md](LEARNING_ROADMAP.md) for full details.

| Phase | Focus | Status |
|-------|-------|--------|
| 1. Foundations | Lab infrastructure, AD setup, baseline documentation | Complete |
| 2. Intrusion Detection | SIEM operation, detection engineering, threat hunting | In Progress |
| 3. Ethical Hacking | Reconnaissance, exploitation, AD attacks | Upcoming |
| 4. Digital Forensics | Disk/memory forensics, malware analysis | In Progress |
| 5. Integration | Purple team exercises, full incident response | Upcoming |

---

## Tools and Technologies

Infrastructure: VMware Workstation, Windows Server 2022, Windows 11, Ubuntu, Kali Linux

Detection and SIEM: Wazuh 4.14.2, Sysmon, Windows Event Logs

Offensive: Nmap, CrackMapExec, Metasploit, BloodHound (planned)

Forensics: Volatility 3, WinPMEM, FLARE VM, Wireshark

---

## Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Volatility 3](https://github.com/volatilityfoundation/volatility3)
- [SANS DFIR Cheat Sheets](https://www.sans.org/posters/)

---

## Contact

Feel free to connect if you have questions about this lab or want to discuss security topics.

LinkedIn: www.linkedin.com/in/ben-mangus |  
Email: Mangusben11@gmail.com
