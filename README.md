# Home Lab Projects

Security home lab documentation and projects.

## Network Configuration

**VMnet8 (10.0.0.0/24)**
| VM | IP | Role |
|---|---|---|
| Kali Linux | 10.0.0.10 | Attack box |
| Metasploitable2 | 10.0.0.11 | Vulnerable target |
| Ubuntu Client | 10.0.0.12 | Monitored endpoint |
| Wazuh Manager | 10.0.0.13 | SIEM/Detection |

**Isolated Network (172.16.0.0/24)**
| VM | IP | Role |
|---|---|---|
| FLARE VM (Win10) | 172.16.0.128 | Malware analysis |
