# SEC_LAB - Home Lab Projects

Security home lab documentation and projects.

## Network Configuration

### VMnet8 (10.0.0.0/24)

**Domain:** lab.local
**DHCP Range:** 10.0.0.10 - 10.0.0.254

| VM                  | IP           | Role                          | Domain     |
|---------------------|--------------|-------------------------------|------------|
| DC01 (Win Server 2022) | 10.0.0.5  | Domain Controller             | lab.local  |
| Kali Linux          | 10.0.0.10    | Attack box                    | -          |
| Metasploitable2     | 10.0.0.11    | Vulnerable target             | -          |
| Ubuntu Client       | 10.0.0.12    | Monitored endpoint            | lab.local  |
| Wazuh Manager       | 10.0.0.13    | SIEM/Detection                | -          |
| Windows 11          | DHCP         | Domain workstation            | lab.local  |

### Isolated Network (172.16.0.0/24)

| VM       | IP            | Role             |
|----------|---------------|------------------|
| FLARE VM | 172.16.0.128  | Malware analysis |
