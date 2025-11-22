# Security Tools Installation Checklist

Reference for setting up attack and defense tools in your lab environment.

---

## Kali Linux - Essential Tools

Most tools come pre-installed on Kali. This checklist covers additional/updated tools.

### Update System First
```bash
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y
```

### Network Reconnaissance
- [x] Nmap (pre-installed)
- [x] Masscan (pre-installed)
- [ ] Rustscan - Fast port scanner
  ```bash
  # Download from https://github.com/RustScan/RustScan/releases
  sudo dpkg -i rustscan_*.deb
  ```
- [ ] Autorecon - Automated reconnaissance
  ```bash
  sudo apt install python3-pip
  pip3 install autorecon
  ```

### Web Application Testing
- [x] Burp Suite (pre-installed)
- [x] Nikto (pre-installed)
- [x] SQLmap (pre-installed)
- [ ] Feroxbuster - Fast directory brute forcing
  ```bash
  sudo apt install feroxbuster
  ```
- [ ] FFuf - Fast web fuzzer
  ```bash
  sudo apt install ffuf
  ```

### Active Directory Tools
- [ ] BloodHound + Neo4j
  ```bash
  sudo apt install bloodhound neo4j
  # Start neo4j and change default password
  sudo neo4j console
  # Access http://localhost:7474, default: neo4j/neo4j
  ```
- [ ] BloodHound Python collector
  ```bash
  pip3 install bloodhound
  ```
- [ ] CrackMapExec
  ```bash
  pip3 install crackmapexec
  ```
- [ ] Impacket suite
  ```bash
  pip3 install impacket
  ```
- [ ] Kerbrute
  ```bash
  # Download from https://github.com/ropnop/kerbrute/releases
  chmod +x kerbrute_linux_amd64
  sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
  ```
- [ ] Evil-WinRM
  ```bash
  sudo gem install evil-winrm
  ```

### Password Cracking
- [x] John the Ripper (pre-installed)
- [x] Hashcat (pre-installed)
- [x] Hydra (pre-installed)
- [ ] SecLists wordlists
  ```bash
  sudo apt install seclists
  # Located at /usr/share/seclists/
  ```

### Exploitation
- [x] Metasploit Framework (pre-installed)
  ```bash
  # Initialize database
  sudo msfdb init
  ```
- [ ] Pwntools (Python exploitation)
  ```bash
  pip3 install pwntools
  ```
- [ ] ROPgadget
  ```bash
  pip3 install ROPgadget
  ```

### Post-Exploitation
- [ ] LinPEAS / WinPEAS
  ```bash
  # Download from https://github.com/carlospolop/PEASS-ng/releases
  # Store in /opt/privesc/
  sudo mkdir -p /opt/privesc
  cd /opt/privesc
  wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
  wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat
  wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
  ```
- [ ] PowerSploit / PowerView
  ```bash
  sudo mkdir -p /opt/powersploit
  cd /opt/powersploit
  git clone https://github.com/PowerShellMafia/PowerSploit.git
  ```

### Reverse Engineering
- [ ] Ghidra
  ```bash
  sudo apt install ghidra
  ```
- [x] Radare2 (pre-installed)
- [ ] pwndbg (GDB enhancement)
  ```bash
  git clone https://github.com/pwndbg/pwndbg
  cd pwndbg
  ./setup.sh
  ```

---

## Windows Target - Defense Tools

### Sysmon (Enhanced Logging)
```powershell
# Download from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Download recommended config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig.xml

# Install Sysmon with config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Sysinternals Suite
```powershell
# Download full suite
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile SysinternalsSuite.zip
Expand-Archive SysinternalsSuite.zip -DestinationPath C:\Tools\Sysinternals
```

Key tools:
- Process Monitor (procmon.exe)
- Process Explorer (procexp.exe)
- Autoruns (autoruns.exe)
- TCPView (tcpview.exe)
- PsExec (psexec.exe)

### Windows Admin Tools
```powershell
# RSAT (Remote Server Administration Tools)
# For AD management from workstation
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

---

## Windows Server - AD Lab Setup

### Install AD DS Role
```powershell
# Install AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest -DomainName "yourlab.local" -InstallDns
```

### Create Lab Users
```powershell
# Create OUs
New-ADOrganizationalUnit -Name "Lab Users" -Path "DC=yourlab,DC=local"
New-ADOrganizationalUnit -Name "Lab Computers" -Path "DC=yourlab,DC=local"

# Create users
$password = ConvertTo-SecureString "LabPassword123!" -AsPlainText -Force
New-ADUser -Name "labuser1" -AccountPassword $password -Enabled $true -Path "OU=Lab Users,DC=yourlab,DC=local"

# Create SPN for Kerberoasting practice
Set-ADUser -Identity labuser1 -ServicePrincipalNames @{Add="HTTP/labuser1.yourlab.local"}
```

---

## Tool Organization

Recommended directory structure on Kali:
```
/opt/
|-- bloodhound/
|-- privesc/
|   |-- linpeas.sh
|   |-- winpeas.exe
|-- powersploit/
|-- wordlists/
    |-- custom/
```

---

## Verification Commands

```bash
# Verify key tools
which nmap rustscan feroxbuster
msfconsole --version
bloodhound --version
crackmapexec --version
impacket-secretsdump --help
```

---

*Update this checklist as you install tools and discover new ones.*
