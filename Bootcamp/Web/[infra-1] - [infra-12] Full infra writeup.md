# Standoff 365 Bootcamp — Full Infrastructure Walkthrough

![](https://img.shields.io/badge/Platform-Standoff_365-purple?style=for-the-badge)
![](https://img.shields.io/badge/Difficulty-Mixed-orange?style=for-the-badge)
![](https://img.shields.io/badge/OS-Windows%20AD%20%2B%20Linux-informational?style=for-the-badge)
![](https://img.shields.io/badge/Category-Infrastructure%20%7C%20AD%20%7C%20Phishing%20%7C%20PrivEsc-orange?style=for-the-badge)
![](https://img.shields.io/badge/Tasks-12%20%2F%2012-brightgreen?style=for-the-badge)

## Summary

A complete walkthrough of the Standoff 365 Bootcamp infrastructure — 12 tasks spanning external reconnaissance, OWA password spraying, VPN access, Active Directory enumeration, lateral movement across Windows workstations, privilege escalation via service binary hijack, credential harvesting from KeePass databases and LSASS dumps, and Kerberoasting. The infrastructure simulates a corporate network (`edu.stf`) with a DMZ perimeter, an internal AD domain, Exchange mail server, MSSQL and SharePoint servers, and multiple employee workstations.

Originally intended to write each task as a separate post, but some tasks are so short they barely warrant a paragraph — especially when the Bootcamp hints essentially hand you the solution. So here's the full chain in one document.

```
External Recon → OWA Password Spray → VPN Access → Internal AD Recon
  → WinRM to HR Workstation → Credential Discovery → Service Binary Hijack (SYSTEM)
  → Lateral Movement (ws_admin creds) → KeePass Cracking → LSASS Dump
  → Kerberoasting → SharePoint Access
```

## MITRE ATT&CK Mapping

| Phase | Tactic | Technique | ID |
|:------|:-------|:----------|:---|
| Email harvesting from website | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Gather Victim Identity Info: Email Addresses](https://attack.mitre.org/techniques/T1589/002/) | `T1589.002` |
| DNS MX record lookup | [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) | [Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | `T1595.002` |
| OWA password spraying | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | `T1110.003` |
| VPN credential reuse | [Initial Access](https://attack.mitre.org/tactics/TA0001/) | [Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) | `T1078.002` |
| Internal network scanning | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | `T1046` |
| LDAP user attribute query | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) | `T1087.002` |
| WinRM remote access | [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/) | `T1021.006` |
| Plaintext credential discovery | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) | `T1552.001` |
| Service binary hijack | [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [Hijack Execution Flow: Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010/) | `T1574.010` |
| Process migration for persistence | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Process Injection](https://attack.mitre.org/techniques/T1055/) | `T1055` |
| KeePass database cracking | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Credentials from Password Stores: Password Managers](https://attack.mitre.org/techniques/T1555/005/) | `T1555.005` |
| LSASS credential dumping | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) | `T1003.001` |
| Kerberoasting | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) | `T1558.003` |

## CVE Reference

| CVE | CVSS 3.1 | Severity | Description |
|:----|:---------|:---------|:------------|
| [CVE-2021-1675](https://nvd.nist.gov/vuln/detail/CVE-2021-1675) | **8.8** | High | PrintNightmare — Windows Print Spooler RCE via malicious printer driver (attempted, did not work on this infrastructure) |

---

## [infra-1] External Reconnaissance — `T1589.002`

The hint directs us to `www.edu.stf` to find email addresses. They're sitting in the page footer — no fuzzing, no source code diving, just scrolling down. Collect them all; every one of these will be useful later.

## [infra-2] Gaining Access to Internal Email — `T1595.002` `T1110.003`

My initial mistake was assuming the mail server lived on the same host as the website. Having already compromised `www.edu.stf` from the web tasks, I checked its internal ports — nothing.

Back to basics. The mail server is a separate host, and `dig` reveals where it lives:

```bash
dig MX edu.stf @10.124.1.240
```

```
;; ANSWER SECTION:
edu.stf.    604800  IN  MX  10 mail.edu.stf.

;; ADDITIONAL SECTION:
mail.edu.stf.  604800  IN  A  10.124.1.203
```

Add `mail.edu.stf` to `/etc/hosts`. Some writeup authors reach for Burp Suite at this point, but for 3 emails and 10 passwords, that's the equivalent of driving a dump truck to the house next door. The `atomizer` CLI tool handles OWA spraying cleanly:

```bash
atomizer owa mail.edu.stf spray.txt users_standoff.txt -i 0:00:01
```

```
[+] Using OWA autodiscover URL: https://exchange.edu.stf/autodiscover/autodiscover.xml
[+] Got internal domain name using OWA: edu
...
[+] Dumped 2 valid accounts to owa_valid_accounts.txt
```

Two valid accounts found. Send an email from either one — the flag arrives in the reply.

## [infra-3] VPN Access — `T1078.002`

This task is directly linked to one of the web tasks. I'd already found the `.ovpn` config file during directory fuzzing. Copy the contents, save as `.ovpn`, connect using the credentials from the previous task.

## [infra-4] Internal Reconnaissance (Active Directory) — `T1046` `T1087.002`

The VPN config reveals the internal network layout:

```
route 10.154.16.0 255.255.254.0
ifconfig 10.154.17.5 255.255.255.224
dhcp-option DNS 10.154.16.134
```

Our internal IP is `10.154.17.5/27` (range `10.154.17.0–10.154.17.31`). The mail server at `10.124.1.203` belongs to the DMZ, but AD resources live in `10.154.16.0/23`.

### Host Discovery

```bash
nmap -sn -v 10.154.16.0/23 -oG live_hosts.txt
grep "Up" live_hosts.txt | awk '{print $2}' > targets.txt
```

Build an `/etc/hosts` file from the results:

```bash
awk '/Status: Up/ && $3 !~ /^\(\)$/ {
    ip = $2; host = $3; gsub(/[()]/, "", host); print ip, host
}' live_hosts.txt > awk-hosts.txt
```

### AD Service Mapping

Targeted port scan for critical AD infrastructure:

```bash
nmap -sS -Pn -p 88,135,139,389,445,3268,3389,80,443 -iL targets.txt -oN ad_services.txt
```

SMB sweep to identify Windows machines, domain membership, and OS versions:

```bash
nxc smb 10.154.16.0/23
```

<img width="1919" height="961" alt="Standoff365_infra_4_smb_scan" src="https://github.com/user-attachments/assets/83908bf9-b44a-4752-8cb5-46025ecd7662" />

With domain credentials, query LDAP for the target user's phone number:

```bash
ldapsearch -x -H ldap://10.154.16.134 \
    -D "r_andrews@edu.stf" -w "dancer" \
    -b "DC=edu,DC=stf" "(sAMAccountName=*rodriquez*)" | grep "phone"
```

## [infra-5] HR Workstation Access — `T1021.006`

WinRM sweep across the internal network with valid credentials:

```bash
nxc winrm 10.154.16.0/23 -u 's_dotson' -p '***'
```

Connect and read the flag.

## [infra-6] HR Department Computer Access — `T1552.001`

This task was designed around **phishing** — craft a Word document with a macro containing a reverse shell, email it to an employee, and catch the callback. I built the macro, tested it locally with Adaptix C2 — perfect session. But on the actual target, emails sent from both accounts at various times simply vanished into the void. No bounce, no response, no callback. The mail equivalent of shouting into a canyon.

**Alternative path:** While scanning one of the workstations, I found plaintext credentials for two `ws_admin` accounts. A quick credential check returned the coveted `(Pwn3d!)` against the target PC. Connect via WinRM, read the flag. Sometimes the scenic route is the only route that exists.

## [infra-7] HR Workstation Privilege Escalation — `T1574.010`

With WinRM access, upload and run **SharpUp** for privilege escalation enumeration:

> **Compilation note:** SharpUp must be compiled with `.NET Framework 4.5` targeting, not the default 3.5. In `SharpUp.csproj`, change `<TargetFrameworkVersion>v3.5</TargetFrameworkVersion>` to `v4.5` before building with `xbuild`. Without this, the binary throws version mismatch errors on the target.

```bash
xbuild SharpUp.csproj /p:Configuration=Release /p:Platform="AnyCPU"
```

Transfer to target and run:

```
C:\Users\S_Dotson\Documents\SharpUp.exe audit
```

<img width="1896" height="910" alt="Standoff365_infra_7_powerup_win_privs" src="https://github.com/user-attachments/assets/38c99a0f-8615-4dcc-93aa-8a19608fd6f5" />


SharpUp identifies a **modifiable service binary** with a stopped service. The exploitation is straightforward: replace the service executable with an Adaptix C2 agent (generated as "Service Exe"), rename the original, drop the payload in its place, and reboot.

<img width="1919" height="933" alt="Standoff365_infra_7_adaptix_c2_winprivesc" src="https://github.com/user-attachments/assets/0c44865b-db7a-46d1-bc71-f3b0b6d99480" />


The new session comes back as `s_dotson` but with **High Integrity Label** and significantly more privileges. Escalate to SYSTEM and migrate into a system process for persistence:

<img width="1897" height="914" alt="Standoff365_infra_7_adaptix_c2_system" src="https://github.com/user-attachments/assets/1e874561-adc5-481a-a503-eb8dc77088ff" />

Flag is at the root of `C:\`.

> **Don't forget:** Run WinPEAS on this box too. It reveals additional `ws_admin` credentials in plaintext — these will be essential for later tasks.

## [infra-8] Second HR Workstation — Lateral Movement

With `ws_admin` credentials from the previous task, the intended local privilege escalation becomes irrelevant. Connect directly, read the flag.

<img width="1638" height="825" alt="Standoff365_infra_8" src="https://github.com/user-attachments/assets/d06823bb-9679-4016-ac23-b6b8d6350335" />

## [infra-9] Internal Service Exploitation — `T1555.005`

This task was supposed to involve **PrintNightmare** ([CVE-2021-1675](https://github.com/cube0x0/CVE-2021-1675)). The vulnerability works by tricking the Windows Print Spooler into loading a malicious DLL as a printer driver — the DLL executes as SYSTEM. Any valid domain credentials are sufficient to trigger it.

I studied it thoroughly. Tested multiple exploit versions, including the Metasploit module. Every attempt returned `rpc_s_access_denied`. The service was either patched or hardened — either way, this path was a dead end.

**Alternative path:** While enumerating neighboring workstations with existing credentials, I found a `Database.kdbx` file (KeePass database) in the Documents folder of `L_Shepherd_admin`.

<img width="1919" height="962" alt="Standoff365_infra_9" src="https://github.com/user-attachments/assets/9f24cbba-d006-42cc-b154-04e91bbd9fa9" />

Crack the KeePass master password with `john`:

```bash
keepass2john Database.kdbx > kp_hash.txt
john kp_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

<img width="1136" height="446" alt="Standoff365_infra_9_database" src="https://github.com/user-attachments/assets/99ed5431-4a64-45ec-ae97-1209c74e3921" />

<img width="1919" height="962" alt="Standoff365_infra_9_database_open" src="https://github.com/user-attachments/assets/2cb9a886-1ace-4108-9f1b-8c0a538b31f3" />


Two new sets of credentials. Use them to access the BACKUP server and read the flag.

## [infra-10] Workstation Admin Account Access — `T1021.006`

The target workstation has SMB with READ/WRITE access to two shares:

<img width="1919" height="959" alt="Standoff365_infra_10" src="https://github.com/user-attachments/assets/5043c6c0-0a73-4588-8990-65a76b6cd153" />

Connect via `smbclient`, read the flag, upload an Adaptix C2 agent for convenience.

> I actually stumbled on this flag *before* solving infra-9 — while crawling through neighboring workstations looking for credentials. Sometimes flags find you.

## [infra-11] Password Recovery — `T1003.001`

The task calls for an LSASS dump via `mimikatz`. But when you already have a SYSTEM-level session in Adaptix C2, there's a more elegant approach:

```
lsadump_secrets
```

<img width="1919" height="962" alt="Standoff365_infra_11" src="https://github.com/user-attachments/assets/49f84794-26fb-4c9b-a484-0ccd202387db" />

The password comes back in **plaintext** — no cracking required. This doesn't always work (LSASS protection, Credential Guard, etc.), but on this box it did.

## [infra-12] Internal Service Exploitation (SharePoint) — `T1558.003`

I spent a significant amount of time chasing the wrong target here — went after MSSQL and BACKUP servers looking for DC access, found inactive websites, extracted credentials, tunneled internal ports. All interesting, all wrong.

The task specifically asks for **SharePoint** (`SHPOINT`). The credentials can be found through straightforward enumeration, but the intended path is **Kerberoasting**:

```bash
nxc ldap edu.stf -u Internet -p Web12345678 --kerberoasting out.txt
```

Crack the TGS hash with `john` — takes about 3 seconds with `rockyou.txt`:

<img width="1919" height="962" alt="Standoff365_infra_12_Kerberoasting" src="https://github.com/user-attachments/assets/0900c9ee-be66-466a-adc2-c110c630b31b" />

Log in via `evil-winrm`, read the flag. Infrastructure complete.

---

## Post-Mortem: Thoughts on the Standoff 365 Bootcamp

This was my first time tackling a full-scale infrastructure engagement, and I completed it in **6 days**. During those 6 days, I filed 3 support tickets — because the infrastructure had a habit of breaking at inconvenient moments.

### The Numbers

According to the completion indicator, **52 people** fully completed the Bootcamp.

<img width="1411" height="297" alt="Screenshot From 2026-06-03 12-33-29" src="https://github.com/user-attachments/assets/1baf362e-4750-45fb-affe-5e1d5eb9b96f" />

Active participants: **2,820**.

<img width="360" height="227" alt="Screenshot From 2026-06-03 12-34-45" src="https://github.com/user-attachments/assets/7a24b269-777d-492c-8c88-08606840d37f" />

That's a **1.84% completion rate**. For a platform that markets its Bootcamp as beginner-friendly, that number deserves examination.

### Why So Low?

**The difficulty wall.** The Bootcamp is labeled for beginners, but multiple tasks require intermediate-to-advanced Active Directory knowledge, C2 framework experience, and the ability to pivot when intended exploit paths fail. Most newcomers likely hit a wall within the first few tasks.

**Infrastructure instability.** During my run, the web application lost its database connection on a Friday evening. Support responded on Monday morning. Two days of downtime with no workaround. If this happens on a key task — say, the VPN config that gates access to the entire internal network — you're simply stuck. This is likely the biggest contributor to dropout: people sit down on a free evening to hack, hit a broken task, file a ticket, and by the time it's resolved, the motivation has evaporated.

**Stale hints.** Some hints reference exploits or paths that no longer work on the current infrastructure. PrintNightmare, for instance, was part of the intended solution for infra-9 but consistently returned access denied errors. I found alternative paths, but a less experienced participant would reasonably assume they're doing something wrong and give up.

**Hints that aren't hints.** On the opposite end, some "hints" are outright solutions: "use exploit X with CVE number Y." Not necessarily bad for learning, but it sets an inconsistent expectation — sometimes you're expected to research and discover, sometimes you're handed the answer.

### What Works

The infrastructure itself — when it's running — is a solid Windows AD environment with realistic complexity. The mix of Linux servers (Debian, Ubuntu) and Windows workstations provides genuine experience with `netexec`, `impacket`, `certipy-ad`, and C2 frameworks in a networked environment rather than isolated boxes. The vulnerabilities aren't the overused CTF classics — there's real configuration variety that mirrors what you'd find in a corporate penetration test.

And it's free. That matters.

### The Free Tier Trade-Off

But free means no SLA. Don't be surprised if you come home from work excited to hack and find a broken task. Don't expect weekend support. Don't expect the VPN config task to be available if the web server it depends on is down. The platform is valuable *despite* these issues, not *because* they're absent.

> **Final note:** As of writing, I haven't officially "completed" the Bootcamp — the final task requires a written report reviewed by a jury, and it's been under review for 6 days. So factor in patience as a skill you'll need.

My experience. Others may have a perfectly smooth run. But after talking to colleagues, I know I'm not the only one who didn't.

---

*Writeup by [@alfabuster](https://github.com/alfabuster)*
