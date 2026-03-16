<p align="center">
  <img src="Standoff_365.jpg" alt="Standoff 365 Banner" width="600">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Standoff_365-FF4136?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyTDIgMTloMjBMMTIgMnptMCAxMWgtMlY5aDJ2NHptMCAzaC0ydi0yaDJ2MnoiLz48L3N2Zz4=&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Focus-Red_Team_|_Offensive_Security-critical?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Focus">
  <img src="https://img.shields.io/badge/Type-Cyberbattle_|_Cyberrange-blueviolet?style=for-the-badge&logo=target&logoColor=white" alt="Type">
  <img src="https://img.shields.io/badge/OS-Linux_|_Windows-informational?style=for-the-badge&logo=linux&logoColor=white" alt="OS">
</p>

<h1 align="center">⚔️ Standoff 365 — Writeups</h1>

<p align="center">
  <i>Writeups from the <a href="https://standoff365.com">Standoff 365</a> platform — cyberbattles, cyberrange challenges, and red team engagements on hyperrealistic infrastructure replicas.</i>
</p>

---

## 🔥 About Standoff 365

[Standoff 365](https://standoff365.com) is a cybersecurity platform by [Positive Technologies](https://www.ptsecurity.com/) that goes far beyond traditional CTF competitions. Instead of isolated VMs and toy challenges, Standoff simulates **full-scale virtual states** with real-world industry segments — banking, energy, oil & gas, metallurgy, IT, logistics, and urban infrastructure.

Red teams breach perimeters, perform lateral movement, and trigger **critical events** across interconnected enterprise environments. Think of it as HTB Pro Labs on steroids — with live blue teams actively hunting you in real time.

### Platform Products

| Product | Description |
|:---|:---|
| **[Cyberbattle](https://cyberbattle.standoff365.com)** | International cyber exercise — red teams vs blue teams on a virtual state infrastructure |
| **[Cyberrange](https://range.standoff365.com)** | 24/7 online environment for practicing security testing and vulnerability detection |
| **[Bug Bounty](https://bugbounty.standoff365.com)** | Russia's largest bug bounty platform with 100+ programs |
| **[Cyberbones](https://standoff365.com)** | Online simulator for incident investigation based on real cyberbattle cases |

---

## 📂 Repository Structure

Each engagement or challenge has its own directory with a detailed writeup:

```
Standoff-365-Writeups/
│
├── Bootcamp/
│   ├── [web-1-1] Remote code execution (RCE) on library.edu.stf/
│   │   └── writeup.md
│   └── ...
│
├── cyberrange/
│   ├── challenge-name/
│   │   └── writeup.md
│   └── ...
│
└── README.md
```

---

## 📋 Writeup Format

Every writeup follows a consistent structure adapted for multi-stage, infrastructure-level engagements:

| Section | Description |
|:---|:---|
| **Summary** | One-liner: industry segment → attack chain → critical event triggered |
| **Reconnaissance** | Perimeter scanning, service enumeration, OSINT on the segment |
| **Initial Access** | Perimeter breach, exploiting external-facing services |
| **Lateral Movement** | Pivoting through internal networks, credential harvesting, domain escalation |
| **Critical Event** | Triggering the target objective (data exfiltration, ICS disruption, etc.) |
| **Vulnerabilities** | Discovered CVEs, misconfigurations, and logic flaws |
| **Lessons Learned** | Key takeaways, TTPs mapped to MITRE ATT&CK where applicable |

---

## 🛠 Toolbox

| Phase | Tools |
|:---|:---|
| **Scanning** | Nmap, Rustscan, Masscan |
| **Web** | Burp Suite, ffuf, Gobuster, Nuclei |
| **Exploitation** | Metasploit, custom scripts, CrackMapExec |
| **Post-Exploitation** | LinPEAS, WinPEAS, BloodHound, Mimikatz, Rubeus |
| **Pivoting** | Ligolo-ng, Chisel, SSH tunneling, proxychains |
| **AD Attacks** | Impacket, Certipy, BloodHound, ldapdomaindump |
| **General** | Python, CyberChef, John the Ripper, Hashcat |

---

## ⚠️ Disclaimer

These writeups are published strictly for **educational and documentation purposes**.  
All engagements were conducted within the authorized scope of the Standoff 365 platform.  
Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

<p align="center">
  <a href="https://standoff365.com/profile/alfabuster/"><img src="https://img.shields.io/badge/Standoff_365-Profile-FF4136?style=flat-square&logo=target&logoColor=white" alt="Standoff 365"></a>
  <a href="https://github.com/alfabuster"><img src="https://img.shields.io/badge/GitHub-@alfabuster-181717?style=flat-square&logo=github&logoColor=white" alt="GitHub"></a>
</p>
