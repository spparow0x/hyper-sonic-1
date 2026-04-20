# 🚀 Hyper-Sonic v1.1 (SECURE)
**Unified Reconnaissance Tool: Smart NMAP + DIRB Parser**

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Hyper-Sonic is an advanced, high-performance reconnaissance tool written in C. It seamlessly unifies **NMAP** port scanning and **DIRB** web directory brute-forcing into a single, intelligent pipeline. Designed for ethical hackers and penetration testers, it automatically parses open web ports and conditionally triggers directory enumeration, saving valuable time and bandwidth.

---

## ✨ Key Features

* **🧠 Smart Pipeline:** Automatically detects open web ports (80, 443, 8080, 8443) from the Nmap scan. If no web ports are open, it intelligently cancels the DIRB scan.
* **🛡️ Hardened Security:** Built-in rigorous input validation to prevent command injection and path traversal attacks during target parsing.
* **⚡ Native Performance:** Uses low-level system calls (`fork`, `execvp`) instead of unsafe `system()` wrappers for executing sub-processes.
* **🎨 Beautiful Output:** Features a clean, colorized terminal UI with categorized HTTP status codes and parsed XML results.
* **📁 Auto-Export:** Option to save clean outputs directly to a designated directory for reporting.

---

## 🛠️ Prerequisites

This tool relies on a Linux/Unix environment with the following packages installed:
* `gcc` (for compilation)
* `nmap`
* `dirb`

*(For Debian/Kali/Ubuntu)*:
```bash
sudo apt update
sudo apt install build-essential nmap dirb
```
## ⚙️ Compilation & Installation
Clone the repository and compile the source code using GCC:

```bash
git clone https://github.com/spparow0x/hyper-sonic.git
cd hyper-sonic
gcc hyper-sonic.c -o hyper-sonic
```
## 📖 Usage
```bash
./hyper-sonic [OPTIONS] <target>
```
### Options:

| Flag | Description |
| :--- | :--- |
| `-n` | Run **NMAP** scan only. |
| `-d` | Run **DIRB** scan only. |
| `-a` | Aggressive mode (Nmap `-A`). |
| `-s` | Stealth SYN scan (Requires `sudo`). |
| `-p` | Specify ports (e.g., `80,443` or `1-1000`). |
| `-w` | Wordlist path for DIRB (default: `common.txt`). |
| `-o` | Save outputs to a specific directory. |
| `-h` | Show help and usage banner. |
## Examples:
1. Full Smart Scan (Default):

```bash
./hyper-sonic scanme.nmap.org
```
2. Stealth Scan on specific ports, saving output:

```bash
sudo ./hyper-sonic -s -p 22,80,443 -o ./recon_results 10.0.0.1
```
3. Directory Brute-Force only with custom wordlist:

```bash
./hyper-sonic -d -w /usr/share/wordlists/dirb/big.txt http://10.0.0.1
```
## ⚠️ Legal Disclaimer
Hyper-Sonic is created strictly for educational purposes and authorized ethical hacking. Do not use this tool against any system, network, or application that you do not own or have explicit, documented permission to test. The author is not responsible for any misuse, damage, or illegal activities caused by this tool. Stay legal, stay sharp.

Developed with 💻 and ☕ by: EL KARKOUBI YOUSSEF(spparow0x)
