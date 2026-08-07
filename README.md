<div align="center">

# 🐍 Cockpit Lite — MCP Server

**Lightweight, single-file MCP Server for pentesting — packed with *rare* features most MCPs don't have.**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%2F%20Parrot%20OS-black)]()

Only **471 lines of code**, a single file, yet it ships features usually found only in much larger frameworks.

</div>

---

## ✨ Rare Features (seldom seen in other MCPs)

- 🚀 **Parallel Recon** — run `nmap`, `httpx`, `whatweb`, `subfinder` simultaneously via a thread pool
- 🗄️ **Findings DB + Dedup** — SQLite-backed, automatic deduplication via SHA-256 hashing
- 🏷️ **COMPLIANCE Auto-Tag** — every finding is auto-mapped to **OWASP Top 10 + PCI-DSS + CWE**
- 🕵️ **Intel Correlation** — automatic Shodan & CVE enrichment after scans
- 🧭 **Attack Path Analyzer** — per-open-port exploit advice (MITRE-informed)
- 🔄 **Scan Diff Engine** — compare two scans to detect environment changes over time
- 📄 **Self-contained HTML Report** — no WeasyPrint, pure Python (lighter & zero native deps)

## 🧰 Wrapped Tools

`nmap` · `rustscan` · `httpx` · `whatweb` · `subfinder` · `dnsenum` · `whois` · `nuclei` · `nikto` · `gobuster` · `ffuf` · `sqlmap` · `arjun` · `wafw00f` · `theharvester` · `searchsploit`

## 📦 Installation

```bash
git clone https://github.com/kom9/-hacking-cockpit-lite-.git
cd -hacking-cockpit-lite-
pip install -r requirements.txt
```

Install the pentest tools you want to use (the server invokes tools **natively** on the host — Kali / Parrot OS recommended):

```bash
sudo apt install -y nmap sqlmap nuclei nikto gobuster ffuf whatweb httpx subfinder
```

## ⚙️ MCP Client Configuration

Add to your MCP client config (e.g. `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cockpit-lite": {
      "command": "python3",
      "args": ["/absolute/path/to/hacking_cockpit_lite.py"],
      "env": { "SHODAN_API_KEY": "", "VIRUSTOTAL_API_KEY": "" }
    }
  }
}
```

**Optional environment variables:** `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` — enable intel correlation.

## 🚀 Exposed MCP Tools

| Tool | Description |
|------|-------------|
| `cockpit_status` | System health & installed tools |
| `run_recon` | **Parallel** recon + auto intel correlation |
| `run_web_scan` | whatweb + nikto + nuclei chain |
| `run_tool` | Run a single allowlisted tool |
| `project_create` | Create a new project |
| `findings_list` | List findings with compliance tags |
| `analyze_attack_path` | Attack path analyzer |
| `scan_diff` | Diff engine between two scans |
| `generate_report` | Self-contained HTML report |

### Usage example

```
> Create project "acme" with scope 192.168.1.0/24
> run_recon against 192.168.1.10 (parallel)
> analyze attack path for project "acme"
> generate HTML report for project "acme"
```

## 📂 Storage

Data is stored in `~/cockpit_lite/` (database `cockpit_lite.db`, reports, workspace).

## ⚠️ Legal & Responsible Use

For **authorized** security testing and education only. You are solely responsible for complying with all applicable laws and for having explicit written permission before testing any system or network. The author assumes **no liability** for misuse.

## 📄 License

[MIT](LICENSE)
