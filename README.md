<div align="center">

# 🐍 Cockpit Lite — MCP Server

**Ringan, mandiri (single-file), tapi fitur CADAS yang jarang ada di MCP lain.**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%2F%20Parrot%20OS-black)]()

Hanya **471 baris** kode, satu file, tetapi membawa fitur "rare tech" yang biasanya hanya ada di framework besar:

</div>

---

## ✨ Fitur CADAS (jarang ada di MCP lain)

- 🚀 **Parallel Recon** — jalankan `nmap`, `httpx`, `whatweb`, `subfinder` serentak (ThreadPool)
- 🗄️ **Findings DB + Dedup** — SQLite, hapus duplikat otomatis via hash
- 🏷️ **Auto-tag COMPLIANCE** — setiap temuan otomatis dipetakan ke **OWASP Top 10 + PCI-DSS + CWE**
- 🕵️ **Intel Correlation** — enrichment Shodan & CVE otomatis setelah scan
- 🧭 **Attack Path Analyzer** — saran langkah exploit per port terbuka (MITRE-informed)
- 🔄 **Scan Diff Engine** — bandingkan dua scan untuk deteksi perubahan lingkungan
- 📄 **HTML Report MANDIRI** — tanpa WeasyPrint, pure Python (lebih ringan)

## 🧰 Tools yang diwrap

`nmap` · `rustscan` · `httpx` · `whatweb` · `subfinder` · `dnsenum` · `whois` · `nuclei` · `nikto` · `gobuster` · `ffuf` · `sqlmap` · `arjun` · `wafw00f` · `theharvester` · `searchsploit`

## 📦 Installasi

```bash
git clone https://github.com/kom9/-hacking-cockpit-lite-.git
cd -hacking-cockpit-lite-
pip install -r requirements.txt
```

> Install tools yang ingin dipakai (contoh: `sudo apt install -y nmap sqlmap nuclei ...`).
> Server memanggil tools **native di host** (direkomendasikan Kali / Parrot OS).

## ⚙️ Konfigurasi MCP Client

Tambah ke config MCP client Anda (mis. `claude_desktop_config.json`):

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

**Environment variables (opsional):** `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` untuk intel correlation.

## 🚀 Tools MCP yang diekspos

| Tool | Fungsi |
|------|--------|
| `cockpit_status` | Kesehatan sistem & tools online |
| `run_recon` | **Parallel** recon + intel correlation otomatis |
| `run_web_scan` | Chain whatweb + nikto + nuclei |
| `run_tool` | Jalankan satu tool dari allowlist |
| `project_create` | Buat project baru |
| `findings_list` | List temuan dengan compliance tag |
| `analyze_attack_path` | Attack path analyzer |
| `scan_diff` | Diff engine dua scan |
| `generate_report` | HTML report mandiri |

### Contoh penggunaan

```
> Buat project "acme" scope 192.168.1.0/24
> run_recon terhadap 192.168.1.10 (parallel)
> analisis attack path project "acme"
> generate report HTML project "acme"
```

## 📂 Storage

Data disimpan di `~/cockpit_lite/` (DB `cockpit_lite.db`, reports, workspace).

## ⚠️ Legal & Responsible Use

Untuk **pengujian keamanan yang diizinkan** dan edukasi saja. Anda bertanggung jawab mematuhi hukum dan memiliki izin tertulis sebelum menguji sistem apa pun.

## 📄 License

[MIT](LICENSE)
