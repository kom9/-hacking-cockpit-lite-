#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  COCKPIT LITE - MCP Server v1.0                              ║
║  Ringan, mandiri (single-file), tapi FITUR CADAS yang jarang  ║
║  ada di MCP lain:                                            ║
║   • Parallel Recon (ThreadPool)                              ║
║   • Findings DB + dedup + auto-tag COMPLIANCE (OWASP/PCI/CWE)║
║   • Intel Correlation otomatis (Shodan/CVE pasca-scan)        ║
║   • Attack Path Analyzer (MITRE-informed)                    ║
║   • Scan Diff Engine (bandingkan 2 scan)                     ║
║   • HTML Report MANDIRI (tanpa WeasyPrint)                   ║
╚══════════════════════════════════════════════════════════════╝
Dependensi: mcp (wajib), requests (opsional). Jalankan via stdio.
"""
import asyncio
import subprocess
import shlex
import shutil
import os
import sys
import re
import json
import hashlib
import sqlite3
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Server("cockpit-lite")

# ── Path & Storage ──────────────────────────────────────────────
BASE = os.path.expanduser("~/cockpit_lite")
REPORT_DIR = os.path.join(BASE, "reports")
WORKSPACE = os.path.join(BASE, "workspace")
DB_PATH = os.path.join(BASE, "cockpit_lite.db")
for d in (BASE, REPORT_DIR, WORKSPACE):
    os.makedirs(d, exist_ok=True)

# ── API Keys (via env — SALAH SATU kunci "rare tech" kami) ──────
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# ── Tool Allowlist (sebagian, tapi cukup utk fase pro) ──────────
CORE_TOOLS = {
    "nmap": "Network mapper / port & service scan",
    "rustscan": "Ultra-fast port scanner",
    "httpx": "HTTP probing & tech detection",
    "whatweb": "Web technology fingerprinting",
    "subfinder": "Passive subdomain discovery",
    "dnsenum": "DNS enumeration",
    "whois": "Domain registration lookup",
    "nuclei": "Template-based vuln scanner",
    "nikto": "Web server vulnerability scanner",
    "gobuster": "Directory/DNS brute-forcer",
    "ffuf": "Web fuzzer",
    "sqlmap": "SQL injection assessment",
    "arjun": "HTTP parameter discovery",
    "wafw00f": "WAF detection",
    "theharvester": "OSINT email/subdomain discovery",
    "searchsploit": "Exploit-db search",
}

# ── Compliance mapping (fitur LANGKA: auto-tag OWASP/PCI/CWE) ───
COMPLIANCE_MAP = {
    "sql injection":   {"owasp": "A03:2021-Injection",              "pci": "6.5.1", "cwe": 89},
    "xss":             {"owasp": "A03:2021-Injection",              "pci": "6.5.7", "cwe": 79},
    "injection":       {"owasp": "A03:2021-Injection",              "pci": "6.5.1", "cwe": 74},
    "broken auth":     {"owasp": "A07:2021-Identification and Authentication Failures", "pci": "8.1.1", "cwe": 287},
    "default cred":    {"owasp": "A07:2021-Identification and Authentication Failures", "pci": "2.1",  "cwe": 1392},
    "sensitive data":  {"owasp": "A02:2021-Cryptographic Failures", "pci": "3.2.1", "cwe": 312},
    "misconfig":       {"owasp": "A05:2021-Security Misconfiguration", "pci": "2.2", "cwe": 16},
    "outdated":        {"owasp": "A06:2021-Vulnerable and Outdated Components", "cwe": 1104},
    "open redirect":   {"owasp": "A01:2021-Broken Access Control", "cwe": 601},
    "rce":             {"owasp": "A03:2021-Injection", "cwe": 78},
    "path traversal":  {"owasp": "A01:2021-Broken Access Control", "cwe": 22},
    "open port":       {"pci": "1.1.1"},
}

# ── Database ────────────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, scope TEXT,
            created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, project_id TEXT, tool TEXT, target TEXT,
            title TEXT, severity TEXT DEFAULT 'info', category TEXT,
            cwe_id INTEGER, owasp TEXT, pci TEXT, cvss REAL,
            raw TEXT, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT,
            tool TEXT, target TEXT, command TEXT, out TEXT,
            duration REAL, created_at TEXT DEFAULT (datetime('now')));
    """)
    c.commit(); c.close()

init_db()

def sev_score(title, raw):
    t = (title + " " + (raw or "")).lower()
    if any(k in t for k in ("critical", "rce", "sql injection", "sqli", "root", "eternalblue", "unauthenticated rce", "takeover")):
        return "critical"
    if any(k in t for k in ("high", "remote code", "injection", "shell", "bypass", "sensitive data", "xss", "ssrf")):
        return "high"
    if any(k in t for k in ("medium", "misconfig", "information disclosure", "enum", "weak")):
        return "medium"
    if any(k in t for k in ("low", "info", "version", "notice", "open port")):
        return "low"
    return "info"

def auto_tag(title, raw):
    txt = (title + " " + (raw or "")).lower()
    for key, tags in COMPLIANCE_MAP.items():
        if key in txt:
            return tags
    return {}

def add_finding(project_id, tool, target, title, raw, severity=None, cvss=0.0):
    if severity is None:
        severity = sev_score(title, raw)
    tags = auto_tag(title, raw)
    fid = hashlib.sha256(f"{tool}|{target}|{title}".encode()).hexdigest()[:16]
    c = db()
    exists = c.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
    if not exists:
        c.execute(
            "INSERT INTO findings (id,project_id,tool,target,title,severity,"
            "category,cwe_id,owasp,pci,cvss,raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, project_id, tool, target, title, severity,
             tags.get("category", ""), tags.get("cwe"), tags.get("owasp", ""),
             tags.get("pci", ""), cvss, raw[:2000]))
        c.commit()
    c.close()
    return fid  # dedup otomatis

# ── Intel Correlation (fitur LANGKA) ────────────────────────────
def shodan_lookup(ip):
    if not SHODAN_KEY:
        return None
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            return (f"[SHODAN] {ip} | Org: {d.get('org','?')} | OS: {d.get('os','?')} | "
                    f"Ports: {d.get('ports', [])}")
    except Exception:
        pass
    return None

def cve_for(title):
    """Rekam CVE dari judul/raw bila ada (mis. CVE-2021-XXXX)."""
    m = re.search(r"CVE-\d{4}-\d{4,7}", title or "")
    if not m:
        return None
    out = shutil.which("searchsploit")
    if out:
        try:
            p = subprocess.run(["searchsploit", m.group(0)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=20)
            return (m.group(0) + "\n" + p.stdout[:1200])
        except Exception:
            return m.group(0)
    return m.group(0)

def enrich(project_id, target, findings):
    """Auto enriches: shodan for IPs + cve for findings (jarang ada)."""
    enrich = []
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", target))
    for ip in list(ips)[:3]:
        s = shodan_lookup(ip)
        if s:
            enrich.append(s)
    for f in findings:
        cv = cve_for(f.get("title") or f.get("raw", ""))
        if cv:
            enrich.append(cv)
    return enrich

# ── Tool Runner ─────────────────────────────────────────────────
def run_one(tool, args, timeout=180):
    start = time.time()
    if not shutil.which(tool):
        return tool, f"[SKIP] {tool} tidak terinstal.", True, 0.0
    try:
        p = subprocess.run(shlex.split(f"{tool} {args}"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        out = p.stdout or p.stderr or "(no output)"
        return tool, out, p.returncode != 0, time.time() - start
    except subprocess.TimeoutExpired:
        return tool, f"[TIMEOUT] >{timeout}s", True, time.time() - start
    except Exception as e:
        return tool, f"[ERROR] {e}", True, time.time() - start

# ── Advance: Parallel Recon (fitur LANGKA) ──────────────────────
RECON_ARGS = {
    "nmap": "-sV -sC -T4", "rustscan": "-a --ulimit 5000",
    "httpx": "-title -tech-detect -status-code", "whatweb": "-v",
    "subfinder": "-silent", "dnsenum": "", "whois": "",
}
def parallel_recon(target, tools=None, timeout=300, project_id=""):
    tools = tools or ["nmap", "httpx", "whatweb"]
    avail = [(t, RECON_ARGS.get(t, target)) for t in tools if shutil.which(t)]
    if not avail:
        return "[PARALLEL] Tidak ada tool recon tersedia."
    out = ["═"*56, f" [PARALLEL RECON: {target}]", "═"*56]
    with ThreadPoolExecutor(max_workers=min(len(avail), 8)) as ex:
        futs = {ex.submit(run_one, t, args, timeout): t for t, args in avail}
        for f in as_completed(futs):
            tool, text, err, dur = f.result()
            out.append(f"\n── {tool.upper()} ({dur:.1f}s) ──\n{text[:2500]}")
            if project_id and tool == "nmap":
                for line in text.splitlines():
                    m = re.match(r"^(\d+)/tcp\s+open\s+(.*)", line)
                    if m:
                        add_finding(project_id, "nmap", target,
                                    f"Open port {m.group(1)}/{m.group(2).strip()}",
                                    line, severity="info")
                        c = db()
                        c.execute("INSERT OR IGNORE INTO scans (project_id,tool,target,command,out,duration) "
                                  "VALUES (?,?,?,?,?,?)",
                                  (project_id, "nmap", target, "nmap -sV -sC -T4 " + target,
                                   text, dur))
                        c.commit(); c.close()
    out.append("═"*56)
    if project_id:
        enr = enrich(project_id, target, [])
        if enr:
            out.append("\n[INTEL CORRELATION]\n" + "\n".join(enr))
    return "\n".join(out)

# ── Advance: Attack Path Analyzer (fitur LANGKA) ────────────────
PORT_ADVICE = {
    "21": ("FTP", ["hydra ftp brute", "cek anonymous access"]),
    "22": ("SSH", ["ssh-audit", "hydra ssh", "cek weak keys"]),
    "25": ("SMTP", ["smtp-user-enum", "cek open relay"]),
    "53": ("DNS", ["dnsrecon", "zone transfer"]),
    "80": ("HTTP", ["nikto", "nuclei", "gobuster dir", "cek robots.txt"]),
    "110": ("POP3", ["pop3 brute", "cek creds lemah"]),
    "135": ("MSRPC", ["rpcdump", "enum RPC"]),
    "139/445": ("SMB", ["enum4linux", "smbmap", "netexec SMB", "cek EternalBlue (MS17-010)"]),
    "443": ("HTTPS", ["nikto", "nuclei", "cek SSL cert"]),
    "1433": ("MSSQL", ["hydra mssql", "sqsh for DB"]),
    "3306": ("MySQL", ["hydra mysql", "cek anonymous login"]),
    "3389": ("RDP", ["crowbar rdp", "cek BlueKeep CVE-2019-0708"]),
    "5432": ("PostgreSQL", ["hydra postgres"]),
    "5985": ("WinRM", ["evil-winrm", "netexec winrm"]),
    "6379": ("Redis", ["redis-cli", "cek no-auth"]),
    "8080": ("HTTP-Alt", ["nikto", "nuclei", "cek default admin panels"]),
}
def attack_path(project_id):
    c = db()
    findings = c.execute("SELECT * FROM findings WHERE project_id=? ORDER BY severity", (project_id,)).fetchall()
    ports = [r["title"] for r in findings if r["tool"] == "nmap"]
    lines = ["═"*56, " [ATTACK PATH ANALYZER]", "═"*56,
             "\n[PORT → NEXT STEP]"]
    seen = set()
    for t in ports:
        m = re.search(r"open port (\d+)", t, re.I)
        if not m: continue
        p = m.group(1)
        if p in seen: continue
        seen.add(p)
        advice = None
        for key, val in PORT_ADVICE.items():
            if p in key.split("/"):          # cocok "445" pada key "139/445"
                advice = val; break
        svc, steps = advice if advice else (p, ["fresh scan / fuzz"])
        lines.append(f"  • {p} ({svc}) → " + "; ".join(steps))
    crit = [r for r in findings if r["severity"] in ("critical", "high")]
    lines.append("\n[CRITICAL / HIGH FINDINGS]")
    if crit:
        for r in crit:
            line = f"  🔴 [{r['severity'].upper()}] {r['title']} ({r['target']})"
            if r["cwe_id"]:
                line += f" | CWE-{r['cwe_id']} | {r['owasp']}"
            lines.append(line)
    else:
        lines.append("  Tidak ada temuan critical/high. Lanjut enum.")
    lines.append("\n[REKOMENDASI] Lanjut: exploit sesuai service, lalu pivoting/priv-esc.")
    c.close()
    return "\n".join(lines)

# ── Advance: Scan Diff Engine (fitur LANGKA) ────────────────────
def scan_diff(project_id, scan1, scan2):
    c = db()
    s1 = c.execute("SELECT * FROM scans WHERE id=?", (scan1,)).fetchone()
    s2 = c.execute("SELECT * FROM scans WHERE id=?", (scan2,)).fetchone()
    c.close()
    if not s1 or not s2:
        return "[DIFF] Salah satu scan tidak ditemukan."
    import difflib
    a, b = (s1["out"] or "").splitlines(), (s2["out"] or "").splitlines()
    diff = difflib.unified_diff(a, b, fromfile=f"scan#{scan1}", tofile=f"scan#{scan2}", lineterm="")
    return ("═"*56 + "\n [SCAN DIFF: #%d → #%d]\n" + "═"*56 + "\n%s") % (scan1, scan2,
        "\n".join(d for d in diff if d.startswith(("+", "-", "@"))))

# ── Advance: HTML Report MANDIRI (tanpa WeasyPrint) ─────────────
def html_report(project_id):
    c = db()
    proj = c.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not proj:
        c.close(); return "[REPORT] Project tidak ditemukan."
    fnd = c.execute("SELECT * FROM findings WHERE project_id=? ORDER BY severity", (project_id,)).fetchall()
    c.close()
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in fnd: sev[f["severity"]] = sev.get(f["severity"], 0) + 1

    rows = "".join(
        f"<tr><td><span class='b {f['severity']}'>{f['severity']}</span></td>"
        f"<td>{f['title']}</td><td>{f['target']}</td><td>{f['tool']}</td>"
        f"<td>{f['cwe_id'] or ''}</td><td>{f['owasp'] or ''}</td></tr>"
        for f in fnd)

    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Cockpit Lite Report - {proj['name']}</title><style>
body{{font-family:Segoe UI,Arial;background:#0a0e17;color:#c9d1d9;margin:0;padding:30px}}
h1{{color:#00ff88}} h2{{color:#58a6ff;border-left:3px solid #58a6ff;padding-left:10px}}
.b{{padding:3px 9px;border-radius:4px;font-weight:bold}}
.critical{{background:#da3633;color:#fff}}.high{{background:#f0883e}}
.medium{{background:#d29922}}.low{{background:#238636;color:#fff}}.info{{background:#30363d}}
table{{width:100%;border-collapse:collapse;margin-top:10px}}
th,td{{padding:8px;text-align:left;border-bottom:1px solid #21262d}}
</style></head><body>
<h1>🛡️ Cockpit Lite — Pentest Report</h1>
<div>Project: <b>{proj['name']}</b> | Scope: {proj['scope'] or 'N/A'} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
<h2>CEMO Summary</h2><p>Critical {sev['critical']} · High {sev['high']} · Medium {sev['medium']} · Low {sev['low']} · Info {sev['info']}</p>
<h2>Findings ({len(fnd)})</h2>
<table><tr><th>Severity</th><th>Title</th><th>Target</th><th>Tool</th><th>CWE</th><th>OWASP</th></tr>{rows}</table>
<p style='color:#484f58;margin-top:30px'>Generated by Cockpit Lite MCP.</p>
</body></html>"""

    path = os.path.join(REPORT_DIR, f"report_{proj['name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return f"[REPORT] Disimpan: `{path}`\nRingkasan: {sev}"

# ── HUD ─────────────────────────────────────────────────────────
def hud():
    online = sum(1 for t in CORE_TOOLS if shutil.which(t))
    c = db()
    pj = c.execute("SELECT COUNT(*) c FROM projects").fetchone()["c"]
    fnd = c.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
    c.close()
    return (f"COCKPIT LITE HUD\n  Tools online : {online}/{len(CORE_TOOLS)}\n"
            f"  Projects     : {pj}\n  Findings     : {fnd}\n"
            f"  DB           : {DB_PATH}")

# ── MCP Tool Registration ───────────────────────────────────────
@app.list_tools()
async def list_tools():
    return [
        types.Tool(name="cockpit_status", description="Kesehatan sistem & tools online.", inputSchema={"type":"object","properties":{}}),
        types.Tool(name="run_recon", description="PARALLEL recon (nmap/httpx/whatweb/subfinder) + intel correlation otomatis.",
                   inputSchema={"type":"object","properties":{
                       "target":{"type":"string"},"tools":{"type":"array","items":{"type":"string"}},
                       "project_id":{"type":"string"}},"required":["target"]}),
        types.Tool(name="run_web_scan", description="Web vuln chain: whatweb + nikto + nuclei, simpan ke DB.",
                   inputSchema={"type":"object","properties":{
                       "target":{"type":"string"},"project_id":{"type":"string"}},"required":["target"]}),
        types.Tool(name="run_tool", description="Jalankan satu tool dari allowlist.",
                   inputSchema={"type":"object","properties":{
                       "tool_name":{"type":"string"},"args":{"type":"string"},"timeout":{"type":"integer"}},"required":["tool_name","args"]}),
        types.Tool(name="project_create", description="Buat project baru.",
                   inputSchema={"type":"object","properties":{
                       "name":{"type":"string"},"scope":{"type":"string"}},"required":["name"]}),
        types.Tool(name="findings_list", description="List temuan sebuah project (dengan compliance + CVE).",
                   inputSchema={"type":"object","properties":{"project_id":{"type":"string"}},"required":["project_id"]}),
        types.Tool(name="analyze_attack_path", description="Attack path analyzer MITRE-informed dari findings.",
                   inputSchema={"type":"object","properties":{"project_id":{"type":"string"}},"required":["project_id"]}),
        types.Tool(name="scan_diff", description="Diff engine: bandingkan dua scan untuk deteksi perubahan.",
                   inputSchema={"type":"object","properties":{
                       "project_id":{"type":"string"},"scan1":{"type":"integer"},"scan2":{"type":"integer"}},
                       "required":["project_id","scan1","scan2"]}),
        types.Tool(name="generate_report", description="HTML report mandiri (tanpa WeasyPrint).",
                   inputSchema={"type":"object","properties":{"project_id":{"type":"string"}},"required":["project_id"]}),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    try:
        if name == "cockpit_status":
            return [types.TextContent(type="text", text=hud())]

        elif name == "run_recon":
            tgt = arguments.get("target"); pid = arguments.get("project_id", "")
            tools = arguments.get("tools") or ["nmap", "httpx", "whatweb"]
            return [types.TextContent(type="text", text=parallel_recon(tgt, tools, project_id=pid))]

        elif name == "run_web_scan":
            tgt = arguments.get("target"); pid = arguments.get("project_id", "")
            out = ["═"*56, f" [WEB SCAN: {tgt}]", "═"*56]
            for tool, args in (("whatweb","-v"), ("nikto","-h"), ("nuclei","-u")):
                t, text, err, dur = run_one(tool, f"{args} {tgt}", 300)
                out.append(f"\n── {t.upper()} ({dur:.1f}s) ──\n{text[:2500]}")
                if pid:
                    add_finding(pid, tool, tgt, f"{tool} scan on {tgt}", text[:2000])
            out.append("═"*56)
            return [types.TextContent(type="text", text="\n".join(out))]

        elif name == "run_tool":
            tool = arguments.get("tool_name"); args = arguments.get("args", "")
            to = int(arguments.get("timeout", 180))
            if tool not in CORE_TOOLS:
                return [types.TextContent(type="text", text=f"[ERR] Tool tidak ada di allowlist: {tool}")]
            t, text, err, dur = run_one(tool, args, to)
            return [types.TextContent(type="text", text=f"── {t.upper()} ({dur:.1f}s) ──\n{text}")]

        elif name == "project_create":
            import uuid
            pid = uuid.uuid4().hex[:8]
            c = db()
            c.execute("INSERT INTO projects (id,name,scope) VALUES (?,?,?)",
                      (pid, arguments.get("name"), arguments.get("scope", "")))
            c.commit(); c.close()
            return [types.TextContent(type="text", text=f"[PROJECT] Dibuat: {pid} ({arguments.get('name')})")]

        elif name == "findings_list":
            pid = arguments.get("project_id")
            c = db()
            rows = c.execute("SELECT * FROM findings WHERE project_id=? ORDER BY severity", (pid,)).fetchall()
            c.close()
            if not rows:
                return [types.TextContent(type="text", text="[EMPTY] Tidak ada temuan.")]
            lines = ["FINDINGS (w/ compliance):"]
            for r in rows:
                lines.append(f"  [{r['severity'].upper()}] {r['title']} | {r['target']} | {r['tool']}"
                             + (f" | CWE-{r['cwe_id']} {r['owasp']}" if r['cwe_id'] else ""))
            return [types.TextContent(type="text", text="\n".join(lines))]

        elif name == "analyze_attack_path":
            return [types.TextContent(type="text", text=attack_path(arguments.get("project_id")))]

        elif name == "scan_diff":
            return [types.TextContent(type="text", text=scan_diff(arguments.get("project_id"),
                     int(arguments.get("scan1")), int(arguments.get("scan2"))))]

        elif name == "generate_report":
            return [types.TextContent(type="text", text=html_report(arguments.get("project_id")))]

        raise ValueError(f"Tool tidak dikenal: {name}")
    except Exception as e:
        return [types.TextContent(type="text", text=f"[ERROR] {e}")]

async def main():
    sys.stderr.write(f"\n[COCKPIT LITE] Ready | {sum(1 for t in CORE_TOOLS if shutil.which(t))}/{len(CORE_TOOLS)} tools online\n")
    async with stdio_server() as (rs, ws):
        await app.run(rs, ws, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
