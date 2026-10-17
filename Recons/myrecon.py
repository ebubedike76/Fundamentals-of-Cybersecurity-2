#!/usr/bin/env python3
"""
Personal Recon Pipeline - Production Edition
Requires: subfinder, httpx, nuclei (Go tools on PATH)
Usage: ./myrecon.py target.com
"""

import subprocess
import sys
import json
import shutil
import os
from pathlib import Path
from datetime import datetime

# ─── Configuration ───
TOOLS = ["subfinder", "httpx", "nuclei"]
AUDIT_LOG = Path.home() / ".myrecon_audit.jsonl"

# ─── Tool Check (fail-fast, not fail-open) ───
def check_tools():
    missing = [t for t in TOOLS if not shutil.which(t)]
    if missing:
        print(f"[!] Missing: {', '.join(missing)}")
        print("[!] Install with:")
        for t in missing:
            print(f"    go install github.com/projectdiscovery/{t}/cmd/{t}@latest")
        sys.exit(1)

# ─── Safe Subprocess Runner ───
def run(cmd, timeout=600):
    """Run command, never crash, always return string output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if result.returncode != 0:
            return ""
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout: {cmd[0]}")
        return ""
    except (OSError, FileNotFoundError):
        print(f"[!] Failed: {cmd[0]}")
        return ""

# ─── Audit Trail ───
def audit(action, target, detail=""):
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "action": action,
        "target": target,
        "detail": detail
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ─── Phase 1: Subdomains ───
def phase_subdomains(target, outdir):
    print(f"\n[1/3] Subfinder → {target}")
    audit("subfinder_start", target)
    
    outfile = outdir / "subdomains.txt"
    run(["subfinder", "-d", target, "-silent", "-timeout", "30", "-o", str(outfile)])
    
    if not outfile.exists():
        print("[!] Subfinder produced no output")
        return []
    
    subs = [l.strip() for l in outfile.read_text().splitlines() if l.strip()]
    print(f"    Found {len(subs)} subdomains")
    audit("subfinder_done", target, f"{len(subs)} subdomains")
    return subs

# ─── Phase 2: Live Hosts ───
def phase_httpx(subs, outdir):
    if not subs:
        print("[!] No subdomains to probe")
        return []
    
    print(f"\n[2/3] Httpx → {len(subs)} targets")
    audit("httpx_start", str(len(subs)))
    
    subs_file = outdir / "subdomains.txt"
    outfile = outdir / "live_hosts.json"
    
    run([
        "httpx", "-l", str(subs_file), "-json", "-silent",
        "-tech-detect", "-status-code", "-title", "-timeout", "10",
        "-o", str(outfile)
    ])
    
    if not outfile.exists():
        print("[!] Httpx produced no output")
        return []
    
    live = []
    for line in outfile.read_text().splitlines():
        try:
            data = json.loads(line)
            live.append(data.get("url") or data.get("input"))
        except json.JSONDecodeError:
            continue
    
    live = [h for h in live if h]
    print(f"    {len(live)} live hosts")
    audit("httpx_done", str(len(live)))
    return live

# ─── Phase 3: Nuclei ───
def phase_nuclei(live, outdir):
    if not live:
        print("[!] No live hosts to scan")
        return []
    
    print(f"\n[3/3] Nuclei → {len(live)} hosts (this takes time)")
    audit("nuclei_start", str(len(live)))
    
    live_file = outdir / "live_hosts.txt"
    live_file.write_text("\n".join(live))
    outfile = outdir / "findings.jsonl"
    
    run([
        "nuclei", "-l", str(live_file),
        "-severity", "critical,high,medium",
        "-jsonl", "-silent", "-timeout", "10",
        "-o", str(outfile)
    ], timeout=1800)
    
    if not outfile.exists():
        print("[!] Nuclei produced no output")
        return []
    
    findings = []
    for line in outfile.read_text().splitlines():
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    
    print(f"    {len(findings)} findings")
    audit("nuclei_done", str(len(findings)))
    return findings

# ─── Report ───
def write_report(target, outdir, subs, live, findings):
    report = outdir / "REPORT.txt"
    lines = [
        "=" * 50,
        f"RECON REPORT: {target}",
        f"Generated: {datetime.utcnow().isoformat()}",
        "=" * 50,
        "",
        f"Subdomains found: {len(subs)}",
        f"Live hosts: {len(live)}",
        f"Findings: {len(findings)}",
        "",
        "─" * 50,
        "LIVE HOSTS",
        "─" * 50,
    ]
    lines.extend(live[:20])  # cap at 20 for readability
    if len(live) > 20:
        lines.append(f"... and {len(live) - 20} more")
    
    lines.extend(["", "─" * 50, "FINDINGS", "─" * 50])
    for f in findings[:10]:
        name = f.get("info", {}).get("name", "unknown")
        sev = f.get("info", {}).get("severity", "?")
        host = f.get("host", "?")
        lines.append(f"[{sev.upper()}] {name} @ {host}")
    
    report.write_text("\n".join(lines))
    print(f"\n[+] Report: {report}")

# ─── Main ───
def main():
    if len(sys.argv) != 2:
        print("Usage: ./myrecon.py <target.com>")
        sys.exit(1)
    
    target = sys.argv[1].strip().lower()
    check_tools()
    audit("session_start", target)
    
    outdir = Path(f"recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Target: {target}")
    print(f"[*] Output: {outdir}")
    
    subs = phase_subdomains(target, outdir)
    live = phase_httpx(subs, outdir)
    findings = phase_nuclei(live, outdir)
    
    write_report(target, outdir, subs, live, findings)
    audit("session_end", target)
    print(f"\n[+] Done. Audit: {AUDIT_LOG}")

if __name__ == "__main__":
    main()
