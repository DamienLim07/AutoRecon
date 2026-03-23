#!/usr/bin/env python3
"""
AutoRecon - Web Reconnaissance Tool
By Damien Lim | github.com/DamienLim07

Philosophy: tools run at native speed via tee.
Python orchestrates, saves, then post-processes for the report.
"""

import subprocess
import os
import re
import sys
import datetime
import argparse
import shutil
import webbrowser
import urllib.request
from pathlib import Path

# ─────────────────────────────────────────────
# Colors
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════╗
  ║           A U T O R E C O N              ║
  ║       Web Reconnaissance Tool            ║
  ║   github.com/DamienLim07 | CTF Edition   ║
  ╚═══════════════════════════════════════════╝{C.RESET}
""")

def info(msg):     print(f"{C.CYAN}[*]{C.RESET} {msg}")
def success(msg):  print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):     print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):    print(f"{C.RED}[-]{C.RESET} {msg}")
def section(msg):
    print(f"\n{C.BOLD}{C.YELLOW}{'─'*54}")
    print(f"  {msg}  [{ts_short()}]")
    print(f"{'─'*54}{C.RESET}")

def ts():       return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def ts_short(): return datetime.datetime.now().strftime("%H:%M:%S")

# ─────────────────────────────────────────────
# Web Service Detection
# ─────────────────────────────────────────────
WEB_KEYWORDS = [
    "http", "https", "apache", "nginx", "iis", "lighttpd",
    "werkzeug", "tornado", "gunicorn", "uvicorn", "jetty",
    "tomcat", "weblogic", "websphere", "caddy", "web", "www",
]

def is_web(service: str, version: str = "") -> bool:
    combined = f"{service} {version}".lower()
    return any(k in combined for k in WEB_KEYWORDS)

# ─────────────────────────────────────────────
# Tool Check
# ─────────────────────────────────────────────
TOOLS = {
    "nmap":     "sudo apt install nmap",
    "gobuster": "sudo apt install gobuster",
    "nikto":    "sudo apt install nikto",
    "whatweb":  "sudo apt install whatweb",
    "curl":     "sudo apt install curl",
}

def check_tools():
    section("TOOL CHECK")
    missing = []
    for tool, install in TOOLS.items():
        if shutil.which(tool):
            success(f"{tool:12} found")
        else:
            error(f"{tool:12} NOT FOUND  →  {install}")
            missing.append(tool)
    if not missing:
        success("All tools ready.")
    return missing

# ─────────────────────────────────────────────
# Native Run via tee
# Runs command at full native speed.
# Output goes directly to terminal AND saved to file via tee.
# ─────────────────────────────────────────────
def run_tee(cmd: list, save_path: Path, timeout: int = 600):
    """
    Run cmd with output piped through tee to save_path.
    Terminal sees native output at full speed.
    Returns exit code.
    """
    tee_cmd = f"{' '.join(cmd)} | tee {save_path}"
    print(f"{C.DIM}  $ {tee_cmd}{C.RESET}\n")
    try:
        result = subprocess.run(
            tee_cmd,
            shell=True,
            timeout=timeout
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        warn(f"Timed out after {timeout}s")
        return -1
    except Exception as e:
        error(f"Error: {e}")
        return -1

# ─────────────────────────────────────────────
# Silent Run (for curl pre-checks — no terminal output needed)
# ─────────────────────────────────────────────
def run_silent(cmd: list, timeout: int = 15) -> str:
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

# ─────────────────────────────────────────────
# Read saved file
# ─────────────────────────────────────────────
def read_file(path: Path) -> str:
    try:
        content = path.read_text(errors="replace")
        # Strip ANSI escape codes saved by tee from tools like WhatWeb
        return re.sub(r'\x1b\[[0-9;]*m', '', content)
    except Exception:
        return ""

# ─────────────────────────────────────────────
# Flag Pattern
# ─────────────────────────────────────────────
GENERIC_KEYWORDS = [
    "flag", "password", "passwd", "secret",
    "token", "key", "admin", "login", "<!--"
]

def build_pattern(prefix: str) -> re.Pattern:
    parts = [re.escape(k) for k in GENERIC_KEYWORDS]
    if prefix:
        parts.insert(0, re.escape(prefix) + r"\{[^}]*\}")
    return re.compile("|".join(parts), re.IGNORECASE)

def find_flag_hits(text: str, pattern: re.Pattern) -> list:
    if not text or not pattern:
        return []
    return list(set(pattern.findall(text)))

def highlight(text: str, pattern: re.Pattern) -> str:
    if not pattern or not text:
        return text
    return pattern.sub(lambda m: f'<mark class="fh">{m.group(0)}</mark>', text)

# ─────────────────────────────────────────────
# Nmap
# ─────────────────────────────────────────────
def run_nmap(target: str, full: bool, output_dir: Path) -> tuple:
    section("PHASE 1 — NMAP")
    save = output_dir / "nmap.txt"

    flags = ["-sV", "-sC", "-T4", "--open", "--stats-every", "30s"]
    if full:
        flags += ["-p-"]
        info("Full scan (-p-) — catches all ports including high ones. This will take a while.")
    else:
        info("Top 1000 ports. Use -f for full scan of all 65535 ports.")

    run_tee(["nmap"] + flags + [target], save, timeout=900)
    success(f"[{ts_short()}] Nmap done. Saved → {save.name}")

    # Parse open ports from saved file
    output    = read_file(save)
    open_ports = []
    for m in re.finditer(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$", output, re.MULTILINE):
        open_ports.append({
            "port":    int(m.group(1)),
            "proto":   m.group(2),
            "service": m.group(3).strip(),
            "version": (m.group(4) or "").strip(),
            "raw":     m.group(0).strip(),
        })

    return output, open_ports

# ─────────────────────────────────────────────
# Pre-checks (robots, sitemap, flag.txt, flag.php)
# Curl runs silently, results shown as summary
# ─────────────────────────────────────────────
CTF_PATHS = ["robots.txt", "sitemap.xml", "flag.txt", "flag.php"]

def run_prechecks(target: str, web_ports: list, output_dir: Path) -> list:
    section("PHASE 2 — QUICK CTF PRE-CHECKS")
    results = []

    for p in web_ports:
        port   = p["port"]
        scheme = p["proto_scheme"]
        base   = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

        for path in CTF_PATHS:
            url = f"{base}/{path}"
            info(f"Checking {url} ...")

            # Use curl to get status code and content
            status = run_silent(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L", "--max-time", "8", url])
            
            if status == "200":
                content = run_silent(["curl", "-s", "-L", "--max-time", "8", url])
                content_type = run_silent(["curl", "-s", "-I", "--max-time", "8", "-w", "%{content_type}", "-o", "/dev/null", url])
                
                is_binary = any(t in content_type.lower() for t in ["image/", "audio/", "video/", "application/zip", "application/octet-stream"])
                
                if is_binary:
                    warn(f"  [BINARY] {url}  [{content_type}]  — download manually")
                    results.append({"url": url, "status": "200", "binary": True, "content": None, "content_type": content_type})
                else:
                    success(f"  [200] {url}  ({len(content)} bytes)")
                    # Save
                    safe = path.replace(".", "_")
                    (output_dir / f"precheck_{port}_{safe}.txt").write_text(content)
                    results.append({"url": url, "status": "200", "binary": False, "content": content, "content_type": content_type})
            else:
                print(f"  {C.DIM}[{status}] {url}{C.RESET}")
                results.append({"url": url, "status": status, "binary": False, "content": None})

    success(f"[{ts_short()}] Pre-checks done.")
    return results

# ─────────────────────────────────────────────
# Web Recon — WhatWeb + Nikto + Gobuster
# All run at native speed via tee
# ─────────────────────────────────────────────
def run_web_recon(target: str, web_ports: list, wordlist: str, threads: int, extensions: str, output_dir: Path) -> dict:
    results = {}

    for p in web_ports:
        port   = p["port"]
        scheme = p["proto_scheme"]
        url    = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

        section(f"PHASE 3 — WEB RECON  [{url}]")
        port_data = {"url": url, "port": port}

        # ── WhatWeb ──
        info(f"[{ts_short()}] WhatWeb...")
        ww_save = output_dir / f"whatweb_{port}.txt"
        run_tee(["whatweb", "-a", "1", url], ww_save, timeout=60)
        success(f"[{ts_short()}] WhatWeb done.")
        port_data["whatweb_file"] = ww_save

        # ── Nikto ──
        info(f"[{ts_short()}] Nikto...")
        nk_save = output_dir / f"nikto_{port}.txt"
        run_tee(["nikto", "-h", url, "-maxtime", "120"], nk_save, timeout=150)
        success(f"[{ts_short()}] Nikto done.")
        port_data["nikto_file"] = nk_save

        # ── Gobuster ──
        info(f"[{ts_short()}] Gobuster (threads: {threads}, wordlist: {wordlist})...")
        if extensions:
            info(f"Extensions: {extensions}")
        else:
            info("No extensions — directory scan only. Use -x php,html,txt to add extensions.")
        gb_save = output_dir / f"gobuster_{port}.txt"
        gb_cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "--no-error",
        ]
        if extensions:
            gb_cmd += ["-x", extensions]

        # Use tee so output goes to terminal AND file simultaneously
        tee_cmd = " ".join(gb_cmd) + f" | tee {gb_save}"
        try:
            subprocess.run(tee_cmd, shell=True, timeout=600)
        except subprocess.TimeoutExpired:
            warn("Gobuster timed out.")
        except Exception as e:
            error(f"Gobuster error: {e}")
        success(f"[{ts_short()}] Gobuster done.")
        port_data["gobuster_file"] = gb_save

        gb_output = read_file(gb_save)
        if not gb_output.strip():
            warn(f"Gobuster output file is empty: {gb_save}")
        else:
            info(f"Gobuster saved {len(gb_output.splitlines())} lines to {gb_save.name}")
        port_data["gobuster_file"] = gb_save

        # ── Parse Gobuster output for clickable paths and 200s ──
        gb_output = read_file(gb_save)
        paths_200 = []
        for line in gb_output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                path   = m.group(1)
                status = m.group(2)
                if status == "200":
                    paths_200.append(path)

        # ── Curl 200 paths silently ──
        curl_results = []
        if paths_200:
            info(f"[{ts_short()}] Curling {len(paths_200)} path(s) with status 200...")
            for path in paths_200:
                full_url   = f"{url}{path}"
                content    = run_silent(["curl", "-s", "-L", "--max-time", "8", full_url])
                ct         = run_silent(["curl", "-s", "-I", "--max-time", "8", "-w", "%{content_type}", "-o", "/dev/null", full_url])
                is_binary  = any(t in ct.lower() for t in ["image/", "audio/", "video/", "application/zip", "application/octet-stream"])
                is_login   = bool(re.search(r"<form", content, re.I) and re.search(r"password|login", content, re.I))

                if not is_binary and content:
                    safe = path.strip("/").replace("/", "_") or "root"
                    (output_dir / f"curl_{port}_{safe}.txt").write_text(content)

                curl_results.append({
                    "path":     path,
                    "url":      full_url,
                    "binary":   is_binary,
                    "content":  content[:3000] if not is_binary else None,
                    "ct":       ct,
                    "is_login": is_login,
                })
                status_str = f"[BINARY: {ct}]" if is_binary else f"({len(content)} bytes)"
                login_str  = "  🔑 LOGIN PAGE" if is_login else ""
                success(f"  {path}  {status_str}{login_str}")
            success(f"[{ts_short()}] Curl done.")

        port_data["curl_results"] = curl_results
        results[port] = port_data

    return results

# ─────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────
def generate_report(target, nmap_raw, open_ports, precheck_results,
                    web_results, web_ports, flag_prefix, output_dir, scan_start):

    now          = ts()
    flag_pattern = build_pattern(flag_prefix or "")
    filename     = f"recon_{target.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path  = output_dir / filename

    def strip_ansi(t):
        if not t: return ""
        return re.sub(r'\x1b\[[0-9;]*m', '', t)

    def esc(t):
        if not t: return "<em style='color:#3a4a5a'>No output.</em>"
        return (strip_ansi(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\n","<br>"))

    def esc_hl(t):
        return highlight(esc(t), flag_pattern)

    # Count flag hits across all saved files
    all_hits = []
    for f in output_dir.glob("*.txt"):
        content = read_file(f)
        hits    = find_flag_hits(content, flag_pattern)
        for h in hits:
            all_hits.append({"file": f.name, "match": h})

    # ── TOC ──
    toc = '<li><a href="#s-nmap">Nmap</a></li>'
    toc += '<li><a href="#s-prechecks">Pre-Checks</a></li>'
    for port, d in web_results.items():
        toc += f'<li><a href="#s-port-{port}">Port {port}</a><ul>'
        toc += f'<li><a href="#s-whatweb-{port}">WhatWeb</a></li>'
        toc += f'<li><a href="#s-nikto-{port}">Nikto</a></li>'
        toc += f'<li><a href="#s-gobuster-{port}">Gobuster</a></li>'
        toc += f'<li><a href="#s-curl-{port}">200 Paths</a></li>'
        toc += '</ul></li>'
    toc += '<li><a href="#s-flags">Flag Matches</a></li>'
    toc += '<li><a href="#s-nonweb">Non-Web Services</a></li>'

    # ── Nmap table ──
    port_rows = ""
    for p in open_ports:
        tag = '<span class="wtag">WEB</span>' if is_web(p["service"], p["version"]) else ""
        port_rows += f"<tr><td>{p['port']}/{p['proto']}</td><td>{p['service']} {tag}</td><td>{p['version']}</td></tr>"

    # ── Pre-check cards ──
    pre_html = ""
    for r in precheck_results:
        if r["status"] != "200":
            pre_html += f'<div class="pcard dim"><span class="purl">{r["url"]}</span> <span class="sb s{r["status"]}">{r["status"]}</span></div>'
        elif r.get("binary"):
            pre_html += f'<div class="pcard warn"><span class="purl">{r["url"]}</span> <span class="sb sbin">BINARY</span> {r.get("content_type","")}</div>'
        else:
            hits = find_flag_hits(r.get("content",""), flag_pattern)
            hbadge = f'<span class="fbadge">⚑ {len(hits)} match(es)</span>' if hits else ""
            pre_html += f"""<div class="pcard found">
              <div class="ph"><span class="purl">{r["url"]}</span><span class="sb s200">200</span>{hbadge}</div>
              <pre class="prev">{esc_hl(r.get("content","")[:3000])}</pre>
            </div>"""

    # ── Web sections ──
    web_html = ""
    for port, d in web_results.items():
        url = d["url"]

        # Gobuster paths as clickable links
        gb_raw    = read_file(d["gobuster_file"])
        gb_links  = ""
        for line in gb_raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", line)
            if m:
                path   = m.group(1)
                status = m.group(2)
                full   = f"{url}{path}"
                sc     = "s200" if status == "200" else "sother"
                gb_links += f'<div class="gbline"><a href="{full}" target="_blank" class="gbpath">{path}</a> <span class="sb {sc}">{status}</span></div>'
        if not gb_links:
            gb_links = "<p class='nr'>No paths found.</p>"

        # Curl previews
        curl_html = ""
        for cr in d.get("curl_results", []):
            badges = ""
            if cr.get("is_login"): badges += '<span class="lbadge">🔑 LOGIN</span>'
            hits = find_flag_hits(cr.get("content",""), flag_pattern)
            if hits: badges += f'<span class="fbadge">⚑ {len(hits)} match(es)</span>'

            if cr["binary"]:
                curl_html += f'<div class="pcard warn"><span class="purl">{cr["url"]}</span> <span class="sb sbin">BINARY</span> {cr["ct"]}</div>'
            else:
                curl_html += f"""<div class="pcard found">
                  <div class="ph"><a href="{cr['url']}" target="_blank" class="purl">{cr['url']}</a>{badges}</div>
                  <pre class="prev">{esc_hl(cr.get("content",""))}</pre>
                </div>"""

        web_html += f"""
        <div id="s-port-{port}" class="port-hdr">PORT {port} — <span>{url}</span></div>

        <div class="card" id="s-whatweb-{port}">
          <div class="ch"><span class="ci">◈</span><h2>WHATWEB</h2></div>
          <pre class="out">{esc_hl(read_file(d["whatweb_file"]))}</pre>
        </div>

        <div class="card" id="s-nikto-{port}">
          <div class="ch"><span class="ci">◈</span><h2>NIKTO</h2></div>
          <pre class="out">{esc_hl(read_file(d["nikto_file"]))}</pre>
        </div>

        <div class="card" id="s-gobuster-{port}">
          <div class="ch"><span class="ci">◈</span><h2>GOBUSTER — CLICKABLE PATHS</h2></div>
          <div class="gblist">{gb_links}</div>
        </div>

        <div class="card" id="s-curl-{port}">
          <div class="ch"><span class="ci">◈</span><h2>200 PATH PREVIEWS</h2></div>
          <div class="pcards">{curl_html or "<p class='nr'>No 200 paths.</p>"}</div>
        </div>"""

    # ── Flag hits section ──
    if all_hits:
        frows = "".join([f"<tr><td>{h['file']}</td><td><mark class='fh'>{h['match']}</mark></td></tr>" for h in all_hits])
        flag_section = f"""<div class="card" id="s-flags">
          <div class="ch warn-ch"><span class="ci">⚑</span><h2>{len(all_hits)} POTENTIAL FLAG MATCH(ES)</h2></div>
          <table><thead><tr><th>FILE</th><th>MATCH</th></tr></thead><tbody>{frows}</tbody></table>
        </div>"""
    else:
        flag_section = f"""<div class="card" id="s-flags">
          <div class="ch"><span class="ci">◈</span><h2>FLAG MATCHES</h2></div>
          <p class="nr">No matches found for pattern: <code>{flag_prefix or "generic keywords"}</code></p>
        </div>"""

    # ── Non-web services ──
    nonweb = [p for p in open_ports if not is_web(p["service"], p["version"])]
    if nonweb:
        nw_rows = "".join([f"<tr><td>{p['port']}/{p['proto']}</td><td>{p['service']}</td><td>{p['version']}</td></tr>" for p in nonweb])
        nonweb_html = f"""<div class="card warn-card" id="s-nonweb">
          <div class="ch warn-ch"><span class="ci">⚠</span><h2>NON-WEB SERVICES — CONSIDER FURTHER ENUMERATION</h2></div>
          <table><thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th></tr></thead><tbody>{nw_rows}</tbody></table>
        </div>"""
    else:
        nonweb_html = ""

    # ── Web service badges ──
    badges = " ".join([f'<span class="badge">{p["proto_scheme"].upper()}:{p["port"]}</span>' for p in web_ports]) \
             or '<span class="badge warn">NO WEB SERVICES</span>'

    flag_count_html = f'<div class="fcount">⚑ {len(all_hits)} potential flag match(es)</div>' if all_hits else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AutoRecon — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
  :root{{--bg:#090b0f;--sur:#0e1116;--bor:#1a2030;--acc:#00ffe0;--warn:#ff4757;--ok:#00e676;--txt:#b8cad8;--dim:#3a4a5a;--mono:'Share Tech Mono',monospace;--ui:'Rajdhani',sans-serif}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--txt);font-family:var(--ui);font-size:15px;line-height:1.6;display:flex}}
  body::before{{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,224,.01) 2px,rgba(0,255,224,.01) 4px);pointer-events:none;z-index:9999}}
  #toc{{position:fixed;top:0;left:0;width:220px;height:100vh;background:#080a0e;border-right:1px solid var(--bor);overflow-y:auto;padding:1.5rem 1rem;z-index:100;font-family:var(--mono);font-size:.7rem}}
  #toc h3{{color:var(--acc);letter-spacing:.2em;font-size:.68rem;margin-bottom:1rem;font-weight:400}}
  #toc ul{{list-style:none;padding:0}}
  #toc ul ul{{padding-left:1rem;margin-top:.2rem}}
  #toc li{{margin-bottom:.3rem}}
  #toc a{{color:var(--dim);text-decoration:none;transition:color .15s}}
  #toc a:hover{{color:var(--acc)}}
  #main{{margin-left:220px;flex:1;min-width:0}}
  header{{padding:2.5rem 3rem;border-bottom:1px solid var(--bor);position:relative;overflow:hidden}}
  header::after{{content:'RECON';position:absolute;right:2rem;top:50%;transform:translateY(-50%);font-family:var(--mono);font-size:7rem;color:rgba(0,255,224,.025);letter-spacing:1rem;pointer-events:none}}
  .ey{{font-family:var(--mono);font-size:.7rem;color:var(--acc);letter-spacing:.25em;margin-bottom:.5rem}}
  h1{{font-size:2rem;font-weight:700;color:#fff}}
  h1 span{{color:var(--acc)}}
  .meta{{margin-top:.8rem;font-family:var(--mono);font-size:.75rem;color:var(--dim);display:flex;gap:2rem;flex-wrap:wrap}}
  .meta b{{color:var(--txt);font-weight:400}}
  .brow{{margin-top:1rem;display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}}
  .bl{{font-family:var(--mono);font-size:.65rem;color:var(--dim);letter-spacing:.15em;margin-right:.3rem}}
  .badge{{font-family:var(--mono);font-size:.68rem;padding:.2rem .8rem;border:1px solid rgba(0,255,224,.35);background:rgba(0,255,224,.07);color:var(--acc)}}
  .badge.warn{{border-color:rgba(255,71,87,.35);background:rgba(255,71,87,.07);color:var(--warn)}}
  .fcount{{font-family:var(--mono);font-size:.82rem;color:#ffd700;background:rgba(255,215,0,.08);border:1px solid rgba(255,215,0,.3);padding:.3rem 1rem;margin-top:.8rem;display:inline-block}}
  main{{max-width:1100px;margin:0 auto;padding:2rem 3rem 5rem;display:flex;flex-direction:column;gap:1.5rem}}
  .card{{background:var(--sur);border:1px solid var(--bor);position:relative;overflow:hidden}}
  .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,var(--acc),transparent 60%)}}
  .warn-card::before{{background:linear-gradient(90deg,var(--warn),transparent 60%)}}
  .ch{{display:flex;align-items:center;gap:.8rem;padding:.9rem 1.5rem;border-bottom:1px solid var(--bor);background:rgba(0,255,224,.02)}}
  .warn-ch{{background:rgba(255,71,87,.04)}}
  .ci{{color:var(--acc);font-size:.9rem}}
  .ch h2{{font-family:var(--mono);font-size:.8rem;font-weight:400;color:var(--acc);letter-spacing:.15em}}
  .warn-ch h2{{color:var(--warn)}}
  pre.out{{font-family:var(--mono);font-size:.78rem;color:var(--txt);padding:1.5rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all;line-height:1.8}}
  table{{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:.78rem}}
  th{{background:rgba(0,255,224,.04);color:var(--acc);padding:.6rem 1.5rem;text-align:left;letter-spacing:.12em;font-weight:400;border-bottom:1px solid var(--bor)}}
  td{{padding:.55rem 1.5rem;border-bottom:1px solid rgba(26,32,48,.6);color:var(--txt)}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:rgba(0,255,224,.025)}}
  .wtag{{font-family:var(--mono);font-size:.6rem;padding:.1rem .4rem;border:1px solid rgba(0,255,224,.4);color:var(--acc);vertical-align:middle;margin-left:.4rem}}
  .port-hdr{{font-family:var(--mono);font-size:.85rem;color:#fff;padding:.6rem 0;margin-top:.5rem;border-top:1px solid var(--bor)}}
  .port-hdr span{{color:var(--acc)}}
  .gblist{{padding:1rem 1.5rem;display:flex;flex-direction:column;gap:.4rem}}
  .gbline{{display:flex;align-items:center;gap:.8rem}}
  .gbpath{{font-family:var(--mono);font-size:.8rem;color:var(--acc);text-decoration:none;transition:color .15s}}
  .gbpath:hover{{color:#fff;text-decoration:underline}}
  .pcards{{display:flex;flex-direction:column;gap:.8rem;padding:1rem 1.5rem}}
  .pcard{{border:1px solid var(--bor);background:#0b0d12;padding:1rem}}
  .pcard.found{{border-color:rgba(0,230,118,.2)}}
  .pcard.warn{{border-color:rgba(255,71,87,.2);color:var(--warn)}}
  .pcard.dim{{opacity:.45}}
  .ph{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:.7rem}}
  .purl{{font-family:var(--mono);font-size:.78rem;color:var(--acc);text-decoration:none}}
  .purl:hover{{text-decoration:underline}}
  .sb{{font-family:var(--mono);font-size:.62rem;padding:.15rem .55rem}}
  .s200{{background:rgba(0,230,118,.12);color:var(--ok);border:1px solid rgba(0,230,118,.3)}}
  .sother{{background:rgba(255,165,0,.12);color:orange;border:1px solid rgba(255,165,0,.3)}}
  .sbin{{background:rgba(255,71,87,.12);color:var(--warn);border:1px solid rgba(255,71,87,.3)}}
  .s404,.s301,.s302,.s403{{background:rgba(100,100,100,.12);color:#888;border:1px solid #333}}
  .fbadge{{font-family:var(--mono);font-size:.62rem;padding:.15rem .55rem;background:rgba(255,215,0,.12);color:#ffd700;border:1px solid rgba(255,215,0,.3)}}
  .lbadge{{font-family:var(--mono);font-size:.62rem;padding:.15rem .55rem;background:rgba(255,165,0,.12);color:orange;border:1px solid rgba(255,165,0,.3)}}
  pre.prev{{font-family:var(--mono);font-size:.75rem;color:var(--txt);white-space:pre-wrap;word-break:break-all;line-height:1.7;max-height:280px;overflow-y:auto;padding:.8rem;background:#090b0e;border:1px solid var(--bor);margin-top:.5rem}}
  mark.fh{{background:#ffd70030;color:#ffd700;border-bottom:1px solid #ffd700;font-weight:bold}}
  .nr{{font-family:var(--mono);font-size:.78rem;color:var(--dim);padding:1rem 1.5rem}}
  code{{font-family:var(--mono);color:var(--acc);font-size:.8rem}}
  footer{{text-align:center;padding:1.5rem;font-family:var(--mono);font-size:.72rem;color:var(--dim);border-top:1px solid var(--bor)}}
  footer a{{color:var(--acc);text-decoration:none}}
</style>
</head>
<body>
<nav id="toc">
  <h3>// CONTENTS</h3>
  <ul>{toc}</ul>
</nav>
<div id="main">
<header>
  <div class="ey">// WEB RECONNAISSANCE REPORT</div>
  <h1>Target: <span>{target}</span></h1>
  <div class="meta">
    <div>GENERATED &nbsp;<b>{now}</b></div>
    <div>STARTED &nbsp;<b>{scan_start}</b></div>
    <div>FLAG PREFIX &nbsp;<b>{flag_prefix or "generic keywords"}</b></div>
  </div>
  <div class="brow"><span class="bl">WEB SERVICES //</span>{badges}</div>
  {flag_count_html}
</header>
<main>
  <div class="card" id="s-nmap">
    <div class="ch"><span class="ci">◈</span><h2>NMAP — OPEN PORTS</h2></div>
    <table><thead><tr><th>PORT</th><th>SERVICE</th><th>VERSION</th></tr></thead>
    <tbody>{port_rows or '<tr><td colspan="3" style="color:var(--dim);padding:1rem 1.5rem">No open ports found.</td></tr>'}</tbody></table>
    <pre class="out">{esc(nmap_raw)}</pre>
  </div>
  <div class="card" id="s-prechecks">
    <div class="ch"><span class="ci">◈</span><h2>QUICK CTF PRE-CHECKS</h2></div>
    <div class="pcards">{pre_html or "<p class='nr'>No results.</p>"}</div>
  </div>
  {web_html}
  {flag_section}
  {nonweb_html}
</main>
<footer>
  AutoRecon by <a href="https://github.com/DamienLim07">Damien Lim</a>
  &nbsp;·&nbsp; Authorized testing only &nbsp;·&nbsp; {now}
</footer>
</div>
</body>
</html>"""

    report_path.write_text(html)
    return report_path

# ─────────────────────────────────────────────
# Terminal Summary
# ─────────────────────────────────────────────
def print_summary(target, open_ports, web_ports, precheck_results, web_results, output_dir, report_path, flag_prefix):
    section("SCAN COMPLETE — SUMMARY")
    flag_pattern = build_pattern(flag_prefix or "")

    nonweb = [p for p in open_ports if not is_web(p["service"], p["version"])]

    print(f"\n  {C.BOLD}Target       :{C.RESET} {target}")
    print(f"  {C.BOLD}Open ports   :{C.RESET} {len(open_ports)}")
    print(f"  {C.BOLD}Web services :{C.RESET} {len(web_ports)}")

    # Interesting 200 paths
    paths_200 = []
    for r in precheck_results:
        if r["status"] == "200":
            paths_200.append(r["url"])
    for d in web_results.values():
        for cr in d.get("curl_results", []):
            paths_200.append(cr["url"])
    print(f"  {C.BOLD}200 paths    :{C.RESET} {len(paths_200)}")
    for p in paths_200[:8]:
        print(f"    {C.GREEN}→{C.RESET} {p}")
    if len(paths_200) > 8:
        print(f"    {C.DIM}... and {len(paths_200)-8} more in report{C.RESET}")

    # Flag hits
    all_hits = []
    for f in output_dir.glob("*.txt"):
        hits = find_flag_hits(read_file(f), flag_pattern)
        all_hits.extend(hits)
    if all_hits:
        print(f"\n  {C.BOLD}{C.YELLOW}⚑ {len(all_hits)} potential flag match(es) — check report!{C.RESET}")
    else:
        print(f"\n  {C.DIM}No flag pattern matches.{C.RESET}")

    if nonweb:
        print(f"\n  {C.YELLOW}[!] Non-web services — consider further enumeration:{C.RESET}")
        for p in nonweb:
            print(f"    {C.YELLOW}→{C.RESET} {p['port']:5}/{p['proto']}  {p['service']} {p['version']}")

    print(f"\n  {C.BOLD}Report :{C.RESET} {report_path}")
    print()

# ─────────────────────────────────────────────
# Wordlist Finder
# ─────────────────────────────────────────────
WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
]

def find_wordlist():
    for p in WORDLISTS:
        if os.path.exists(p):
            return p
    return None

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(description="AutoRecon — CTF Web Recon Tool by Damien Lim")
    parser.add_argument("target",                                          help="Target IP or hostname")
    parser.add_argument("-f", "--full",      action="store_true",          help="Full port scan (-p-)")
    parser.add_argument("-w", "--wordlist",  default=None,                 help="Gobuster wordlist path")
    parser.add_argument("-t", "--threads",   type=int, default=40,         help="Gobuster threads (default: 40)")
    parser.add_argument("-o", "--output",    default="./recon_output",     help="Output directory")
    parser.add_argument("-p", "--prefix",    default=None,                 help="Flag prefix e.g. picoCTF")
    parser.add_argument("-x", "--extensions", default=None,
        help="Gobuster extensions e.g. php,html,txt (default: none)")
    parser.add_argument("--port",            type=int, default=None,       help="Skip Nmap, scan specific port directly")
    parser.add_argument("--proto",           choices=["http","https"],     help="Protocol for --port")
    args = parser.parse_args()

    target     = args.target
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_start = ts()

    # Flag prefix
    flag_prefix = args.prefix
    if not flag_prefix:
        try:
            flag_prefix = input(f"{C.CYAN}[*]{C.RESET} Flag prefix (e.g. picoCTF) or Enter to skip: ").strip()
        except (EOFError, KeyboardInterrupt):
            flag_prefix = ""
    flag_prefix = flag_prefix or None
    if flag_prefix:
        success(f"Flag pattern: {flag_prefix}{{...}} + generic keywords")
    else:
        info("No prefix — generic keywords only (flag, password, secret...)")

    # Wordlist
    wordlist = args.wordlist or find_wordlist()
    if not wordlist:
        error("No wordlist found. sudo apt install seclists  or use -w")
        sys.exit(1)

    info(f"Wordlist : {wordlist}")
    info(f"Threads  : {args.threads}")
    info(f"Output   : {output_dir.resolve()}")
    print()

    check_tools()

    # ── Skip Nmap if port provided ──
    if args.port:
        port  = args.port
        proto = args.proto
        if not proto:
            try:
                pi = input(f"{C.CYAN}[*]{C.RESET} Protocol for port {port} [http/https] or Enter to auto-detect: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                pi = ""
            if pi in ("http", "https"):
                proto = pi
            else:
                info("Auto-detecting protocol...")
                proto = "http"
                for s in ("https", "http"):
                    test = f"{s}://{target}:{port}" if port not in (80,443) else f"{s}://{target}"
                    out  = run_silent(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", test])
                    if out and out != "000":
                        proto = s
                        success(f"Auto-detected: {proto}")
                        break
                else:
                    warn("Could not auto-detect, defaulting to http")

        info(f"Skipping Nmap — port {port} ({proto})")
        web_ports  = [{"port": port, "proto": "tcp", "service": "http", "version": "", "raw": "", "proto_scheme": proto}]
        open_ports = web_ports
        nmap_raw   = f"[Nmap skipped — user specified port {port} ({proto})]"

    else:
        # Phase 1 — Nmap
        nmap_raw, open_ports = run_nmap(target, args.full, output_dir)

        web_ports = []
        for p in open_ports:
            if is_web(p["service"], p["version"]):
                combined = f"{p['service']} {p['version']}".lower()
                scheme   = "https" if ("ssl" in combined or "https" in combined) else "http"
                web_ports.append({**p, "proto_scheme": scheme})

        if not web_ports:
            warn("No web services detected.")
            nonweb = [p for p in open_ports if not is_web(p["service"], p["version"])]
            if nonweb:
                warn("Non-web services found — consider further enumeration:")
                for p in nonweb:
                    print(f"  {C.YELLOW}→{C.RESET} {p['port']}/{p['proto']}  {p['service']} {p['version']}")
            sys.exit(0)

    # Phase 2 — Pre-checks
    precheck_results = run_prechecks(target, web_ports, output_dir)

    # Phase 3 — Web recon
    web_results = run_web_recon(target, web_ports, wordlist, args.threads, args.extensions, output_dir)

    # Phase 4 — Report
    section("PHASE 4 — GENERATING REPORT")
    report_path = generate_report(
        target, nmap_raw, open_ports, precheck_results,
        web_results, web_ports, flag_prefix, output_dir, scan_start
    )
    success(f"Report saved: {C.BOLD}{report_path}{C.RESET}")

    try:
        webbrowser.open(report_path.resolve().as_uri())
        success("Report opened in browser.")
    except Exception:
        warn("Could not auto-open browser. Open manually.")

    print_summary(target, open_ports, web_ports, precheck_results, web_results, output_dir, report_path, flag_prefix)

if __name__ == "__main__":
    main()
