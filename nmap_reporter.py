#!/usr/bin/env python3

import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import html
import textwrap

# SAFETY / CONFIG

# Default: do NOT run nmap automatically. You must either:
#   pass --run-nmap on the command line (explicit)
#   OR change RUN_NMAP = True below (not recommended without permission)
RUN_NMAP = False

# Default nmap command template (customise if you know what you're doing)
NMAP_CMD_TEMPLATE = ["nmap", "-sV", "-0", "-oX", "{xml_out}", "{target}"]
# -sV: service/version detection
# -0: OS detection (requires root for some probes)
# -oX: output to XML (we parse that)


# Helper: run nmap (optional)

def run_nmap(target: str, xml_out: str) -> int:
# Runs nmap with the configured command template, writing XML to xml_out.
# Returns the subprocess return code.
# WARNING: only run against authorised targets.
    cmd = [p.format(xml_out=xml_out, target=target) for p in NMAP_CMD_TEMPLATE]
    print(f"[+] Running nmap: {' '.join(cmd)}")
    try:
        completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        print("[-] nmap executable not found, Install nmap or ensure it's in your PATH.")
        raise
    print(f"[+] nmap finished (returncode={completed.returncode}).")
    # Optionally print stdout/stderr for debgging (commented out for neatness)
    # print(completed.stdout)
    # print(file=sys.stderr)
    return completed.returncode


# Parser: Basic Nmap XML -> Python structures

def parse_nmap_xml(xml_path: str):
# Parse Nmap XML output and return a structured dict.
    tree = ET.parse(xml_path)
    root = tree.getroot()

    result = {'scan_info': {}, 'hosts': []}

    # top-level scan info (if present)
    scaninfo = root.find('scaninfo')
    if scaninfo is not None:
        result['scan_info'] = scaninfo.attrib

    # iterate hosts
    for h in root.findall('host'):
        # status
        status_elem = h.find('status')
        status = status_elem.attrib.get('state') if status_elem is not None else 'unknown'

    # address(es)
    addr = None
    addrs = []
    for a in h.findall('address'):
        addr_type = a.attrib.get('addrtype', '')
        addr_val = a.attrib.get('addr', '')
        addrs.append({'type': addr_type, 'addr': addr_val})
        if addr_type == 'ipv4' and addr is None:
            addr = addr_val

    # hostnames
    hostnames = []
    hn = h.find('hostnames')
    if hn is not None:
        for name in hn.findall('hostname'):
            hostnames.append(name.attrib.get('name', ''))

    # ports
    ports_list = []
    ports = h.find('ports')
    if ports is not None:
        for p in ports.findall('port'):
            portid = p.attrib.get('portid')
            protocol = p.attrib.get('protocol')
            state = ''
            state_elem = p.find('state')
            if state_elem is not None:
                state = state_elem.attrib.get('state', '')
            service_name = ''
            product = ''
            version = ''
            svc = p.find('service')
            if svc is not None:
                service_name = svc.attrib.get ('name', '')
                product = svc.attrib.get('product', '')
                version = svc.attrib.get('version', '')
            ports_list.append({
                'portid': portid,
                'protocol': protocol,
                'state': state,
                'state': state,
                'service': service_name,
                'product': product,
                'version': version
            })

    # os best guess
    os_elem = h.find('os')
    os_info = {}
    if os_elem is not None:
        # try to pick the bestmatch element
        best = os_elem.find('osmatch')
        if  best is not None:
            os_info = best.attrib
        else:
            # collect osclass info
            classes = []
            for c in os_elem.findall('osclass'):
                classes.append(c.attrib)
            if classes:
                os_info['osclass'] = classes

    host_record = {
        'status': status,
        'addr': addr if addr else (addrs[0]['addr'] if addrs else None),
        'addresses': addrs,
        'hostnames': hostnames,
        'ports': ports_list,
        'os': os_info
    }
    result['hosts'].append(host_record)

    return result


# Reporter: Markdown & HTML

def generate_markdown_report(scan_data: dict, title="Nmap Scan Report") -> str:
# Create a Markdown fornmatted report from parsed scan data.
    md_lines = []
    md_lines.append(f"# {title}")
    md_lines.append(f"*Genereated: {datetime.utcnow().isoformat()} UTC*")
    md_lines.append("")
    si = scan_data.get('scan_info', {})
    if si:
        md_lines.append("## Scan info")
        for k, v in si.items():
            md_lines.append(f"- **{k}**: {v}")
        md_lines.append("")

    md_lines.append("## Hosts")
    for host in scan_data.get('hosts', []):
        addr = host.get('addr') or 'unknown'
        md_lines.append(f"### Host: {addr}")
        md_lines.append(f"- Status: **{host.get('status')}**")
        if host.get('hostnames'):
            md_lines.append(f"- Hostnames: {', '.join(host.get('hostnames'))}")
        
        # addresses
        addrs = ", ".join(f"{a['type']}:{a['addr']}" for a in host.get('addresses', []))
        if addrs:
            md_lines.append(f"- Addresses: {addrs}")

        # OS (best guess)
        if host.get('os'):
            md_lines.append(f"- OS Guess: {host['os']}")

        # Ports
        if host.get('ports'):
            md_lines.append("")
            md_lines.append("### Open/Filtered ports")
            md_lines.append("| Port | Proto | State| Service | Product | Version |")
            md_lines.append("---:|:---:|:---:|:---|:---|:---|")
            for p in host['ports']:
                md_lines.append(
                    f"| {p['portid']} | {p['protocol']} | {p['state']} | "
                    f"{p['service'] or '-'} | {p['product'] or '-'} | {p['version'] or '-'} |"
                )
        md_lines.append("")     # nlank line between hosts

    return "\n".join(md_lines)

def markdown_to_simple_html(md: str) -> str:
# Very small conversion of headings, tables and lists
    html_lines = []
    for line in md.splitlines():
        if line.startswith("# "):
            html_lines.append(f"<h1>{html.escape(line[2:].strip())}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{html.escape(line[3:].strip())}</h2>")
        elif line.startswith("### "):
            html_lines.append(f"<h3>{html.escape(line[4:].strip())}</h3>")
        elif line.startswith("#### "):
            html_lines.append(f"<h4>{html.escape(line[5:].strip())}</h4>")
        elif line.startswith("|"):
            # crude table handling: we will collect all table rows and render a simple table
            # To keep this simple, we will build tables on the fly (not fully generic)
            html_lines.append(line)  # keep for now and post-process
        elif line.startswith("- **"):
            # simple bolded list item
            html_lines.append(f"<p><strong>{html.escape(line[3:].strip())}</strong></p>")
        elif line.startswith("- "):
            html_lines.append(f"<li>{html.escape(line[2:])}</li>")
        elif line.strip() == "":
            html_lines.append("<br/>")
        else:
            # plain paragraph fallback; escape to avoid injection
            html_lines.append(f"<p>{html.escape(line)}</p>")

    # assemble and convert crude table blocks between lines starting with '|'
    joined = "\n".join(html_lines)
    # convert table rows: lines that start with '|' into a table
    if "|" in joined:
        rows = [ln for ln in joined.splitlines() if ln.strip().startswith("|")]
        if rows:
            table_html = ["<table border='1' cellspacing='0' cellpadding='4'>"]
            for r in rows:
                # split by '|' and ignore empty leading/trailing cells
                cells = [c.strip() for c in r.split("|")[1:-1]]
                # first row may be header separator detected by '---' => treat previous row as header
                # For simplicity, we will treat the first row as header if it looks like header
                # But our markdown includes header and separator; skip separator rows that look like '---'
                if all(set(c) <= set("-:") for c in cells):
                    continue
                # If this is first table row and contains text, make it header row
                if rows.index(r) == 0:
                    table_html.append("<thead><tr>" + "".join(f"<th>{html.escape(c)}</th>" for c in cells) + "</tr></thead>")
                    table_html.append("<tbody>")
                else:
                    table_html.append("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in cells) + "</tr>")
            table_html.append("</tbody></table>")
            # replace the rows in joined with table_html
            # naive approach: remove the table row lines and append table html
            new_lines = [ln for ln in joined.splitlines() if not (ln.strip().startswith("|"))]
            # insert table_html after first occurrence of a header like title (approx)
            new_lines.append("\n".join(table_html))
            joined = "\n".join(new_lines)

        # wrap final HTML
    final_html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Nmap Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
    th {{ background: #f4f4f4; }}
    pre {{ background: #f8f8f8; padding: 10px; overflow-x: auto; }}
  </style>
</head>
<body>
{joined}
</body>
</html>"""
    return final_html


# Main CLI & Clue

def main():
    parser = argparse.ArgumentParser(description="Nmap XML parser + report generator (beginner friendly).")
    parser.add_argument("--xml", "-x", help="Input Nmap XML file to parse (if you already have one).")
    parser.add_argument("--out", "-o", default="nmap_report", help="Output base filename (no extension).")
    parser.add_argument("--target", "-t", help="Target for nmap (host or network) if you want the script to run nmap.")
    parser.add_argument("--run-nmap", action="store_true", help="Allow the script to run nmap (disabled by default). Use only with permission.")
    args = parser.parse_args()

    xml_path = args.xml
    if args.run_nmap or RUN_NMAP:
        # if user requested to run nmap via CLI or we changed the constant
        if not args.target:
            print("[-] To run nmap you must specify --target TARGET (and ensure you have permission).")
            sys.exit(1)
        # create output filename
        xml_path = f"{args.out}.xml"
        # run nmap
        rc = run_nmap(args.target, xml_path)
        if rc != 0:
            print("[-] nmap returned non-zero exit code. Check nmap output. Aborting.")
            sys.exit(rc)
        print(f"[+] nmap XML saved to {xml_path}")

    if not xml_path:
        print("[-] No XML provided. Either pass --xml FILE or use --run-nmap with --target.")
        sys.exit(1)

    if not Path(xml_path).exists():
        print(f"[-] XML file not found: {xml_path}")
        sys.exit(1)

    print(f"[+] Parsing XML: {xml_path}")
    parsed = parse_nmap_xml(xml_path)

    print("[+] Generating Markdown report...")
    md = generate_markdown_report(parsed, title=f"Nmap Scan Report ({Path(xml_path).name})")
    md_file = f"{args.out}.md"
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[+] Markdown report written: {md_file}")

    print("[+] Generating HTML report...")
    html_text = markdown_to_simple_html(md)
    html_file = f"{args.out}.html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_text)
    print(f"[+] HTML report written: {html_file}")

    print("[+] Done. Open the HTML report in a browser or inspect the Markdown file.")

if __name__ == "__main__":
    main()