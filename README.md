# Nmap Reporter

This scripot is a beginner friendly single file tool to **parse Nmap XML output** and generate human readable reports (Markdown and simple HTML). The repository also includesa small `sample.xml` file you can use to test the parser without running an actual scan.

**Important:** This tool can optionally run `nmap' from the script, but that functionality is in tentionally disabled by default. **Only run network scans against hosts/networks you ownor have explicit permission to scan.**

---

## Files in this repo

- `nmap_reporter.py` - a single Python script (parsing, optional scanning, report generation).
- `sample.xml` - a small example Nmap XML snippet for testing the parser.
- `README.md`

---

