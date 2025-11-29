# Nmap Reporter

This scripot is a beginner friendly single file tool to **parse Nmap XML output** and generate human readable reports (Markdown and simple HTML). The repository also includesa small `sample.xml` file you can use to test the parser without running an actual scan.

**Important:** This tool can optionally run `nmap' from the script, but that functionality is in tentionally disabled by default. **Only run network scans against hosts/networks you ownor have explicit permission to scan.**

---

## Files in this repo

- `nmap_reporter.py` - a single Python script (parsing, optional scanning, report generation).
- `sample.xml` - a small example Nmap XML snippet for testing the parser.
- `README.md`

---

## Requirements

- Python 3.8+
- Optional: `nmap` installed on your machine if you plan to run scans via the script:

  On Debian/Ubuntu: `sudo apt update && sudo apt install nmap`
  
  On macOS (Homebrew): `brew install nmap`

---

## What is Nmap?

- Nmap (short for Network Mapper) is a free, open-source tool used to discover devices on a network and gather information about them.
- It checks which computers are online, what ports they have open, and what services or software they’re running.

Think of it as knocking on all the doors of machines on a network and seeing who answers and what they say.

---

## Usage

1. Clone the repo:

```
git clone https://github.com/coder0name0dre/nmap_reporter.git
cd nmap_reporter
```

2. Run the parser on the included sample XML:

`python3 nmap_reporter.py --xml sample.xml --out test_report`

3. Output files:

  - `test_report.md` - Markdown report
  - `test_report.html` - simple HTML report you can open in a web browser

---

## Optional: Run `nmap` from the script (explicit, gated)

