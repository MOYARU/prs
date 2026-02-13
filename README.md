```text
██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗██╔════╝
██████╔╝██████╔╝███████╗
██╔═══╝ ██╔══██╗╚════██║
██║     ██║  ██║███████║
╚═╝     ╚═╝  ╚═╝╚══════╝
```
<p align="center">
  <h1>PRS v1.8.0</h1>
  <h3>Passive Reconnaissance Scanner</h3>
  <p>
    <strong>Defensive-First Web Security Scanner</strong><br>
  </p>

  <p>
    <a href="https://github.com/MOYARU/PRS-project/releases">
      <img src="https://img.shields.io/github/v/release/MOYARU/PRS-project?color=5865F2" alt="Release">
    </a>
    <a href="https://github.com/MOYARU/PRS-project/stargazers">
      <img src="https://img.shields.io/github/stars/MOYARU/PRS-project?style=social" alt="Stars">
    </a>
    <img src="https://img.shields.io/github/go-mod/go-version/MOYARU/PRS-project?color=00ADD8" alt="Go">
    <img src="https://img.shields.io/github/license/MOYARU/PRS-project?color=green" alt="MIT">
  </p>
</p>

---
 
### Key Features
- **Real-time Language Switching**: Toggle between English and Korean instantly.
- **Intuitive Output**: Clean console output + detailed HTML reports.
- **Crawling & Form Extraction**: Automatically discovers URLs and extracts form data.
- **Defensive Focus**: Identifies vulnerabilities without direct exploitation.

## Build & Installation
```
git clone https://github.com/MOYARU/PRS-project.git

cd PRS-project

go build -o prs.exe

./prs

prs example.com
```

or use makefile to build
```
make

make run

make deps
```

### start

**./prs**

```bash
# scan
prs https://example.com

prs https://example.com --depth 3 --json

# active mode
prs https://example.com --active

# delay 300ms
prs https://example.com --delay 300
```
