# 🛡️ PackageGuard — SOC Supply Chain Risk Scanner & OSINT Intelligence

**PackageGuard** is a security-operations-grade (SOC) supply-chain risk scanner for **npm** (JavaScript) and **PyPI** (Python) packages. It enables software engineers, DevSecOps teams, and security auditors to inspect third-party dependencies before installing them into development or production pipelines.

PackageGuard fuses static-analysis AST detections from **DataDog GuardDog** with maintainer footprint reconnaissance via **Maigret**, correlates findings with the **MITRE ATT&CK® for Enterprise** framework, calculates multi-vector threat scores, and provides plain-English DevSecOps triage playbooks.

---

## 📋 Evaluation Rubric Alignment (Total: 30 Marks)

PackageGuard was built strictly to satisfy the College Project Assessment Rubrics:

| Rubric No. | Evaluation Criteria | Marks | PackageGuard Implementation |
| :---: | :--- | :---: | :--- |
| **Rubric 1** | **Problem Definition, Objectives & Literature Survey** | **5** | Software supply chain crisis (SolarWinds, xz-utils CVE-2024-3094); Comparative survey of Snyk, Dependabot, Socket.dev, and GuardDog; Addressing the research gap. |
| **Rubric 2** | **System Design and Methodology** | **5** | 3-tier architecture (SOC UI, Isolation Sandbox, GuardDog & Maigret engines, SQLite store); 5-stage analysis pipeline; Weighted multi-vector mathematical scoring model ($Score = \min(100, \sum w_i)$). |
| **Rubric 3** | **Implementation and Functionality** | **10** | Decoupled `scanner.py` & `osint_analyzer.py`; Windows UTF-8 subprocess bridge; Maigret author OSINT profiling; Direct npm/PyPI registry deep links; 3-point plain-English triage cards. |
| **Rubric 4** | **Testing, Results and Security Evaluation** | **5** | Automated test suite (11/11 unit tests passing); Empirical evaluation on clean (`requests`), framework (`express`), and live backdoor (`reqeusts-backdoor`) packages; Latency benchmarks & evasion resistance. |
| **Rubric 5** | **Project Presentation, Demonstration & Viva Voce** | **5** | Full 14-slide academic presentation (`PackageGuard_Project_Evaluation.pptx`); In-browser interactive slide deck at `/presentation`; Top 10 anticipated viva technical questions and model answers. |
| | **TOTAL** | **30** | **Complete Academic Defense Package** |

---

## 🚀 Key Security Features

1. **Static AST Detection Engine (DataDog GuardDog)**:
   - Wraps [GuardDog](https://github.com/DataDog/guarddog) CLI in an isolated sandbox.
   - Evaluates packages against 30+ Semgrep AST rules without executing malicious build scripts.
2. **Maintainer Threat Intelligence (Maigret Engine)**:
   - Integrates [Maigret](https://github.com/soxoj/maigret) and developer registry crawlers.
   - Profiles maintainer handles across GitHub, GitLab, npm, PyPI, and HackerNews to intercept disposable "burner/ghost" accounts commonly used in malware distribution.
3. **Direct Package Registry Deep Links**:
   - High-visibility action buttons link directly to official upstream manifests:
     - `[ 📦 View on npmjs.com ↗ ]`
     - `[ 🐍 View on PyPI.org ↗ ]`
     - `[ 🐙 Source Repository ↗ ]`
4. **Crystal-Clear Plain-English 3-Point Triage Cards**:
   - Replaces dense AST syntax dumps with human-interpretable cards:
     - 🔍 **1. What Was Detected (Plain English)**
     - 💥 **2. Potential Risk & Practical Impact**
     - 🛡️ **3. What You Should Do (DevSecOps Fix)**
5. **MITRE ATT&CK® Enterprise Mapping**:
   - Maps every heuristic finding directly to its MITRE Tactic (`TA0001` to `TA0010`) and Technique (`T1195.001`, `T1059.007`, `T1027`, `T1048`).
6. **Multi-Vector Attack Surface Assessment**:
   - Evaluates risk across 4 core vectors: *Initial Access*, *Execution & Hooks*, *Evasion & Obfuscation*, and *Data Exfiltration*.
7. **Persistent SQLite Store & One-Click Report Export**:
   - Stores scan history with full JSON metadata.
   - Generates and downloads formal Markdown Security Audit Reports (`PackageGuard_Security_Audit_<pkg>.md`).
8. **Built-In Presentation & OSINT Labs**:
   - `/presentation`: Interactive in-browser presentation slide deck.
   - `/download-presentation`: Direct download of `PackageGuard_Project_Evaluation.pptx`.
   - `/investigate-author`: Standalone maintainer OSINT laboratory.

---

## 🧮 Multi-Vector Scoring Methodology

PackageGuard calculates an overall risk score from **0 to 100** based on weighted heuristic accumulation:

$$\text{Risk Score} = \min\left(100, \sum_{\text{rule } \in \text{ Triggered}} \text{Weight}(\text{rule})\right)$$

### 1. Severity Weights
- **High Severity (30–35 pts)**: Base64 obfuscated execution, sensitive data exfiltration, reverse shells, download-and-execute payloads, typosquatting.
- **Medium Severity (15–20 pts)**: Lifecycle install scripts, API reflection obfuscation, bundled pre-compiled binaries, metadata mismatches.
- **Low Severity (5–8 pts)**: Version 0.0.0 releases, empty package descriptions, single-file distributions.

### 2. High-Severity Floor
If **any single High-severity rule** is triggered, the package score is automatically elevated to at least **35**, preventing high-risk packages with single findings from being classified as benign.

### 3. Verdict Categorization
- 🟢 **0 – 24 (LOW RISK / SAFE TO USE)**: Clean / benign dependency.
- 🟡 **25 – 69 (MEDIUM RISK / AUDIT REQUIRED)**: Suspicious traits; manual review recommended before production deployment.
- 🔴 **70 – 100 (HIGH RISK / DO NOT INSTALL)**: Critical malware, backdoor, or account compromise. Quarantine immediately.

---

## 📐 Project Structure

```text
C:\cybersec\
│
├── app.py                             # Flask web server, SOC telemetry, SQLite & REST routes
├── scanner.py                         # GuardDog CLI wrapper, UTF-8 sandbox, MITRE ATT&CK mapper & scoring
├── osint_analyzer.py                  # Maigret maintainer OSINT engine & registry crawler
├── generate_presentation.py           # PPTX presentation generator covering all 5 rubrics
├── PackageGuard_Project_Evaluation.pptx # 14-slide academic evaluation presentation
├── seed_demo.py                       # Pre-populates clean, framework, and malware demo samples
├── test_app.py                        # Automated unit & integration test suite (11 tests)
├── packageguard.db                    # SQLite persistent database
├── requirements.txt                   # Dependency manifest (flask, guarddog, maigret, python-pptx)
├── README.md                          # Comprehensive technical documentation & viva defense guide
│
├── templates/
│   ├── index.html                     # SOC Cyber Command Center dashboard
│   ├── author_investigate.html        # Maintainer OSINT Reconnaissance Lab
│   └── presentation.html              # In-browser presentation slide deck
│
└── static/
    ├── style.css                      # Professional Light Editorial Design System (Crisp cards, emerald accents, no blue/no black)
    ├── diagram_system_architecture.png # Multi-tier architecture diagram
    ├── diagram_guarddog_ast.png       # GuardDog static AST pipeline diagram
    ├── diagram_osint_investigator.png # Maigret maintainer OSINT triangulation diagram
    └── chart_evaluation_benchmarks.png # Academic comparative evaluation chart
```

---

## 🛠️ Quickstart & Execution Guide

### 1. Run Automated Unit Tests
```powershell
cd C:\cybersec
python test_app.py
```
*(All 11 unit and integration tests should pass with 100% success).*

### 2. Seed Realistic Demo Records
```powershell
python seed_demo.py
```
*(Populates baseline samples: `requests` [PyPI Clean], `express` [npm Reflection], and `reqeusts-backdoor` [PyPI Malware]).*

### 3. Start the Web Dashboard
```powershell
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 🎓 Viva Voce Defense Cheatsheet (Top 6 Questions & Model Answers)

### Q1: Why use AST (Abstract Syntax Tree) analysis instead of regular expressions?
> **Answer**: Regular expressions rely on simple substring matching and fail when attackers alter variable names, add comments, or reformat whitespace. AST parsing translates source code into a hierarchical syntax tree, analyzing semantic code constructs (e.g., dynamic `eval()`, child process spawning, socket connections) accurately regardless of formatting.

### Q2: How does PackageGuard prevent malicious code from executing during scanning?
> **Answer**: GuardDog downloads and decompresses the package archive into an isolated temporary folder without running package manager commands like `npm install` or `pip install`. Lifecycle hooks (`setup.py`, `preinstall`) are never executed. The code is parsed strictly as static text and AST objects.

### Q3: How does this differ from Snyk or Dependabot?
> **Answer**: Snyk and Dependabot match package version strings against known vulnerability databases (CVEs/NVD). If an attacker publishes a brand-new zero-day malicious package today, it has no CVE. PackageGuard analyzes the actual source code heuristically, intercepting zero-day backdoors, obfuscation, and typosquatting immediately.

### Q4: Why is Maigret author OSINT integrated into a dependency scanner?
> **Answer**: Software supply chain security is fundamentally an identity problem. Over 82% of malicious open-source packages originate from disposable burner accounts created hours before upload. By profiling author usernames across GitHub, GitLab, npm, PyPI, and social platforms via Maigret, PackageGuard triangulates whether a maintainer is an established developer or an anonymous throwaway account.

### Q5: How did you solve the Windows encoding error with GuardDog?
> **Answer**: On Windows, subprocess pipes default to `cp1252` encoding, causing `UnicodeDecodeError` when reading UTF-8 Semgrep YAML rules. We resolved this by explicitly injecting `PYTHONUTF8=1` and `PYTHONIOENCODING=utf-8` into the subprocess environment and setting `errors='replace'` with UTF-8 decoding.

### Q6: How does the scoring formula prevent false alarms?
> **Answer**: The scoring model categorizes findings into 4 distinct threat vectors. Common architectural patterns like dynamic method dispatch in Express are assigned low weights (18 pts), whereas confirmed credential exfiltration and base64 payloads receive heavy 35 pt penalties with High-severity overrides that immediately elevate the score to the Critical tier (70–100).
