"""
scanner.py - Core Scanning, Scoring, & MITRE ATT&CK Engine for PackageGuard
===========================================================================

This module wraps DataDog's GuardDog CLI scanner, executes package scans in a
subprocess, parses the resulting JSON findings, correlates them with the
MITRE ATT&CK for Enterprise framework, computes multi-dimensional threat vector
scores, integrates Maigret author OSINT intelligence, and provides plain-English
DevSecOps remediation guidance.

Author: College Project viva implementation
Underlying Engine: DataDog GuardDog (Apache-2.0)
OSINT Engine: Maigret (GPL-3.0) & Registry Crawlers
"""

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import osint_analyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping & Rule Knowledge Base
# ---------------------------------------------------------------------------
RULE_CATALOG: Dict[str, Dict[str, Any]] = {
    # High Severity Threats (Malware, C2, Backdoors, Supply Chain Takeover)
    "exec-base64": {
        "name": "Base64 Obfuscated Execution",
        "severity": "High",
        "weight": 35,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.002: Software Packing / Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/002/",
        "description": "The package decodes and dynamically executes base64-encoded strings (eval/exec). Attackers frequently use this technique to hide malicious payloads from static analysis.",
        "remediation": "Quarantine the package immediately. Inspect the decoded payload in an isolated sandbox. Replace with a trusted alternative or pin to an audited version.",
    },
    "npm-exec-base64": {
        "name": "Base64 Obfuscated Execution",
        "severity": "High",
        "weight": 35,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.002: Software Packing / Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/002/",
        "description": "The npm package decodes and evaluates base64 data at runtime (e.g., eval(Buffer.from(..., 'base64'))), typically hiding malicious code.",
        "remediation": "Do not install this package. Check npm advisory database and investigate the AST of the flagged file using a JavaScript deobfuscator.",
    },
    "threat-runtime-obfuscation-base64exec": {
        "name": "Base64 Obfuscated Execution",
        "severity": "High",
        "weight": 35,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.002: Software Packing / Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/002/",
        "description": "Executes decoded base64 strings dynamically, a common indicator of concealed malware payloads.",
        "remediation": "Block installation in CI/CD pipeline using pre-commit security linters.",
    },
    "exfiltrate-sensitive-data": {
        "name": "Sensitive Data Exfiltration",
        "severity": "High",
        "weight": 35,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0010: Exfiltration",
        "mitre_technique": "T1048: Exfiltration Over Alternative Protocol",
        "mitre_url": "https://attack.mitre.org/techniques/T1048/",
        "description": "The package gathers sensitive files or system tokens and transmits them to external IP addresses or domains without authorization.",
        "remediation": "Block outbound network egress for build agents. Rotate all exposed environment variables, SSH keys, and cloud API tokens immediately.",
    },
    "npm-exfiltrate-sensitive-data": {
        "name": "Sensitive Data Exfiltration",
        "severity": "High",
        "weight": 35,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0010: Exfiltration",
        "mitre_technique": "T1048: Exfiltration Over Alternative Protocol",
        "mitre_url": "https://attack.mitre.org/techniques/T1048/",
        "description": "Detects unauthorized exfiltration of sensitive credentials, environment secrets, or SSH keys to remote endpoints.",
        "remediation": "Inspect network endpoints in the package code. Revoke and rotate all environment secrets referenced on the development host.",
    },
    "threat-network-exfiltration": {
        "name": "Network Data Exfiltration / C2",
        "severity": "High",
        "weight": 35,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0010: Exfiltration",
        "mitre_technique": "T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol",
        "mitre_url": "https://attack.mitre.org/techniques/T1048/003/",
        "description": "Transmits data to known suspicious Command & Control (C2) domains or unauthorized network endpoints.",
        "remediation": "Add flagged domains to corporate DNS sinkholes and egress firewalls.",
    },
    "threat-network-reverse-shell": {
        "name": "Reverse Shell Pattern",
        "severity": "High",
        "weight": 35,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1059.006: Command and Scripting Interpreter: Python",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/006/",
        "description": "Opens an interactive command shell back to a remote attacker, providing backdoor access into your server or machine.",
        "remediation": "Treat host as compromised if installed. Isolate the machine from the internal network and initiate incident response protocols.",
    },
    "threat-process-download-exec": {
        "name": "Download and Execute Payload",
        "severity": "High",
        "weight": 35,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1204.002: Malicious File Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1204/002/",
        "description": "Fetches an external binary or script from the internet and executes it on the local operating system.",
        "remediation": "Deny arbitrary outbound network access in CI/CD build environments using network policy isolation.",
    },
    "download-executable": {
        "name": "Download and Execute Payload",
        "severity": "High",
        "weight": 35,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1204.002: Malicious File Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1204/002/",
        "description": "Downloads an executable or script from a remote server and executes it on the host system.",
        "remediation": "Verify whether the binary is legitimate vendor tooling (e.g. headless browsers). If unexpected, remove the package immediately.",
    },
    "typosquatting": {
        "name": "Typosquatting Mimicry",
        "severity": "High",
        "weight": 30,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.001: Compromise Software Dependencies",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/001/",
        "description": "The package name closely resembles a highly popular package (e.g., 'reqeusts' instead of 'requests'). This is a textbook social engineering technique to trick developers into installing malicious clones.",
        "remediation": "Double-check spelling in requirements.txt or package.json. Always verify package download count and GitHub repository stars.",
    },
    "threat-metadata-typosquatting": {
        "name": "Typosquatting Mimicry",
        "severity": "High",
        "weight": 30,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.001: Compromise Software Dependencies",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/001/",
        "description": "Package name closely mimics a trusted popular package, designed to deceive developers during typo mistakes.",
        "remediation": "Enforce package-lock.json pinning and automated dependency review in pull requests.",
    },
    "potentially_compromised_email_domain": {
        "name": "Compromised Maintainer Domain",
        "severity": "High",
        "weight": 30,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1584: Compromise Infrastructure",
        "mitre_url": "https://attack.mitre.org/techniques/T1584/",
        "description": "The maintainer's registered domain has expired or changed ownership, allowing attackers to hijack email verification and publish rogue releases under their identity.",
        "remediation": "Do not upgrade to newer versions of this package until the maintainer's identity is re-established via cryptographic signatures.",
    },
    "unclaimed_maintainer_email_domain": {
        "name": "Unclaimed Maintainer Email Domain",
        "severity": "High",
        "weight": 30,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1584.001: Domains",
        "mitre_url": "https://attack.mitre.org/techniques/T1584/001/",
        "description": "The maintainer's domain is currently available for public registration, leaving the package vulnerable to account takeover.",
        "remediation": "Pin strictly to previously audited versions. Report the unclaimed domain to the registry security team.",
    },
    "code-execution": {
        "name": "Arbitrary Code Execution",
        "severity": "High",
        "weight": 30,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1059: Command and Scripting Interpreter",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Executes shell commands, system binaries, or arbitrary code strings during package import or setup.",
        "remediation": "Audit the exact shell command being executed. Verify if subprocess calls sanitize inputs against command injection.",
    },
    "threat-runtime-dynamic-loader": {
        "name": "Dynamic Runtime Code Loader",
        "severity": "High",
        "weight": 30,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1055: Process Injection",
        "mitre_url": "https://attack.mitre.org/techniques/T1055/",
        "description": "Fetches and imports secondary code files at runtime, evading initial package inspection.",
        "remediation": "Reject packages that pull secondary code from untrusted CDNs or raw IP addresses.",
    },
    "dll-hijacking": {
        "name": "DLL Hijacking Attempt",
        "severity": "High",
        "weight": 30,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0004: Privilege Escalation",
        "mitre_technique": "T1574.001: DLL Search Order Hijacking",
        "mitre_url": "https://attack.mitre.org/techniques/T1574/001/",
        "description": "Attempts to drop or reference shared library DLLs in untrusted paths to hijack privileged system processes.",
        "remediation": "Enforce Safe DLL Search Mode on Windows hosts and scan DLL checksums against known vendor hashes.",
    },
    "npm-dll-hijacking": {
        "name": "DLL Hijacking Attempt",
        "severity": "High",
        "weight": 30,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0004: Privilege Escalation",
        "mitre_technique": "T1574.001: DLL Search Order Hijacking",
        "mitre_url": "https://attack.mitre.org/techniques/T1574/001/",
        "description": "Attempts to execute DLL hijacking by loading libraries from user-writable directories.",
        "remediation": "Ensure node applications run with least privilege and do not have write access to system directories.",
    },
    "steganography": {
        "name": "Steganographic Code Concealment",
        "severity": "High",
        "weight": 30,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.003: Steganography",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/003/",
        "description": "Hides executable code within images or binary assets, decoding and running it dynamically at runtime.",
        "remediation": "Quarantine the package. Open-source libraries almost never bundle steganographic loaders legitimately.",
    },
    "npm-steganography": {
        "name": "Steganographic Code Concealment",
        "severity": "High",
        "weight": 30,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.003: Steganography",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/003/",
        "description": "Hides executable code within image or media assets to evade standard code reviews.",
        "remediation": "Perform file carving and entropy analysis on bundled media files to extract the concealed payload.",
    },
    "repository_integrity_mismatch": {
        "name": "Repository Integrity Mismatch",
        "severity": "High",
        "weight": 28,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.002: Compromise Software Supply Chain",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/002/",
        "description": "The package tarball contains files that do not exist in the linked source code repository (e.g. GitHub), indicating unexpected or stealthily added code.",
        "remediation": "Compare git commit tree with registry tarball. Do not deploy packages with phantom release files.",
    },
    "risky_new_dependency": {
        "name": "Risky New Dependency Introduced",
        "severity": "High",
        "weight": 25,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.001: Compromise Software Dependencies",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/001/",
        "description": "A newly introduced sub-dependency in this package release has triggered significant security flags.",
        "remediation": "Run transitive dependency audit using 'npm audit' or 'pip-audit' to identify the flagged sub-package.",
    },

    # Medium Severity Threats (Suspicious Evasion / Lifecycle / Metadata)
    "shady-links": {
        "name": "Suspicious External URLs",
        "severity": "Medium",
        "weight": 18,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1071.001: Web Protocols",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "Contains hardcoded URLs linking to URL shorteners (bit.ly), temporary pastebins, or anonymous file-sharing services often used for staging payloads.",
        "remediation": "Inspect resolved destinations of short links. Disallow unverified shortener domains in code review standards.",
    },
    "threat-network-outbound-shady-links": {
        "name": "Suspicious External URLs",
        "severity": "Medium",
        "weight": 18,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1071.001: Web Protocols",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "The package contacts URL shorteners or anonymous file sharing services.",
        "remediation": "Verify whether short URLs resolve to legitimate documentation or unauthorized binary hosting.",
    },
    "api-obfuscation": {
        "name": "API Call Obfuscation",
        "severity": "Medium",
        "weight": 18,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027: Obfuscated Files or Information",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Obfuscates sensitive API calls using reflection, string manipulation, or getattr tricks to hinder static code scanners.",
        "remediation": "Audit the flagged function invocations to verify whether dynamic dispatch is used for legitimate framework routing or evasion.",
    },
    "npm-api-obfuscation": {
        "name": "API Call Obfuscation",
        "severity": "Medium",
        "weight": 18,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027: Obfuscated Files or Information",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Obfuscates method calls dynamically (e.g. obj[key](...)), evading standard static analysis patterns.",
        "remediation": "Review the specific file location. Popular libraries (like express routing) use dynamic dispatch, but unvetted libraries should be inspected.",
    },
    "npm-install-script": {
        "name": "Install-Time Lifecycle Hook",
        "severity": "Medium",
        "weight": 18,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1059.007: JavaScript Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "The package executes arbitrary scripts during 'npm install' (preinstall/postinstall). While legitimate packages occasionally do this for native builds, it is also the primary vector for automated npm malware execution.",
        "remediation": "Run 'npm install --ignore-scripts' or add 'ignore-scripts=true' to your repository's .npmrc file to prevent automatic script execution.",
    },
    "new_install_script": {
        "name": "Newly Added Install Hook",
        "severity": "Medium",
        "weight": 20,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1059.007: JavaScript Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "This version introduced an install-time lifecycle script (pre/postinstall) to a package that previously never used one, which is a classic pattern of compromised package takeovers.",
        "remediation": "Hold update. Inspect git diff between the previous release and current release to see what command the install script invokes.",
    },
    "threat-npm-preinstall-script": {
        "name": "npm Preinstall Script",
        "severity": "High",
        "weight": 30,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0002: Execution",
        "mitre_technique": "T1059.007: JavaScript Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/007/",
        "description": "Contains npm preinstall lifecycle scripts, which execute arbitrary code before any package validation can occur.",
        "remediation": "Do not install without '--ignore-scripts'. Preinstall hooks have no build justification in modern JavaScript workflows.",
    },
    "deceptive_author": {
        "name": "Disposable Author Identity",
        "severity": "Medium",
        "weight": 15,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1589: Gather Victim Identity Information",
        "mitre_url": "https://attack.mitre.org/techniques/T1589/",
        "description": "The package maintainer's registered contact email belongs to a disposable or burner email provider (e.g. Mailinator, GuerrillaMail), obscuring maintainer accountability.",
        "remediation": "Prefer packages backed by known organizations or maintainers with established public GitHub profiles and GPG/Sigstore signatures.",
    },
    "bundled_binary": {
        "name": "Bundled Binary Executables",
        "severity": "Medium",
        "weight": 15,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.001: Binary Packing",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/001/",
        "description": "Ships pre-compiled native binaries (.exe, .so, .dll) inside the package archive instead of compiling from verifiable open source code.",
        "remediation": "Submit bundled binaries to VirusTotal. Prefer dependencies built from source or using reproducible CI build attestations.",
    },
    "direct_url_dependency": {
        "name": "Direct URL Dependency",
        "severity": "Medium",
        "weight": 15,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.001: Compromise Software Dependencies",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/001/",
        "description": "Specifies dependencies via raw HTTP/HTTPS URLs rather than immutable registry version pins, breaking reproducibility and integrity.",
        "remediation": "Replace raw URL dependencies with fixed versions pinned to the official registry and verified with subresource integrity hashes.",
    },
    "metadata_mismatch": {
        "name": "Metadata vs Manifest Mismatch",
        "severity": "Medium",
        "weight": 15,
        "category": "Initial Access",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1036: Masquerading",
        "mitre_url": "https://attack.mitre.org/techniques/T1036/",
        "description": "The registry metadata contradicts the package manifest (package.json or setup.py), which can indicate deliberate tamper attempts.",
        "remediation": "Inspect version numbers and repository links inside package.json to verify consistency with npm registry listing.",
    },
    "npm_metadata_mismatch": {
        "name": "Metadata vs Manifest Mismatch",
        "severity": "Medium",
        "weight": 15,
        "category": "Initial Access",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1036: Masquerading",
        "mitre_url": "https://attack.mitre.org/techniques/T1036/",
        "description": "Discrepancy found between npm registry metadata and package manifest contents.",
        "remediation": "Verify that package name and repository fields in package.json match the npm registry entry.",
    },
    "pyarmor": {
        "name": "Commercial Code Obfuscation (PyArmor)",
        "severity": "Medium",
        "weight": 18,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027.002: Software Packing",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/002/",
        "description": "The source code is encrypted using PyArmor. While commercial apps use it, open-source libraries rarely do, and malware authors frequently employ it to hide malicious logic.",
        "remediation": "Reject encrypted Python packages. Open-source libraries in PyPI should provide human-readable, auditable Python code.",
    },
    "silent-process-execution": {
        "name": "Silent Process Spawning",
        "severity": "Medium",
        "weight": 15,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1562: Impair Defenses",
        "mitre_url": "https://attack.mitre.org/techniques/T1562/",
        "description": "Spawns subprocesses while redirecting standard output and error streams to /dev/null or NUL to hide activity from terminal users.",
        "remediation": "Audit code that silences process stderr/stdout to confirm whether it is concealing unauthorized background command execution.",
    },
    "npm-silent-process-execution": {
        "name": "Silent Process Spawning",
        "severity": "Medium",
        "weight": 15,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1562: Impair Defenses",
        "mitre_url": "https://attack.mitre.org/techniques/T1562/",
        "description": "Suppresses process standard I/O to run background commands without user awareness.",
        "remediation": "Audit child_process calls with stdio: 'ignore' to identify what background process is being launched.",
    },
    "cmd-overwrite": {
        "name": "Shell Command Overwrite",
        "severity": "Medium",
        "weight": 18,
        "category": "Execution & Hooks",
        "mitre_tactic": "TA0003: Persistence",
        "mitre_technique": "T1546: Event-Triggered Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1546/",
        "description": "Attempts to overwrite or shadow standard system shell utilities with custom wrappers.",
        "remediation": "Audit system PATH and ensure user-installed package directories do not precede system binary folders (/bin, /usr/bin).",
    },
    "clipboard-access": {
        "name": "Clipboard Snooping",
        "severity": "Medium",
        "weight": 18,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0009: Collection",
        "mitre_technique": "T1115: Clipboard Data",
        "mitre_url": "https://attack.mitre.org/techniques/T1115/",
        "description": "Reads or writes to the operating system clipboard, a common technique for stealing copied crypto wallet addresses or passwords.",
        "remediation": "Unless the package is an explicit clipboard utility, remove it immediately. It may be an active crypto-address swapper.",
    },
    "screenshot": {
        "name": "Screen Capture Capability",
        "severity": "Medium",
        "weight": 18,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0009: Collection",
        "mitre_technique": "T1113: Screen Capture",
        "mitre_url": "https://attack.mitre.org/techniques/T1113/",
        "description": "Captures screenshots of the victim's desktop, typical of spyware and infostealers.",
        "remediation": "Verify legitimate need for screen capture capabilities. Quarantine if unexpected.",
    },
    "suspicious_passwd_access_linux": {
        "name": "Shadow/Passwd File Access",
        "severity": "Medium",
        "weight": 20,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0006: Credential Access",
        "mitre_technique": "T1003.008: /etc/passwd and /etc/shadow",
        "mitre_url": "https://attack.mitre.org/techniques/T1003/008/",
        "description": "Attempts to read '/etc/passwd' or '/etc/shadow' system files.",
        "remediation": "Ensure applications run in containerized environments with strict DAC/AppArmor profiles preventing access to system credential databases.",
    },
    "unicode": {
        "name": "Unicode Homoglyph Obfuscation",
        "severity": "Medium",
        "weight": 12,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1036.002: Right-to-Left Override",
        "mitre_url": "https://attack.mitre.org/techniques/T1036/002/",
        "description": "Uses invisible characters or unicode homoglyphs that look like standard ASCII characters to deceive human code reviewers.",
        "remediation": "Configure IDEs and pre-commit linters to reject bidirectional or zero-width unicode characters in source files.",
    },
    "provenance_regression": {
        "name": "Build Provenance Regression",
        "severity": "Medium",
        "weight": 15,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.002: Compromise Software Supply Chain",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/002/",
        "description": "A package release dropped npm provenance / Sigstore signing that was present in prior versions, suggesting an unverified out-of-band build.",
        "remediation": "Enforce build provenance verification in package managers. Reject versions lacking cryptographic provenance attestations.",
    },

    # Low Severity Heuristics (Informational / Minor Anomaly)
    "release_zero": {
        "name": "Version 0.0.0 Release",
        "severity": "Low",
        "weight": 8,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1195.001: Compromise Software Dependencies",
        "mitre_url": "https://attack.mitre.org/techniques/T1195/001/",
        "description": "The package was published with version 0.0.0, which is often used in automated test uploads or dependency confusion placeholders.",
        "remediation": "Verify if the package is a placeholder or internal dependency confusion test. Avoid using 0.0.0 packages in production.",
    },
    "single_python_file": {
        "name": "Single-File Package Distribution",
        "severity": "Low",
        "weight": 5,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027: Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Package contains only a single standalone Python file rather than a standard module structure.",
        "remediation": "Inspect the single file directly. Many simple utility packages legitimately use single-file modules.",
    },
    "empty_information": {
        "name": "Empty Description / Metadata",
        "severity": "Low",
        "weight": 5,
        "category": "Initial Access",
        "mitre_tactic": "TA0001: Initial Access",
        "mitre_technique": "T1589: Identity Information",
        "mitre_url": "https://attack.mitre.org/techniques/T1589/",
        "description": "Package has no documentation, description, or author information on the registry.",
        "remediation": "Encourage documentation hygiene. Verify package source code repository before integrating.",
    },
    "serialize-environment": {
        "name": "Environment Variable Inspection",
        "severity": "Low",
        "weight": 8,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0009: Collection",
        "mitre_technique": "T1082: System Information Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1082/",
        "description": "Inspects and serializes process environment variables (which may contain API tokens and DB credentials).",
        "remediation": "Avoid storing high-privilege credentials in plaintext environment variables where child dependencies can read them.",
    },
    "npm-serialize-environment": {
        "name": "Environment Variable Inspection",
        "severity": "Low",
        "weight": 8,
        "category": "Data Exfiltration",
        "mitre_tactic": "TA0009: Collection",
        "mitre_technique": "T1082: System Information Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1082/",
        "description": "Reads and serializes process environment variables.",
        "remediation": "Use fine-grained secret management (e.g. AWS Secrets Manager, HashiCorp Vault) rather than broad process.env injection.",
    },
    "obfuscation": {
        "name": "General Code Obfuscation",
        "severity": "Medium",
        "weight": 15,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027: Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "description": "Code contains unusual variable mangling, character escapes, or dense packers designed to evade standard detection.",
        "remediation": "De-obfuscate and inspect code with static analysis tools. Legitimate open source code should be readable.",
    },
    "npm-obfuscation": {
        "name": "General Code Obfuscation",
        "severity": "Medium",
        "weight": 15,
        "category": "Evasion & Obfuscation",
        "mitre_tactic": "TA0005: Defense Evasion",
        "mitre_technique": "T1027: Obfuscated Files",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "description": "JavaScript payload contains heavy variable mangling or packed constructs.",
        "remediation": "Use web-based JavaScript beautifiers or AST linters to inspect the true functionality of the script.",
    },
}


def _generate_plain_english_triage(rule_id: str, meta: Dict[str, Any]) -> Dict[str, str]:
    """Generates crystal-clear, plain-English triage guidance for students and developers."""
    name = meta.get("name", rule_id)
    sev = meta.get("severity", "Medium")

    plain_detection = meta.get("description", "")
    risk_impact = ""
    what_to_do = meta.get("remediation", "")

    rule_lower = rule_id.lower()
    name_lower = name.lower()

    if "base64" in rule_lower or "obfuscat" in name_lower or "pyarmor" in rule_lower:
        plain_detection = "The code conceals and runs encoded instructions dynamically at runtime rather than clear, readable source code."
        risk_impact = "Attackers frequently hide backdoors, remote shells, and crypto-stealers inside obfuscated code to evade security scanners."
        what_to_do = "Quarantine this package. Do not install until you deobfuscate the script or replace it with an official open-source alternative."
    elif "exfil" in rule_lower or "stealer" in rule_lower or "passwd" in rule_lower:
        plain_detection = "The package attempts to read sensitive local credentials (tokens, private keys, passwords) and send them across the internet."
        risk_impact = "High risk of credential theft: cloud API keys, SSH private keys, and environment variables (.env) can be transmitted to an attacker's server."
        what_to_do = "Immediately disconnect the machine or build agent from the internet. Rotate all AWS, GitHub, database, and system credentials."
    elif "shell" in rule_lower or "exec" in rule_lower or "sh_exec" in rule_lower or "download" in rule_lower:
        plain_detection = "The package spawns an external system process or downloads an external executable binary during execution."
        risk_impact = "Allows the package to run arbitrary OS-level commands with the full privileges of your terminal or server user account."
        what_to_do = "Block installation. Inspect the spawned command to verify if it is legitimate native build tooling or malicious payload delivery."
    elif "typo" in rule_lower:
        plain_detection = "The package name is deceptively similar to a popular legitimate package (Typosquatting attack)."
        risk_impact = "Developers who make a single typing error accidentally install malware masquerading as a popular library."
        what_to_do = "Verify the exact spelling of the package in the official documentation. Uninstall immediately if you intended to install the popular package."
    elif "install" in rule_lower or "hook" in rule_lower or "script" in rule_lower:
        plain_detection = "The package executes custom scripts automatically upon running 'npm install' or 'pip install'."
        risk_impact = "Malware runs before you even write a single line of code importing the library, taking over build machines silently."
        what_to_do = "Add 'ignore-scripts=true' to your .npmrc or avoid running setup.py directly without sandboxing."
    elif "clipboard" in rule_lower:
        plain_detection = "The package accesses your operating system clipboard to read or modify copied contents."
        risk_impact = "Crypto-clippers swap copied Bitcoin/Ethereum addresses with attacker addresses during copy-paste operations."
        what_to_do = "Unless this package is an intentional clipboard utility, remove it immediately and scan system for clipboard hijackers."
    else:
        risk_impact = f"{sev}-severity risk to application integrity and build environment trust."
        what_to_do = meta.get("remediation", "Review package source code in an isolated container before deploying.")

    return {
        "plain_detection": plain_detection,
        "risk_impact": risk_impact,
        "what_to_do": what_to_do,
    }


def _humanize_rule_id(rule_id: str) -> str:
    """Fallback function to turn raw rule IDs into clean English titles."""
    clean = re.sub(r"^(threat-|capability-|npm-)", "", rule_id)
    clean = clean.replace("-", " ").replace("_", " ").replace(".", " ")
    return clean.title()


def _get_rule_meta(rule_id: str) -> Dict[str, Any]:
    """Retrieve metadata for a rule, falling back to heuristic inference if unknown."""
    if rule_id in RULE_CATALOG:
        return RULE_CATALOG[rule_id]

    normalized = rule_id.lower().replace("_", "-")
    for known_key, meta in RULE_CATALOG.items():
        if known_key in normalized or normalized in known_key:
            return meta

    # General fallback for any future rule additions
    severity = "Medium"
    weight = 15
    category = "Evasion & Obfuscation"
    mitre_tactic = "TA0005: Defense Evasion"
    mitre_technique = "T1027: Obfuscated Files or Information"
    mitre_url = "https://attack.mitre.org/techniques/T1027/"

    if any(k in normalized for k in ["exfil", "shell", "exec", "backdoor", "trojan", "typo", "stealer"]):
        severity = "High"
        weight = 30
        if "exfil" in normalized or "stealer" in normalized:
            category = "Data Exfiltration"
            mitre_tactic = "TA0010: Exfiltration"
            mitre_technique = "T1048: Exfiltration Over Alternative Protocol"
            mitre_url = "https://attack.mitre.org/techniques/T1048/"
        elif "typo" in normalized:
            category = "Initial Access"
            mitre_tactic = "TA0001: Initial Access"
            mitre_technique = "T1195.001: Compromise Software Dependencies"
            mitre_url = "https://attack.mitre.org/techniques/T1195/001/"
        else:
            category = "Execution & Hooks"
            mitre_tactic = "TA0002: Execution"
            mitre_technique = "T1059: Command and Scripting Interpreter"
            mitre_url = "https://attack.mitre.org/techniques/T1059/"
    elif any(k in normalized for k in ["zero", "single", "empty", "read", "download"]):
        severity = "Low"
        weight = 8
        category = "Initial Access"
        mitre_tactic = "TA0001: Initial Access"
        mitre_technique = "T1195.001: Compromise Software Dependencies"
        mitre_url = "https://attack.mitre.org/techniques/T1195/001/"

    return {
        "name": _humanize_rule_id(rule_id),
        "severity": severity,
        "weight": weight,
        "category": category,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "mitre_url": mitre_url,
        "description": f"Heuristic rule '{rule_id}' was triggered during analysis of the package source code or registry metadata.",
        "remediation": f"Audit package source code and verify whether rule '{rule_id}' represents legitimate behavior or malicious intent.",
    }


def compute_risk_score(flagged_rules: List[Dict[str, Any]]) -> Tuple[int, str, str, str, Dict[str, int]]:
    """
    Computes overall risk score (0-100) and sub-scores for the 4 core threat vectors:
    1. Initial Access & Supply Chain
    2. Execution & Lifecycle Hooks
    3. Evasion & Obfuscation
    4. Data Exfiltration

    Returns:
        (score, verdict, badge_class, summary, category_scores)
    """
    category_scores = {
        "Initial Access": 0,
        "Execution & Hooks": 0,
        "Evasion & Obfuscation": 0,
        "Data Exfiltration": 0,
    }

    if not flagged_rules:
        return (
            0,
            "LOW RISK",
            "low",
            "No malicious indicators or suspicious heuristics were flagged by GuardDog. Package appears clean and compliant.",
            category_scores,
        )

    # Accumulate category weights
    for rule in flagged_rules:
        cat = rule.get("category", "Evasion & Obfuscation")
        weight = rule.get("weight", 15)
        if cat in category_scores:
            category_scores[cat] += weight
        else:
            category_scores["Evasion & Obfuscation"] += weight

    # Normalize category scores to max 100
    for cat in category_scores:
        category_scores[cat] = min(100, category_scores[cat])

    total_weight = sum(rule.get("weight", 15) for rule in flagged_rules)
    score = min(100, total_weight)

    high_count = sum(1 for r in flagged_rules if r.get("severity") == "High")
    med_count = sum(1 for r in flagged_rules if r.get("severity") == "Medium")
    low_count = sum(1 for r in flagged_rules if r.get("severity") == "Low")

    if high_count > 0 and score < 35:
        score = 35

    if score >= 70:
        verdict = "HIGH RISK"
        badge_class = "high"
        summary = (
            f"CRITICAL THREAT: {len(flagged_rules)} heuristic rule(s) triggered, including {high_count} High-severity "
            "finding(s). High likelihood of supply-chain attack, backdoors, or malicious intent. Do NOT install."
        )
    elif score >= 25:
        verdict = "MEDIUM RISK"
        badge_class = "medium"
        summary = (
            f"SUSPICIOUS ACTIVITY: {len(flagged_rules)} heuristic rule(s) triggered ({med_count} Medium, {low_count} Low). "
            "Package exhibits suspicious behaviors (e.g., dynamic execution, install scripts, or unusual metadata). "
            "Manual review recommended before deployment."
        )
    else:
        verdict = "LOW RISK"
        badge_class = "low"
        summary = (
            f"LOW RISK: {len(flagged_rules)} minor heuristic(s) triggered with low security impact. "
            "Package appears safe for ordinary usage."
        )

    return score, verdict, badge_class, summary, category_scores


def _extract_flagged_rules(raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parses GuardDog JSON output and extracts all triggered rules into a structured format
    with MITRE ATT&CK mappings, plain English explanations, and remediation advice.
    """
    flagged: List[Dict[str, Any]] = []
    seen_rules = set()

    # 1. Parse 'results' mapping (Standard GuardDog output)
    results_map = raw_data.get("results")
    if isinstance(results_map, dict):
        for rule_id, finding_val in results_map.items():
            if finding_val is None or finding_val == {} or finding_val == []:
                continue

            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            meta = _get_rule_meta(rule_id)

            details_list: List[Dict[str, str]] = []
            if isinstance(finding_val, list):
                for item in finding_val:
                    if isinstance(item, dict):
                        details_list.append({
                            "location": str(item.get("location", "N/A")),
                            "code": str(item.get("code", "")).strip(),
                            "message": str(item.get("message", "")).strip(),
                        })
                    else:
                        details_list.append({"location": "Finding", "code": "", "message": str(item)})
            elif isinstance(finding_val, dict):
                details_list.append({
                    "location": str(finding_val.get("location", "Package Metadata / Analysis")),
                    "code": str(finding_val.get("code", "")).strip(),
                    "message": str(finding_val.get("message", json.dumps(finding_val))).strip(),
                })
            elif isinstance(finding_val, str):
                details_list.append({
                    "location": "Package Metadata",
                    "code": "",
                    "message": finding_val,
                })
            else:
                details_list.append({
                    "location": "Heuristic Triggered",
                    "code": "",
                    "message": str(finding_val),
                })

            triage = _generate_plain_english_triage(rule_id, meta)
            flagged.append({
                "rule_id": rule_id,
                "name": meta["name"],
                "severity": meta["severity"],
                "weight": meta["weight"],
                "category": meta["category"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique": meta["mitre_technique"],
                "mitre_url": meta["mitre_url"],
                "description": meta["description"],
                "remediation": meta["remediation"],
                "plain_detection": triage["plain_detection"],
                "risk_impact": triage["risk_impact"],
                "what_to_do": triage["what_to_do"],
                "findings": details_list,
            })

    # 2. Check for 'risks' array (GuardDog 3.x formatted findings)
    risks_list = raw_data.get("risks")
    if isinstance(risks_list, list):
        for risk in risks_list:
            if not isinstance(risk, dict):
                continue
            rule_id = risk.get("rule_name") or risk.get("rule_id") or risk.get("id") or "unknown_threat"
            if rule_id in seen_rules:
                continue
            seen_rules.add(rule_id)

            meta = _get_rule_meta(rule_id)
            findings = [{
                "location": str(risk.get("file_path") or risk.get("location") or "Source Code"),
                "code": str(risk.get("threat_code") or risk.get("code") or "").strip(),
                "message": str(risk.get("threat_description") or risk.get("message") or "").strip(),
            }]
            triage = _generate_plain_english_triage(rule_id, meta)
            flagged.append({
                "rule_id": rule_id,
                "name": meta["name"],
                "severity": meta["severity"],
                "weight": meta["weight"],
                "category": meta["category"],
                "mitre_tactic": meta["mitre_tactic"],
                "mitre_technique": meta["mitre_technique"],
                "mitre_url": meta["mitre_url"],
                "description": meta["description"],
                "remediation": meta["remediation"],
                "plain_detection": triage["plain_detection"],
                "risk_impact": triage["risk_impact"],
                "what_to_do": triage["what_to_do"],
                "findings": findings,
            })

    # Sort flagged rules by severity: High first, then Medium, then Low
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    flagged.sort(key=lambda r: severity_order.get(r["severity"], 3))

    return flagged


def generate_markdown_audit_report(package_name: str, ecosystem: str, score: int, verdict: str,
                                   summary: str, category_scores: Dict[str, int],
                                   flagged_rules: List[Dict[str, Any]],
                                   metadata: Optional[Dict[str, Any]] = None,
                                   author_osint: Optional[Dict[str, Any]] = None) -> str:
    """
    Generates a formal, printable Markdown Security Audit Report suitable for viva submission.
    """
    reg_url = (metadata or {}).get("registry_url", f"https://www.npmjs.com/package/{package_name}" if ecosystem == "npm" else f"https://pypi.org/project/{package_name}/")
    author = (metadata or {}).get("author", "Unknown Maintainer")
    version = (metadata or {}).get("version", "Latest")
    license_str = (metadata or {}).get("license", "Not specified")

    lines = [
        f"# 🛡️ Security Audit Report: {package_name} ({ecosystem.upper()})",
        f"**Generated by**: PackageGuard Supply-Chain Security Analyzer",
        f"**Underlying Detection Engine**: DataDog GuardDog (Semgrep / AST Analysis)",
        f"**Maintainer OSINT Engine**: Maigret & Registry Footprint Profiler",
        f"**Official Registry**: [{reg_url}]({reg_url})",
        f"**Author / Maintainer**: `{author}` | **Version**: `{version}` | **License**: `{license_str}`",
        f"**Risk Score**: `{score} / 100` | **Verdict**: `{verdict}`",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        summary,
        "",
        "### Threat Vector Matrix",
        f"- **Initial Access & Supply Chain Risk**: `{category_scores.get('Initial Access', 0)} / 100`",
        f"- **Execution & Lifecycle Hooks Risk**: `{category_scores.get('Execution & Hooks', 0)} / 100`",
        f"- **Evasion & Obfuscation Risk**: `{category_scores.get('Evasion & Obfuscation', 0)} / 100`",
        f"- **Data Exfiltration Risk**: `{category_scores.get('Data Exfiltration', 0)} / 100`",
        "",
        "---",
        "",
        "## 2. Maintainer Threat Intelligence & OSINT Reconnaissance (Maigret)",
    ]

    if author_osint:
        lines.extend([
            f"- **Author Identity**: `{author_osint.get('username')}`",
            f"- **Reputation Score**: `{author_osint.get('reputation_score')}/100` ({author_osint.get('reputation_verdict')})",
            f"- **Verified Accounts Found**: {author_osint.get('accounts_found')}",
            f"- **Assessment**: {author_osint.get('summary')}",
        ])
        if author_osint.get("profiles"):
            lines.append("- **Discovered Public Profiles**:")
            for p in author_osint.get("profiles", []):
                lines.append(f"  - [{p.get('platform')}]({p.get('url')}): {p.get('status')}")
    else:
        lines.append("- *Author OSINT profiling pending or not queried.*")

    lines.extend([
        "",
        "---",
        "",
        "## 3. MITRE ATT&CK® Correlation & Findings Breakdown",
    ])

    if not flagged_rules:
        lines.append("\n✅ **No security anomalies detected.** The package passed all heuristic tests.")
    else:
        for idx, rule in enumerate(flagged_rules, 1):
            lines.extend([
                f"\n### Finding #{idx}: {rule['name']} (`{rule['rule_id']}`)",
                f"- **Severity**: `{rule['severity']}` (Impact Weight: {rule['weight']} pts)",
                f"- **Category**: {rule['category']}",
                f"- **MITRE ATT&CK Tactic**: {rule['mitre_tactic']}",
                f"- **MITRE ATT&CK Technique**: [{rule['mitre_technique']}]({rule['mitre_url']})",
                f"- **What Was Detected (Plain English)**: {rule.get('plain_detection', rule['description'])}",
                f"- **Potential Risk & Impact**: {rule.get('risk_impact', 'Security anomaly in dependencies.')}",
                f"- **Actionable Remediation**: {rule.get('what_to_do', rule['remediation'])}",
            ])
            if rule.get("findings"):
                lines.append("- **Technical Evidence**:")
                for item in rule["findings"]:
                    if item.get("location"):
                        lines.append(f"  - Location: `{item['location']}`")
                    if item.get("message"):
                        lines.append(f"  - Details: {item['message']}")
                    if item.get("code"):
                        lines.append(f"  - Code Snippet:\n    ```\n    {item['code']}\n    ```")

    lines.extend([
        "",
        "---",
        "",
        "## 4. DevSecOps Defense Checklist",
        "- [ ] **Package Pinning**: Pin exact package version and cryptographic SHA-512 hashes in lockfiles (`package-lock.json` or `requirements.txt`).",
        "- [ ] **Disable Install Scripts**: Configure `.npmrc` with `ignore-scripts=true` to block preinstall hook execution.",
        "- [ ] **Registry Verification**: Inspect maintainer profile, download statistics, and verified publisher provenance.",
        "- [ ] **Transitive Dependency Auditing**: Run automated dependency scanning in CI/CD pipelines.",
        "",
        "---",
        "*Report generated automatically by PackageGuard.*",
    ])

    return "\n".join(lines)


def _scan_direct_python(package_name: str, ecosystem: str) -> Optional[Dict[str, Any]]:
    """
    Direct in-process fallback using GuardDog's Python API if the CLI hangs on WHOIS or subprocess limits.
    Runs in under 3 seconds by excluding blocking port 43 network rules.
    """
    try:
        import sys
        guarddog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guarddog")
        if guarddog_path not in sys.path:
            sys.path.insert(0, guarddog_path)

        if ecosystem == "npm":
            from guarddog.scanners.npm_package_scanner import NPMPackageScanner
            scanner = NPMPackageScanner()
        else:
            from guarddog.scanners.pypi_package_scanner import PackageScanner
            scanner = PackageScanner()

        # Filter out slow/hanging network WHOIS rules
        slow_rules = {"unclaimed_maintainer_email_domain", "potentially_compromised_email_domain"}
        active_rules = scanner.analyzer.metadata_ruleset - slow_rules

        result = scanner.scan_remote(package_name, rules=active_rules)
        if isinstance(result, dict):
            if "package" not in result:
                result["package"] = package_name
            return result
    except Exception as exc:
        logger.warning(f"In-process scanner fallback error for '{package_name}': {exc}")
    return None


def scan_package(package_name: str, ecosystem: str, timeout_seconds: int = 120) -> Dict[str, Any]:
    """
    Executes GuardDog scan against a package in the specified ecosystem.
    """
    package_name = package_name.strip()
    ecosystem = ecosystem.strip().lower()

    if not package_name:
        return {
            "success": False,
            "error": "Package name cannot be empty.",
            "package": "",
            "ecosystem": ecosystem,
        }

    if ecosystem not in ("npm", "pypi"):
        return {
            "success": False,
            "error": f"Invalid ecosystem '{ecosystem}'. Supported ecosystems are 'npm' and 'pypi'.",
            "package": package_name,
            "ecosystem": ecosystem,
        }

    # Validate package naming characters
    if ecosystem == "npm":
        if not re.match(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$", package_name, re.IGNORECASE):
            return {
                "success": False,
                "error": f"Invalid npm package name format: '{package_name}'.",
                "package": package_name,
                "ecosystem": ecosystem,
            }
    else:  # pypi
        if not re.match(r"^[A-Za-z0-9_.\-]+$", package_name):
            return {
                "success": False,
                "error": f"Invalid PyPI package name format: '{package_name}'.",
                "package": package_name,
                "ecosystem": ecosystem,
            }

    # Locate GuardDog binary
    guarddog_bin = shutil.which("guarddog")
    if not guarddog_bin and os.name == "nt":
        candidate = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python310\Scripts\guarddog.exe")
        if os.path.exists(candidate):
            guarddog_bin = candidate

    # Exclude slow/hanging network WHOIS rules that cause 60s socket hangs on port 43
    cmd = [
        guarddog_bin or "guarddog",
        ecosystem,
        "scan",
        package_name,
        "-x", "unclaimed_maintainer_email_domain",
        "-x", "potentially_compromised_email_domain",
        "--output-format=json",
    ]

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    logger.info(f"Running command: {' '.join(cmd)}")

    raw_data: Optional[Dict[str, Any]] = None

    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
            encoding="utf-8",
            errors="replace",
        )
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        if stdout:
            try:
                raw_data = json.loads(stdout)
            except json.JSONDecodeError:
                json_match = re.search(r"(\{.*\})", stdout, re.DOTALL)
                if json_match:
                    try:
                        raw_data = json.loads(json_match.group(1))
                    except Exception:
                        pass
    except subprocess.TimeoutExpired:
        logger.warning(f"Subprocess CLI timed out for '{package_name}'. Triggering fast in-process fallback...")
        raw_data = _scan_direct_python(package_name, ecosystem)
    except FileNotFoundError:
        logger.warning("GuardDog binary not found in PATH. Triggering fast in-process fallback...")
        raw_data = _scan_direct_python(package_name, ecosystem)
    except Exception as exc:
        logger.warning(f"Subprocess execution error ({exc}). Triggering fast in-process fallback...")
        raw_data = _scan_direct_python(package_name, ecosystem)

    # If CLI did not produce valid data, attempt fast in-process scan before erroring
    if not raw_data:
        raw_data = _scan_direct_python(package_name, ecosystem)

    if not raw_data:
        err_msg = stderr or stdout or f"GuardDog process exited with code {process.returncode}."
        if "404" in err_msg or "not found" in err_msg.lower():
            return {
                "success": False,
                "error": f"Package '{package_name}' was not found in the {ecosystem.upper()} registry (404 Not Found).",
                "package": package_name,
                "ecosystem": ecosystem,
            }
        return {
            "success": False,
            "error": f"Failed to parse scanner output. Output was: {err_msg[:400]}",
            "package": package_name,
            "ecosystem": ecosystem,
        }

    # Check for reported 404 in JSON errors dictionary
    errors_dict = raw_data.get("errors")
    if isinstance(errors_dict, dict) and errors_dict:
        for err_key, err_val in errors_dict.items():
            err_str = str(err_val)
            if "404" in err_str or "not found" in err_str.lower():
                return {
                    "success": False,
                    "error": f"Package '{package_name}' was not found in the {ecosystem.upper()} registry (404 Not Found).",
                    "package": package_name,
                    "ecosystem": ecosystem,
                }
            if "download" in err_key.lower():
                return {
                    "success": False,
                    "error": f"Failed to download package '{package_name}' from {ecosystem.upper()}: {err_str}",
                    "package": package_name,
                    "ecosystem": ecosystem,
                }

    # Extract Flagged Rules & Compute Scores
    flagged_rules = _extract_flagged_rules(raw_data)
    score, verdict, badge_class, summary, category_scores = compute_risk_score(flagged_rules)

    # Extract official registry metadata & direct package registry link
    metadata = osint_analyzer.extract_package_metadata(package_name, ecosystem)
    registry_url = metadata.get("registry_url", "")
    author_name = metadata.get("author", "Unknown Maintainer")

    # Execute Maintainer OSINT reconnaissance (Maigret + Developer footprint)
    author_osint = osint_analyzer.run_maigret_osint(author_name)

    # Generate complete markdown audit report
    audit_report = generate_markdown_audit_report(
        package_name=raw_data.get("package", package_name),
        ecosystem=ecosystem,
        score=score,
        verdict=verdict,
        summary=summary,
        category_scores=category_scores,
        flagged_rules=flagged_rules,
        metadata=metadata,
        author_osint=author_osint,
    )

    return {
        "success": True,
        "package": raw_data.get("package", package_name),
        "ecosystem": ecosystem,
        "score": score,
        "verdict": verdict,
        "badge_class": badge_class,
        "summary": summary,
        "category_scores": category_scores,
        "issues_count": len(flagged_rules),
        "flagged_rules": flagged_rules,
        "registry_url": registry_url,
        "metadata": metadata,
        "author_osint": author_osint,
        "audit_report_md": audit_report,
        "raw_json": raw_data,
        "raw_json_str": json.dumps(raw_data, indent=2),
    }
