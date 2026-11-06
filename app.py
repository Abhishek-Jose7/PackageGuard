"""
app.py - Flask Web Application for PackageGuard (SOC Cyber Dashboard)
=====================================================================

PackageGuard: A supply-chain security risk scanner for npm and PyPI packages.
Wraps the GuardDog detection engine and exposes a SOC-grade threat intelligence
dashboard with MITRE ATT&CK correlation, multi-vector risk scoring, actionable
remediation playbooks, persistent SQLite scan history, and report export.

Author: College Project viva implementation
Technology Stack:
- Python 3.10+
- Flask (Routing, Templates, Request Handling)
- SQLite3 (Local Persistent Scan History)
- GuardDog CLI (Subprocess-driven security scanner via scanner.py)
"""

import datetime
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional
from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, url_for

import osint_analyzer
import scanner

# ---------------------------------------------------------------------------
# Application Configuration & Logging Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packageguard.db")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
)
logger = logging.getLogger("packageguard")


# ---------------------------------------------------------------------------
# SQLite Database Management
# ---------------------------------------------------------------------------
def get_db_connection() -> sqlite3.Connection:
    """
    Creates and returns a thread-safe connection to the local SQLite database.
    row_factory is set to sqlite3.Row to allow dict-like column access.
    """
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initializes or migrates the SQLite database table for scan history.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                badge_class TEXT NOT NULL,
                summary TEXT,
                flagged_count INTEGER NOT NULL DEFAULT 0,
                flagged_rules_json TEXT,
                category_scores_json TEXT,
                audit_report_md TEXT,
                raw_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Attempt to add newer columns if the table already existed previously
        for col_stmt in [
            "ALTER TABLE scans ADD COLUMN category_scores_json TEXT",
            "ALTER TABLE scans ADD COLUMN audit_report_md TEXT",
            "ALTER TABLE scans ADD COLUMN registry_url TEXT",
            "ALTER TABLE scans ADD COLUMN metadata_json TEXT",
            "ALTER TABLE scans ADD COLUMN author_osint_json TEXT",
        ]:
            try:
                cursor.execute(col_stmt)
            except sqlite3.OperationalError:
                pass

        conn.commit()
    logger.info("SQLite database initialized successfully.")


def get_telemetry_stats() -> Dict[str, Any]:
    """
    Computes live SOC telemetry metrics from the database for the top dashboard bar:
    - Total Packages Inspected
    - Malicious / Suspicious Packages Flagged
    - Clean Packages Verified
    - Top Attack Vector / Heuristic Observed
    """
    stats = {
        "total_scans": 0,
        "threats_detected": 0,
        "clean_packages": 0,
        "primary_threat": "None Observed",
    }
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM scans")
        row = cursor.fetchone()
        stats["total_scans"] = row["total"] if row else 0

        cursor.execute("SELECT COUNT(*) AS threats FROM scans WHERE score >= 25")
        row = cursor.fetchone()
        stats["threats_detected"] = row["threats"] if row else 0

        cursor.execute("SELECT COUNT(*) AS clean FROM scans WHERE score < 25")
        row = cursor.fetchone()
        stats["clean_packages"] = row["clean"] if row else 0

        # Determine most common triggered rule from history
        cursor.execute("SELECT flagged_rules_json FROM scans WHERE flagged_count > 0")
        rows = cursor.fetchall()
        rule_counts: Dict[str, int] = {}
        for r in rows:
            try:
                rules = json.loads(r["flagged_rules_json"] or "[]")
                for rule in rules:
                    name = rule.get("name", "Unknown Heuristic")
                    rule_counts[name] = rule_counts.get(name, 0) + 1
            except Exception:
                pass

        if rule_counts:
            top_rule = max(rule_counts.items(), key=lambda x: x[1])
            stats["primary_threat"] = f"{top_rule[0]} ({top_rule[1]}x)"
        elif stats["total_scans"] > 0:
            stats["primary_threat"] = "All Scans Clean"

    return stats


def save_scan_to_db(scan_data: Dict[str, Any]) -> int:
    """
    Persists a completed package scan result to the SQLite database.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                package_name, ecosystem, score, verdict, badge_class,
                summary, flagged_count, flagged_rules_json, category_scores_json,
                registry_url, metadata_json, author_osint_json,
                audit_report_md, raw_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_data["package"],
                scan_data["ecosystem"],
                scan_data["score"],
                scan_data["verdict"],
                scan_data["badge_class"],
                scan_data["summary"],
                scan_data["issues_count"],
                json.dumps(scan_data.get("flagged_rules", [])),
                json.dumps(scan_data.get("category_scores", {})),
                scan_data.get("registry_url", ""),
                json.dumps(scan_data.get("metadata", {})),
                json.dumps(scan_data.get("author_osint", {})),
                scan_data.get("audit_report_md", ""),
                scan_data.get("raw_json_str", "{}"),
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_recent_scans(limit: int = 15) -> List[Dict[str, Any]]:
    """
    Fetches the most recent scans from SQLite ordered by creation time descending.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, package_name, ecosystem, score, verdict, badge_class,
                   flagged_count, created_at, registry_url
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Fetches a specific scan by its primary key ID and unpacks its JSON fields.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None

        data = dict(row)
        try:
            data["flagged_rules"] = json.loads(data.get("flagged_rules_json") or "[]")
        except Exception:
            data["flagged_rules"] = []

        try:
            data["category_scores"] = json.loads(data.get("category_scores_json") or "{}")
        except Exception:
            data["category_scores"] = {
                "Initial Access": 0,
                "Execution & Hooks": 0,
                "Evasion & Obfuscation": 0,
                "Data Exfiltration": 0,
            }

        try:
            data["metadata"] = json.loads(data.get("metadata_json") or "{}")
        except Exception:
            data["metadata"] = {}

        try:
            data["author_osint"] = json.loads(data.get("author_osint_json") or "{}")
        except Exception:
            data["author_osint"] = {}

        data["package"] = data["package_name"]
        data["issues_count"] = data["flagged_count"]
        data["raw_json_str"] = data.get("raw_json", "{}")

        # Fallback for registry_url if missing in older record
        if not data.get("registry_url"):
            pkg = data["package_name"]
            eco = data["ecosystem"]
            data["registry_url"] = f"https://www.npmjs.com/package/{pkg}" if eco == "npm" else f"https://pypi.org/project/{pkg}/"

        # If audit report was not previously saved in older record, generate dynamically
        if not data.get("audit_report_md"):
            data["audit_report_md"] = scanner.generate_markdown_audit_report(
                package_name=data["package_name"],
                ecosystem=data["ecosystem"],
                score=data["score"],
                verdict=data["verdict"],
                summary=data.get("summary", ""),
                category_scores=data["category_scores"],
                flagged_rules=data["flagged_rules"],
                metadata=data["metadata"],
                author_osint=data["author_osint"],
            )

        return data


# ---------------------------------------------------------------------------
# Web Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    """
    Single-page dashboard route:
    - GET: Displays the package scanner form, SOC telemetry bar, and scan history.
    - POST: Executes a scan for the submitted package name & ecosystem.
    """
    recent_scans = get_recent_scans()
    telemetry_stats = get_telemetry_stats()
    active_scan: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None

    selected_package = ""
    selected_ecosystem = "pypi"

    if request.method == "POST":
        selected_package = request.form.get("package_name", "").strip()
        selected_ecosystem = request.form.get("ecosystem", "pypi").strip().lower()

        logger.info(f"Incoming scan request: package='{selected_package}', ecosystem='{selected_ecosystem}'")

        result = scanner.scan_package(selected_package, selected_ecosystem)

        if not result.get("success"):
            error_message = result.get("error", "An unknown error occurred during scanning.")
            logger.warning(f"Scan failed for '{selected_package}': {error_message}")
        else:
            scan_id = save_scan_to_db(result)
            result["id"] = scan_id
            active_scan = result
            recent_scans = get_recent_scans()
            telemetry_stats = get_telemetry_stats()
            logger.info(f"Scan completed successfully for '{selected_package}' (Score: {result['score']}/100)")

    return render_template(
        "index.html",
        active_scan=active_scan,
        error_message=error_message,
        recent_scans=recent_scans,
        telemetry_stats=telemetry_stats,
        selected_package=selected_package,
        selected_ecosystem=selected_ecosystem,
    )


@app.route("/scan/<int:scan_id>", methods=["GET"])
def view_scan(scan_id: int):
    """
    Loads and displays the full report for a previous scan from SQLite history.
    """
    historical_scan = get_scan_by_id(scan_id)
    recent_scans = get_recent_scans()
    telemetry_stats = get_telemetry_stats()

    if not historical_scan:
        return render_template(
            "index.html",
            active_scan=None,
            error_message=f"Scan record with ID #{scan_id} was not found.",
            recent_scans=recent_scans,
            telemetry_stats=telemetry_stats,
            selected_package="",
            selected_ecosystem="pypi",
        )

    return render_template(
        "index.html",
        active_scan=historical_scan,
        error_message=None,
        recent_scans=recent_scans,
        telemetry_stats=telemetry_stats,
        selected_package=historical_scan["package_name"],
        selected_ecosystem=historical_scan["ecosystem"],
    )


@app.route("/export/<int:scan_id>", methods=["GET"])
def export_report(scan_id: int):
    """
    Generates and downloads a formal Markdown Security Audit Report for submission or documentation.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "Scan report not found", 404

    report_text = scan.get("audit_report_md", "")
    filename = f"PackageGuard_Security_Audit_{scan['package_name']}_{scan['ecosystem']}.md"

    return Response(
        report_text,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/investigate-author", methods=["GET", "POST"])
def investigate_author():
    """
    Dedicated Maintainer Threat Intelligence & Internet-Wide OSINT Reconnaissance Lab.
    Investigates identities across the whole internet: usernames, emails, full names, and domains.
    """
    query = (
        request.args.get("query", "").strip()
        or request.args.get("username", "").strip()
        or request.form.get("query", "").strip()
        or request.form.get("username", "").strip()
    )
    osint_result: Optional[Dict[str, Any]] = None

    if query:
        logger.info(f"Running Internet-Wide OSINT reconnaissance for '{query}'")
        osint_result = osint_analyzer.investigate_identity(query)

    return render_template(
        "author_investigate.html",
        username=query,
        query=query,
        osint_result=osint_result,
    )


@app.route("/api/osint/<path:query>", methods=["GET"])
def api_osint(query: str):
    """
    JSON REST API endpoint for on-demand internet-wide OSINT lookups.
    """
    data = osint_analyzer.investigate_identity(query)
    return jsonify(data)


@app.route("/presentation", methods=["GET"])
def presentation():
    """
    Web-based Presentation Deck aligned with the 5 College Assessment Rubrics:
    Rubric 1 (5M): Problem Definition, Objectives & Literature Survey
    Rubric 2 (5M): System Design & Methodology
    Rubric 3 (10M): Implementation & Functionality
    Rubric 4 (5M): Testing, Results & Security Evaluation
    Rubric 5 (5M): Project Presentation, Demonstration & Viva Voce
    """
    return render_template("presentation.html")


@app.route("/download-presentation", methods=["GET"])
def download_presentation():
    """
    Serves the generated PackageGuard_Project_Evaluation.pptx file for college submission.
    """
    pptx_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PackageGuard_Project_Evaluation.pptx")
    if not os.path.exists(pptx_path):
        import generate_presentation
        generate_presentation.build_powerpoint()

    return send_file(
        pptx_path,
        as_attachment=True,
        download_name="PackageGuard_Project_Evaluation.pptx",
        mimetype="application/vnd.openxmlformats-officedocument.presentationml.presentation",
    )


@app.route("/clear-history", methods=["POST"])
def clear_history():
    """
    Convenience endpoint for resetting scan history during college testing/viva demos.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
    logger.info("Scan history cleared.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------
init_db()

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  🛡️  PackageGuard — SOC Supply Chain Security Dashboard")
    print("  Engine: DataDog GuardDog CLI | MITRE ATT&CK Matrix Correlation")
    print("  Web Server: http://127.0.0.1:5000")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
