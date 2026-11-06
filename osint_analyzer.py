"""
osint_analyzer.py - Comprehensive Internet-Wide OSINT Reconnaissance & Maintainer Threat Intelligence
=====================================================================================================

Performs automated identity intelligence across the entire internet:
- Supports Usernames, Email Addresses, Full Names, and Domains
- Multi-category investigation: Social Media, Developer Registries, Messaging, Publishing, Email OSINT
- Concurrent multi-threaded reconnaissance (ThreadPoolExecutor) for sub-2-second speed
- Intercepts disposable "burner / ghost" accounts used in supply chain malware campaigns

Author: College Project viva implementation
"""

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "sharklasers.com", "yopmail.com", "throwawaymail.com", "trashmail.com",
    "dispostable.com", "getairmail.com", "temp-mail.org", "fakeinbox.com",
    "mohmal.com", "crazymailing.com", "generator.email", "armyspy.com",
    "cuvox.de", "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
    "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "protonmail.com", "proton.me", "aol.com", "zoho.com",
    "gmx.com", "mail.com", "yandex.com",
}


def extract_package_metadata(package_name: str, ecosystem: str) -> Dict[str, Any]:
    """Fetches official registry metadata from npm or PyPI."""
    package_name = package_name.strip()
    ecosystem = ecosystem.strip().lower()

    meta = {
        "package_name": package_name,
        "ecosystem": ecosystem,
        "author": "Unknown Maintainer",
        "author_email": "",
        "version": "Latest",
        "license": "Not specified",
        "homepage": "",
        "repository": "",
        "registry_url": "",
    }

    if ecosystem == "npm":
        meta["registry_url"] = f"https://www.npmjs.com/package/{package_name}"
        try:
            req = urllib.request.Request(
                f"https://registry.npmjs.org/{package_name}",
                headers={"User-Agent": "PackageGuard-OSINT/3.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode("utf-8"))
                
                author_obj = data.get("author")
                if isinstance(author_obj, dict):
                    meta["author"] = author_obj.get("name", "Unknown")
                    meta["author_email"] = author_obj.get("email", "")
                elif isinstance(author_obj, str):
                    meta["author"] = author_obj

                if not meta["author"] or meta["author"] == "Unknown Maintainer":
                    maintainers = data.get("maintainers", [])
                    if maintainers and isinstance(maintainers[0], dict):
                        meta["author"] = maintainers[0].get("name", "Unknown")
                        meta["author_email"] = maintainers[0].get("email", "")

                dist_tags = data.get("dist-tags", {})
                latest_ver = dist_tags.get("latest", "")
                if latest_ver:
                    meta["version"] = latest_ver
                    latest_obj = data.get("versions", {}).get(latest_ver, {})
                    meta["license"] = latest_obj.get("license", meta["license"])
                    meta["homepage"] = latest_obj.get("homepage", "")

                repo = data.get("repository", {})
                if isinstance(repo, dict):
                    meta["repository"] = repo.get("url", "")
                elif isinstance(repo, str):
                    meta["repository"] = repo
        except Exception as e:
            logger.warning(f"Could not fetch npm registry metadata for {package_name}: {e}")

    elif ecosystem == "pypi":
        meta["registry_url"] = f"https://pypi.org/project/{package_name}/"
        try:
            req = urllib.request.Request(
                f"https://pypi.org/pypi/{package_name}/json",
                headers={"User-Agent": "PackageGuard-OSINT/3.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                data = json.loads(res.read().decode("utf-8"))
                info = data.get("info", {})
                meta["author"] = info.get("author") or info.get("maintainer") or "Unknown"
                meta["author_email"] = info.get("author_email") or info.get("maintainer_email") or ""
                meta["version"] = info.get("version", "Latest")
                meta["license"] = info.get("license") or "Not specified"
                meta["homepage"] = info.get("home_page") or info.get("project_url") or ""
                meta["repository"] = info.get("project_urls", {}).get("Source", "") or info.get("project_urls", {}).get("Repository", "")
        except Exception as e:
            logger.warning(f"Could not fetch PyPI registry metadata for {package_name}: {e}")

    return meta


def _check_url(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 3.5) -> Tuple[bool, Optional[int]]:
    """Checks if a target URL exists (HTTP 200/301/302)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if headers:
        default_headers.update(headers)

    try:
        req = urllib.request.Request(url, headers=default_headers)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            if res.status in (200, 301, 302):
                return True, res.status
    except urllib.error.HTTPError as he:
        if he.code in (200, 301, 302):
            return True, he.code
    except Exception:
        pass
    return False, None


def investigate_identity(query: str, top_sites: int = 15, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Investigates an identity across the WHOLE internet.
    Supports:
    - Usernames (e.g., 'kennethreitz', 'tj', 'shadow_ops_temp99')
    - Email Addresses (e.g., 'rosemariehowell@outlook.com')
    - Full Names (e.g., 'Rosemarie Howell')
    - Domains / URLs (e.g., 'datadoghq.com')
    """
    raw_query = query.strip()
    if not raw_query:
        return {
            "query": "",
            "query_type": "Unknown",
            "username": "Unknown",
            "accounts_found": 0,
            "profiles": [],
            "categories_discovered": [],
            "reputation_score": 0,
            "reputation_verdict": "EMPTY QUERY",
            "badge_class": "high",
            "summary": "No identity query provided for OSINT investigation.",
            "is_ghost_author": True,
        }

    # 1. Detect Query Type
    query_type = "Username"
    email_address = ""
    email_intel = {}
    canonical_username = raw_query

    # Check for email format
    email_match = re.search(r"[\w\.-]+@([\w\.-]+\.\w+)", raw_query)
    if email_match or "@" in raw_query and "." in raw_query:
        query_type = "Email Address"
        email_address = email_match.group(0).lower() if email_match else raw_query.lower()
        local_part, domain_part = email_address.split("@", 1)
        canonical_username = re.sub(r"[^A-Za-z0-9_-]", "", local_part)
        
        # Email Intelligence Analysis
        is_disposable = domain_part in DISPOSABLE_EMAIL_DOMAINS
        is_freemail = domain_part in FREE_EMAIL_DOMAINS
        email_intel = {
            "email": email_address,
            "domain": domain_part,
            "is_disposable": is_disposable,
            "is_freemail": is_freemail,
            "classification": "Burner/Disposable Domain" if is_disposable else ("Free Public Webmail" if is_freemail else "Custom/Enterprise Domain"),
        }

    # Check for Domain format
    elif "." in raw_query and not " " in raw_query and not "/" in raw_query:
        query_type = "Domain"
        domain_name = raw_query.lower().replace("https://", "").replace("http://", "").split("/")[0]
        canonical_username = domain_name.split(".")[0]

    # Check for Full Name
    elif " " in raw_query:
        query_type = "Full Name"
        canonical_username = re.sub(r"[^A-Za-z0-9]", "", raw_query.lower())

    else:
        # Standard Username / Handle
        canonical_username = re.sub(r"[^A-Za-z0-9_-]", "", raw_query)

    profiles: List[Dict[str, Any]] = []

    # 2. Define Internet-Wide OSINT Targets across 5 Distinct Categories
    # We inspect the whole web: Social Networks, Developer Hubs, Messaging, Blogs, Identity Services
    targets = [
        # --- Category 1: Social Media & Public Networks ---
        {
            "platform": "Reddit",
            "category": "Social Network",
            "url": f"https://www.reddit.com/user/{canonical_username}/about.json",
            "profile_url": f"https://www.reddit.com/user/{canonical_username}",
            "type": "json_check",
            "check": lambda: _check_reddit(canonical_username),
        },
        {
            "platform": "X (Twitter)",
            "category": "Social Network",
            "url": f"https://x.com/{canonical_username}",
            "profile_url": f"https://x.com/{canonical_username}",
            "type": "web",
            "check": lambda: _check_url(f"https://x.com/{canonical_username}"),
        },
        {
            "platform": "YouTube",
            "category": "Social / Media",
            "url": f"https://www.youtube.com/@{canonical_username}",
            "profile_url": f"https://www.youtube.com/@{canonical_username}",
            "type": "web",
            "check": lambda: _check_url(f"https://www.youtube.com/@{canonical_username}"),
        },
        {
            "platform": "Pinterest",
            "category": "Social / Media",
            "url": f"https://www.pinterest.com/{canonical_username}/",
            "profile_url": f"https://www.pinterest.com/{canonical_username}/",
            "type": "web",
            "check": lambda: _check_url(f"https://www.pinterest.com/{canonical_username}/"),
        },

        # --- Category 2: Developer & Open Source Platforms ---
        {
            "platform": "GitHub",
            "category": "Developer Registry",
            "url": f"https://api.github.com/users/{canonical_username}",
            "profile_url": f"https://github.com/{canonical_username}",
            "type": "api",
            "check": lambda: _check_github(canonical_username),
        },
        {
            "platform": "GitLab",
            "category": "Developer Registry",
            "url": f"https://gitlab.com/api/v4/users?username={canonical_username}",
            "profile_url": f"https://gitlab.com/{canonical_username}",
            "type": "api",
            "check": lambda: _check_gitlab(canonical_username),
        },
        {
            "platform": "npm Registry",
            "category": "Package Ecosystem",
            "url": f"https://registry.npmjs.org/-/v1/search?text=maintainer:{canonical_username}&size=1",
            "profile_url": f"https://www.npmjs.com/~{canonical_username}",
            "type": "api",
            "check": lambda: _check_npm(canonical_username),
        },
        {
            "platform": "PyPI",
            "category": "Package Ecosystem",
            "url": f"https://pypi.org/user/{canonical_username}/",
            "profile_url": f"https://pypi.org/user/{canonical_username}/",
            "type": "web",
            "check": lambda: _check_url(f"https://pypi.org/user/{canonical_username}/"),
        },
        {
            "platform": "HackerNews",
            "category": "Tech Community",
            "url": f"https://hacker-news.firebaseio.com/v0/user/{canonical_username}.json",
            "profile_url": f"https://news.ycombinator.com/user?id={canonical_username}",
            "type": "api",
            "check": lambda: _check_hn(canonical_username),
        },
        {
            "platform": "DockerHub",
            "category": "Container Ecosystem",
            "url": f"https://hub.docker.com/v2/users/{canonical_username}/",
            "profile_url": f"https://hub.docker.com/u/{canonical_username}",
            "type": "api",
            "check": lambda: _check_dockerhub(canonical_username),
        },
        {
            "platform": "Dev.to",
            "category": "Tech Community",
            "url": f"https://dev.to/api/users/by_username?url={canonical_username}",
            "profile_url": f"https://dev.to/{canonical_username}",
            "type": "api",
            "check": lambda: _check_devto(canonical_username),
        },

        # --- Category 3: Communications & Messaging ---
        {
            "platform": "Telegram",
            "category": "Messaging Network",
            "url": f"https://t.me/{canonical_username}",
            "profile_url": f"https://t.me/{canonical_username}",
            "type": "web",
            "check": lambda: _check_telegram(canonical_username),
        },
        {
            "platform": "Keybase",
            "category": "Identity & Cryptography",
            "url": f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={canonical_username}",
            "profile_url": f"https://keybase.io/{canonical_username}",
            "type": "api",
            "check": lambda: _check_keybase(canonical_username),
        },

        # --- Category 4: Creative, Content & Blogs ---
        {
            "platform": "Medium",
            "category": "Blogging / Publishing",
            "url": f"https://medium.com/@{canonical_username}",
            "profile_url": f"https://medium.com/@{canonical_username}",
            "type": "web",
            "check": lambda: _check_url(f"https://medium.com/@{canonical_username}"),
        },
        {
            "platform": "Substack",
            "category": "Newsletters / Publishing",
            "url": f"https://{canonical_username}.substack.com",
            "profile_url": f"https://{canonical_username}.substack.com",
            "type": "web",
            "check": lambda: _check_url(f"https://{canonical_username}.substack.com"),
        },
        {
            "platform": "Wikipedia (User)",
            "category": "Encyclopedia / Community",
            "url": f"https://en.wikipedia.org/wiki/User:{canonical_username}",
            "profile_url": f"https://en.wikipedia.org/wiki/User:{canonical_username}",
            "type": "web",
            "check": lambda: _check_url(f"https://en.wikipedia.org/wiki/User:{canonical_username}"),
        },
    ]

    # Check Gravatar if email is present
    if email_address:
        email_hash = hashlib.md5(email_address.strip().lower().encode("utf-8")).hexdigest()
        targets.append({
            "platform": "Gravatar Global Profile",
            "category": "Global Identity",
            "url": f"https://en.gravatar.com/{email_hash}.json",
            "profile_url": f"https://gravatar.com/{email_hash}",
            "type": "api",
            "check": lambda: _check_gravatar(email_hash),
        })

    # 3. Concurrently Execute Internet Checks (ThreadPoolExecutor)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        future_to_target = {
            executor.submit(target["check"]): target
            for target in targets
        }
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                found, status_text = future.result()
                if found:
                    profiles.append({
                        "platform": target["platform"],
                        "category": target["category"],
                        "url": target["profile_url"],
                        "status": status_text or "Active / Verified Profile",
                        "verified": True,
                    })
            except Exception as e:
                logger.debug(f"OSINT check error for {target['platform']}: {e}")

    # 4. Supplementary Maigret CLI invocation if available
    maigret_bin = shutil.which("maigret")
    if maigret_bin and len(profiles) < 3 and len(canonical_username) >= 3:
        try:
            cmd = [
                maigret_bin,
                canonical_username,
                "--top-sites", str(top_sites),
                "--timeout", "4",
                "--no-progressbar",
            ]
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8, env=env, errors="replace")
            for line in res.stdout.splitlines():
                match = re.search(r"\[\+\]\s+([A-Za-z0-9\s]+):\s+(https?://\S+)", line)
                if match:
                    plat = match.group(1).strip()
                    url = match.group(2).strip()
                    if not any(p["platform"].lower() == plat.lower() for p in profiles):
                        profiles.append({
                            "platform": plat,
                            "category": "Social & Web Footprint (Maigret)",
                            "url": url,
                            "status": "Discovered via Maigret CLI",
                            "verified": True,
                        })
        except Exception as e:
            logger.debug(f"Maigret probe notice: {e}")

    # Sort profiles by category priority
    category_priority = {
        "Global Identity": 0,
        "Developer Registry": 1,
        "Package Ecosystem": 2,
        "Tech Community": 3,
        "Social Network": 4,
        "Messaging Network": 5,
        "Blogging / Publishing": 6,
    }
    profiles.sort(key=lambda p: category_priority.get(p.get("category", ""), 9))

    # 5. Extract Unique Categories Discovered
    categories = sorted(list(set(p.get("category", "General") for p in profiles)))
    found_count = len(profiles)

    # 6. Compute Multi-Vector Internet Credibility Score (0-100)
    has_github = any("GitHub" in p["platform"] for p in profiles)
    has_pkg = any("npm" in p["platform"] or "PyPI" in p["platform"] for p in profiles)
    has_social = any("Social" in p.get("category", "") or "Blogging" in p.get("category", "") for p in profiles)
    is_burner_email = email_intel.get("is_disposable", False)

    reputation = min(100, found_count * 18)
    if has_github:
        reputation = max(reputation, 55)
    if has_github and has_pkg:
        reputation = max(reputation, 80)
    if has_github and has_social:
        reputation = max(reputation, 85)
    if len(categories) >= 3:
        reputation = min(100, reputation + 15)

    # Severe penalty for disposable burner emails
    if is_burner_email:
        reputation = min(15, reputation)

    # Verdict Assignment
    if reputation >= 75:
        verdict = "VERIFIED WEB FOOTPRINT"
        badge_class = "low"
        summary = (
            f"Query '{raw_query}' is an established public entity discovered across {found_count} platforms "
            f"in {len(categories)} categories. High identity confidence; low risk of disposable impersonation."
        )
        is_ghost = False
    elif reputation >= 35:
        verdict = "MODERATE WEB PRESENCE"
        badge_class = "medium"
        summary = (
            f"Identity '{raw_query}' was located on {found_count} public platforms. "
            "Moderate presence identified. Manual review recommended before granting administrative privileges."
        )
        is_ghost = False
    else:
        verdict = "GHOST / BURNER IDENTITY"
        badge_class = "high"
        if is_burner_email:
            summary = (
                f"CRITICAL RISK: '{raw_query}' is registered under a known DISPOSABLE / BURNER email service "
                f"({email_intel.get('domain')}). Common tactic in targeted supply-chain malware attacks."
            )
        else:
            summary = (
                f"CRITICAL WARNING: No verifiable identity presence found for '{raw_query}' across the internet. "
                "Matches the profile of a disposable burner account created exclusively for single-use deployment."
            )
        is_ghost = True

    return {
        "query": raw_query,
        "query_type": query_type,
        "username": canonical_username,
        "email_intel": email_intel,
        "accounts_found": found_count,
        "profiles": profiles,
        "categories_discovered": categories,
        "reputation_score": reputation,
        "reputation_verdict": verdict,
        "badge_class": badge_class,
        "summary": summary,
        "is_ghost_author": is_ghost,
    }


def run_maigret_osint(username: str, top_sites: int = 15, timeout: float = 3.5) -> Dict[str, Any]:
    """Compatibility wrapper that calls the internet-wide identity investigator."""
    return investigate_identity(username, top_sites=top_sites, timeout=timeout)


# ---------------------------------------------------------------------------
# Specialized Platform Probers (API & Header parsers)
# ---------------------------------------------------------------------------
def _check_github(username: str) -> Tuple[bool, str]:
    url = f"https://api.github.com/users/{username}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                repos = data.get("public_repos", 0)
                followers = data.get("followers", 0)
                name = data.get("name") or username
                return True, f"Active Developer: {name} ({repos} repos, {followers} followers)"
    except Exception:
        pass
    return False, ""


def _check_gitlab(username: str) -> Tuple[bool, str]:
    url = f"https://gitlab.com/api/v4/users?username={username}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                if isinstance(data, list) and len(data) > 0 and data[0].get("username", "").lower() == username.lower():
                    return True, f"GitLab Member: {data[0].get('name', username)}"
    except Exception:
        pass
    return False, ""


def _check_npm(username: str) -> Tuple[bool, str]:
    url = f"https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                total = data.get("total", 0)
                if total > 0:
                    return True, f"Official npm Publisher ({total} package(s))"
    except Exception:
        pass
    return False, ""


def _check_hn(username: str) -> Tuple[bool, str]:
    url = f"https://hacker-news.firebaseio.com/v0/user/{username}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                body = res.read().decode("utf-8").strip()
                if body and body != "null":
                    data = json.loads(body)
                    karma = data.get("karma", 0)
                    return True, f"HackerNews Contributor ({karma} karma)"
    except Exception:
        pass
    return False, ""


def _check_reddit(username: str) -> Tuple[bool, str]:
    url = f"https://www.reddit.com/user/{username}/about.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                karma = data.get("data", {}).get("total_karma", 0)
                return True, f"Reddit Account ({karma} karma)"
    except Exception:
        pass
    return False, ""


def _check_dockerhub(username: str) -> Tuple[bool, str]:
    url = f"https://hub.docker.com/v2/users/{username}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                return True, "DockerHub Container Publisher"
    except Exception:
        pass
    return False, ""


def _check_devto(username: str) -> Tuple[bool, str]:
    url = f"https://dev.to/api/users/by_username?url={username}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                return True, f"Dev.to Author: {data.get('name', username)}"
    except Exception:
        pass
    return False, ""


def _check_keybase(username: str) -> Tuple[bool, str]:
    url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                data = json.loads(res.read().decode("utf-8"))
                them = data.get("them", [])
                if them and them[0] is not None:
                    return True, "Keybase Cryptographic Identity Verified"
    except Exception:
        pass
    return False, ""


def _check_telegram(username: str) -> Tuple[bool, str]:
    url = f"https://t.me/{username}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                content = res.read().decode("utf-8", errors="ignore")
                # Telegram pages contain 'tgme_page_extra' or profile title if user exists
                if "tgme_page_title" in content and "If you have Telegram" in content:
                    return True, "Telegram Channel / Contact Active"
    except Exception:
        pass
    return False, ""


def _check_gravatar(email_hash: str) -> Tuple[bool, str]:
    url = f"https://en.gravatar.com/{email_hash}.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PackageGuard-OSINT/3.0"})
        with urllib.request.urlopen(req, timeout=3.5) as res:
            if res.status == 200:
                return True, "Gravatar Global Verified Identity"
    except Exception:
        pass
    return False, ""
