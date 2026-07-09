#!/usr/bin/env python3
"""
Checks a Tenable Vulnerability Management container's onboarding status against
the public API: connectivity, scanner/agent linkage, first scan, and recent
scan results.

Auth: TIO_ACCESS_KEY / TIO_SECRET_KEY env vars (API keys, not a password).
Stdlib only — no third-party dependencies.
"""

import json
import os
import socket
import sys
import urllib.request
import urllib.error

API_BASE = "https://cloud.tenable.com"
API_HOST = "cloud.tenable.com"


def check_connectivity():
    """Returns True if cloud.tenable.com:443 is reachable from this machine.
    A failure here means every downstream check will also fail — this is the
    prerequisite gate (firewall/proxy blocking outbound 443), not a scanner
    or agent problem."""
    try:
        with socket.create_connection((API_HOST, 443), timeout=5):
            return True
    except OSError:
        return False


def api_get(path, access_key, secret_key):
    url = API_BASE + path
    req = urllib.request.Request(url)
    req.add_header("X-ApiKeys", f"accessKey={access_key}; secretKey={secret_key}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API error {e.code} on {path}: {body[:300]}") from e


def check_network_scanners(access_key, secret_key):
    """Returns (has_network_scanner, scanner_count). Raises RuntimeError on API failure."""
    data = api_get("/scanners", access_key, secret_key)
    scanners = data.get("scanners", [])
    network = [s for s in scanners if s.get("type") != "agent" and s.get("status") == "on"]
    return (len(network) > 0, len(network))


def check_agents(access_key, secret_key):
    """Returns (has_agent, agent_count). Raises RuntimeError on API failure."""
    agents_data = api_get("/agents", access_key, secret_key)
    agents = agents_data.get("agents", [])
    linked_agents = [a for a in agents if a.get("status") in ("on", "online")]
    return (len(linked_agents) > 0, len(linked_agents))


def check_scans(access_key, secret_key):
    """Returns (has_completed_scan, most_recent_scan_name, most_recent_scan_status)."""
    data = api_get("/scans", access_key, secret_key)
    scans = data.get("scans") or []
    completed = [s for s in scans if s.get("status") == "completed"]
    if not scans:
        return (False, None, None)
    most_recent = sorted(scans, key=lambda s: s.get("last_modification_date", 0), reverse=True)[0]
    return (len(completed) > 0, most_recent.get("name"), most_recent.get("status"))


def check_findings(access_key, secret_key):
    """Returns approximate open vulnerability count via the vulns workbench, as a
    proxy for whether there is anything to view. This does NOT measure whether the
    customer has actually looked at the Findings/Explore UI — the API cannot see
    UI navigation. Treat this purely as 'is there something waiting for them.'"""
    try:
        data = api_get("/workbenches/vulnerabilities?date_range=30", access_key, secret_key)
        return data.get("total_vuln_count") or data.get("total") or 0
    except RuntimeError:
        return None


def check_tags(access_key, secret_key):
    """Returns the count of tag category/value pairs defined on the container, as
    a proxy for whether any tagging strategy has been set up. Tagging setup itself
    (CSV import, OS auto-tagging, business-unit rules) is delegated to Hexa MCP
    where available — this check only tells the skill whether to offer that step."""
    try:
        data = api_get("/tags/values?limit=1", access_key, secret_key)
        return data.get("pagination", {}).get("total", len(data.get("values", [])))
    except RuntimeError:
        return None


def main():
    access_key = os.environ.get("TIO_ACCESS_KEY")
    secret_key = os.environ.get("TIO_SECRET_KEY")
    if not access_key or not secret_key:
        print(json.dumps({
            "error": "Set TIO_ACCESS_KEY and TIO_SECRET_KEY env vars (Settings > My Account > API Keys in Tenable Vulnerability Management)."
        }))
        sys.exit(1)

    result = {}

    if not check_connectivity():
        result["connectivity_ok"] = False
        result["onboarding_stage"] = "fix_connectivity"
        print(json.dumps(result, indent=2))
        return
    result["connectivity_ok"] = True

    has_network = has_agent = None  # None = check failed, status unknown
    try:
        has_network, scanner_count = check_network_scanners(access_key, secret_key)
        result["scanner_linked"] = has_network
        result["linked_scanner_count"] = scanner_count
    except RuntimeError as e:
        result["scanner_check_error"] = str(e)

    try:
        has_agent, agent_count = check_agents(access_key, secret_key)
        result["agent_linked"] = has_agent
        result["linked_agent_count"] = agent_count
    except RuntimeError as e:
        result["agent_check_error"] = str(e)

    try:
        has_completed, recent_name, recent_status = check_scans(access_key, secret_key)
        result["has_completed_scan"] = has_completed
        result["most_recent_scan_name"] = recent_name
        result["most_recent_scan_status"] = recent_status
    except RuntimeError as e:
        result["scan_check_error"] = str(e)
        has_completed = False

    # A completed scan proves something scanning-capable was linked at some point,
    # even if the live scanner/agent check above errored (e.g. an API key with
    # insufficient scope for /agents). Don't tell a customer to "link a
    # scanner/agent" when their scan history already contradicts that.
    linked = bool(has_network) or bool(has_agent) or has_completed

    both_checks_failed = has_network is None and has_agent is None
    if both_checks_failed and not has_completed:
        result["onboarding_stage"] = "check_linkage_error"
        print(json.dumps(result, indent=2))
        return

    vuln_count = None
    if linked:
        vuln_count = check_findings(access_key, secret_key)
        result["open_vuln_count_last_30d"] = vuln_count

    if has_completed:
        result["tag_count"] = check_tags(access_key, secret_key)

    if not linked:
        stage = "link_scanner_or_agent"
    elif not has_completed:
        stage = "run_first_scan"
    elif vuln_count in (0, None):
        stage = "review_scan_status"
    elif not result.get("tag_count"):
        stage = "setup_tagging"
    else:
        stage = "view_findings"

    result["onboarding_stage"] = stage
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
