# VM Onboarding Guide

A Claude Code skill that checks a Tenable Vulnerability Management customer's
real account state — connectivity, scanner/agent linkage, first scan, findings,
tagging — and guides them through whichever onboarding step they're stuck on,
instead of pointing them at generic documentation.

## What it does

65% of new Tenable VM customers fail onboarding within 90 days. The biggest
single cliff is scanner/agent linkage; the second-biggest is customers who scan
but never look at results. This skill:

1. Checks the customer's account via the Tenable Vulnerability Management API
   (connectivity, scanners, agents, scans, vulnerability workbench, tags).
2. Determines which onboarding stage they're stuck at: fixing connectivity,
   linking a scanner/agent, running a first scan, reviewing scan status,
   setting up tagging, or viewing findings.
3. Walks them through that specific step conversationally, re-checking real
   account state rather than trusting "I did it" at face value. For tagging,
   it hands off to Hexa MCP tools when available (Hexa's Tagging skill already
   does this well) rather than duplicating that logic.

**Scope:** the five highest-impact onboarding steps identified by fleet-wide
funnel analysis — connectivity, scanner/agent linkage, first scan, the
scan-to-findings milestone bridge, and tagging setup. Dashboards, role-based
personalization, and gamification are out of scope — see
[Known Limitations](SKILL.md#known-limitations-do-not-overclaim-these).

## Prerequisites

- Claude Code (or another skill-compatible client).
- Python 3 (stdlib only — no dependencies to install).
- A Tenable Vulnerability Management account with API access. Generate an API
  key pair under **Settings > My Account > API Keys** — takes under a minute.

## How to run

1. Copy or symlink this directory into your Claude Code skills path, e.g.:
   ```bash
   cp -r vm-onboarding-guide ~/.claude/skills/
   ```
2. Set your API credentials:
   ```bash
   export TIO_ACCESS_KEY="your-access-key"
   export TIO_SECRET_KEY="your-secret-key"
   ```
3. In a Claude Code session, say something like "I just signed up for Tenable,
   how do I get started?" or "I ran a scan but don't see any results." The
   skill activates automatically based on its description.

You can also run the status check directly, outside the skill:
```bash
python3 scripts/check_onboarding_status.py
```

## What it outputs

The status script prints JSON, e.g.:
```json
{
  "connectivity_ok": true,
  "scanner_linked": false,
  "agent_linked": true,
  "linked_agent_count": 1,
  "has_completed_scan": true,
  "most_recent_scan_name": "Basic Network Scan",
  "most_recent_scan_status": "completed",
  "open_vuln_count_last_30d": 42,
  "tag_count": 3,
  "onboarding_stage": "view_findings"
}
```

The skill then uses `onboarding_stage` to decide what to say next.

## Known limitations

See the [Known Limitations section in SKILL.md](SKILL.md#known-limitations-do-not-overclaim-these)
for the full list — most importantly: the API can confirm a scan ran and
vulnerabilities exist, but it cannot confirm the customer actually opened the
Findings page. This skill infers "ready to view," not "viewed."

## License

MIT — see [LICENSE](LICENSE).
