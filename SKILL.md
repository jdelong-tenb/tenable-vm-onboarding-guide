---
name: vm-onboarding-guide
description: Walks a new Tenable Vulnerability Management customer through onboarding — checking whether they've linked a scanner/agent, run a scan, and reviewed findings — and guides them through whichever step they're stuck on. Invoke when a customer says things like "I just signed up for Tenable," "how do I get started," "I ran a scan but don't see anything," or "I'm stuck setting up my scanner."
---

# VM Onboarding Guide

## Why this exists

New Tenable Vulnerability Management customers drop off hard in the first 90 days.
Fleet-wide data (see `~/work/hexa_onboarding_analysis/` if available) shows most
customers who get stuck do so at one of two points: they never link a scanner or
agent, or they run a scan but never look at the results. This skill checks a
customer's actual account state via the Tenable Vulnerability Management API and
walks them through whatever step comes next — instead of generic documentation
that doesn't know where they are.

**Scope (Phase 1 only):** this skill covers scanner/agent linkage and first-scan
guidance. It does not do tagging, dashboard setup, or role-based personalization —
those are separate, larger workstreams (see Known Limitations).

## Step 1 — Check account status

Run the status checker:

```bash
python3 scripts/check_onboarding_status.py
```

Requires `TIO_ACCESS_KEY` and `TIO_SECRET_KEY` env vars — the customer's own
Tenable Vulnerability Management API keys (Settings > My Account > API Keys, or
ask them to generate one if they don't have it, it takes under a minute).

If the keys aren't set, ask the customer for them before doing anything else.
Do not guess at account state — always check.

The script returns JSON with an `onboarding_stage` field: one of
`link_scanner_or_agent`, `run_first_scan`, `review_scan_status`, or
`view_findings`.

## Step 2 — Guide based on stage

### `link_scanner_or_agent`
Neither a network scanner nor an agent is linked. Ask which fits their environment:
- **Agent** (recommended for laptops/workstations, anything mobile, or if they
  want the fastest path to a first scan): direct them to download the Nessus
  Agent from Settings > Sensors, and to generate a linking key from the same
  page. Confirm the agent shows "on"/"online" in `/agents` before moving on —
  check-in can take a few minutes.
- **Network scanner** (recommended for scanning ranges of servers/infrastructure
  they don't want to install software on individually): direct them to deploy a
  Tenable Core scanner appliance or Nessus scanner, then link it with a linking
  key from Settings > Sensors.
- If they hit a connectivity problem (can't reach `cloud.tenable.com`), that's a
  firewall/proxy issue on their end — ports 443 outbound, no on-prem inbound
  needed for agent or cloud-linked scanners.

Re-run the status check after they say they've linked something, don't just take
their word for it.

### `run_first_scan`
Something is linked but no scan has completed. Guide them to run a basic
scan — a "Basic Network Scan" template pointed at whatever the linked
scanner/agent can see is the fastest path to real results. Avoid recommending
advanced/credentialed scan templates for a first scan; save that for later once
they've seen the product work end to end.

### `review_scan_status`
A scan completed but returned no vulnerabilities (or the API check errored).
This is either genuinely a clean scan target (small/well-patched target — tell
them that's a good sign but suggest scanning a larger or more representative
range) or the scan errored/was misconfigured — check `most_recent_scan_status`
in the script output and look at the scan's own error detail in the UI if it
isn't `completed`.

### `view_findings`
Everything is working — scanner/agent linked, a scan completed, and there are
open vulnerabilities on file. The customer's real remaining gap is just
navigating to where findings live. Point them at **Scans > [their scan] >
Vulnerabilities**, not just the Explore page — both surfaces show the same
underlying findings, but customers who only look at Explore undercount what
they've actually found. Ask if they want a walkthrough of reading a specific
finding (severity, plugin output, remediation) or if they're comfortable
exploring on their own from here.

## Known limitations (do not overclaim these)

- **No tagging, dashboard, or role-personalization guidance.** Out of scope for
  this skill — those need their own workstream (tagging is a Hexa "Can Do" per
  the internal gap analysis, but isn't wired into this skill yet).
- **No persistent milestone tracking.** This skill checks live state each time
  it's invoked; it does not remember where a customer left off between sessions
  or notify anyone proactively. Full persistence is a larger backend investment
  (internally scoped as "Phase 3," no committed timeline as of this writing).
- **The API can't see UI navigation.** `view_findings` stage is inferred from
  "a scan completed and vulnerabilities exist," not from confirming the customer
  actually opened the Findings page. Don't tell a customer "you've viewed your
  findings" — tell them findings exist and are ready to view.
- **Cloud-scanner auto-provisioning isn't specially handled.** If a customer's
  environment auto-connects via a cloud connector without ever generating a
  linking key, this skill should still detect it correctly via `/scanners` and
  `/agents`, but this hasn't been validated against a real cloud-connector-only
  account. Flag this to the customer as "let me know if this doesn't match what
  you're seeing" rather than asserting certainty.

## Design notes for anyone extending this

This intentionally talks to the customer's own Tenable Vulnerability Management
API directly rather than depending on any internal Hexa MCP tooling — as of this
writing, Hexa's MCP server does not have scanner/agent linkage verification
tools (`get_linking_key` / `check_scanner_linked` were proposed, not built). If
those ship later, swap `scripts/check_onboarding_status.py`'s API calls for the
equivalent Hexa MCP tool calls, but keep the stage-based guidance logic in this
file — it's the reusable part.
