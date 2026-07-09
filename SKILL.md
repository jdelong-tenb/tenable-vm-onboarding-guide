---
name: vm-onboarding-guide
description: Walks a new Tenable Vulnerability Management customer through onboarding — connectivity, scanner/agent linkage, first scan, findings, and tagging — and guides them through whichever step they're stuck on. Invoke when a customer says things like "I just signed up for Tenable," "how do I get started," "I ran a scan but don't see anything," "my scanner won't link," or "how do I set up tags."
---

# VM Onboarding Guide

## Why this exists

New Tenable Vulnerability Management customers drop off hard in the first 90 days.
Fleet-wide data (see `~/work/hexa_onboarding_analysis/` if available) shows:
65% fail onboarding within 90 days, and the single biggest cliff is scanner/agent
linkage — most customers never link one at all. Of those who do scan, most never
look at the results (the "scan-to-findings" cliff). This skill checks a customer's
actual account state via the Tenable Vulnerability Management API and walks them
through whatever step comes next — instead of generic documentation that doesn't
know where they are.

**Scope:** the five highest-impact steps identified in the onboarding gap analysis:
1. Connectivity (can they reach Tenable's cloud at all)
2. Scanner/agent linkage (the biggest cliff)
3. First scan + policy configuration
4. Scan-to-findings milestone bridge (the #1 tracked gap — no other tooling
   anywhere detects "scanned but never viewed findings")
5. Tagging setup (delegated to Hexa MCP where available — see Step 3 below)

Dashboards, role-based personalization, and gamification are explicitly out of
scope — see Known Limitations.

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

**API key permission level matters.** Confirmed against a live account: a
"Scan Manager"-level key (permissions 64) can read `/scanners` and `/scans` but
gets a `403 Insufficient scope` on `/agents` — only "Administrator"-level keys
(permissions 128) can list agents. The script handles this gracefully (each
check fails independently, and a completed scan is treated as proof something
was linked even if `/agents` errors), but if the customer's `agent_check_error`
shows a 403, tell them agent-linkage status specifically can't be confirmed
with their current key — not that no agent is linked. Suggest they generate an
Administrator-level key if they need agent status confirmed.

The script returns JSON with an `onboarding_stage` field: one of
`fix_connectivity`, `check_linkage_error`, `link_scanner_or_agent`,
`run_first_scan`, `review_scan_status`, `setup_tagging`, or `view_findings`.

## Step 2 — Guide based on stage

### `fix_connectivity`
`cloud.tenable.com:443` isn't reachable from wherever this check ran. Nothing
else downstream — scanner linking, agent check-in, scanning — will work until
this is fixed. This is almost always a firewall/proxy blocking outbound 443 on
the customer's network, not a Tenable-side issue. Ask them to run the check
again from the machine that will actually host the scanner/agent (not
necessarily this machine), and to confirm with their network team that
outbound 443 to `cloud.tenable.com` is allowed. No inbound ports are required
for agent or cloud-linked scanner connectivity.

### `check_linkage_error`
Both the `/scanners` and `/agents` checks failed (see `scanner_check_error` /
`agent_check_error` in the output), and there's no completed-scan history to
fall back on either. Look at the actual error text before saying anything to
the customer:
- A `403 Insufficient scope` on both usually means the API key's permission
  level (Scan Manager or lower) can't read sensor data at all — ask them for
  an Administrator-level key, or check status themselves in Settings > Sensors.
- Any other error (401, 5xx, timeout) is worth re-running once before assuming
  it's a key problem — could be transient.
- Do not tell the customer "you haven't linked anything" here — that's the
  `link_scanner_or_agent` stage, and it means something different: this stage
  means the check itself failed, not that linkage was confirmed absent.

### `link_scanner_or_agent`
Connectivity is fine, but neither a network scanner nor an agent is linked. Ask
which fits their environment:
- **Agent** (recommended for laptops/workstations, anything mobile, or if they
  want the fastest path to a first scan): direct them to download the Nessus
  Agent from Settings > Sensors, and to generate a linking key from the same
  page. Confirm the agent shows "on"/"online" in `/agents` before moving on —
  check-in can take a few minutes.
- **Network scanner** (recommended for scanning ranges of servers/infrastructure
  they don't want to install software on individually): direct them to deploy a
  Tenable Core scanner appliance or Nessus scanner, then link it with a linking
  key from Settings > Sensors.
- If they hit a connectivity problem specifically at this step (can't reach
  `cloud.tenable.com` from the scanner/agent host even though Step 1 passed
  elsewhere), that's a firewall/proxy issue local to that host, not their
  whole network.

Re-run the status check after they say they've linked something, don't just take
their word for it.

### `run_first_scan`
Something is linked but no scan has completed. Guide them to run a basic
scan — a "Basic Network Scan" template pointed at whatever the linked
scanner/agent can see is the fastest path to real results. Avoid recommending
advanced/credentialed scan templates for a first scan; save that for later once
they've seen the product work end to end. If they already have a scan running
or configured but it's not the right template, help them reconfigure rather than
starting over — Scans > [scan] > Configure covers policy changes without
needing a new scan.

### `review_scan_status`
A scan exists but either returned no vulnerabilities, or its
`most_recent_scan_status` isn't `completed`. Check that status field first:
- **`completed` with 0 vulns:** genuinely a clean scan target (small or
  well-patched — tell them that's a good sign, but suggest scanning a larger
  or more representative range to actually exercise the product) or the vuln
  check itself errored (`open_vuln_count_last_30d: null` — re-run the check).
- **`canceled`:** the scan didn't run to completion — often means it was
  stopped manually or timed out against an unreachable target. Ask them to
  re-launch it rather than troubleshooting the cancel itself; if it cancels
  again, that usually points back to scanner/agent connectivity to the scan
  target, not the Tenable platform.
- **`aborted` / other error status:** look at the scan's own error detail in
  the UI (Scans > [scan] > click in for the failure reason) — don't guess at
  the cause from the API status string alone.

### `setup_tagging`
Scanning and findings are working, but no tags are defined yet. This is where
Hexa is actually strong — offer it as the faster path rather than walking them
through the CSV-upload UI manually:
- If Hexa MCP tools are available in this session, tell the customer Hexa can
  take a CSV of names + IP ranges (or business-unit/device-name patterns) and
  create the tags directly, or auto-suggest tags from OS/asset data already in
  their scan results — ask if they'd like to try that path.
- If Hexa MCP isn't available, fall back to: Settings > Tags > download the CSV
  template, fill in name + IP range pairs, upload it back. Environment
  (Prod/Dev/Staging), OS type, and business unit are the three tagging
  dimensions worth setting up first.
- Tagging isn't a hard blocker to viewing findings — mention it's available but
  don't block the `view_findings` conversation on it if the customer just wants
  to see their results first.

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

- **No dashboard or role-personalization guidance.** Out of scope for this
  skill — those need their own workstream (dashboard/role-based routing is a
  Hexa "Partial" per the internal gap analysis, but isn't wired into this
  skill yet).
- **No gamification or progress badges.** Not attempted — the gap analysis
  rates this "Cannot Do" today for Hexa and it's XL effort; not part of this
  skill's scope.
- **No persistent milestone tracking across sessions.** This skill checks live
  state each time it's invoked; it does not remember where a customer left off
  between sessions or notify anyone proactively. The scan-to-findings bridge
  (Step 2's `run_first_scan` → `review_scan_status` → `view_findings`
  progression) is inferred fresh each run from live API state, not stored.
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
- **Tagging delegation to Hexa MCP is opportunistic, not guaranteed.** This
  skill doesn't ship its own tagging logic — it hands off to Hexa MCP tools
  when they're present in the session and falls back to manual CSV-upload
  instructions when they're not. It does not verify Hexa MCP's tag creation
  succeeded; if the customer says a Hexa-created tag isn't showing up, re-run
  the status check rather than assuming success.

## Design notes for anyone extending this

Connectivity, scanner/agent linkage, first-scan, and milestone-bridge checks all
talk to the customer's own Tenable Vulnerability Management API directly rather
than depending on internal Hexa MCP tooling — as of this writing, Hexa's MCP
server does not have scanner/agent linkage verification tools
(`get_linking_key` / `check_scanner_linked` were proposed, not built; see
`~/work/hexa_onboarding_analysis/data/gap_matrix.csv` rows 2.3/2.4/3.8, all rated
Partial or Cannot Do). If those ship later, swap
`scripts/check_onboarding_status.py`'s API calls for the equivalent Hexa MCP tool
calls, but keep the stage-based guidance logic in this file — it's the reusable
part.

Tagging is the one exception: per the gap analysis, Hexa's Tagging skill (15
tools, CSV/XLSX parsing via `SpreadsheetParser`, `create_tag`,
`get_recommended_tags`) is rated **Can Do today**, confirmed working end-to-end
in manual testing. That's why `setup_tagging` guidance defers to Hexa MCP
instead of reimplementing CSV parsing here — duplicating a capability Hexa
already has would just create two divergent tagging paths.
