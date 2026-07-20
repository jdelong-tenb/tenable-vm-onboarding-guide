---
name: vm-onboarding-guide
description: Walks a new Tenable Vulnerability Management user through onboarding — connectivity, scanner/agent linkage, first scan, findings, and tagging — and guides them through whichever step they're stuck on. Invoke when someone says things like "I just signed up for Tenable," "how do I get started," "I ran a scan but don't see anything," "my scanner won't link," or "how do I set up tags."
---

# VM Onboarding Guide

## Why this exists

Generic onboarding docs don't know where a new Tenable Vulnerability
Management user actually is — whether they've linked a scanner yet, whether
their first scan finished, or whether they've looked at the results. In
practice, the steps people get stuck on most are scanner/agent linkage, and —
for those who do scan — actually looking at the results afterward (the
"scan-to-findings" gap). This skill checks the user's actual account state via
the Tenable Vulnerability Management API and walks them through whatever step
comes next — instead of generic documentation that doesn't know where they
are.

This skill is **not official Tenable support** and isn't a substitute for it —
it's a community-built Claude Code skill that reads your own account via the
public API and gives best-effort guidance. If something looks wrong or you're
stuck, Tenable Support and your account team are the authoritative path.

**Scope:** five onboarding steps that most commonly trip people up:
1. Connectivity (can they reach Tenable's cloud at all)
2. Scanner/agent linkage (the most common early sticking point)
3. First scan + policy configuration
4. Scan-to-findings milestone bridge (no other tooling detects "scanned but
   never viewed findings")
5. Tagging setup (delegated to Hexa MCP where available — see Step 3 below)

**Scale assumption:** this skill's checks (most-recent-scan status, a single
linked/not-linked verdict, one vuln count) are calibrated for a user with a
handful of scanners/agents and a small scan history — the normal shape of a
brand-new account. On an established enterprise account with dozens of
scanners and a large scan history, "the most recent scan across the whole
account failed" is a much weaker signal — it could be one abandoned ad-hoc scan
while hundreds of others succeeded. If the account clearly has an established
fleet rather than a fresh signup, treat this skill's verdicts as a rough
starting point, not a diagnosis, and ask what they're actually seeing before
trusting the stage label.

Dashboards, role-based personalization, and gamification are explicitly out of
scope — see Known Limitations.

## Step 1 — Check account status

Run the status checker:

```bash
python3 scripts/check_onboarding_status.py
```

Requires `TIO_ACCESS_KEY` and `TIO_SECRET_KEY` env vars — the user's own
Tenable Vulnerability Management API keys (Settings > My Account > API Keys, or
ask them to generate one if they don't have it, it takes under a minute).

If the keys aren't set, ask the user for them before doing anything else.
Do not guess at account state — always check.

**API key permission level matters.** Confirmed against a live account: a
"Scan Manager"-level key (permissions 64) can read `/scanners` and `/scans` but
gets a `403 Insufficient scope` on `/agents` — only "Administrator"-level keys
(permissions 128) can list agents. The script handles this gracefully (each
check fails independently, and a completed scan is treated as proof something
was linked even if `/agents` errors), but if the user's `agent_check_error`
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
the user's network, not a Tenable-side issue. Ask them to run the check
again from the machine that will actually host the scanner/agent (not
necessarily this machine), and to confirm with their network team that
outbound 443 to `cloud.tenable.com` is allowed. No inbound ports are required
for agent or cloud-linked scanner connectivity.

Note: `connectivity_ok: true` only proves a bare TCP handshake succeeded — it
doesn't prove the actual HTTPS API calls will work. A TLS-intercepting proxy
can pass this check and still break every downstream call. If `connectivity_ok`
is `true` but every other check errors with something other than a clean 401/403
(timeouts, SSL errors, malformed responses), suspect a TLS-inspecting proxy on
the user's network rather than trusting connectivity is fully fine.

### `check_linkage_error`
Both the `/scanners` and `/agents` checks failed (see `scanner_check_error` /
`agent_check_error` in the output), and there's no completed-scan history to
fall back on either. Look at the actual error text before saying anything to
the user:
- A `403 Insufficient scope` on both usually means the API key's permission
  level (Scan Manager or lower) can't read sensor data at all — ask them for
  an Administrator-level key, or check status themselves in Settings > Sensors.
- Any other error (401, 5xx, timeout) is worth re-running once before assuming
  it's a key problem — could be transient.
- Do not tell the user "you haven't linked anything" here — that's the
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
A scan exists but either the most recent one didn't complete cleanly, or the
findings/tag checks came back empty or errored. Check the specific fields:
- **`most_recent_scan_status` isn't `completed`:** this takes priority — a
  user can have a long history of successful scans and still have their
  latest one fail. See the status-specific guidance below.
- **`completed` with `open_vuln_count_last_30d: 0`:** genuinely a clean scan
  target (small or well-patched — tell them that's a good sign, but suggest
  scanning a larger or more representative range to actually exercise the
  product).
- **`vuln_check_error` present instead of a count:** the findings check itself
  failed (e.g. permission issue) — re-run the check rather than telling the
  user their scan came back clean. An errored check is not evidence of a
  clean environment.
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
through the CSV-upload UI manually. But first, check who you're actually
talking to: Hexa MCP tools being available in *this* session only tells you
what's installed here — it does not mean the user knows what Hexa is. If a
Tenable employee (support engineer, SE, CSM) is running this skill on a
user's behalf, their own session may have Hexa MCP loaded even though the
user has never heard the name. Don't drop "Hexa" into a conversation with
an end user who didn't bring it up themselves; instead:
- If you're talking directly with the user, either don't name Hexa at all
  ("there's a faster way to set this up than the CSV template — want me to
  build it from your existing scan data?") or introduce it briefly ("Tenable
  has an AI assistant called Hexa that can do this from a CSV or your scan
  data automatically") before using it.
- If you're a Tenable employee (support engineer, SE, CSM) setting this up on
  a user's behalf, it's fine to reference Hexa directly.
- If Hexa MCP tools are available in this session, they can take a CSV of
  names + IP ranges (or business-unit/device-name patterns) and create the
  tags directly, or auto-suggest tags from OS/asset data already in their scan
  results — ask if they'd like to try that path.
- If Hexa MCP isn't available, fall back to: Settings > Tags > download the CSV
  template, fill in name + IP range pairs, upload it back. Environment
  (Prod/Dev/Staging), OS type, and business unit are the three tagging
  dimensions worth setting up first.
- Tagging isn't a hard blocker to viewing findings — mention it's available but
  don't block the `view_findings` conversation on it if the user just wants
  to see their results first.
- A newly created dynamic tag (one with an IP/OS/business-unit filter rather
  than a manually-assigned static tag) doesn't populate with matching assets
  instantly — Tenable evaluates the rule against the asset inventory in the
  background, and the tag sits in a `WAITING` status (visible in Settings >
  Tags) until that finishes. Confirmed live: ~20 minutes for a ~60-asset
  account, roughly matching Tenable's own guidance that this scales with
  asset count (typically 10-15 min, longer for larger inventories). If the
  user checks Inventory/Exposure Management right after creating a tag and
  sees "No data available... you must first generate data by creating tags,"
  that's this same lag, not a failure — the tag exists (confirmed immediately
  via the tags API/Hexa), it just hasn't finished matching assets yet. Tell
  them to check Settings > Tags for a `WAITING` vs `COMPLETE` status rather
  than re-creating the tag or assuming Hexa failed. If the status stays
  `WAITING` well past ~30 minutes, or shows an error in the rule detail box,
  that's worth troubleshooting the filter itself (Settings > Tags > click
  into the tag to see the rule) rather than waiting further.

### `view_findings`
Everything is working — scanner/agent linked, a scan completed, and there are
open vulnerabilities on file. The user's real remaining gap is just
navigating to where findings live. Point them at **Scans > [their scan] >
Vulnerabilities**, not just the Explore page — both surfaces show the same
underlying findings, but users who only look at Explore undercount what
they've actually found. Ask if they want a walkthrough of reading a specific
finding (severity, plugin output, remediation) or if they're comfortable
exploring on their own from here.

Confirmed live on a two-scan account: pointing a user at a single scan's
Vulnerabilities tab undercounts the same way Explore does if they have more
than one active scan (e.g. separate scans per site/location) — one scan
showed 80 vuln instances, the other 47, account-wide total 128. If
`most_recent_scan_name` is the only scan you mention and the account
plausibly has more than one (ask, or note if `linked_scanner_count` > 1
hints at multiple sites), say "check each of your scans, or use the
account-wide Vulnerabilities workbench for the full picture" rather than
pointing at just the one scan the status check happened to surface.

## Known limitations (do not overclaim these)

- **No dashboard or role-personalization guidance.** Out of scope for this
  skill — those need their own workstream and aren't wired into this skill
  yet.
- **No gamification or progress badges.** Not attempted — out of scope for
  this skill.
- **No persistent milestone tracking across sessions.** This skill checks live
  state each time it's invoked; it does not remember where a user left off
  between sessions or notify anyone proactively. The scan-to-findings bridge
  (Step 2's `run_first_scan` → `review_scan_status` → `view_findings`
  progression) is inferred fresh each run from live API state, not stored.
- **The API can't see UI navigation.** `view_findings` stage is inferred from
  "a scan completed and vulnerabilities exist," not from confirming the user
  actually opened the Findings page. Don't tell a user "you've viewed your
  findings" — tell them findings exist and are ready to view.
- **Cloud-scanner auto-provisioning isn't specially handled.** If a user's
  environment auto-connects via a cloud connector without ever generating a
  linking key, this skill should still detect it correctly via `/scanners` and
  `/agents`, but this hasn't been validated against a real cloud-connector-only
  account. Flag this to the user as "let me know if this doesn't match what
  you're seeing" rather than asserting certainty.
- **Tagging delegation to Hexa MCP is opportunistic, not guaranteed.** This
  skill doesn't ship its own tagging logic — it hands off to Hexa MCP tools
  when they're present in the session and falls back to manual CSV-upload
  instructions when they're not. It does not verify Hexa MCP's tag creation
  succeeded; if the user says a Hexa-created tag isn't showing up, re-run
  the status check rather than assuming success.
- **`tag_count` reflects tag definitions, not finished asset-matching.**
  `check_tags()` hits `/tags/values?limit=1`, which counts tag category/value
  pairs that exist — it does not wait for or reflect whether a dynamic tag's
  filter rule has finished matching assets (see the `setup_tagging` WAITING
  note above). A nonzero `tag_count` right after Hexa creates a tag is real
  and correct; it does not mean the tag has any assets visible yet in
  Tenable One / Exposure Management's Inventory view. Don't treat "Inventory
  shows no data for this tag" as contradicting a nonzero `tag_count` — they
  measure different things.
- **Connectivity check is TCP-only, not a full API health check.** `check_connectivity()`
  only confirms a bare TCP handshake to `cloud.tenable.com:443` — it doesn't
  validate TLS or exercise the actual API. A TLS-intercepting proxy can pass
  this check while still breaking every downstream call. See the note under
  `fix_connectivity` above.
- **A failed check is not the same as a confirmed-empty result.** `scanner_check_error`,
  `agent_check_error`, `vuln_check_error`, and `tag_check_error` all mean the
  check itself didn't run to completion — not that the underlying thing is
  absent. Don't tell a user "you have no vulnerabilities" or "no tags are
  set up" if the corresponding `*_check_error` field is present instead of a
  count; tell them the check couldn't run and offer to re-run it.
- **Calibrated for new accounts, not fleet-scale ones.** The stage logic looks
  at one "most recent scan" and a handful of aggregate counts across the whole
  account. On an established account with a large scanner fleet and scan
  history, these are weak signals — see the Scale assumption note in "Why this
  exists" above.

## Design notes for anyone extending this

Connectivity, scanner/agent linkage, first-scan, and milestone-bridge checks all
talk to the user's own Tenable Vulnerability Management API directly rather
than depending on Hexa MCP tooling — as of this writing, Hexa's MCP
server does not have scanner/agent linkage verification tools. If those ship
later, swap `scripts/check_onboarding_status.py`'s API calls for the
equivalent Hexa MCP tool calls, but keep the stage-based guidance logic in
this file — it's the reusable part.

Tagging is the one exception: Hexa's Tagging skill already handles CSV/XLSX
parsing and tag creation/recommendation well, confirmed working end-to-end in
manual testing. That's why `setup_tagging` guidance defers to Hexa MCP
instead of reimplementing CSV parsing here — duplicating a capability Hexa
already has would just create two divergent tagging paths.
