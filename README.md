# Windows 365 Endpoint Network Validator

A PowerShell-based readiness tool for validating Windows 365, Azure Virtual Desktop, and Intune connectivity with a shareable HTML report.

## At a Glance

- Tests required Windows 365, Azure Virtual Desktop, and Intune endpoints from one script
- Supports host network, client network, or combined validation modes
- Generates a self-contained interactive HTML report and JSON sidecar
- Surfaces firewall, DNS, TLS, wildcard, and IP-range findings in a practical operator view

## Overview

Windows 365 readiness checks are often split across documentation, one-off scripts, and manual interpretation. This project packages those checks into a single PowerShell workflow that validates endpoint reachability and produces a reviewable browser-based report.

The main artifact is [Test-W365-Endpoints-v10.ps1](./Test-W365-Endpoints-v10.ps1).

The script is designed to run directly on the target Windows device without requiring a separate web app or backend service.

## Why It Matters

- Speeds up Windows 365 and AVD network readiness assessments
- Produces output that network, endpoint, and architecture teams can review together
- Turns raw connectivity checks into actionable remediation guidance

## Feature Highlights

- Single-file PowerShell entry point with no deployment overhead
- Host, client, and combined validation modes for different testing contexts
- Interactive HTML report with tabs, KPIs, filtering, and detailed endpoint results
- JSON sidecar output for comparison, automation, or downstream processing
- Azure RTT reference integration to support Cloud PC planning conversations

## Preview

The report experience includes:

- A dark, data-rich dashboard with summary KPIs and per-category views
- Drill-in tables for Windows 365, AVD, Intune, and client-side dependencies
- Action-oriented output for firewall, wildcard, DNS, and TLS issues

Screenshots or a sanitized demo report can be added once the public artifact set is finalized.

## Files

- [Test-W365-Endpoints-v10.ps1](./Test-W365-Endpoints-v10.ps1): Main validator script and interactive report generator
- [Azure Network RTT Stats - April 2026/azure-rtt-reference-apr2026.json](./Azure%20Network%20RTT%20Stats%20-%20April%202026/azure-rtt-reference-apr2026.json): Azure region RTT reference data used by the report
- [sample-output/W365-Results-sanitized-sample.html](./sample-output/W365-Results-sanitized-sample.html): Sanitized interactive sample report for previews and screenshots
- [sample-output/W365-Results-sanitized-sample.json](./sample-output/W365-Results-sanitized-sample.json): Sanitized JSON sample matching the public report
- [GITHUB_ABOUT.md](./GITHUB_ABOUT.md): Recommended GitHub description, website, and topics
- [LINKEDIN_POSTS.md](./LINKEDIN_POSTS.md): Draft launch posts for sharing the project publicly

## Sample Output

The repository includes a sanitized sample HTML report and matching JSON payload under [sample-output](./sample-output/README.md). These files preserve the report structure and remediation flow while removing local device, network, and egress identifiers.

## How to Use

1. Run the validator on the target Windows device with PowerShell 5.1 or later.
2. Choose host mode, client mode, or both depending on the scenario you want to validate.
3. Review the generated HTML report and JSON output to identify readiness gaps and next actions.

### Example

```powershell
.\Test-W365-Endpoints-v10.ps1
```

Optional parameters in the script let you control output path, prompt suppression, browser launch behavior, timeout, and parallelism.

## Attribution

This project builds on the original Windows 365 endpoint validation work published by Shannon Fritz from Microsoft. The upstream attribution is preserved in the script header.

## Positioning

This project is best suited for engineers, architects, and administrators who need a concrete way to validate Windows 365 connectivity requirements and produce a usable output for remediation planning.