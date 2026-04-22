# Windows 365 Endpoint Network Validator

A PowerShell-based readiness tool for validating Windows 365, Azure Virtual Desktop, and Intune connectivity with a shareable HTML report.

The main artifact is [Test-W365-Endpoints.ps1](./Test-W365-Endpoints.ps1). It runs directly on the target Windows device and produces a self-contained HTML report plus JSON output.

## What It Does

- Tests required Windows 365, Azure Virtual Desktop, and Intune endpoints from one script
- Supports host network, client network, or combined validation modes
- Generates a self-contained interactive HTML report and JSON sidecar
- Surfaces firewall, DNS, TLS, wildcard, and IP-range findings in a practical operator view
- Adds Azure RTT reference data to support Cloud PC planning and review conversations

## Preview

The report experience includes:

- A dark, data-rich dashboard with summary KPIs and per-category views
- Drill-in tables for Windows 365, AVD, Intune, and client-side dependencies
- Action-oriented output for firewall, wildcard, DNS, and TLS issues

Actual screenshots from the sanitized sample report are included below.

Overview tab:

![Overview tab](./sample-output/screenshots/overview-tab-live.png)

Round Trip Times tab:

![Round Trip Times tab](./sample-output/screenshots/rtt-tab-live.png)

Readiness Signals tab:

![Readiness Signals tab](./sample-output/screenshots/readiness-tab-live.png)

## Files

- [Test-W365-Endpoints.ps1](./Test-W365-Endpoints.ps1): Main validator script and interactive report generator
- [Azure Network RTT Stats - April 2026/azure-rtt-reference-apr2026.json](./Azure%20Network%20RTT%20Stats%20-%20April%202026/azure-rtt-reference-apr2026.json): Azure region RTT reference data used by the report
- [sample-output](./sample-output/README.md): Sanitized sample HTML, matching JSON, and preview screenshots for browsing the report experience

## Sample Output

The repository includes a sanitized sample HTML report and matching JSON payload under [sample-output](./sample-output/README.md). These files preserve the report structure and remediation flow while removing local device, network, and egress identifiers.

## How to Use

1. Run the validator on the target Windows device with PowerShell 5.1 or later.
2. Choose host mode, client mode, or both depending on the scenario you want to validate.
3. Review the generated HTML report and JSON output to identify readiness gaps and next actions.

### Example

```powershell
.\Test-W365-Endpoints.ps1
```

Optional parameters in the script let you control output path, prompt suppression, browser launch behavior, timeout, and parallelism.

## Attribution

This project builds on the original Windows 365 endpoint validation idea and first PowerShell script published by Shannon Fritz from Microsoft.

This repository extends that foundation with a different packaging approach, additional validation and reporting layers, and a public sample set. Credit for the original concept and starting script belongs to Shannon Fritz, and the upstream attribution is also preserved in the script header.