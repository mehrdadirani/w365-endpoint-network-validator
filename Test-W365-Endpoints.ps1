#Requires -Version 5.1
<#
.SYNOPSIS
  W365 Endpoint Network Validator
    Tests TCP connectivity to all Windows 365, AVD, and Intune endpoints
    and generates an interactive HTML report.
  Includes consolidated client-facing ownership so DNS, firewall,
  proxy, wildcard, and IP range issues roll up to the Infrastructure
  - Network/Firewall Team.

.DESCRIPTION
    Run this script from:
      - The Cloud PC or provisioning VNet (Host Network mode)
      - The user's physical device (Client Network mode)
      - Or both

    The script saves a self-contained HTML report and a JSON sidecar
    to the same folder as the script (or $env:TEMP if run from UNC path).

.NOTES
    Endpoint lists sourced from:
      https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network
      https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint
      https://learn.microsoft.com/en-us/intune/fundamentals/endpoints
      https://endpoints.office.com (Intune MEM - fetched live, supplemented)
      https://learn.microsoft.com/en-us/azure/networking/azure-network-latency
    Attribution:
      This script was inspired by and builds on the original Windows 365 endpoint validation work published by Shannon Fritz from Microsoft.
      Shannon Fritz GitHub profile:
        https://gist.github.com/shannonfritz
      Original PowerShell script:
        https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3
    Last reviewed: 2026-Apr-16
#>

  param(
    [ValidateSet('Host', 'Client', 'Both')]
    [string]$Mode = 'Both',

    [string]$OutputPath,

    [switch]$NoPrompt,

    [switch]$SkipBrowser,

    [ValidateRange(1000, 15000)]
    [int]$TimeoutMs = 4000,

    [ValidateRange(2, 32)]
    [int]$MaxParallel = 12
  )

  $ScriptVersion  = 'current'
$ScriptName     = 'W365 Endpoint Network Validator'

$StaticEndpointReviewDate = [datetime]'2026-04-16'
$EndpointCurrencyThresholdDays = 30
$EndpointDocumentationTargets = @(
  [PSCustomObject]@{ name = 'Windows 365 requirements'; uri = 'https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network' }
  [PSCustomObject]@{ name = 'Azure Virtual Desktop required endpoints'; uri = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint' }
  [PSCustomObject]@{ name = 'Intune network endpoints'; uri = 'https://learn.microsoft.com/en-us/intune/fundamentals/endpoints' }
)
$SecureWebGatewayPattern = 'zscaler|netskope|iboss|skyhigh|blue\s*coat|broadcom|proxysg|symantec|fortinet|palo\s*alto|umbrella|forcepoint|cloudflare\s*gateway|web\s*gateway|secure\s*web\s*gateway'
$AzureBackboneRttReferencePathCandidates = @(
  (Join-Path $PSScriptRoot 'Azure Network RTT Stats - April 2026\azure-rtt-reference-apr2026.json'),
  (Join-Path (Split-Path $PSScriptRoot -Parent) 'W365-Endpoints-Network-Connectivity\Azure Network RTT Stats - April 2026\azure-rtt-reference-apr2026.json')
)
$AzureBackboneRttReferencePath = $AzureBackboneRttReferencePathCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $AzureBackboneRttReferencePath) {
  $AzureBackboneRttReferencePath = $AzureBackboneRttReferencePathCandidates[0]
}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT PATH
# ─────────────────────────────────────────────────────────────────────────────
  $OutputFolder = if ($OutputPath) {
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if (-not (Test-Path $resolvedOutput)) {
      New-Item -Path $resolvedOutput -ItemType Directory -Force | Out-Null
    }
    $resolvedOutput
  } elseif ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
    $PSScriptRoot
  } else {
    $env:TEMP
  }
$Timestamp    = Get-Date -Format 'yyyyMMdd-HHmmss'

# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT ARRAYS
# ─────────────────────────────────────────────────────────────────────────────
function New-EndpointEntry {
  param(
    [string]$Hostname,
    [string]$Ports = '443',
    [string]$Protocol = 'TCP',
    [string]$Description = ''
  )

  [PSCustomObject]@{
    Hostname = $Hostname
    Ports = $Ports
    Protocol = $Protocol
    Description = $Description
  }
}

$endpoints_w365 = @(
    '*.infra.windows365.microsoft.com',
    'login.microsoftonline.com',
    'login.live.com',
    'enterpriseregistration.windows.net',
    'global.azure-devices-provisioning.net:443,5671',
    'hm-iot-in-prod-prap01.azure-devices.net:443,5671',
    'hm-iot-in-prod-prau01.azure-devices.net:443,5671',
    'hm-iot-in-prod-preu01.azure-devices.net:443,5671',
    'hm-iot-in-prod-prna01.azure-devices.net:443,5671',
    'hm-iot-in-prod-prna02.azure-devices.net:443,5671',
    'hm-iot-in-2-prod-preu01.azure-devices.net:443,5671',
    'hm-iot-in-2-prod-prna01.azure-devices.net:443,5671',
    'hm-iot-in-3-prod-preu01.azure-devices.net:443,5671',
    'hm-iot-in-3-prod-prna01.azure-devices.net:443,5671',
    'hm-iot-in-4-prod-prna01.azure-devices.net:443,5671'
)

$clientendpoints_w365 = @(
    'login.microsoftonline.com',
    '*.wvd.microsoft.com',
    '*.servicebus.windows.net',
    'go.microsoft.com',
    'aka.ms',
    'learn.microsoft.com',
    'privacy.microsoft.com',
    '*.cdn.office.net',
    'graph.microsoft.com',
    'windows.cloud.microsoft',
    'windows365.microsoft.com',
    '*.events.data.microsoft.com:80',
    '*.microsoftaik.azure.net',
    'www.microsoft.com:80',
    '*.aikcertaia.microsoft.com:80',
    'azcsprodeusaikpublish.blob.core.windows.net:80',
    'cacerts.digicert.com:80',
    'cacerts.digicert.cn:80',
    'cacerts.geotrust.com:80',
    'caissuers.microsoft.com:80',
    'crl3.digicert.com:80',
    'crl4.digicert.com:80',
    'crl.digicert.cn:80',
    'ocsp.digicert.com:80',
    'ocsp.digicert.cn:80',
    'oneocsp.microsoft.com:80'
)

$endpoints_avd = @(
    'login.microsoftonline.com:443',
    '*.wvd.microsoft.com:443',
    'catalogartifact.azureedge.net:443',
    '*.prod.warm.ingest.monitor.core.windows.net:443',
    'gcs.prod.monitoring.core.windows.net:443',
    'azkms.core.windows.net:1688',
    'mrsglobalsteus2prod.blob.core.windows.net:443',
    'wvdportalstorageblob.blob.core.windows.net:443',
    '169.254.169.254:80',
    '168.63.129.16:80',
    'oneocsp.microsoft.com:80',
    'www.microsoft.com:80',
    '*.aikcertaia.microsoft.com:80',
    'azcsprodeusaikpublish.blob.core.windows.net:80',
    '*.microsoftaik.azure.net:80',
    'ctldl.windowsupdate.com:80',
    'aka.ms:443',
    '*.service.windows.cloud.microsoft:443',
    '*.windows.cloud.microsoft:443',
    '*.windows.static.microsoft:443'
)

  $documentedEndpoints_avd = @(
    (New-EndpointEntry -Hostname '51.5.0.0/16' -Ports '3478' -Protocol 'UDP' -Description 'Relayed RDP connectivity')
    (New-EndpointEntry -Hostname '168.63.129.16' -Ports '32526' -Protocol 'TCP' -Description 'Session Host Health Monitoring')
    (New-EndpointEntry -Hostname 'login.windows.net' -Ports '443' -Protocol 'TCP' -Description 'Sign in to Microsoft Online Services and Microsoft 365')
    (New-EndpointEntry -Hostname 'www.msftconnecttest.com' -Ports '80' -Protocol 'TCP' -Description 'Detects if the session host is connected to the internet')
  )

  $documentedEndpoints_intune = @(
    (New-EndpointEntry -Hostname '*.manage.microsoft.com' -Ports '443' -Protocol 'TCP' -Description 'Intune client and host service')
    (New-EndpointEntry -Hostname 'manage.microsoft.com' -Ports '443' -Protocol 'TCP' -Description 'Intune client and host service')
    (New-EndpointEntry -Hostname '*.dm.microsoft.com' -Ports '443' -Protocol 'TCP' -Description 'Intune client and host service')
    (New-EndpointEntry -Hostname 'EnterpriseEnrollment.manage.microsoft.com' -Ports '443' -Protocol 'TCP' -Description 'Intune client and host service')
    (New-EndpointEntry -Hostname 'graph.windows.net' -Ports '80,443' -Protocol 'TCP' -Description 'Authentication and Identity, includes Microsoft Entra ID and Entra ID related services')
    (New-EndpointEntry -Hostname 'certauth.enterpriseregistration.windows.net' -Ports '80,443' -Protocol 'TCP' -Description 'Identity supporting services and CDNs')
    (New-EndpointEntry -Hostname '*.notify.windows.com' -Ports '443' -Protocol 'TCP' -Description 'Windows Push Notification Services dependency')
    (New-EndpointEntry -Hostname '*.wns.windows.com' -Ports '443' -Protocol 'TCP' -Description 'Windows Push Notification Services dependency')
    (New-EndpointEntry -Hostname 'sinwns1011421.wns.windows.com' -Ports '443' -Protocol 'TCP' -Description 'Windows Push Notification Services dependency')
    (New-EndpointEntry -Hostname 'sin.notify.windows.com' -Ports '443' -Protocol 'TCP' -Description 'Windows Push Notification Services dependency')
    (New-EndpointEntry -Hostname '*.dl.delivery.mp.microsoft.com' -Ports '80,443' -Protocol 'TCP' -Description 'MDM Delivery Optimization metadata')
    (New-EndpointEntry -Hostname '*.do.dsp.mp.microsoft.com' -Ports '80,443' -Protocol 'TCP' -Description 'MDM Delivery Optimization cloud service')
    (New-EndpointEntry -Hostname '*.update.microsoft.com' -Ports '80,443' -Protocol 'TCP' -Description 'Windows Autopilot Windows Update dependency')
    (New-EndpointEntry -Hostname '*.windowsupdate.com' -Ports '80,443' -Protocol 'TCP' -Description 'Windows Autopilot Windows Update dependency')
    (New-EndpointEntry -Hostname 'adl.windows.com' -Ports '80,443' -Protocol 'TCP' -Description 'Windows Autopilot Windows Update dependency')
    (New-EndpointEntry -Hostname 'tsfe.trafficshaping.dsp.mp.microsoft.com' -Ports '80,443' -Protocol 'TCP' -Description 'Windows Autopilot Delivery Optimization dependency')
  )

function Resolve-EndpointDescription {
  param(
    [string]$Hostname,
    [string]$Category,
    [string]$ExistingDescription = ''
  )

  if (-not [string]::IsNullOrWhiteSpace($ExistingDescription)) {
    return $ExistingDescription
  }

  switch ($Category) {
    'W365-Host' {
      switch -Wildcard ($Hostname) {
        '*.infra.windows365.microsoft.com' { return 'Windows 365 service endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        'login.microsoftonline.com' { return 'Registration endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        'login.live.com' { return 'Registration endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        'enterpriseregistration.windows.net' { return 'Registration endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        'global.azure-devices-provisioning.net' { return 'Registration endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        'hm-iot-in-*.azure-devices.net' { return 'Registration endpoint for Cloud PC provisioning and Azure Network Connection health checks' }
        default { return 'Windows 365 service endpoint for provisioning and health checks' }
      }
    }
    'W365-Client' {
      switch -Wildcard ($Hostname) {
        'login.microsoftonline.com' { return 'Authentication to Microsoft Online Services' }
        '*.wvd.microsoft.com' { return 'Service traffic' }
        '*.servicebus.windows.net' { return 'Troubleshooting data' }
        'go.microsoft.com' { return 'Microsoft FWLinks' }
        'aka.ms' { return 'Microsoft URL shortener' }
        'learn.microsoft.com' { return 'Documentation' }
        'privacy.microsoft.com' { return 'Privacy statement' }
        '*.cdn.office.net' { return 'Automatic updates' }
        'graph.microsoft.com' { return 'Service traffic' }
        'windows.cloud.microsoft' { return 'Connection center' }
        'windows365.microsoft.com' { return 'Service traffic' }
        '*.events.data.microsoft.com' { return 'Client telemetry' }
        '*.microsoftaik.azure.net' { return 'Certificates' }
        '*.aikcertaia.microsoft.com' { return 'Certificates' }
        'azcsprodeusaikpublish.blob.core.windows.net' { return 'Certificates' }
        'www.microsoft.com' { return 'Certificates' }
        'oneocsp.microsoft.com' { return 'Certificates' }
        'cacerts.digicert.com' { return 'Certificate chain validation dependency' }
        'cacerts.digicert.cn' { return 'Certificate chain validation dependency' }
        'cacerts.geotrust.com' { return 'Certificate chain validation dependency' }
        'caissuers.microsoft.com' { return 'Certificate chain validation dependency' }
        'crl3.digicert.com' { return 'Certificate revocation list dependency' }
        'crl4.digicert.com' { return 'Certificate revocation list dependency' }
        'crl.digicert.cn' { return 'Certificate revocation list dependency' }
        'ocsp.digicert.com' { return 'Online certificate status protocol dependency' }
        'ocsp.digicert.cn' { return 'Online certificate status protocol dependency' }
        default { return 'Azure Virtual Desktop remote desktop client endpoint required for Cloud PC connectivity' }
      }
    }
    'AVD-Host' {
      switch -Wildcard ($Hostname) {
        'login.microsoftonline.com' { return 'Authentication to Microsoft Online Services' }
        '51.5.0.0/16' { return 'Relayed RDP connectivity' }
        '*.wvd.microsoft.com' { return 'Service traffic including TCP based RDP connectivity' }
        'catalogartifact.azureedge.net' { return 'Azure Marketplace' }
        '*.prod.warm.ingest.monitor.core.windows.net' { return 'Agent traffic diagnostic output' }
        'gcs.prod.monitoring.core.windows.net' { return 'Agent traffic' }
        'azkms.core.windows.net' { return 'Windows activation' }
        'mrsglobalsteus2prod.blob.core.windows.net' { return 'Agent and side-by-side (SXS) stack updates' }
        'wvdportalstorageblob.blob.core.windows.net' { return 'Azure portal support' }
        '169.254.169.254' { return 'Azure Instance Metadata Service (IMDS)' }
        '168.63.129.16' { return 'Session Host Health Monitoring' }
        'login.windows.net' { return 'Sign in to Microsoft Online Services and Microsoft 365' }
        '*.events.data.microsoft.com' { return 'Telemetry Service' }
        'www.msftconnecttest.com' { return 'Detects if the session host is connected to the internet' }
        '*.prod.do.dsp.mp.microsoft.com' { return 'Windows Update' }
        '*.sfx.ms' { return 'Updates for OneDrive client software' }
        '*.azure-dns.com' { return 'Azure DNS resolution' }
        '*.azure-dns.net' { return 'Azure DNS resolution' }
        '*eh.servicebus.windows.net' { return 'Diagnostic settings' }
        'oneocsp.microsoft.com' { return 'Certificates' }
        '*.aikcertaia.microsoft.com' { return 'Certificates' }
        'azcsprodeusaikpublish.blob.core.windows.net' { return 'Certificates' }
        '*.microsoftaik.azure.net' { return 'Certificates' }
        'ctldl.windowsupdate.com' { return 'Certificates' }
        'www.microsoft.com' { return 'Certificates' }
        'aka.ms' { return 'Microsoft URL shortener, used during session host deployment on Azure Local' }
        '*.service.windows.cloud.microsoft' { return 'Service traffic' }
        '*.windows.cloud.microsoft' { return 'Service traffic' }
        '*.windows.static.microsoft' { return 'Service traffic' }
        default { return 'Azure Virtual Desktop session host endpoint' }
      }
    }
    'Intune-MEM' {
      switch -Wildcard ($Hostname) {
        '*.manage.microsoft.com' { return 'Intune client and host service' }
        'manage.microsoft.com' { return 'Intune client and host service' }
        '*.dm.microsoft.com' { return 'Intune client and host service' }
        'EnterpriseEnrollment.manage.microsoft.com' { return 'Intune client and host service' }
        'login.microsoftonline.com' { return 'Authentication and Identity, includes Microsoft Entra ID and Entra ID related services' }
        'graph.windows.net' { return 'Authentication and Identity, includes Microsoft Entra ID and Entra ID related services' }
        'enterpriseregistration.windows.net' { return 'Identity supporting services and CDNs' }
        'certauth.enterpriseregistration.windows.net' { return 'Identity supporting services and CDNs' }
        '*.events.data.microsoft.com' { return 'Used by managed devices to send required functional data to the Intune data collection endpoint' }
        '*.notify.windows.com' { return 'Windows Push Notification Services dependency' }
        '*.wns.windows.com' { return 'Windows Push Notification Services dependency' }
        'sinwns1011421.wns.windows.com' { return 'Windows Push Notification Services dependency' }
        'sin.notify.windows.com' { return 'Windows Push Notification Services dependency' }
        '*.do.dsp.mp.microsoft.com' { return 'Delivery Optimization cloud service' }
        '*.dl.delivery.mp.microsoft.com' { return 'Delivery Optimization metadata' }
        '*.update.microsoft.com' { return 'Windows Autopilot Windows Update dependency' }
        '*.windowsupdate.com' { return 'Windows Autopilot Windows Update dependency' }
        'adl.windows.com' { return 'Windows Autopilot Windows Update dependency' }
        'tsfe.trafficshaping.dsp.mp.microsoft.com' { return 'Windows Autopilot Delivery Optimization dependency' }
        'time.windows.com' { return 'Windows Autopilot NTP sync' }
        'clientconfig.passport.net' { return 'Windows Autopilot WNS dependency' }
        'windowsphone.com' { return 'Windows Autopilot WNS dependency' }
        '*.s-microsoft.com' { return 'Windows Autopilot WNS dependency' }
        'c.s-microsoft.com' { return 'Windows Autopilot WNS dependency' }
        'ekop.intel.com' { return 'Windows Autopilot third-party deployment dependency' }
        'ekcert.spserv.microsoft.com' { return 'Windows Autopilot third-party deployment dependency' }
        'ftpm.amd.com' { return 'Windows Autopilot third-party deployment dependency' }
        'lgmsapeweu.blob.core.windows.net' { return 'Windows Autopilot diagnostics upload' }
        'lgmsapewus2.blob.core.windows.net' { return 'Windows Autopilot diagnostics upload' }
        'lgmsapesea.blob.core.windows.net' { return 'Windows Autopilot diagnostics upload' }
        'lgmsapeaus.blob.core.windows.net' { return 'Windows Autopilot diagnostics upload' }
        'lgmsapeind.blob.core.windows.net' { return 'Windows Autopilot diagnostics upload' }
        '*.support.services.microsoft.com' { return 'Remote Help feature dependency' }
        'remoteassistance.support.services.microsoft.com' { return 'Remote Help feature dependency' }
        'teams.microsoft.com' { return 'Remote Help feature dependency' }
        'edge.skype.com' { return 'Remote Help feature dependency' }
        '*.trouter.communication.microsoft.com' { return 'Remote Help feature dependency' }
        '*.trouter.communications.svc.cloud.microsoft' { return 'Remote Help feature dependency' }
        '*.trouter.teams.microsoft.com' { return 'Remote Help feature dependency' }
        'go-amer.trouter.communications.svc.cloud.microsoft' { return 'Remote Help feature dependency for NA and ROW customers' }
        'go-apac.trouter.communications.svc.cloud.microsoft' { return 'Remote Help feature dependency for APAC customers' }
        'go-eu.trouter.communications.svc.cloud.microsoft' { return 'Remote Help feature dependency for EU customers' }
        '*.webpubsub.azure.com' { return 'Remote Help web pubsub dependency' }
        '*.monitor.azure.com' { return 'Remote Help diagnostics and monitoring dependency' }
        'js.monitor.azure.com' { return 'Remote Help diagnostics and monitoring dependency' }
        'browser.pipe.aria.microsoft.com' { return 'Remote Help diagnostics and monitoring dependency' }
        'fd.api.orgmsg.microsoft.com' { return 'Organizational messages' }
        'ris.prod.api.personalization.ideas.microsoft.com' { return 'Organizational messages' }
        'displaycatalog.mp.microsoft.com' { return 'Microsoft Store API' }
        'purchase.md.mp.microsoft.com' { return 'Microsoft Store API' }
        'licensing.mp.microsoft.com' { return 'Microsoft Store API' }
        'storeedgefd.dsx.mp.microsoft.com' { return 'Microsoft Store API' }
        'cdn.storeedgefd.dsx.mp.microsoft.com' { return 'Microsoft-hosted Win32 app fallback cache' }
        '*.powershellgallery.com' { return 'PowerShell package source dependency' }
        'cdn.oneget.org' { return 'Package source dependency' }
        'go.microsoft.com' { return 'Endpoint discovery' }
        'login.live.com' { return 'Consumer Outlook.com, OneDrive, Device authentication, and Microsoft account' }
        'config.edge.skype.com' { return 'Feature deployment dependency' }
        'ecs.office.com' { return 'Feature deployment dependency' }
        '*.officeconfig.msocdn.com' { return 'Office Customization Service provides Office deployment configuration and cloud policy management' }
        'config.office.com' { return 'Office Customization Service provides Office deployment configuration and cloud policy management' }
        'intunecdnpeasd.azureedge.net' { return 'Android AOSP dependency' }
        'intunecdnpeasd.manage.microsoft.com' { return 'Android AOSP dependency' }
        'macsidecar.manage.microsoft.com' { return 'macOS app and script deployment dependency' }
        'macsidecarprod.azureedge.net' { return 'macOS app and script deployment dependency' }
        'naprodimedatapri.azureedge.net' { return 'North America Win32 apps and PowerShell scripts content delivery' }
        'naprodimedatasec.azureedge.net' { return 'North America Win32 apps and PowerShell scripts content delivery' }
        'naprodimedatahotfix.azureedge.net' { return 'North America Win32 apps and PowerShell scripts content delivery' }
        'imeswda-afd-primary.manage.microsoft.com' { return 'North America Win32 apps and PowerShell scripts service endpoint' }
        'imeswda-afd-secondary.manage.microsoft.com' { return 'North America Win32 apps and PowerShell scripts service endpoint' }
        'imeswda-afd-hotfix.manage.microsoft.com' { return 'North America Win32 apps and PowerShell scripts service endpoint' }
        'intunemaape*.attest.azure.net' { return 'Microsoft Azure Attestation endpoint for Windows 11 device health compliance' }
        default { return 'Microsoft Intune endpoint from the live MEM endpoint feed' }
      }
    }
  }

  return 'Endpoint description unavailable'
}

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   $ScriptName $ScriptVersion" -ForegroundColor Cyan
Write-Host "║   Windows 365 · AVD · Intune Endpoint Connectivity Test  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "NOTE: You must have write permission to the output folder to save the HTML, JSON, and retry script outputs." -ForegroundColor Yellow
Write-Host "Output folder: $OutputFolder" -ForegroundColor DarkYellow
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# MODE SELECTION
# ─────────────────────────────────────────────────────────────────────────────
function Resolve-TestMode {
  param(
    [string]$DefaultMode,
    [switch]$Silent
  )

  if ($Silent) {
    return $DefaultMode
  }

  Write-Host "Select the test mode:" -ForegroundColor Yellow
  Write-Host "  1 - Host Network   (from the Cloud PC / provisioning VNet)"
  Write-Host "  2 - Client Network (from the user's physical device)"
  Write-Host "  3 - Both           (default)"
  Write-Host ""

  $defaultChoice = @{ Host = '1'; Client = '2'; Both = '3' }[$DefaultMode]
  $userChoice = Read-Host "Enter choice [default: $defaultChoice]"
  if ([string]::IsNullOrWhiteSpace($userChoice)) {
    return $DefaultMode
  }

  switch ($userChoice.Trim()) {
    '1' { 'Host' }
    '2' { 'Client' }
    '3' { 'Both' }
    default { $DefaultMode }
  }
}

function Get-WinHttpProxySummary {
  try {
    $raw = (& netsh winhttp show proxy 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
      return 'Unavailable'
    }
    if ($raw -match 'Direct access \(no proxy server\)') {
      return 'Direct'
    }

    $lines = $raw -split "`r?`n" |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ }

    $summaryLines = @(
      $lines | Where-Object { $_ -match '^Proxy Server' }
      $lines | Where-Object { $_ -match '^Bypass List' }
    ) | Where-Object { $_ }

    if ($summaryLines) {
      return ($summaryLines -join ' | ')
    }

    return $raw
  } catch {
    return 'Unavailable'
  }
}

function Get-NetworkContext {
  $context = [ordered]@{
    interfaceAlias       = ''
    interfaceDescription = ''
    ipv4Address          = ''
    defaultGateway       = ''
    dnsServers           = @()
    dnsSuffix            = ''
    winHttpProxy         = Get-WinHttpProxySummary
    winInetProxyEnabled  = 'Unknown'
    winInetProxyServer   = ''
    winInetAutoConfigUrl = ''
    winInetAutoDetect    = 'Unknown'
    httpsProxy           = $env:HTTPS_PROXY
    httpProxy            = $env:HTTP_PROXY
    noProxy              = $env:NO_PROXY
  }

  try {
    $internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    $context.winInetProxyEnabled = if ($internetSettings.ProxyEnable -eq 1) { 'Enabled' } else { 'Disabled' }
    $context.winInetProxyServer = $internetSettings.ProxyServer
    $context.winInetAutoConfigUrl = $internetSettings.AutoConfigURL
    $context.winInetAutoDetect = if ($internetSettings.AutoDetect -eq 1) { 'Enabled' } else { 'Disabled' }
  } catch {
    # Keep defaults if WinINet settings are unavailable.
  }

  try {
    $config = Get-NetIPConfiguration |
      Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } |
      Sort-Object @{ Expression = { if ($_.IPv4DefaultGateway) { 0 } else { 1 } } }, InterfaceMetric |
      Select-Object -First 1

    if ($config) {
      $context.interfaceAlias = $config.InterfaceAlias
      $context.interfaceDescription = $config.NetAdapter.InterfaceDescription
      $context.ipv4Address = ($config.IPv4Address | Select-Object -ExpandProperty IPAddress -First 1)
      $context.defaultGateway = ($config.IPv4DefaultGateway | Select-Object -ExpandProperty NextHop -First 1)
      $context.dnsServers = @($config.DNSServer.ServerAddresses | Where-Object { $_ })
      $context.dnsSuffix = $config.NetProfile.Name
    }
  } catch {
    # Leave defaults if the NetTCPIP cmdlets are unavailable.
  }

  return $context
}

function Get-OperatingSystemContext {
  $context = [ordered]@{
    name    = ''
    version = ''
    build   = ''
    summary = ''
  }

  function Resolve-NormalizedWindowsName {
    param(
      [string]$ProductName,
      [string]$Build
    )

    if ([string]::IsNullOrWhiteSpace($ProductName)) {
      return $ProductName
    }

    $normalized = $ProductName
    $majorBuild = 0
    if ($Build) {
      $majorBuild = [int](($Build -split '\.')[0])
    }

    if ($majorBuild -ge 22000 -and $normalized -match '^Windows 10\b') {
      $normalized = $normalized -replace '^Windows 10', 'Windows 11'
    }

    return $normalized
  }

  try {
    $nt = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $productName = [string]$nt.ProductName
    $displayVersion = [string]$nt.DisplayVersion
    if ([string]::IsNullOrWhiteSpace($displayVersion)) {
      $displayVersion = [string]$nt.ReleaseId
    }

    $build = [string]$nt.CurrentBuild
    if ($nt.PSObject.Properties.Name -contains 'UBR' -and $null -ne $nt.UBR -and $build) {
      $build = "$build.$($nt.UBR)"
    }

    $productName = Resolve-NormalizedWindowsName -ProductName $productName -Build $build

    $context.name = $productName
    $context.version = $displayVersion
    $context.build = $build
    $context.summary = (@($productName, $displayVersion) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
  } catch {
    # Fall back to CIM if registry values are unavailable.
  }

  if ([string]::IsNullOrWhiteSpace($context.name) -or [string]::IsNullOrWhiteSpace($context.build)) {
    try {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
      if ([string]::IsNullOrWhiteSpace($context.name)) { $context.name = [string]$os.Caption }
      if ([string]::IsNullOrWhiteSpace($context.version)) { $context.version = [string]$os.Version }
      if ([string]::IsNullOrWhiteSpace($context.build)) { $context.build = [string]$os.BuildNumber }
    } catch {
      # Keep defaults if CIM is unavailable.
    }
  }

  $context.name = Resolve-NormalizedWindowsName -ProductName $context.name -Build $context.build

  if ([string]::IsNullOrWhiteSpace($context.summary)) {
    $context.summary = (@($context.name, $context.version) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
  }

  return $context
}

function Test-LikelySecureWebGateway {
  param(
    [string[]]$Texts
  )

  $joined = (@($Texts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' | ')
  if ([string]::IsNullOrWhiteSpace($joined)) {
    return $false
  }

  return $joined -match $SecureWebGatewayPattern
}

function Get-CertificateDnsNames {
  param(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  $names = New-Object System.Collections.Generic.List[string]
  if (-not $Certificate) {
    return @()
  }

  try {
    $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($sanExtension) {
      $formatted = (New-Object System.Security.Cryptography.AsnEncodedData($sanExtension.Oid, $sanExtension.RawData)).Format($true)
      foreach ($match in [regex]::Matches($formatted, 'DNS Name=(?<dns>[^,\r\n]+)')) {
        $dnsName = $match.Groups['dns'].Value.Trim()
        if ($dnsName) {
          $null = $names.Add($dnsName)
        }
      }
    }
  } catch {
    # Keep best-effort parsing only.
  }

  if ($names.Count -eq 0 -and $Certificate.Subject -match 'CN\s*=\s*(?<cn>[^,]+)') {
    $null = $names.Add($matches['cn'].Trim())
  }

  return @($names | Select-Object -Unique)
}

function Test-CertificateNameMatch {
  param(
    [string]$Hostname,
    [string[]]$Names
  )

  if ([string]::IsNullOrWhiteSpace($Hostname) -or -not $Names -or -not $Names.Count) {
    return $false
  }

  $target = $Hostname.Trim().ToLowerInvariant()
  foreach ($name in $Names) {
    if ([string]::IsNullOrWhiteSpace($name)) {
      continue
    }

    $candidate = $name.Trim().ToLowerInvariant()
    if ($candidate -eq $target) {
      return $true
    }

    if ($candidate.StartsWith('*.')) {
      $suffix = $candidate.Substring(1)
      if ($target.EndsWith($suffix)) {
        return $true
      }
    }
  }

  return $false
}

function Test-RebootPending {
  $signals = New-Object System.Collections.Generic.List[string]

  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $null = $signals.Add('CBS RebootPending')
  }
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $null = $signals.Add('Windows Update RebootRequired')
  }

  try {
    $sessionManager = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
    if ($sessionManager.PendingFileRenameOperations) {
      $null = $signals.Add('PendingFileRenameOperations')
    }
  } catch {
    # Ignore missing session manager values.
  }

  return [PSCustomObject]@{
    isPending = $signals.Count -gt 0
    detail    = if ($signals.Count) { $signals -join ' | ' } else { 'No reboot-pending markers found.' }
  }
}

function Get-ProxyDiagnostics {
  param(
    [int]$TimeoutSec = 8
  )

  $diagnostics = [ordered]@{
    status                    = 'Unknown'
    testUrl                   = 'https://login.microsoftonline.com'
    proxyConfigured           = 'No'
    proxyUri                  = ''
    proxyAuthRequired         = 'Unknown'
    proxyAuthenticate         = ''
    secureWebGatewaySuspected = 'No'
    detail                    = ''
  }

  try {
    $targetUri = [uri]$diagnostics.testUrl
    $systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    if ($systemProxy) {
      $resolvedProxy = $systemProxy.GetProxy($targetUri)
      if ($resolvedProxy -and $resolvedProxy.AbsoluteUri -ne $targetUri.AbsoluteUri) {
        $diagnostics.proxyConfigured = 'Yes'
        $diagnostics.proxyUri = $resolvedProxy.AbsoluteUri
        $diagnostics.status = 'ProxyConfigured'
      } else {
        $diagnostics.status = 'Direct'
      }

      $request = [System.Net.HttpWebRequest]::Create($targetUri)
      $request.Method = 'HEAD'
      $request.Timeout = $TimeoutSec * 1000
      $request.ReadWriteTimeout = $TimeoutSec * 1000
      $request.AllowAutoRedirect = $false
      $request.Proxy = $systemProxy
      $request.UserAgent = 'W365EndpointValidator/5.0'
      if ($request.Proxy) {
        try { $request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials } catch {}
      }

      try {
        $response = [System.Net.HttpWebResponse]$request.GetResponse()
        $diagnostics.detail = "HTTP $([int]$response.StatusCode) $($response.StatusDescription)"
        if ($diagnostics.proxyConfigured -eq 'Yes') {
          $diagnostics.proxyAuthRequired = 'No'
        }
        $response.Close()
      } catch [System.Net.WebException] {
        $webResponse = $_.Exception.Response
        if ($webResponse) {
          $statusCode = [int]$webResponse.StatusCode
          $diagnostics.detail = "HTTP $statusCode $($webResponse.StatusDescription)"
          $diagnostics.proxyAuthenticate = [string]$webResponse.Headers['Proxy-Authenticate']
          if ($statusCode -eq 407 -or $diagnostics.proxyAuthenticate) {
            $diagnostics.proxyAuthRequired = 'Yes'
          } elseif ($diagnostics.proxyConfigured -eq 'Yes') {
            $diagnostics.proxyAuthRequired = 'No'
          }
          $webResponse.Close()
        } else {
          $diagnostics.detail = $_.Exception.Message
          if ($_.Exception.Message -match '407|proxy') {
            $diagnostics.proxyAuthRequired = 'Yes'
          }
        }
      }
    }
  } catch {
    $diagnostics.status = 'Unavailable'
    $diagnostics.detail = $_.Exception.Message
  }

  if (Test-LikelySecureWebGateway @($diagnostics.proxyUri, $diagnostics.proxyAuthenticate, $diagnostics.detail)) {
    $diagnostics.secureWebGatewaySuspected = 'Yes'
  }

  return $diagnostics
}

function Get-PublicEgressContext {
  param(
    [hashtable]$ProxyDiagnostics,
    [int]$TimeoutSec = 8
  )

  $context = [ordered]@{
    status                    = 'Unavailable'
    route                     = if ($ProxyDiagnostics.proxyConfigured -eq 'Yes') { 'Proxy' } else { 'Direct' }
    ip                        = ''
    asn                       = ''
    organization              = ''
    city                      = ''
    region                    = ''
    country                   = ''
    location                  = ''
    timezone                  = ''
    secureWebGatewaySuspected = if ($ProxyDiagnostics.secureWebGatewaySuspected -eq 'Yes') { 'Yes' } else { 'No' }
    detail                    = ''
  }

  $providers = @(
    'https://ipinfo.io/json',
    'https://ipapi.co/json/'
  )

  foreach ($provider in $providers) {
    try {
      $response = Invoke-RestMethod -Uri $provider -Method Get -TimeoutSec $TimeoutSec -Headers @{ 'User-Agent' = 'W365EndpointValidator/5.0' } -ErrorAction Stop
      if ($response.ip) {
        $context.status = 'Pass'
        $context.ip = [string]$response.ip
        $context.organization = [string]$(if ($response.org) { $response.org } elseif ($response.org_name) { $response.org_name } else { '' })
        if ($context.organization -match '^(?<asn>AS\d+)\s+(?<org>.+)$') {
          $context.asn = $matches['asn']
          $context.organization = $matches['org']
        }
        $context.city = [string]$response.city
        $context.region = [string]$response.region
        $context.country = [string]$(if ($response.country_name) { $response.country_name } elseif ($response.country) { $response.country } else { '' })
        $context.location = [string]$(if ($response.loc) { $response.loc } elseif ($response.latitude -and $response.longitude) { "$($response.latitude),$($response.longitude)" } else { '' })
        $context.timezone = [string]$response.timezone
        break
      }
    } catch {
      $context.detail = $_.Exception.Message
    }
  }

  if (Test-LikelySecureWebGateway @($context.organization, $ProxyDiagnostics.proxyUri, $ProxyDiagnostics.proxyAuthenticate)) {
    $context.secureWebGatewaySuspected = 'Yes'
  }

  if ($context.status -eq 'Pass' -and [string]::IsNullOrWhiteSpace($context.detail)) {
    $context.detail = if ($context.organization) { "Public egress resolved via $($context.organization)." } else { 'Public egress identity resolved.' }
  }

  return $context
}

function Get-EnvironmentFingerprint {
  param(
    [hashtable]$NetworkContext,
    [hashtable]$ProxyDiagnostics,
    [hashtable]$PublicEgressContext
  )

  $fingerprint = [ordered]@{
    interfaceType          = ''
    connectedSsid          = ''
    vpnDetected            = 'No'
    vpnAdapters            = @()
    domainJoined           = 'Unknown'
    entraJoined            = 'Unknown'
    deviceId               = ''
    secureWebGateway       = 'No'
    secureWebGatewayHint   = ''
    rebootPending          = 'No'
    rebootPendingDetail    = ''
  }

  try {
    $adapter = Get-NetAdapter -Name $NetworkContext.interfaceAlias -ErrorAction Stop | Select-Object -First 1
    $fingerprint.interfaceType = @($adapter.NdisPhysicalMedium, $adapter.PhysicalMediaType, $adapter.MediaType | Where-Object { $_ })[0]
  } catch {
    # Leave blank if adapter details are unavailable.
  }

  if (($NetworkContext.interfaceAlias -match 'wi-?fi|wireless') -or ($NetworkContext.interfaceDescription -match 'wi-?fi|wireless')) {
    try {
      $wlan = (& netsh wlan show interfaces 2>$null | Out-String)
      foreach ($line in $wlan -split "`r?`n") {
        if ($line -match '^\s*SSID\s*:\s*(.+)$' -and $line -notmatch 'BSSID') {
          $fingerprint.connectedSsid = $matches[1].Trim()
          break
        }
      }
    } catch {
      # Ignore SSID detection failures.
    }
  }

  try {
    $vpnAdapters = Get-NetAdapter | Where-Object {
      $_.Status -eq 'Up' -and (($_.Name + ' ' + $_.InterfaceDescription) -match 'vpn|anyconnect|globalprotect|wireguard|tailscale|forti|pulse\s*secure|juniper|tap|tun|zscaler')
    }
    if ($vpnAdapters) {
      $fingerprint.vpnDetected = 'Yes'
      $fingerprint.vpnAdapters = @($vpnAdapters | ForEach-Object { $_.Name })
    }
  } catch {
    # Ignore VPN heuristics if adapter enumeration fails.
  }

  try {
    $dsreg = (& dsregcmd /status 2>$null | Out-String)
    if ($dsreg) {
      if ($dsreg -match 'AzureAdJoined\s*:\s*(YES|NO)') { $fingerprint.entraJoined = $matches[1] }
      if ($dsreg -match 'DomainJoined\s*:\s*(YES|NO)') { $fingerprint.domainJoined = $matches[1] }
      if ($dsreg -match 'DeviceId\s*:\s*(.+)') { $fingerprint.deviceId = $matches[1].Trim() }
    }
  } catch {
    # Ignore dsregcmd failures.
  }

  $rebootState = Test-RebootPending
  $fingerprint.rebootPending = if ($rebootState.isPending) { 'Yes' } else { 'No' }
  $fingerprint.rebootPendingDetail = $rebootState.detail

  if ((Test-LikelySecureWebGateway @($ProxyDiagnostics.proxyUri, $PublicEgressContext.organization)) -or $ProxyDiagnostics.secureWebGatewaySuspected -eq 'Yes' -or $PublicEgressContext.secureWebGatewaySuspected -eq 'Yes') {
    $fingerprint.secureWebGateway = 'Yes'
  }

  $fingerprint.secureWebGatewayHint = (@($ProxyDiagnostics.proxyUri, $PublicEgressContext.organization) | Where-Object { $_ }) -join ' | '
  return $fingerprint
}

function Get-TimeSyncContext {
  param(
    [int]$TimeoutSec = 8
  )

  $context = [ordered]@{
    status         = 'Unknown'
    serviceStatus  = 'Unknown'
    source         = ''
    lastSync       = ''
    clockOffsetMs  = ''
    detail         = ''
  }

  try {
    $service = Get-Service -Name W32Time -ErrorAction Stop
    $context.serviceStatus = [string]$service.Status
  } catch {
    $context.detail = $_.Exception.Message
  }

  try {
    $rawStatus = (& w32tm /query /status 2>$null | Out-String)
    foreach ($line in $rawStatus -split "`r?`n") {
      if ($line -match '^\s*Source\s*:\s*(.+)$') { $context.source = $matches[1].Trim() }
      if ($line -match '^\s*Last Successful Sync Time\s*:\s*(.+)$') { $context.lastSync = $matches[1].Trim() }
    }
  } catch {
    if (-not $context.detail) { $context.detail = $_.Exception.Message }
  }

  try {
    $response = Invoke-WebRequest -Uri 'https://www.microsoft.com' -Method Head -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
    $dateHeader = [string]$response.Headers['Date']
    if ($dateHeader) {
      $remoteTime = [DateTimeOffset]::Parse($dateHeader).ToUniversalTime()
      $localTime = [DateTimeOffset]::UtcNow
      $offsetMs = [math]::Round(($localTime - $remoteTime).TotalMilliseconds, 0)
      $context.clockOffsetMs = [int]$offsetMs
    }
  } catch {
    if (-not $context.detail) { $context.detail = $_.Exception.Message }
  }

  $absoluteOffset = if ($context.clockOffsetMs -ne '') { [math]::Abs([double]$context.clockOffsetMs) } else { [double]::NaN }
  if ($context.serviceStatus -eq 'Running' -and -not [double]::IsNaN($absoluteOffset)) {
    if ($absoluteOffset -le 300000) {
      $context.status = 'Pass'
    } elseif ($absoluteOffset -le 900000) {
      $context.status = 'Warn'
    } else {
      $context.status = 'Fail'
    }
  } elseif ($context.serviceStatus -eq 'Running') {
    $context.status = 'Warn'
  } else {
    $context.status = 'Fail'
  }

  if ([string]::IsNullOrWhiteSpace($context.detail)) {
    $context.detail = if ($context.clockOffsetMs -ne '') { "Approximate UTC drift: $($context.clockOffsetMs) ms." } else { 'Unable to calculate clock drift from HTTPS Date header.' }
  }

  return $context
}

function Get-StunMappedAddress {
  param(
    [byte[]]$ResponseBytes
  )

  if (-not $ResponseBytes -or $ResponseBytes.Length -lt 20) {
    return ''
  }

  $magicCookie = [byte[]](0x21,0x12,0xA4,0x42)
  $offset = 20
  while ($offset + 4 -le $ResponseBytes.Length) {
    $attrType = [System.BitConverter]::ToUInt16([byte[]]@($ResponseBytes[$offset + 1], $ResponseBytes[$offset]), 0)
    $attrLength = [System.BitConverter]::ToUInt16([byte[]]@($ResponseBytes[$offset + 3], $ResponseBytes[$offset + 2]), 0)
    $valueOffset = $offset + 4
    if ($valueOffset + $attrLength -gt $ResponseBytes.Length) {
      break
    }

    if ($attrType -eq 0x0020 -and $attrLength -ge 8) {
      $family = $ResponseBytes[$valueOffset + 1]
      if ($family -eq 0x01) {
        $portBytes = [byte[]]@($ResponseBytes[$valueOffset + 2], $ResponseBytes[$valueOffset + 3])
        $port = [System.BitConverter]::ToUInt16([byte[]]@($portBytes[1], $portBytes[0]), 0) -bxor 0x2112
        $ipBytes = @(
          $ResponseBytes[$valueOffset + 4] -bxor $magicCookie[0],
          $ResponseBytes[$valueOffset + 5] -bxor $magicCookie[1],
          $ResponseBytes[$valueOffset + 6] -bxor $magicCookie[2],
          $ResponseBytes[$valueOffset + 7] -bxor $magicCookie[3]
        )
        return (([System.Net.IPAddress]::new($ipBytes)).IPAddressToString + ":$port")
      }
    }

    $offset = $valueOffset + $attrLength
    if ($attrLength % 4 -ne 0) {
      $offset += 4 - ($attrLength % 4)
    }
  }

  return ''
}

function Invoke-StunBindingTest {
  param(
    [string]$TargetHost,
    [int]$Port,
    [int]$TimeoutMs
  )

  $result = [ordered]@{
    host            = $TargetHost
    port            = $Port
    status          = 'Fail'
    roundTripMs     = -1
    mappedAddress   = ''
    detail          = ''
  }

  $udpClient = $null
  try {
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.Client.ReceiveTimeout = $TimeoutMs
    $udpClient.Client.SendTimeout = $TimeoutMs
    $targetAddress = ([System.Net.Dns]::GetHostAddresses($TargetHost) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1)
    if (-not $targetAddress) {
      throw [System.Exception]::new('No IPv4 address returned for STUN target.')
    }

    $transactionId = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($transactionId)
    $requestBytes = New-Object byte[] 20
    $requestBytes[0] = 0x00
    $requestBytes[1] = 0x01
    $requestBytes[4] = 0x21
    $requestBytes[5] = 0x12
    $requestBytes[6] = 0xA4
    $requestBytes[7] = 0x42
    [Array]::Copy($transactionId, 0, $requestBytes, 8, 12)

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $remoteEndpoint = New-Object System.Net.IPEndPoint($targetAddress, $Port)
    [void]$udpClient.Send($requestBytes, $requestBytes.Length, $remoteEndpoint)
    $responseEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $responseBytes = $udpClient.Receive([ref]$responseEndpoint)
    $watch.Stop()

    if ($responseBytes -and $responseBytes.Length -ge 20) {
      $result.status = 'Pass'
      $result.roundTripMs = [int]$watch.ElapsedMilliseconds
      $result.mappedAddress = Get-StunMappedAddress -ResponseBytes $responseBytes
      $result.detail = if ($result.mappedAddress) { "STUN binding response received from $($responseEndpoint.Address)." } else { 'STUN response received.' }
    }
  } catch {
    $result.detail = $_.Exception.Message
  } finally {
    if ($udpClient) {
      try { $udpClient.Close() } catch {}
    }
  }

  return $result
}

function Get-UdpShortpathReadiness {
  param(
    [int]$TimeoutMs
  )

  $stun = Invoke-StunBindingTest -TargetHost 'stun.l.google.com' -Port 19302 -TimeoutMs $TimeoutMs
  return [ordered]@{
    generalUdpStatus      = $stun.status
    generalUdpRttMs       = $stun.roundTripMs
    natPublicEndpoint     = $stun.mappedAddress
    shortpathStatus       = if ($stun.status -eq 'Pass') { 'Likely Ready' } else { 'At Risk' }
    shortpathPort         = 3478
    shortpathRequirement  = 'Outbound UDP 3478 to Microsoft TURN relay ranges for AVD and Windows 365 Shortpath.'
    detail                = if ($stun.status -eq 'Pass') { 'Generic outbound UDP and return traffic succeeded. This is a heuristic, not a direct Microsoft TURN validation.' } else { "Generic UDP binding test failed: $($stun.detail)" }
  }
}

function Get-TlsCertificateProbe {
  param(
    [string]$Hostname,
    [int]$Port = 443,
    [int]$TimeoutMs = 4000
  )

  $probe = [ordered]@{
    hostname                = $Hostname
    port                    = $Port
    status                  = 'Unavailable'
    tlsProtocol             = ''
    certificateSubject      = ''
    certificateIssuer       = ''
    certificateThumbprint   = ''
    certificateNames        = @()
    sanMatch                = 'Unknown'
    chainStatus             = ''
    sslInspectionSuspected  = 'No'
    detail                  = ''
    responseTimeMs          = -1
  }

  $client = $null
  $netStream = $null
  $sslStream = $null
  $capturedCert = $null
  $capturedPolicyErrors = [System.Net.Security.SslPolicyErrors]::None
  $capturedChainStatuses = @()

  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $async = $client.BeginConnect($Hostname, $Port, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      throw [System.TimeoutException]::new("TLS connect timeout after ${TimeoutMs}ms")
    }

    $client.EndConnect($async)
    $watch.Stop()
    $probe.responseTimeMs = [int]$watch.ElapsedMilliseconds

    $netStream = $client.GetStream()
    $sslStream = New-Object System.Net.Security.SslStream($netStream, $false, ([System.Net.Security.RemoteCertificateValidationCallback]{
      param($sender, $certificate, $chain, $sslPolicyErrors)
      if ($certificate) {
        try { $capturedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate } catch {}
      }
      $capturedPolicyErrors = $sslPolicyErrors
      $capturedChainStatuses = if ($chain) { @($chain.ChainStatus | Where-Object { $_.Status -ne 'NoError' } | ForEach-Object { [string]$_.Status }) } else { @() }
      return $true
    }))
    $sslStream.ReadTimeout = $TimeoutMs
    $sslStream.WriteTimeout = $TimeoutMs
    $sslStream.AuthenticateAsClient($Hostname)

    $probe.tlsProtocol = [string]$sslStream.SslProtocol
    if (-not $capturedCert -and $sslStream.RemoteCertificate) {
      try { $capturedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate } catch {}
    }
    if ($capturedCert) {
      $probe.certificateSubject = $capturedCert.Subject
      $probe.certificateIssuer = $capturedCert.Issuer
      $probe.certificateThumbprint = $capturedCert.Thumbprint
      $probe.certificateNames = @(Get-CertificateDnsNames -Certificate $capturedCert)
      $probe.sanMatch = if (Test-CertificateNameMatch -Hostname $Hostname -Names $probe.certificateNames) { 'Yes' } else { 'No' }
      $probe.sslInspectionSuspected = if (Test-LikelySecureWebGateway @($probe.certificateSubject, $probe.certificateIssuer)) { 'Yes' } else { 'No' }
    }

    $probe.chainStatus = if ($capturedChainStatuses.Count) { $capturedChainStatuses -join ', ' } else { 'Trusted' }
    if ($capturedPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None -and $probe.sanMatch -ne 'No' -and $probe.chainStatus -eq 'Trusted') {
      $probe.status = 'Pass'
      $probe.detail = 'TLS certificate presented and chain built successfully.'
    } else {
      $probe.status = 'Issue'
      $detailParts = @("Policy: $capturedPolicyErrors", "Chain: $($probe.chainStatus)")
      if ($probe.certificateIssuer) { $detailParts += "Issuer: $($probe.certificateIssuer)" }
      $probe.detail = $detailParts -join ' | '
    }
  } catch {
    $probe.status = 'Fail'
    $probe.detail = $_.Exception.Message
  } finally {
    if ($sslStream) { try { $sslStream.Dispose() } catch {} }
    if ($netStream) { try { $netStream.Dispose() } catch {} }
    if ($client) { try { $client.Close() } catch {} }
  }

  return [PSCustomObject]$probe
}

function Invoke-CertificateReadinessChecks {
  param(
    [int]$TimeoutMs
  )

  $targets = @(
    'login.microsoftonline.com',
    'graph.microsoft.com',
    'windows365.microsoft.com'
  )

  return @($targets | ForEach-Object { Get-TlsCertificateProbe -Hostname $_ -Port 443 -TimeoutMs $TimeoutMs })
}

function Get-EndpointCurrencyStatus {
  param(
    [datetime]$ReviewedOn,
    [int]$StaleAfterDays
  )

  $daysSinceReview = [int](New-TimeSpan -Start $ReviewedOn -End (Get-Date)).TotalDays
  $documents = @()
  foreach ($target in $EndpointDocumentationTargets) {
    $document = [ordered]@{
      name         = $target.name
      uri          = $target.uri
      reachable    = 'No'
      lastModified = ''
      etag         = ''
      detail       = ''
    }

    try {
      $response = Invoke-WebRequest -Uri $target.uri -Method Head -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
      $document.reachable = 'Yes'
      $document.lastModified = [string]$response.Headers['Last-Modified']
      $document.etag = [string]$response.Headers['ETag']
    } catch {
      $document.detail = $_.Exception.Message
    }

    $documents += [PSCustomObject]$document
  }

  return [ordered]@{
    status           = if ($daysSinceReview -gt $StaleAfterDays) { 'Warn' } else { 'Pass' }
    reviewedOn       = $ReviewedOn.ToString('yyyy-MM-dd')
    daysSinceReview  = $daysSinceReview
    staleAfterDays   = $StaleAfterDays
    detail           = if ($daysSinceReview -gt $StaleAfterDays) { 'Static Windows 365 and AVD endpoint lists should be reviewed before deployment.' } else { 'Static endpoint lists are within the freshness window.' }
    documents        = $documents
  }
}

$AzureLatencyRegions = @(
  [PSCustomObject]@{ regionId = 'canadacentral'; displayName = 'Canada Central'; location = 'Toronto' }
  [PSCustomObject]@{ regionId = 'eastus';         displayName = 'East US';         location = 'Virginia' }
  [PSCustomObject]@{ regionId = 'westus';         displayName = 'West US';         location = 'California' }
  [PSCustomObject]@{ regionId = 'westus2';        displayName = 'West US 2';       location = 'Washington' }
  [PSCustomObject]@{ regionId = 'uksouth';        displayName = 'UK South';        location = 'London' }
  [PSCustomObject]@{ regionId = 'uaenorth';       displayName = 'UAE North';       location = 'Dubai' }
  [PSCustomObject]@{ regionId = 'centralindia';   displayName = 'Central India';   location = 'Pune' }
  [PSCustomObject]@{ regionId = 'australiaeast';  displayName = 'Australia East';  location = 'New South Wales' }
  [PSCustomObject]@{ regionId = 'brazilsouth';    displayName = 'Brazil South';    location = 'Sao Paulo' }
)

$AzureLatencySampleCount = 10

function Get-MedianInt {
  param(
    [int[]]$Values
  )

  if (-not $Values -or -not $Values.Count) {
    return -1
  }

  $sorted = @($Values | Sort-Object)
  $mid = [int][Math]::Floor($sorted.Count / 2)
  if ($sorted.Count % 2 -eq 0) {
    return [int][Math]::Round(($sorted[$mid - 1] + $sorted[$mid]) / 2, 0)
  }

  return [int]$sorted[$mid]
}

function Test-AzureLatencyTarget {
  param(
    [string]$StorageAccountName,
    [int]$TimeoutMs
  )

  $request = $null
  $response = $null
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $url = "https://${StorageAccountName}.blob.core.windows.net/public/latency-test.json?_=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.Method = 'HEAD'
    $request.Timeout = $TimeoutMs
    $request.ReadWriteTimeout = $TimeoutMs
    $request.AllowAutoRedirect = $false
    $request.UserAgent = 'W365EndpointValidator/3.0'

    $response = [System.Net.HttpWebResponse]$request.GetResponse()
    $watch.Stop()

    return [PSCustomObject]@{
      ok        = $true
      latencyMs = [int]$watch.ElapsedMilliseconds
      detail    = "HTTP $([int]$response.StatusCode) $($response.StatusDescription)"
    }
  } catch {
    $watch.Stop()
    return [PSCustomObject]@{
      ok        = $false
      latencyMs = -1
      detail    = $_.Exception.Message
    }
  } finally {
    if ($response) {
      try { $response.Close() } catch {}
    }
  }
}

function Invoke-AzureLatencyTests {
  param(
    [object[]]$Regions,
    [int]$TimeoutMs,
    [int]$SampleCount
  )

  $storagePrefixes = @('s3', 's8', 'q9')
  $results = @()

  foreach ($region in $Regions) {
    Write-Host ("  Measuring RTT to {0} ({1}) with {2} samples..." -f $region.displayName, $region.location, $SampleCount) -ForegroundColor DarkGray

    $matched = $null
    $attemptDetails = @()
    foreach ($prefix in $storagePrefixes) {
      $storageAccountName = "$prefix$($region.regionId)"
      $successfulSamples = @()
      $latestLatency = -1
      $lastFailure = ''

      for ($sampleIndex = 1; $sampleIndex -le $SampleCount; $sampleIndex++) {
        $attempt = Test-AzureLatencyTarget -StorageAccountName $storageAccountName -TimeoutMs $TimeoutMs
        if ($attempt.ok) {
          $successfulSamples += [int]$attempt.latencyMs
          $latestLatency = [int]$attempt.latencyMs
        } else {
          $lastFailure = $attempt.detail
        }
      }

      if ($successfulSamples.Count -gt 0) {
        $medianLatency = Get-MedianInt -Values $successfulSamples
        $matched = [PSCustomObject]@{
          regionId            = $region.regionId
          displayName         = $region.displayName
          location            = $region.location
          storageAccountName  = $storageAccountName
          status              = 'Pass'
          latencyMs           = $medianLatency
          medianLatencyMs     = $medianLatency
          latestLatencyMs     = $latestLatency
          minLatencyMs        = ($successfulSamples | Measure-Object -Minimum).Minimum
          maxLatencyMs        = ($successfulSamples | Measure-Object -Maximum).Maximum
          requestedSamples    = $SampleCount
          successfulSamples   = $successfulSamples.Count
          samples             = @($successfulSamples)
          method              = "HTTPS HEAD x$SampleCount"
          detail              = if ($lastFailure) { "$($successfulSamples.Count)/$SampleCount successful samples | last error: $lastFailure" } else { "$($successfulSamples.Count)/$SampleCount successful samples" }
        }
        break
      }

      $attemptDetails += ("{0}: {1}" -f $storageAccountName, $(if ($lastFailure) { $lastFailure } else { 'No successful samples collected.' }))
    }

    if (-not $matched) {
      $matched = [PSCustomObject]@{
        regionId            = $region.regionId
        displayName         = $region.displayName
        location            = $region.location
        storageAccountName  = ''
        status              = 'Unavailable'
        latencyMs           = -1
        medianLatencyMs     = -1
        latestLatencyMs     = -1
        minLatencyMs        = -1
        maxLatencyMs        = -1
        requestedSamples    = $SampleCount
        successfulSamples   = 0
        samples             = @()
        method              = "HTTPS HEAD x$SampleCount"
        detail              = if ($attemptDetails) { $attemptDetails -join ' | ' } else { 'No Azure latency target responded.' }
      }
    }

    $results += $matched
  }

  return $results
}

function Expand-EndpointEntries {
  param(
    [object[]]$EntryList,
    [string]$Category,
    [ref]$Sequence
  )

  $tasks = @()
  foreach ($entry in $EntryList) {
    $hostname = ''
    $portList = '443'
    $protocol = 'TCP'
    $description = ''

    if ($entry -is [string]) {
      $parts = $entry.Split(':')
      $hostname = $parts[0]
      $portList = if ($parts.Length -gt 1) { $parts[1] } else { '443' }
    } else {
      $hostname = [string]$entry.Hostname
      $portList = if ($entry.Ports) { [string]$entry.Ports } elseif ($entry.Port) { [string]$entry.Port } else { '443' }
      $protocol = if ($entry.Protocol) { [string]$entry.Protocol } else { 'TCP' }
      $description = [string]$entry.Description
    }

    $description = Resolve-EndpointDescription -Hostname $hostname -Category $Category -ExistingDescription $description

    foreach ($port in $portList.Split(',')) {
      $tasks += [PSCustomObject]@{
        sequence = $Sequence.Value
        hostname = $hostname
        port     = [int]$port
        protocol = $protocol
        description = $description
        category = $Category
      }
      $Sequence.Value++
    }
  }

  return $tasks
}

function Remove-DuplicateEndpointTasks {
  param(
    [object[]]$Tasks
  )

  $seen = @{}
  $deduped = New-Object System.Collections.ArrayList
  foreach ($task in $Tasks) {
    $key = ('{0}|{1}|{2}|{3}' -f $task.category, $task.hostname, $task.port, $task.protocol)
    if ($seen.ContainsKey($key)) {
      continue
    }
    $seen[$key] = $true
    [void]$deduped.Add($task)
  }

  return @($deduped)
}

$EndpointProbeScript = {
  param(
    [string]$Hostname,
    [int]$Port,
    [string]$Protocol,
    [string]$Description,
    [string]$Category,
    [int]$Sequence,
    [int]$TimeoutMs
  )

  function New-ProbeResult {
    param(
      [string]$Result,
      [string]$DnsStatus,
      [string]$TcpStatus,
      [string]$TlsStatus,
      [int]$ResponseTime,
      [string]$FailureStage,
      [string]$Detail,
      [string]$TestedHost,
      [string]$ResolvedAddresses,
      [string]$TlsProtocol = '',
      [string]$TlsCertificateSubject = '',
      [string]$TlsCertificateIssuer = '',
      [string]$TlsCertificateThumbprint = '',
      [string]$TlsSanMatch = '',
      [string]$TlsChainStatus = '',
      [string]$SslInspectionSuspected = 'No'
    )

    [PSCustomObject]@{
      sequence          = $Sequence
      hostname          = $Hostname
      port              = $Port
      result            = $Result
      dnsStatus         = $DnsStatus
      tcpStatus         = $TcpStatus
      tlsStatus         = $TlsStatus
      responseTime_ms   = $ResponseTime
      protocol          = $Protocol
      description       = $Description
      category          = $Category
      testedHost        = $TestedHost
      resolvedAddresses = $ResolvedAddresses
      failureStage      = $FailureStage
      detail            = $Detail
      tlsProtocol       = $TlsProtocol
      tlsCertificateSubject = $TlsCertificateSubject
      tlsCertificateIssuer = $TlsCertificateIssuer
      tlsCertificateThumbprint = $TlsCertificateThumbprint
      tlsSanMatch = $TlsSanMatch
      tlsChainStatus = $TlsChainStatus
      sslInspectionSuspected = $SslInspectionSuspected
    }
  }

  function Get-CertificateDnsNames {
    param(
      [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $names = New-Object System.Collections.Generic.List[string]
    if (-not $Certificate) {
      return @()
    }

    try {
      $sanExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
      if ($sanExtension) {
        $formatted = (New-Object System.Security.Cryptography.AsnEncodedData($sanExtension.Oid, $sanExtension.RawData)).Format($true)
        foreach ($match in [regex]::Matches($formatted, 'DNS Name=(?<dns>[^,\r\n]+)')) {
          $dnsName = $match.Groups['dns'].Value.Trim()
          if ($dnsName) {
            $null = $names.Add($dnsName)
          }
        }
      }
    } catch {
      # Best-effort only.
    }

    if ($names.Count -eq 0 -and $Certificate.Subject -match 'CN\s*=\s*(?<cn>[^,]+)') {
      $null = $names.Add($matches['cn'].Trim())
    }

    return @($names | Select-Object -Unique)
  }

  function Test-CertificateNameMatch {
    param(
      [string]$Hostname,
      [string[]]$Names
    )

    if ([string]::IsNullOrWhiteSpace($Hostname) -or -not $Names -or -not $Names.Count) {
      return $false
    }

    $target = $Hostname.Trim().ToLowerInvariant()
    foreach ($name in $Names) {
      if ([string]::IsNullOrWhiteSpace($name)) {
        continue
      }

      $candidate = $name.Trim().ToLowerInvariant()
      if ($candidate -eq $target) {
        return $true
      }

      if ($candidate.StartsWith('*.')) {
        $suffix = $candidate.Substring(1)
        if ($target.EndsWith($suffix)) {
          return $true
        }
      }
    }

    return $false
  }

  function Test-SslInspectionHeuristic {
    param(
      [string[]]$Texts
    )

    $pattern = 'zscaler|netskope|iboss|skyhigh|blue\s*coat|broadcom|proxysg|symantec|fortinet|palo\s*alto|umbrella|forcepoint|cloudflare\s*gateway|web\s*gateway|secure\s*web\s*gateway'
    $joined = (@($Texts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' | ')
    if ([string]::IsNullOrWhiteSpace($joined)) {
      return $false
    }

    return $joined -match $pattern
  }

  $testedHost = $Hostname

  if ($testedHost -eq 'time.windows.com' -and $Port -eq 443) {
    $Port = 80
  }

  if ($Hostname.StartsWith('*.')) {
    return New-ProbeResult -Result 'Wildcard' -DnsStatus 'Skipped' -TcpStatus 'Skipped' -TlsStatus 'Skipped' -ResponseTime -1 -FailureStage '' -Detail 'Wildcard endpoint requires allowlist review; direct validation is not performed.' -TestedHost $Hostname -ResolvedAddresses '' -TlsProtocol ''
  }

  if ($Protocol -ne 'TCP') {
    return New-ProbeResult -Result 'IP Range' -DnsStatus 'Skipped' -TcpStatus 'Skipped' -TlsStatus 'Skipped' -ResponseTime -1 -FailureStage '' -Detail 'Documented IP range or non-TCP requirement. Manual allowlist review is required because the TCP probe engine cannot validate it directly.' -TestedHost $testedHost -ResolvedAddresses '' -TlsProtocol ''
  }

  $resolvedAddressText = ''
  try {
    $addresses = [System.Net.Dns]::GetHostAddresses($testedHost) |
      Where-Object {
        $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
      }

    if (-not $addresses) {
      throw [System.Exception]::new('No IP addresses returned.')
    }

    $resolvedAddressText = (($addresses | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique) -join ', ')
  } catch {
    return New-ProbeResult -Result 'DNS Fail' -DnsStatus 'Fail' -TcpStatus 'Skipped' -TlsStatus 'Skipped' -ResponseTime -1 -FailureStage 'DNS' -Detail $_.Exception.Message -TestedHost $testedHost -ResolvedAddresses '' -TlsProtocol ''
  }

  $responseTime = -1
  $connectClient = $null
  try {
    $connectClient = New-Object System.Net.Sockets.TcpClient
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $asyncResult = $connectClient.BeginConnect($testedHost, $Port, $null, $null)
    if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      throw [System.TimeoutException]::new("TCP connect timeout after ${TimeoutMs}ms")
    }
    $connectClient.EndConnect($asyncResult)
    $watch.Stop()
    $responseTime = [int]$watch.ElapsedMilliseconds
  } catch {
    return New-ProbeResult -Result 'TCP Fail' -DnsStatus 'Pass' -TcpStatus 'Fail' -TlsStatus 'Skipped' -ResponseTime -1 -FailureStage 'TCP' -Detail $_.Exception.Message -TestedHost $testedHost -ResolvedAddresses $resolvedAddressText -TlsProtocol ''
  } finally {
    if ($connectClient) {
      try { $connectClient.Close() } catch {}
    }
  }

  $tlsStatus = 'Skipped'
  $tlsProtocol = ''
  $tlsCertificateSubject = ''
  $tlsCertificateIssuer = ''
  $tlsCertificateThumbprint = ''
  $tlsSanMatch = ''
  $tlsChainStatus = ''
  $sslInspectionSuspected = 'No'
  if ($Port -eq 443) {
    $tlsClient = $null
    $netStream = $null
    $sslStream = $null
    $capturedCert = $null
    $capturedPolicyErrors = [System.Net.Security.SslPolicyErrors]::None
    $capturedChainStatuses = @()
    try {
      $tlsClient = New-Object System.Net.Sockets.TcpClient
      $tlsAsync = $tlsClient.BeginConnect($testedHost, $Port, $null, $null)
      if (-not $tlsAsync.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
        throw [System.TimeoutException]::new("TLS pre-connect timeout after ${TimeoutMs}ms")
      }

      $tlsClient.EndConnect($tlsAsync)
      $netStream = $tlsClient.GetStream()
      $sslStream = New-Object System.Net.Security.SslStream($netStream, $false, ([System.Net.Security.RemoteCertificateValidationCallback]{
        param($sender, $certificate, $chain, $sslPolicyErrors)
        if ($certificate) {
          try { $capturedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate } catch {}
        }
        $capturedPolicyErrors = $sslPolicyErrors
        $capturedChainStatuses = if ($chain) { @($chain.ChainStatus | Where-Object { $_.Status -ne 'NoError' } | ForEach-Object { [string]$_.Status }) } else { @() }
        return $true
      }))
      $sslStream.ReadTimeout = $TimeoutMs
      $sslStream.WriteTimeout = $TimeoutMs
      $sslStream.AuthenticateAsClient($testedHost)
      $tlsStatus = 'Pass'
      $tlsProtocol = [string]$sslStream.SslProtocol

      if (-not $capturedCert -and $sslStream.RemoteCertificate) {
        try { $capturedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate } catch {}
      }

      if ($capturedCert) {
        $tlsCertificateSubject = $capturedCert.Subject
        $tlsCertificateIssuer = $capturedCert.Issuer
        $tlsCertificateThumbprint = $capturedCert.Thumbprint
        $certificateNames = Get-CertificateDnsNames -Certificate $capturedCert
        $tlsSanMatch = if (Test-CertificateNameMatch -Hostname $testedHost -Names $certificateNames) { 'Yes' } else { 'No' }
        $tlsChainStatus = if ($capturedChainStatuses.Count) { $capturedChainStatuses -join ', ' } else { 'Trusted' }
        if (Test-SslInspectionHeuristic @($tlsCertificateSubject, $tlsCertificateIssuer)) {
          $sslInspectionSuspected = 'Yes'
        }
      }

      if ($capturedPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None -or $tlsSanMatch -eq 'No' -or ($tlsChainStatus -and $tlsChainStatus -ne 'Trusted')) {
        $detailBits = @("Policy: $capturedPolicyErrors")
        if ($tlsChainStatus) { $detailBits += "Chain: $tlsChainStatus" }
        if ($tlsCertificateIssuer) { $detailBits += "Issuer: $tlsCertificateIssuer" }
        if ($sslInspectionSuspected -eq 'Yes') { $detailBits += 'SSL inspection suspected' }
        return New-ProbeResult -Result 'TLS Fail' -DnsStatus 'Pass' -TcpStatus 'Pass' -TlsStatus 'Fail' -ResponseTime $responseTime -FailureStage 'TLS' -Detail ($detailBits -join ' | ') -TestedHost $testedHost -ResolvedAddresses $resolvedAddressText -TlsProtocol $tlsProtocol -TlsCertificateSubject $tlsCertificateSubject -TlsCertificateIssuer $tlsCertificateIssuer -TlsCertificateThumbprint $tlsCertificateThumbprint -TlsSanMatch $tlsSanMatch -TlsChainStatus $tlsChainStatus -SslInspectionSuspected $sslInspectionSuspected
      }
    } catch {
      $failureParts = @($_.Exception.Message)
      if ($tlsCertificateIssuer) { $failureParts += "Issuer: $tlsCertificateIssuer" }
      if ($tlsChainStatus) { $failureParts += "Chain: $tlsChainStatus" }
      return New-ProbeResult -Result 'TLS Fail' -DnsStatus 'Pass' -TcpStatus 'Pass' -TlsStatus 'Fail' -ResponseTime $responseTime -FailureStage 'TLS' -Detail ($failureParts -join ' | ') -TestedHost $testedHost -ResolvedAddresses $resolvedAddressText -TlsProtocol $tlsProtocol -TlsCertificateSubject $tlsCertificateSubject -TlsCertificateIssuer $tlsCertificateIssuer -TlsCertificateThumbprint $tlsCertificateThumbprint -TlsSanMatch $tlsSanMatch -TlsChainStatus $tlsChainStatus -SslInspectionSuspected $sslInspectionSuspected
    } finally {
      if ($sslStream) { try { $sslStream.Dispose() } catch {} }
      if ($netStream) { try { $netStream.Dispose() } catch {} }
      if ($tlsClient) { try { $tlsClient.Close() } catch {} }
    }
  }

  return New-ProbeResult -Result 'Pass' -DnsStatus 'Pass' -TcpStatus 'Pass' -TlsStatus $tlsStatus -ResponseTime $responseTime -FailureStage '' -Detail '' -TestedHost $testedHost -ResolvedAddresses $resolvedAddressText -TlsProtocol $tlsProtocol -TlsCertificateSubject $tlsCertificateSubject -TlsCertificateIssuer $tlsCertificateIssuer -TlsCertificateThumbprint $tlsCertificateThumbprint -TlsSanMatch $tlsSanMatch -TlsChainStatus $tlsChainStatus -SslInspectionSuspected $sslInspectionSuspected
}

function Invoke-ParallelEndpointTests {
  param(
    [object[]]$Tasks,
    [int]$TimeoutMs,
    [int]$Concurrency
  )

  if (-not $Tasks -or -not $Tasks.Count) {
    return @()
  }

  $results = New-Object System.Collections.ArrayList
  $completed = 0
  $total = $Tasks.Count

  $scriptText = $EndpointProbeScript.ToString()
  $pool = $null
  $workers = New-Object System.Collections.ArrayList

  try {
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Concurrency)
    $pool.Open()

    foreach ($task in $Tasks) {
      $ps = [System.Management.Automation.PowerShell]::Create()
      $ps.RunspacePool = $pool
      [void]$ps.AddScript($scriptText)
      [void]$ps.AddArgument($task.hostname)
      [void]$ps.AddArgument($task.port)
      [void]$ps.AddArgument($task.protocol)
      [void]$ps.AddArgument($task.description)
      [void]$ps.AddArgument($task.category)
      [void]$ps.AddArgument($task.sequence)
      [void]$ps.AddArgument($TimeoutMs)

      $handle = $ps.BeginInvoke()
      [void]$workers.Add([PSCustomObject]@{
        Task = $task
        PowerShell = $ps
        Handle = $handle
      })
    }

    while ($workers.Count -gt 0) {
      $percent = if ($total -gt 0) { [int](($completed / $total) * 100) } else { 100 }
      Write-Progress -Activity 'Testing endpoints' -Status "$completed of $total complete" -PercentComplete $percent

      $finishedWorkers = @($workers | Where-Object { $_.Handle.IsCompleted })
      if (-not $finishedWorkers.Count) {
        Start-Sleep -Milliseconds 100
        continue
      }

      foreach ($worker in $finishedWorkers) {
        try {
          $jobResult = $worker.PowerShell.EndInvoke($worker.Handle)
          foreach ($record in @($jobResult)) {
            if ($record) {
              [void]$results.Add($record)
            }
          }
        } catch {
          [void]$results.Add([PSCustomObject]@{
            sequence          = $worker.Task.sequence
            hostname          = $worker.Task.hostname
            port              = $worker.Task.port
            result            = 'TCP Fail'
            dnsStatus         = 'Unknown'
            tcpStatus         = 'Fail'
            tlsStatus         = 'Skipped'
            responseTime_ms   = -1
            protocol          = $worker.Task.protocol
            description       = $worker.Task.description
            category          = $worker.Task.category
            testedHost        = ''
            resolvedAddresses = ''
            failureStage      = 'Runspace'
            detail            = $_.Exception.Message
            tlsProtocol       = ''
            tlsCertificateSubject = ''
            tlsCertificateIssuer = ''
            tlsCertificateThumbprint = ''
            tlsSanMatch = ''
            tlsChainStatus = ''
            sslInspectionSuspected = 'No'
          })
        } finally {
          $worker.PowerShell.Dispose()
          [void]$workers.Remove($worker)
          $completed++
        }
      }
    }
  } finally {
    if ($pool) {
      try { $pool.Close() } catch {}
      try { $pool.Dispose() } catch {}
    }
  }

  Write-Progress -Activity 'Testing endpoints' -Completed -Status 'Complete'
  return $results |
    Sort-Object sequence |
    Select-Object hostname, port, protocol, description, result, dnsStatus, tcpStatus, tlsStatus, responseTime_ms, category, testedHost, resolvedAddresses, failureStage, detail, tlsProtocol, tlsCertificateSubject, tlsCertificateIssuer, tlsCertificateThumbprint, tlsSanMatch, tlsChainStatus, sslInspectionSuspected
}

function Add-RemediationMetadata {
  param(
    [object[]]$Results
  )

  foreach ($result in $Results) {
    $remediationCategory = 'No action required'
    $remediationAudience = 'None'
    $nextAction = 'No action required'
    $actionPriority = 0

    switch ($result.result) {
      'DNS Fail' {
        $remediationCategory = 'DNS issue'
        $remediationAudience = 'Infrastructure - Network/Firewall Team'
        $nextAction = 'Review DNS'
        $actionPriority = 3
      }
      'TCP Fail' {
        $remediationCategory = 'Direct firewall block'
        $remediationAudience = 'Infrastructure - Network/Firewall Team'
        $nextAction = 'Open outbound access'
        $actionPriority = 4
      }
      'TLS Fail' {
        $remediationCategory = 'Proxy/TLS inspection issue'
        $remediationAudience = 'Infrastructure - Network/Firewall Team'
        $nextAction = 'Review proxy / SSL inspection'
        $actionPriority = 3
      }
      'Wildcard' {
        $remediationCategory = 'Wildcard allowlist gap'
        $remediationAudience = 'Infrastructure - Network/Firewall Team'
        $nextAction = 'Review wildcard allowlist'
        $actionPriority = 2
      }
      'IP Range' {
        $remediationCategory = 'IP range allowlist gap'
        $remediationAudience = 'Infrastructure - Network/Firewall Team'
        $nextAction = 'Review IP range allowlist'
        $actionPriority = 2
      }
    }

    $result | Add-Member -NotePropertyName remediationCategory -NotePropertyValue $remediationCategory -Force
    $result | Add-Member -NotePropertyName remediationAudience -NotePropertyValue $remediationAudience -Force
    $result | Add-Member -NotePropertyName nextAction -NotePropertyValue $nextAction -Force
    $result | Add-Member -NotePropertyName actionPriority -NotePropertyValue $actionPriority -Force
    $result
  }
}

$TestMode = Resolve-TestMode -DefaultMode $Mode -Silent:$NoPrompt
$TestModeLabel = @{ Host = 'Host Network'; Client = 'Client Network'; Both = 'Both' }[$TestMode]
Write-Host "Test mode: $TestModeLabel" -ForegroundColor Cyan
Write-Host "Concurrency: $MaxParallel  |  Timeout: ${TimeoutMs}ms" -ForegroundColor DarkGray
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK CONTEXT
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Collecting local network context..." -ForegroundColor DarkGray
$NetworkContext = Get-NetworkContext
$OperatingSystemContext = Get-OperatingSystemContext

Write-Host "Collecting proxy and public egress context..." -ForegroundColor DarkGray
$ProxyDiagnostics = Get-ProxyDiagnostics
$PublicEgressContext = Get-PublicEgressContext -ProxyDiagnostics $ProxyDiagnostics

Write-Host "Collecting environment fingerprint..." -ForegroundColor DarkGray
$EnvironmentFingerprint = Get-EnvironmentFingerprint -NetworkContext $NetworkContext -ProxyDiagnostics $ProxyDiagnostics -PublicEgressContext $PublicEgressContext

Write-Host "Collecting time and certificate readiness..." -ForegroundColor DarkGray
$TimeSyncContext = Get-TimeSyncContext
$CertificateReadiness = Invoke-CertificateReadinessChecks -TimeoutMs $TimeoutMs

Write-Host "Collecting UDP and Shortpath readiness..." -ForegroundColor DarkGray
$UdpShortpathReadiness = Get-UdpShortpathReadiness -TimeoutMs $TimeoutMs

Write-Host "Checking endpoint list currency..." -ForegroundColor DarkGray
$EndpointCurrencyStatus = Get-EndpointCurrencyStatus -ReviewedOn $StaticEndpointReviewDate -StaleAfterDays $EndpointCurrencyThresholdDays

# ─────────────────────────────────────────────────────────────────────────────
# AZURE REGION RTT
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Collecting Azure region RTT baselines..." -ForegroundColor DarkGray
$AzureLatencyResults = Invoke-AzureLatencyTests -Regions $AzureLatencyRegions -TimeoutMs $TimeoutMs -SampleCount $AzureLatencySampleCount

$AzureBackboneRttReference = $null
if (Test-Path $AzureBackboneRttReferencePath) {
  try {
    $AzureBackboneRttReference = Get-Content -Path $AzureBackboneRttReferencePath -Raw -Encoding UTF8 | ConvertFrom-Json
  } catch {
    Write-Host "WARNING: Could not load Azure backbone RTT reference data — $_" -ForegroundColor DarkYellow
  }
} else {
  Write-Host "WARNING: Azure backbone RTT reference data file not found at $AzureBackboneRttReferencePath" -ForegroundColor DarkYellow
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN TESTS
# ─────────────────────────────────────────────────────────────────────────────
$allTasks = @()
$sequence = 0
$startTime  = Get-Date

if ($TestMode -in 'Host', 'Both') {
  Write-Host "Queueing host-network endpoint tests..." -ForegroundColor Cyan
  $allTasks += Expand-EndpointEntries -EntryList $endpoints_w365 -Category 'W365-Host' -Sequence ([ref]$sequence)
  $allTasks += Expand-EndpointEntries -EntryList $endpoints_avd -Category 'AVD-Host' -Sequence ([ref]$sequence)
  $allTasks += Expand-EndpointEntries -EntryList $documentedEndpoints_avd -Category 'AVD-Host' -Sequence ([ref]$sequence)

  Write-Host ""
  Write-Host "── Intune (MEM) Endpoints ───────────────────────────────" -ForegroundColor Cyan
  Write-Host "  Queueing documented Intune endpoint additions..." -ForegroundColor DarkGray
  $allTasks += Expand-EndpointEntries -EntryList $documentedEndpoints_intune -Category 'Intune-MEM' -Sequence ([ref]$sequence)
  Write-Host "  Fetching live endpoint list from endpoints.office.com..." -ForegroundColor DarkGray
  try {
    $mem_url  = "https://endpoints.office.com/endpoints/WorldWide?ServiceAreas=MEM&clientrequestid=$([GUID]::NewGuid())"
    $memHosts = (Invoke-RestMethod -Uri $mem_url -UseBasicParsing) |
          Where-Object { $_.ServiceArea -eq 'MEM' -and $_.urls } |
          Select-Object -ExpandProperty urls -Unique
    $allTasks += Expand-EndpointEntries -EntryList $memHosts -Category 'Intune-MEM' -Sequence ([ref]$sequence)
  } catch {
    Write-Host "  WARNING: Could not fetch Intune MEM list — $_" -ForegroundColor DarkYellow
  }
}

if ($TestMode -in 'Client', 'Both') {
  Write-Host "Queueing client-network endpoint tests..." -ForegroundColor Cyan
  $allTasks += Expand-EndpointEntries -EntryList $clientendpoints_w365 -Category 'W365-Client' -Sequence ([ref]$sequence)
}

if ($allTasks.Count) {
  $allTasks = Remove-DuplicateEndpointTasks -Tasks $allTasks
}

Write-Host ""
Write-Host "Starting $($allTasks.Count) endpoint probe(s)..." -ForegroundColor Cyan
$allResults = Invoke-ParallelEndpointTests -Tasks $allTasks -TimeoutMs $TimeoutMs -Concurrency $MaxParallel
$allResults = @(Add-RemediationMetadata -Results $allResults)

$endTime       = Get-Date
$durationSecs  = [int]($endTime - $startTime).TotalSeconds

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
$totalTests  = $allResults.Count
$totalPass   = ($allResults | Where-Object { $_.result -eq 'Pass' }).Count
$totalFail   = ($allResults | Where-Object { $_.result -like '*Fail' }).Count
$totalWild   = ($allResults | Where-Object { $_.result -eq 'Wildcard' }).Count
$totalIpRange = ($allResults | Where-Object { $_.result -eq 'IP Range' }).Count
$totalAdvisory = $totalWild + $totalIpRange

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Results: " -NoNewline
Write-Host "$totalPass PASS" -ForegroundColor Green -NoNewline
Write-Host " / " -NoNewline
Write-Host "$totalFail FAIL" -ForegroundColor Red -NoNewline
Write-Host " / " -NoNewline
Write-Host "$totalAdvisory ADVISORY" -ForegroundColor Yellow -NoNewline
Write-Host "  (${totalTests} total, ${durationSecs}s)"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# BUILD JSON PAYLOAD
# ─────────────────────────────────────────────────────────────────────────────
$reportData = [ordered]@{
    meta    = [ordered]@{
        hostname        = $env:COMPUTERNAME
        scanDate        = (Get-Date -Format 'o')
        testMode        = $TestModeLabel
        durationSeconds = $durationSecs
        scriptVersion   = $ScriptVersion
    timeoutMs       = $TimeoutMs
    maxParallel     = $MaxParallel
    networkContext  = $NetworkContext
    operatingSystem = $OperatingSystemContext
      proxyDiagnostics = $ProxyDiagnostics
      publicEgress     = $PublicEgressContext
      environmentFingerprint = $EnvironmentFingerprint
      timeSync         = $TimeSyncContext
      certificateReadiness = $CertificateReadiness
      udpShortpathReadiness = $UdpShortpathReadiness
      endpointCurrency = $EndpointCurrencyStatus
    }
    azureRtt = $AzureLatencyResults
    azureBackboneRtt = $AzureBackboneRttReference
    results = $allResults
}

    $jsonData = $reportData | ConvertTo-Json -Depth 8 -Compress

# ─────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATE  (W365 Validator Design Upgrade - Cyber/Technical Redesign)
# ─────────────────────────────────────────────────────────────────────────────
$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>W365 Endpoint Network Validator — Design Upgrade</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
<style>
:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --surface2: #1c2128;
  --border:   #30363d;
  --pass:     #3fb950;
  --fail:     #f85149;
  --warn:     #d29922;
  --accent:   #00d4ff;
  --text:     #c9d1d9;
  --muted:    #8b949e;
  --pass-bg:  rgba(63,185,80,0.08);
  --fail-bg:  rgba(248,81,73,0.08);
  --warn-bg:  rgba(210,153,34,0.08);
  --neon:     #00d4ff;
  --neon-glow: 0 0 10px rgba(0, 212, 255, 0.3);
  --neon-intense: 0 0 20px rgba(0, 212, 255, 0.6);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.5}

/* ── Header ─────────────────────────────────────────── */
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.header-left h1{font-size:18px;font-weight:600;color:var(--text)}
.header-left .sub{font-size:12px;color:var(--muted);margin-top:2px}
.header-right{text-align:right;font-size:12px;color:var(--muted);line-height:1.8;white-space:nowrap}
.header-right strong{color:var(--text)}

/* ── Tab bar ─────────────────────────────────────────── */
.tabbar-shell{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;align-items:center;gap:16px}
.tabbar{flex:1 1 auto;min-width:0;padding:0;display:flex;gap:0;overflow-x:auto;scrollbar-width:none}
.tabbar::-webkit-scrollbar{display:none}
.tabbar button{background:none;border:none;border-bottom:2px solid transparent;color:var(--muted);cursor:pointer;font-size:13px;font-weight:500;padding:11px 16px;white-space:nowrap;transition:color .15s,border-color .15s}
.tabbar button:hover{color:var(--text)}
.tabbar button.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-badge{background:var(--fail);border-radius:8px;color:#fff;font-size:10px;font-weight:700;margin-left:5px;padding:1px 5px}
.tabbar-actions{display:flex;align-items:center;justify-content:flex-end;flex:0 0 auto;margin-left:auto;padding:8px 0}

/* ── Tab panels ──────────────────────────────────────── */
.tab-panel{display:none;padding:24px;animation:fadeIn .2s ease}
.tab-panel.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

/* ── Health / context ───────────────────────────────── */
.health-banner{border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:16px;font-size:14px;font-weight:600}
.health-banner .sub{display:block;font-size:12px;font-weight:400;color:var(--muted);margin-top:4px}
.health-ok{background:rgba(63,185,80,.08);border-color:rgba(63,185,80,.45);color:var(--pass)}
.health-warn{background:rgba(210,153,34,.10);border-color:rgba(210,153,34,.45);color:var(--warn)}
.health-bad{background:rgba(248,81,73,.10);border-color:rgba(248,81,73,.45);color:var(--fail)}
.context-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:18px}
.context-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.context-card h3{font-size:12px;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em}
.context-item{display:flex;gap:10px;justify-content:space-between;font-size:12px;padding:4px 0;border-bottom:1px solid rgba(48,54,61,.45)}
.context-item:last-child{border-bottom:none;padding-bottom:0}
.context-item .k{color:var(--muted);min-width:86px}
.context-item .v{text-align:right;word-break:break-word}
.mini-note{margin-top:14px;padding-top:14px;border-top:1px solid rgba(48,54,61,.6)}
.mini-note h4{font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em}
.mini-note p{font-size:12px;color:var(--muted);margin-bottom:10px}
.wildcard-list{display:flex;flex-wrap:wrap;gap:8px}
.wildcard-chip{background:var(--surface2);border:1px solid var(--border);border-radius:999px;color:var(--text);font-family:'Consolas','Courier New',monospace;font-size:11px;padding:5px 10px}
.azure-rtt-section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:18px}
.azure-rtt-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.azure-rtt-head h3{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.azure-rtt-head p{font-size:12px;color:var(--muted);max-width:720px}
.azure-rtt-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.azure-rtt-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px}
.azure-rtt-card h4{font-size:14px;margin-bottom:2px}
.azure-rtt-card .loc{font-size:12px;color:var(--muted);margin-bottom:10px}
.azure-rtt-card .ms{font-size:26px;font-weight:700;line-height:1.1;margin-bottom:8px}
.azure-rtt-card .meta{font-size:11px;color:var(--muted);word-break:break-word}

/* ── KPI cards ───────────────────────────────────────── */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:12px;margin-bottom:24px}
.kpi-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.kpi-card .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.kpi-card .val{font-size:26px;font-weight:700}
.kpi-card .val.c-pass{color:var(--pass)}
.kpi-card .val.c-fail{color:var(--fail)}
.kpi-card .val.c-warn{color:var(--warn)}
.kpi-card .val.c-neutral{color:var(--text)}

/* ── Chart cards ─────────────────────────────────────── */
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-bottom:24px}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.chart-card h3{font-size:12px;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em}
.chart-card canvas{max-height:160px}
.chart-legend{display:flex;justify-content:center;gap:12px;margin-top:10px;font-size:11px;flex-wrap:wrap}
.chart-legend span{display:flex;align-items:center;gap:4px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.overview-shell{display:grid;gap:18px}
.overview-sidebar{display:grid;gap:16px}
.overview-main{display:grid;gap:16px}
.overview-advisory{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.overview-breakdown{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.action-summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:8px}
.action-summary-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.action-summary-card h3{font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em}
.action-summary-card .count{font-size:28px;font-weight:700;line-height:1.1;margin-bottom:8px}
.action-summary-card .top{font-size:12px;color:var(--text);margin-bottom:6px}
.action-summary-card .desc{font-size:12px;color:var(--muted)}
.readiness-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:16px}
.readiness-section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
.readiness-section h3{font-size:12px;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.06em}
.remediation-section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:14px}
.remediation-section h3{font-size:14px;margin-bottom:4px}
.remediation-section .sub{font-size:12px;color:var(--muted);margin-bottom:10px}
.remediation-group{margin-top:12px;padding-top:12px;border-top:1px solid rgba(48,54,61,.6)}
.remediation-group:first-of-type{margin-top:0;padding-top:0;border-top:none}
.remediation-group h4{font-size:12px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em}
.remediation-group p{font-size:12px;color:var(--muted);margin-bottom:8px}
.firewall-summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px}
.firewall-summary-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.firewall-summary-card .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.firewall-summary-card .value{font-size:26px;font-weight:700;line-height:1.05;margin-bottom:6px}
.firewall-summary-card .value.c-pass{color:var(--pass)}
.firewall-summary-card .value.c-warn{color:var(--warn)}
.firewall-summary-card .value.c-fail{color:var(--fail)}
.firewall-summary-card .meta{font-size:12px;color:var(--muted)}
.firewall-layout{display:grid;grid-template-rows:minmax(520px,1fr) auto;gap:28px;min-height:calc(100vh - 290px)}
.firewall-pane-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid rgba(48,54,61,.6)}
.firewall-pane-head h3{font-size:14px;margin-bottom:4px}
.firewall-pane-head .meta{font-size:12px;color:var(--muted);max-width:760px}
.firewall-owner-badge{background:rgba(31,111,235,.14);border:1px solid rgba(88,166,255,.35);border-radius:999px;color:#9ecbff;font-size:11px;font-weight:700;letter-spacing:.05em;padding:6px 10px;text-transform:uppercase;white-space:nowrap}
.firewall-task-section{margin-top:18px;padding-top:18px;border-top:1px solid rgba(48,54,61,.6)}
.firewall-task-section:first-of-type{margin-top:0;padding-top:0;border-top:none}
.firewall-task-section h4{font-size:13px;margin-bottom:6px}
.firewall-task-section p{font-size:12px;color:var(--muted);margin-bottom:10px}
.firewall-item-list{display:grid;gap:8px}
.firewall-item{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.firewall-item-main{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:4px}
.firewall-item-host{font-family:'Consolas','Courier New',monospace;font-size:12px;color:var(--text)}
.firewall-item-action{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.firewall-item-detail{font-size:12px;color:var(--muted)}
.firewall-item-detail strong{color:var(--text)}
.firewall-advisory{margin-top:8px;padding:18px 20px;background:var(--surface);border:1px solid var(--border);border-radius:8px}
.firewall-support-note{margin-top:16px;padding-top:14px;border-top:1px solid rgba(48,54,61,.6);font-size:12px;color:var(--muted)}

/* ── Section header ──────────────────────────────────── */
.sec-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px;gap:12px;flex-wrap:wrap}
.sec-header h2{font-size:16px;font-weight:600}
.sec-header .sub{font-size:12px;color:var(--muted);margin-top:3px}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}

/* ── Buttons ─────────────────────────────────────────── */
.btn{align-items:center;background:var(--accent);border:none;border-radius:6px;color:#fff;cursor:pointer;display:inline-flex;font-size:12px;font-weight:500;gap:5px;padding:6px 13px;transition:opacity .15s;white-space:nowrap}
.btn:hover{opacity:.85}
.btn-ghost{background:var(--surface);border:1px solid var(--border);color:var(--text)}
.btn-green{background:var(--pass)}
.btn-red{background:var(--fail)}
.btn-download{background:linear-gradient(135deg,#2f81f7,#1f6feb);border:1px solid #58a6ff;box-shadow:0 8px 24px rgba(31,111,235,.24);color:#f8fbff;font-weight:700;padding:9px 16px}
.btn-download:hover{opacity:1;filter:brightness(1.08)}

/* ── Toolbar ─────────────────────────────────────────── */
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.toolbar input[type=text]{background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;padding:6px 10px;width:230px;outline:none;transition:border-color .15s}
.toolbar input[type=text]:focus{border-color:var(--accent)}
.toolbar input::placeholder{color:var(--muted)}
.rtt-select{background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;max-width:180px;padding:6px 10px;width:100%}
.chip{background:var(--surface);border:1px solid var(--border);border-radius:14px;color:var(--muted);cursor:pointer;font-size:12px;padding:4px 12px;transition:all .15s}
.chip:hover{color:var(--text)}
.chip.active{background:var(--accent);border-color:var(--accent);color:#fff}

/* ── Table ───────────────────────────────────────────── */
.table-wrap{border:1px solid var(--border);border-radius:8px;overflow:auto;max-height:58vh}
table{border-collapse:collapse;width:100%}
thead th{background:var(--surface);border-bottom:1px solid var(--border);color:var(--muted);font-size:11px;font-weight:600;letter-spacing:.05em;padding:9px 12px;text-align:left;text-transform:uppercase;position:sticky;top:0;z-index:1;user-select:none;cursor:pointer;white-space:nowrap}
thead th:hover{color:var(--text)}
thead th .sort-icon{margin-left:4px;font-size:10px;opacity:.4}
thead th.sort-asc .sort-icon::after{content:'▲'}
thead th.sort-desc .sort-icon::after{content:'▼'}
tbody tr{border-bottom:1px solid rgba(48,54,61,.6);transition:background .1s}
tbody tr:hover{background:rgba(255,255,255,.03)}
tbody td{padding:8px 12px;font-size:13px;vertical-align:middle}
.row-pass{background:rgba(63,185,80,.04)}
.row-fail{background:rgba(248,81,73,.04)}
.row-warn{background:rgba(210,153,34,.04)}
.mono{font-family:'Consolas','Courier New',monospace;font-size:12px}
.empty-row td{color:var(--muted);padding:28px 12px;text-align:center}

/* ── Badges ──────────────────────────────────────────── */
.badge{border-radius:4px;display:inline-flex;align-items:center;font-size:11px;font-weight:600;gap:4px;padding:2px 8px;letter-spacing:.02em}
.badge-pass{background:var(--pass-bg);border:1px solid var(--pass);color:var(--pass)}
.badge-fail{background:var(--fail-bg);border:1px solid var(--fail);color:var(--fail)}
.badge-warn{background:var(--warn-bg);border:1px solid var(--warn);color:var(--warn)}
.badge-neutral{background:rgba(139,148,158,.1);border:1px solid var(--border);color:var(--muted)}
.latency-good{color:var(--pass);font-weight:600}
.latency-warn{color:var(--warn);font-weight:600}
.latency-bad{color:var(--fail);font-weight:600}
.latency-none{color:var(--muted)}

/* ── Port badge ──────────────────────────────────────── */
.port-badge{background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--muted);font-family:'Consolas',monospace;font-size:11px;padding:1px 6px}

/* ── Firewall section ────────────────────────────────── */
.rule-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;min-height:520px;height:100%;max-height:none;overflow-y:auto;padding:18px 20px}
.rule-item{color:var(--fail);font-family:'Consolas','Courier New',monospace;font-size:13px;line-height:2;display:flex;align-items:center;gap:8px}
.rule-item::before{content:'⬥';font-size:10px}
.rule-empty{color:var(--pass);font-size:14px;padding:12px 0}

/* ── Compare ─────────────────────────────────────────── */
.drop-zone{border:2px dashed var(--border);border-radius:10px;cursor:pointer;padding:36px;text-align:center;transition:border-color .2s,background .2s}
.drop-zone:hover,.drop-zone.over{border-color:var(--accent);background:rgba(31,111,235,.04)}
.drop-zone .icon{font-size:36px;margin-bottom:8px}
.drop-zone .hint{font-size:12px;color:var(--muted);margin-top:4px}

/* ── Scrollbar ───────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

/* ── Print ───────────────────────────────────────────── */
@media print{
  .tabbar-shell,.tabbar,.toolbar,.btn-row,.drop-zone{display:none!important}
  .tab-panel{display:block!important;page-break-after:always}
  .table-wrap{max-height:none;overflow:visible;border:1px solid #ddd}
  body{background:#fff;color:#000}
  .header{background:#fff}
}

/* ── Responsive ──────────────────────────────────────── */
@media(max-width:640px){
  .header{flex-direction:column;gap:8px}
  .header-right{text-align:left}
  .tabbar-shell{align-items:stretch;flex-direction:column;padding:0 14px 14px}
  .tabbar-actions{justify-content:stretch;margin-left:0;padding-top:0}
  .tabbar-actions .btn{justify-content:center;width:100%}
  .kpi-grid{grid-template-columns:repeat(2,1fr)}
  .charts-grid{grid-template-columns:1fr}
  .toolbar input[type=text]{width:100%}
  .tab-panel{padding:14px}
}

/* ── CYBER/TECHNICAL ENHANCEMENTS ──────────────────────── */
/* Neon glow badges and accents */
.kpi-card{border-color:var(--border);transition:all .3s ease}
.kpi-card:hover{border-color:var(--neon);box-shadow:var(--neon-glow)}
.kpi-card .val.c-pass{text-shadow:var(--neon-glow);color:var(--pass)}
.kpi-card .val.c-fail{text-shadow:0 0 10px rgba(248,81,73,0.4);color:var(--fail)}
.badge{transition:all .2s ease}
.badge-pass{box-shadow:0 0 8px rgba(63,185,80,0.2)}
.badge-fail{box-shadow:0 0 8px rgba(248,81,73,0.2)}
.badge-pass:hover{box-shadow:0 0 12px rgba(63,185,80,0.4)}
.badge-fail:hover{box-shadow:0 0 12px rgba(248,81,73,0.4)}
/* Monospaced emphasis on hostnames */
.mono{font-weight:500;color:var(--text)}
table tbody tr:hover .mono{color:var(--neon);text-shadow:var(--neon-glow)}
/* Tab active state enhancement */
.tabbar button.active{border-bottom-color:var(--accent);color:var(--neon);text-shadow:0 0 8px rgba(0,212,255,0.3)}
/* Button cyber styling */
.btn-download{background:linear-gradient(135deg,#1f6feb,#0d47a1);border:1px solid var(--neon);box-shadow:0 0 12px rgba(0,212,255,0.2);transition:all .3s ease}
.btn-download:hover{box-shadow:0 0 20px rgba(0,212,255,0.5);transform:translateY(-2px)}
/* Input focus glow */
.toolbar input[type=text]:focus{border-color:var(--neon);box-shadow:0 0 10px rgba(0,212,255,0.3)}
.chip.active{background:var(--accent);border-color:var(--neon);box-shadow:0 0 8px rgba(0,212,255,0.3);color:#fff}
/* Card entrances with animation */
@keyframes cardEnter{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.kpi-card{animation:cardEnter .4s ease-out}
.action-summary-card{animation:cardEnter .4s ease-out}
.context-card{animation:cardEnter .4s ease-out}
/* Table row hover effect */
table tbody tr{transition:background-color .15s,box-shadow .15s}
table tbody tr.row-pass:hover{background:rgba(63,185,80,.08);box-shadow:inset 3px 0 0 var(--pass)}
table tbody tr.row-fail:hover{background:rgba(248,81,73,.08);box-shadow:inset 3px 0 0 var(--fail)}
table tbody tr.row-warn:hover{background:rgba(210,153,34,.1);box-shadow:inset 3px 0 0 var(--warn)}

/* ── DESIGN UPGRADE OVERRIDES (HIGH-VISIBILITY CYBER THEME) ───────────────── */
html,body{
  background:
    radial-gradient(1200px 600px at 0% 0%, rgba(0,212,255,.13), transparent 60%),
    radial-gradient(900px 500px at 100% 20%, rgba(63,185,80,.08), transparent 62%),
    linear-gradient(180deg,#070b13 0%,#0b1220 45%,#0d1117 100%);
  color:#d8ecff;
  font-family:"Consolas","Cascadia Code","Segoe UI",sans-serif;
}
.header{
  position:sticky;
  top:0;
  z-index:20;
  background:linear-gradient(90deg, rgba(7,14,26,.96), rgba(10,24,38,.92));
  border-bottom:1px solid rgba(0,212,255,.35);
  box-shadow:0 8px 30px rgba(0,0,0,.35), inset 0 -1px 0 rgba(0,212,255,.16);
}
.header-left h1{
  color:#8ee8ff;
  letter-spacing:.02em;
  text-shadow:0 0 20px rgba(0,212,255,.45);
}
.theme-pill{
  display:inline-flex;
  align-items:center;
  margin-left:8px;
  padding:2px 8px;
  border-radius:999px;
  border:1px solid rgba(0,212,255,.55);
  background:rgba(0,212,255,.1);
  color:#b7f2ff;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:.08em;
}
.tabbar-shell{
  background:rgba(10,18,30,.9);
  border-bottom:1px solid rgba(0,212,255,.22);
}
.tabbar button{
  border-bottom:none;
  border-radius:10px;
  margin:6px 4px;
  padding:9px 14px;
  color:#8ea4be;
  transition:all .2s ease;
}
.tabbar button:hover{
  color:#dff7ff;
  background:rgba(0,212,255,.12);
}
.tabbar button.active{
  color:#baf5ff;
  background:linear-gradient(180deg, rgba(0,212,255,.24), rgba(0,212,255,.08));
  border:1px solid rgba(0,212,255,.55);
  box-shadow:0 0 0 1px rgba(0,212,255,.2), 0 0 24px rgba(0,212,255,.28);
}
.kpi-card,.chart-card,.context-card,.azure-rtt-section,.overview-breakdown,.readiness-section,.remediation-section,.rule-box,.firewall-advisory{
  background:linear-gradient(180deg, rgba(14,24,40,.88), rgba(11,19,32,.9));
  border:1px solid rgba(110,170,230,.24);
  box-shadow:0 8px 24px rgba(1,8,20,.45);
}
.kpi-card:hover,.chart-card:hover,.context-card:hover,.azure-rtt-card:hover{
  border-color:rgba(0,212,255,.65);
  box-shadow:0 0 0 1px rgba(0,212,255,.15),0 10px 30px rgba(0,212,255,.16);
  transform:translateY(-1px);
}
.btn,.chip.active{
  border:1px solid rgba(0,212,255,.45);
}
.btn-download{
  background:linear-gradient(135deg,#0d3a61,#005fa3);
  border:1px solid rgba(0,212,255,.72);
  box-shadow:0 8px 28px rgba(0,212,255,.22);
}
.btn-download:hover{
  box-shadow:0 10px 34px rgba(0,212,255,.38);
}
.table-wrap{
  border:1px solid rgba(0,212,255,.24);
}
thead th{
  background:linear-gradient(180deg,#11253c 0%, #0e1d30 100%);
  color:#93dfff;
  border-bottom:1px solid rgba(0,212,255,.25);
}
tbody tr:hover{
  background:rgba(0,212,255,.08);
}
.mono{color:#baf5ff;}

.wow-deck{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin:8px 0 18px}
.wow-card{background:linear-gradient(180deg, rgba(16,31,52,.92), rgba(10,20,35,.92));border:1px solid rgba(0,212,255,.24);border-radius:10px;padding:14px}
.wow-card h3{font-size:12px;color:#8fe3ff;letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px}
.wow-sub{font-size:11px;color:var(--muted);margin-bottom:8px}
.wow-canvas-wrap{height:220px;position:relative}
.wow-canvas-wrap canvas{height:100% !important;max-height:none !important}

.rtt-map-section{margin-bottom:14px;background:linear-gradient(180deg, rgba(15,29,46,.92), rgba(10,20,34,.92));border:1px solid rgba(0,212,255,.26);border-radius:10px;padding:14px}
.rtt-map-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.rtt-map-head h3{font-size:12px;color:#9be9ff;text-transform:uppercase;letter-spacing:.08em}
.rtt-map-head p{font-size:12px;color:var(--muted);max-width:760px}
.rtt-intel-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}
.rtt-mini-kpi{background:rgba(10,18,30,.62);border:1px solid rgba(0,212,255,.18);border-radius:8px;padding:10px 12px}
.rtt-mini-kpi .label{font-size:10px;color:#7eb7cf;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.rtt-mini-kpi .value{font-size:18px;font-weight:700;color:#d7f6ff}
.rtt-mini-kpi .meta{font-size:11px;color:var(--muted);margin-top:4px}
.rtt-legend{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.rtt-legend-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;background:rgba(10,18,30,.62);border:1px solid rgba(0,212,255,.18);font-size:11px;color:#ccefff}
.rtt-legend-dot{width:8px;height:8px;border-radius:50%}
.rtt-map-layout{display:grid;grid-template-columns:minmax(290px,.8fr) minmax(0,1.2fr);gap:12px;align-items:start}
.rtt-side-stack{display:grid;gap:10px}
.rtt-route-panel{background:rgba(10,18,30,.85);border:1px solid rgba(0,212,255,.2);border-radius:8px;padding:12px;min-height:100%}
.rtt-route-panel h4{font-size:12px;color:#8fe3ff;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.rtt-route-item{display:flex;justify-content:space-between;gap:10px;border-bottom:1px solid rgba(120,160,200,.2);padding:6px 0;font-size:12px}
.rtt-route-item:last-child{border-bottom:none}
.rtt-route-item .k{color:var(--muted)}
.rtt-route-item .v{color:#d7f4ff;text-align:right}
.rtt-route-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.rtt-route-card{background:rgba(10,18,30,.65);border:1px solid rgba(0,212,255,.12);border-radius:8px;padding:10px;cursor:pointer;transition:all .18s ease}
.rtt-route-card:hover,.rtt-route-card.active{border-color:rgba(0,212,255,.55);box-shadow:0 0 0 1px rgba(0,212,255,.12),0 8px 22px rgba(0,212,255,.1)}
.rtt-route-card-top{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px}
.rtt-route-rank{font-size:10px;color:#7eb7cf;text-transform:uppercase;letter-spacing:.08em}
.rtt-route-name{font-size:13px;color:#d7f6ff;font-weight:600}
.rtt-route-ms{font-size:14px;font-weight:700}
.rtt-route-bar{height:6px;border-radius:999px;background:rgba(120,160,200,.16);overflow:hidden;margin:8px 0 6px}
.rtt-route-bar > span{display:block;height:100%;border-radius:999px}
.rtt-route-meta{display:flex;justify-content:space-between;gap:8px;font-size:11px;color:var(--muted)}

@media(max-width:1100px){
  .wow-deck{grid-template-columns:1fr}
  .rtt-map-layout{grid-template-columns:1fr}
  .rtt-intel-strip{grid-template-columns:repeat(2,minmax(0,1fr))}
  .rtt-route-list{grid-template-columns:1fr}
}

@media (prefers-reduced-motion: no-preference){
  .kpi-card,.chart-card,.context-card,.azure-rtt-card,.btn,.chip,.tabbar button{
    will-change:transform,opacity;
  }
}
</style>
</head>
<body>
<!-- Header: Full-width top bar -->
<div class="header">
  <div class="header-left">
    <h1>🔍 W365 Endpoint Network Validator</h1>
    <div class="sub" id="hdrSub">Running scan…</div>
  </div>
  <div class="header-right" id="hdrMeta"></div>
</div>

<!-- Tab Bar: Horizontal nav -->
<div class="tabbar-shell">
  <div class="tabbar" role="tablist" id="tabbar">
    <button role="tab" class="active" onclick="showTab('overview',this)" aria-selected="true">📊 Overview</button>
    <button role="tab" onclick="showTab('rtt',this)">🌐 Azure RTT</button>
    <button role="tab" onclick="showTab('readiness',this)">🧭 Readiness</button>
    <button role="tab" onclick="showTab('w365host',this)">W365 Cloud PC <span class="tab-badge" id="badge-w365host" style="display:none"></span></button>
    <button role="tab" onclick="showTab('w365client',this)">User Device <span class="tab-badge" id="badge-w365client" style="display:none"></span></button>
    <button role="tab" onclick="showTab('avd',this)">AVD <span class="tab-badge" id="badge-avd" style="display:none"></span></button>
    <button role="tab" onclick="showTab('intune',this)">Intune (MEM) <span class="tab-badge" id="badge-intune" style="display:none"></span></button>
    <button role="tab" onclick="showTab('firewall',this)">🔥 Firewall Rules <span class="tab-badge" id="badge-fw" style="display:none"></span></button>
    <button role="tab" onclick="showTab('compare',this)">⚖️ Compare</button>
  </div>
  <div class="tabbar-actions">
    <button class="btn btn-download" onclick="exportExcel()">⬇ Download Report</button>
  </div>
</div>

<!-- Tab Panels: Content areas -->
<div id="tab-overview" class="tab-panel active">
  <div class="overview-shell">
    <div class="overview-sidebar">
      <div id="healthBanner" class="health-banner health-warn">Loading health summary…</div>
      <div id="contextGrid" class="context-grid"></div>
    </div>
    <div class="overview-main">
      <div class="action-summary-grid" id="actionSummaryGrid"></div>
      <div class="kpi-grid" id="kpiGrid"></div>
      <div class="charts-grid" id="chartsGrid"></div>
      <div class="wow-deck" id="wowDeck">
        <div class="wow-card">
          <h3>Mission Pulse</h3>
          <div class="wow-sub">Per-category pass/fail pressure with animated trend bars.</div>
          <div class="wow-canvas-wrap"><canvas id="wowPulseChart"></canvas></div>
        </div>
        <div class="wow-card">
          <h3>Latency Spectrum</h3>
          <div class="wow-sub">Distribution of measured response times across all tested endpoints.</div>
          <div class="wow-canvas-wrap"><canvas id="wowLatencyChart"></canvas></div>
        </div>
      </div>
      <div class="overview-breakdown">
        <div style="font-size:12px;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.06em;">Category Breakdown</div>
        <div id="catBreakdown"></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: RTT -->
<div id="tab-rtt" class="tab-panel">
  <div class="sec-header">
    <div>
      <h2>Azure RTT and Backbone Reference</h2>
      <div class="sub">Live client-to-Azure RTT plus static April 2026 Azure region-to-region reference data for Cloud PC planning. Informational only and excluded from the endpoint compliance score.</div>
    </div>
    <div class="btn-row"><button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button></div>
  </div>
  <div id="rttContent"></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: READINESS -->
<div id="tab-readiness" class="tab-panel">
  <div class="sec-header">
    <div>
      <h2>Readiness Signals</h2>
      <div class="sub">Supplemental checks for UDP and Shortpath heuristics, proxy pathing, public egress identity, time sync, certificate trust, and endpoint-list freshness.</div>
    </div>
    <div class="btn-row"><button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button></div>
  </div>
  <div id="readinessContent"></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: W365 CLOUD PC -->
<div id="tab-w365host" class="tab-panel">
  <div class="sec-header">
    <div><h2>W365 Cloud PC Endpoints</h2><div class="sub">Required from the Cloud PC / provisioning VNet · Port 443 &amp; 5671</div></div>
    <div class="btn-row">
      <button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button>
    </div>
  </div>
  <div class="toolbar">
    <input type="text" id="s-w365host" placeholder="Search hostname…" oninput="doSearch('w365host',this.value)">
    <button class="chip active" onclick="doFilter('w365host','ALL',this)">All</button>
    <button class="chip" onclick="doFilter('w365host','Pass',this)">✓ Pass</button>
    <button class="chip" onclick="doFilter('w365host','FAIL',this)">✗ Failures</button>
    <button class="chip" onclick="doFilter('w365host','ADVISORY',this)">~ Advisory</button>
    <span id="count-w365host" style="font-size:12px;color:var(--muted);margin-left:4px"></span>
  </div>
  <div class="table-wrap"><table id="tbl-w365host">
    <thead><tr>
      <th onclick="sortTable('w365host',0,this)">Hostname <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',1,this)">Port <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',2,this)">Protocol <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',3,this)">Status <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',4,this)">Response (ms) <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',5,this)">Description <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365host',6,this)">Next Action <span class="sort-icon"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: AVD -->
<div id="tab-avd" class="tab-panel">
  <div class="sec-header">
    <div><h2>AVD Host Endpoints</h2><div class="sub">Required from the session host virtual machines, including documented dependency additions</div></div>
    <div class="btn-row"><button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button></div>
  </div>
  <div class="toolbar">
    <input type="text" id="s-avd" placeholder="Search hostname…" oninput="doSearch('avd',this.value)">
    <button class="chip active" onclick="doFilter('avd','ALL',this)">All</button>
    <button class="chip" onclick="doFilter('avd','Pass',this)">✓ Pass</button>
    <button class="chip" onclick="doFilter('avd','FAIL',this)">✗ Failures</button>
    <button class="chip" onclick="doFilter('avd','ADVISORY',this)">~ Advisory</button>
    <span id="count-avd" style="font-size:12px;color:var(--muted);margin-left:4px"></span>
  </div>
  <div class="table-wrap"><table id="tbl-avd">
    <thead><tr>
      <th onclick="sortTable('avd',0,this)">Hostname <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',1,this)">Port <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',2,this)">Protocol <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',3,this)">Status <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',4,this)">Response (ms) <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',5,this)">Description <span class="sort-icon"></span></th>
      <th onclick="sortTable('avd',6,this)">Next Action <span class="sort-icon"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: INTUNE -->
<div id="tab-intune" class="tab-panel">
  <div class="sec-header">
    <div><h2>Intune (MEM) Endpoints</h2><div class="sub">Microsoft Endpoint Manager — fetched live from endpoints.office.com and supplemented with documented Intune dependencies</div></div>
    <div class="btn-row"><button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button></div>
  </div>
  <div class="toolbar">
    <input type="text" id="s-intune" placeholder="Search hostname…" oninput="doSearch('intune',this.value)">
    <button class="chip active" onclick="doFilter('intune','ALL',this)">All</button>
    <button class="chip" onclick="doFilter('intune','Pass',this)">✓ Pass</button>
    <button class="chip" onclick="doFilter('intune','FAIL',this)">✗ Failures</button>
    <button class="chip" onclick="doFilter('intune','ADVISORY',this)">~ Advisory</button>
    <span id="count-intune" style="font-size:12px;color:var(--muted);margin-left:4px"></span>
  </div>
  <div class="table-wrap"><table id="tbl-intune">
    <thead><tr>
      <th onclick="sortTable('intune',0,this)">Hostname <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',1,this)">Port <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',2,this)">Protocol <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',3,this)">Status <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',4,this)">Response (ms) <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',5,this)">Description <span class="sort-icon"></span></th>
      <th onclick="sortTable('intune',6,this)">Next Action <span class="sort-icon"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: USER DEVICE -->
<div id="tab-w365client" class="tab-panel">
  <div class="sec-header">
    <div><h2>User Device Endpoints</h2><div class="sub">Required from the user's laptop or other physical device / client network — AIA, CRL &amp; OCSP chains included</div></div>
    <div class="btn-row"><button class="btn btn-ghost" onclick="exportExcel()">⬇ Export Excel</button></div>
  </div>
  <div class="toolbar">
    <input type="text" id="s-w365client" placeholder="Search hostname…" oninput="doSearch('w365client',this.value)">
    <button class="chip active" onclick="doFilter('w365client','ALL',this)">All</button>
    <button class="chip" onclick="doFilter('w365client','Pass',this)">✓ Pass</button>
    <button class="chip" onclick="doFilter('w365client','FAIL',this)">✗ Failures</button>
    <button class="chip" onclick="doFilter('w365client','ADVISORY',this)">~ Advisory</button>
    <span id="count-w365client" style="font-size:12px;color:var(--muted);margin-left:4px"></span>
  </div>
  <div class="table-wrap"><table id="tbl-w365client">
    <thead><tr>
      <th onclick="sortTable('w365client',0,this)">Hostname <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',1,this)">Port <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',2,this)">Protocol <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',3,this)">Status <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',4,this)">Response (ms) <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',5,this)">Description <span class="sort-icon"></span></th>
      <th onclick="sortTable('w365client',6,this)">Next Action <span class="sort-icon"></span></th>
    </tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: FIREWALL -->
<div id="tab-firewall" class="tab-panel">
  <div class="sec-header">
    <div><h2>Firewall Rule Recommendations</h2><div class="sub" id="fwSub"></div></div>
    <div class="btn-row">
      <button class="btn btn-ghost" onclick="copyRules()">📋 Copy to Clipboard</button>
      <button class="btn" onclick="downloadRetry()">⬇ Download Retry Script</button>
    </div>
  </div>
    <p id="fwIntro" style="font-size:12px;color:var(--muted);margin-bottom:12px;">
    The following host:port combinations failed all connectivity tests.
    Share this list with your network or firewall team and request these outbound TCP rules be opened.
  </p>
    <div id="firewallSummary" class="firewall-summary-grid"></div>
    <div class="firewall-layout">
      <div class="rule-box" id="ruleBox"></div>
      <div class="firewall-advisory" id="firewallWildcardNote"></div>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════ TAB: COMPARE -->
<div id="tab-compare" class="tab-panel">
  <div class="sec-header">
    <div><h2>Compare Results</h2><div class="sub">Load a previous <code>W365-Results-*.json</code> to see what changed between scans</div></div>
  </div>
  <div class="drop-zone" id="dropZone"
       onclick="document.getElementById('fileInput').click()"
       ondragover="event.preventDefault();this.classList.add('over')"
       ondragleave="this.classList.remove('over')"
       ondrop="onDrop(event)">
    <div class="icon">📂</div>
    <div>Drop a <strong>W365-Results-*.json</strong> file here, or click to browse</div>
    <div class="hint">The JSON sidecar saved alongside the HTML report</div>
    <input id="fileInput" type="file" accept=".json" style="display:none" onchange="onFileSelect(this)">
  </div>
  <div id="compareOut" style="display:none">
    <div class="kpi-grid" id="cmpKpis" style="margin-top:16px"></div>
    <div class="toolbar" style="margin-top:4px">
      <button class="chip active" onclick="doCmpFilter('ALL',this)">All</button>
      <button class="chip" onclick="doCmpFilter('Resolved',this)">Resolved ✓</button>
      <button class="chip" onclick="doCmpFilter('Regressed',this)">Regressed ✗</button>
      <button class="chip" onclick="doCmpFilter('New',this)">New</button>
      <button class="chip" onclick="doCmpFilter('Unchanged',this)">Unchanged</button>
    </div>
    <div class="table-wrap"><table id="tbl-compare">
      <thead><tr>
        <th>Hostname</th><th>Port</th><th>Category</th>
        <th>Previous</th><th>Current</th><th>Change</th>
      </tr></thead>
      <tbody></tbody>
    </table></div>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════ SCRIPT -->
<script>
// ── DATA (injected by PowerShell) ────────────────────────────────
const RAW = ##RESULTS_JSON##;
const results = RAW.results || [];
const azureRtt = RAW.azureRtt || [];
const azureBackboneRtt = RAW.azureBackboneRtt || { rows: [], regions: [] };
const meta    = RAW.meta    || {};

// ── CONSTANTS ────────────────────────────────────────────────────
const CAT_MAP = {
  'W365-Host':  'w365host',
  'AVD-Host':   'avd',
  'Intune-MEM': 'intune',
  'W365-Client':'w365client'
};
const CAT_LABEL = {
  'w365host':  'W365 Cloud PC',
  'avd':       'AVD Host',
  'intune':    'Intune (MEM)',
  'w365client':'User Device'
};
const TABS   = ['w365host','w365client','avd','intune'];
const COLORS = { Pass:'#3fb950', Fail:'#f85149', Wildcard:'#d29922', 'IP Range':'#d29922' };

// Per-tab state
const state = {};
TABS.forEach(t => { state[t] = { filter:'ALL', search:'', sortCol:-1, sortDir:1 }; });

function isFailureResult(result) {
  return /Fail$/.test(result || '');
}

function isAdvisoryResult(result) {
  return result === 'Wildcard' || result === 'IP Range';
}

function latencyClass(ms) {
  if (typeof ms !== 'number' || ms < 0) return 'latency-none';
  if (ms < 150) return 'latency-good';
  if (ms <= 500) return 'latency-warn';
  return 'latency-bad';
}

function statusClass(result) {
  if (result === 'Pass') return 'badge-pass';
  if (isAdvisoryResult(result)) return 'badge-warn';
  if (isFailureResult(result)) return 'badge-fail';
  return 'badge-neutral';
}

function statusIcon(result) {
  if (result === 'Pass') return '✓';
  if (isAdvisoryResult(result)) return '~';
  if (isFailureResult(result)) return '✗';
  return '•';
}

function fmt(value) {
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
  return value ? String(value) : '—';
}

function rttMedianValue(region) {
  return typeof region.medianLatencyMs === 'number' ? region.medianLatencyMs : region.latencyMs;
}

function rttLatestValue(region) {
  return typeof region.latestLatencyMs === 'number' ? region.latestLatencyMs : region.latencyMs;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getLiveRttOptions() {
  return azureRtt
    .filter(region => region.status === 'Pass' && typeof rttMedianValue(region) === 'number' && rttMedianValue(region) >= 0)
    .sort((a, b) => rttMedianValue(a) - rttMedianValue(b));
}

function getDefaultBackboneSelections() {
  const liveOptions = getLiveRttOptions();
  const source = liveOptions[0]?.displayName || azureBackboneRtt.regions?.[0] || '';
  const target = source || azureBackboneRtt.regions?.[0] || '';
  return { source, target };
}

function getBackboneRttValue(source, target) {
  if (!source || !target) return null;
  if (source === target) return 0;
  const rows = azureBackboneRtt.rows || [];
  const direct = rows.find(item => item.source === source && item.target === target);
  if (direct && typeof direct.p50RttMs === 'number') return direct.p50RttMs;
  const reverse = rows.find(item => item.source === target && item.target === source);
  if (reverse && typeof reverse.p50RttMs === 'number') return reverse.p50RttMs;
  return null;
}

function getLiveRttValue(regionName) {
  const match = azureRtt.find(region => region.displayName === regionName && region.status === 'Pass');
  if (!match) return null;
  const median = rttMedianValue(match);
  return typeof median === 'number' && median >= 0 ? median : null;
}

function getCurrentBackbonePlan() {
  const defaults = getDefaultBackboneSelections();
  const source = document.getElementById('backboneSourceRegion')?.value || defaults.source;
  const target = document.getElementById('backboneTargetRegion')?.value || defaults.target;
  const liveClientRtt = getLiveRttValue(source);
  const backboneRtt = getBackboneRttValue(source, target);
  const combinedRtt = typeof liveClientRtt === 'number' && typeof backboneRtt === 'number'
    ? liveClientRtt + backboneRtt
    : null;

  return { source, target, liveClientRtt, backboneRtt, combinedRtt };
}

function renderBackbonePlanner() {
  const plan = getCurrentBackbonePlan();
  const refValue = document.getElementById('backboneReferenceValue');
  const refMeta = document.getElementById('backboneReferenceMeta');
  const combinedValue = document.getElementById('combinedPlanningValue');
  const combinedMeta = document.getElementById('combinedPlanningMeta');

  if (refValue) {
    refValue.textContent = typeof plan.backboneRtt === 'number' ? `${plan.backboneRtt} ms` : '—';
    refValue.className = `ms ${typeof plan.backboneRtt === 'number' ? latencyClass(plan.backboneRtt) : 'latency-none'}`;
  }

  if (refMeta) {
    refMeta.innerHTML = `
      <div><strong>Source region:</strong> ${escapeHtml(plan.source || '—')}</div>
      <div><strong>Cloud PC region:</strong> ${escapeHtml(plan.target || '—')}</div>
      <div><strong>Dataset:</strong> ${escapeHtml(azureBackboneRtt.datasetName || 'Azure backbone reference')}</div>
      <div><strong>Metric:</strong> ${escapeHtml(azureBackboneRtt.metric || 'P50 RTT')}</div>`;
  }

  if (combinedValue) {
    combinedValue.textContent = typeof plan.combinedRtt === 'number' ? `${plan.combinedRtt} ms` : '—';
    combinedValue.className = `ms ${typeof plan.combinedRtt === 'number' ? latencyClass(plan.combinedRtt) : 'latency-none'}`;
  }

  if (combinedMeta) {
    const liveText = typeof plan.liveClientRtt === 'number'
      ? `${plan.liveClientRtt} ms measured from this scan`
      : 'No live RTT result for the selected source region in this scan';
    const backboneText = typeof plan.backboneRtt === 'number'
      ? `${plan.backboneRtt} ms static Azure backbone reference`
      : 'No static Azure backbone value was found for this region pair';
    combinedMeta.innerHTML = `
      <div><strong>Client to Azure:</strong> ${escapeHtml(liveText)}</div>
      <div><strong>Azure to Azure:</strong> ${escapeHtml(backboneText)}</div>
      <div><strong>Use:</strong> Planning estimate only, not an observed end-to-end session RTT.</div>`;
  }
}

function getRemediation(row) {
  const category = row.remediationCategory || 'No action required';
  const audience = row.remediationAudience || 'None';
  const nextAction = row.nextAction || 'No action required';
  const priority = typeof row.actionPriority === 'number' ? row.actionPriority : 0;
  return { category, audience, nextAction, priority };
}

function remediationBadgeClass(row) {
  const remediation = getRemediation(row);
  if (remediation.priority === 0) return 'badge-neutral';
  if (remediation.category === 'Wildcard allowlist gap' || remediation.category === 'IP range allowlist gap' || remediation.category === 'DNS issue') return 'badge-warn';
  return 'badge-fail';
}

function getActionableRows() {
  return results.filter(row => getRemediation(row).priority > 0);
}

function getAudienceDefinitions() {
  return [
    {
      title: 'Infrastructure - Network/Firewall Team',
      defaultAction: 'Review DNS resolution, open outbound access where TCP is blocked, and review SSL inspection, wildcard allowlists, and IP range allowlists for Microsoft traffic.'
    }
  ];
}

function getTopRemediationCategory(rows) {
  const counts = {};
  rows.forEach(row => {
    const key = getRemediation(row).category;
    counts[key] = (counts[key] || 0) + 1;
  });
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'No action required';
}

function renderActionSummary() {
  const target = document.getElementById('actionSummaryGrid');
  const actionable = getActionableRows();
  const audiences = getAudienceDefinitions();

  target.innerHTML = audiences.map(audience => {
    const rows = actionable.filter(row => getRemediation(row).audience === audience.title);
    const topCategory = getTopRemediationCategory(rows);
    const count = rows.length;
    const colorClass = count === 0 ? 'c-pass' : topCategory === 'Wildcard allowlist gap' || topCategory === 'IP range allowlist gap' || topCategory === 'DNS issue' ? 'c-warn' : 'c-fail';

    return `
      <div class="action-summary-card">
        <h3>${audience.title}</h3>
        <div class="count ${colorClass}">${count}</div>
        <div class="top"><strong>Top issue:</strong> ${count ? topCategory : 'No action required'}</div>
        <div class="desc">${count ? audience.defaultAction : 'No immediate action is required for this audience based on the current scan.'}</div>
      </div>`;
  }).join('');
}

// ── INIT ────────────────────────────────────────────────────────
function readinessBadgeClass(status) {
  const value = (status || '').toLowerCase();
  if (value.includes('pass') || value.includes('ready') || value === 'yes' || value === 'direct') return 'badge-pass';
  if (value.includes('warn') || value.includes('likely') || value.includes('unknown') || value === 'proxy') return 'badge-warn';
  if (value.includes('fail') || value.includes('risk') || value === 'no') return 'badge-fail';
  return 'badge-neutral';
}

// ── GSAP Animation Setup ──────────────────────────────────────
function initializeAnimations() {
  // KPI counter animation: animate numbers from 0 to final value
  const kpiVals = document.querySelectorAll('.kpi-card .val');
  kpiVals.forEach((el, idx) => {
    const text = el.textContent.trim();
    const numMatch = text.match(/\d+/);
    if (numMatch) {
      const finalValue = parseInt(numMatch[0], 10);
      const obj = { value: 0 };
      gsap.to(obj, {
        value: finalValue,
        duration: 1.2,
        delay: idx * 0.1,
        ease: 'power2.out',
        onUpdate() { el.textContent = Math.round(obj.value) + (text.includes('%') ? '%' : ''); }
      });
    }
  });

  // Tab button reveal animation
  const tabButtons = document.querySelectorAll('.tabbar button');
  gsap.fromTo(tabButtons, 
    { opacity: 0, y: -8 },
    { opacity: 1, y: 0, duration: 0.5, delay: (i) => i * 0.08, stagger: 0.05 }
  );

  // Card stagger entrance
  const cards = document.querySelectorAll('.action-summary-card, .context-card');
  gsap.fromTo(cards,
    { opacity: 0, y: 12 },
    { opacity: 1, y: 0, duration: 0.6, delay: 0.3, stagger: 0.04, ease: 'back.out' }
  );

  // Table row cascade animation on first show
  setTimeout(() => {
    const rows = document.querySelectorAll('#tbl-w365host tbody tr, #tbl-avd tbody tr, #tbl-intune tbody tr, #tbl-w365client tbody tr');
    gsap.fromTo(rows,
      { opacity: 0, x: -10 },
      { opacity: 1, x: 0, duration: 0.3, stagger: 0.02, ease: 'sine.out' }
    );
  }, 600);
}

// ── Tab Switching with Animation ──────────────────────────────
const originalShowTab = window.showTab;
window.showTab = function(tabName, btn) {
  originalShowTab(tabName, btn);
  // Animate content in
  const panel = document.getElementById(`tab-${tabName}`);
  if (panel) {
    panel.style.opacity = '0';
    gsap.fromTo(panel, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.32, ease: 'power1.out' });
  }
};

window.addEventListener('DOMContentLoaded', () => {
  renderHeader();
  renderHealthBanner();
  renderActionSummary();
  renderNetworkContext();
  renderRttTab();
  renderReadinessTab();
  renderKPIs();
  renderCharts();
  renderWowCharts();
  renderCatBreakdown();
  TABS.forEach(renderTable);
  renderFirewall();
  updateTabBadges();
  bindKeyboardTabs();
  initializeAnimations();
});

// ── HEADER ───────────────────────────────────────────────────────
function renderHeader() {
  const d = meta.scanDate ? new Date(meta.scanDate).toLocaleString() : '—';
  const nic = meta.networkContext?.interfaceAlias ? ` · NIC: ${meta.networkContext.interfaceAlias}` : '';
  const os = meta.operatingSystem?.summary ? ` · OS: ${meta.operatingSystem.summary}` : '';
  document.getElementById('hdrSub').textContent =
    `Test Mode: ${meta.testMode||'—'} · Script ${meta.scriptVersion||'v1.0'}${nic}${os}`;
  document.getElementById('hdrMeta').innerHTML =
    `<strong>${meta.hostname||'Unknown'}</strong><br>${d}<br>Duration: ${meta.durationSeconds||0}s · Timeout: ${meta.timeoutMs||0}ms`;
}

// ── HEALTH / NETWORK CONTEXT ────────────────────────────────────
function renderHealthBanner() {
  const failCount = results.filter(r => isFailureResult(r.result)).length;
  const banner = document.getElementById('healthBanner');
  let klass = 'health-ok';
  let title = '✅ All critical endpoints reachable — Cloud PC provisioning should succeed';
  let detail = 'No DNS, TCP, or TLS blockers were detected in this scan.';

  if (failCount > 0 && failCount <= 3) {
    klass = 'health-warn';
    title = `⚠ ${failCount} endpoint${failCount !== 1 ? 's' : ''} blocked — submit remediation before provisioning`;
    detail = 'Review the affected rows to determine whether the blocker is DNS, firewall, or TLS inspection.';
  } else if (failCount > 3) {
    klass = 'health-bad';
    title = `❌ ${failCount} endpoints blocked — provisioning or sign-in workflows are likely to fail`;
    detail = 'Prioritize TCP failures for firewall changes and TLS failures for proxy or SSL inspection review.';
  }

  banner.className = `health-banner ${klass}`;
  banner.innerHTML = `${title}<span class="sub">${detail}</span>`;
}

function renderNetworkContext() {
  const ctx = meta.networkContext || {};
  const os = meta.operatingSystem || {};
  const env = meta.environmentFingerprint || {};
  const egress = meta.publicEgress || {};
  const cards = [
    {
      title: 'Operating System',
      rows: [
        ['Name', fmt(os.name)],
        ['Version', fmt(os.version)],
        ['Build', fmt(os.build)]
      ]
    },
    {
      title: 'Network Path',
      rows: [
        ['Interface', fmt(ctx.interfaceAlias)],
        ['IPv4', fmt(ctx.ipv4Address)],
        ['Gateway', fmt(ctx.defaultGateway)],
        ['DNS', fmt(ctx.dnsServers)]
      ]
    },
    {
      title: 'Proxy Context',
      rows: [
        ['WinHTTP', fmt(ctx.winHttpProxy)],
        ['WinINet', fmt(ctx.winInetProxyEnabled)],
        ['Proxy Server', fmt(ctx.winInetProxyServer)],
        ['PAC URL', fmt(ctx.winInetAutoConfigUrl)],
        ['Auto Detect', fmt(ctx.winInetAutoDetect)],
        ['HTTPS_PROXY', fmt(ctx.httpsProxy)],
        ['HTTP_PROXY', fmt(ctx.httpProxy)],
        ['NO_PROXY', fmt(ctx.noProxy)]
      ]
    },
    {
      title: 'Environment Fingerprint',
      rows: [
        ['Interface Type', fmt(env.interfaceType)],
        ['SSID', fmt(env.connectedSsid)],
        ['VPN', fmt(env.vpnDetected)],
        ['Domain Joined', fmt(env.domainJoined)],
        ['Entra Joined', fmt(env.entraJoined)],
        ['Reboot Pending', fmt(env.rebootPending)]
      ]
    },
    {
      title: 'Public Egress',
      rows: [
        ['Route', fmt(egress.route)],
        ['Public IP', fmt(egress.ip)],
        ['ASN', fmt(egress.asn)],
        ['Provider', fmt(egress.organization)],
        ['Location', fmt([egress.city, egress.region, egress.country].filter(Boolean).join(', '))],
        ['SWG Suspected', fmt(egress.secureWebGatewaySuspected)]
      ]
    }
  ];

  document.getElementById('contextGrid').innerHTML = cards.map(card => `
    <div class="context-card">
      <h3>${card.title}</h3>
      ${card.rows.map(([k,v]) => `<div class="context-item"><span class="k">${k}</span><span class="v">${v}</span></div>`).join('')}
    </div>
  `).join('');
}

function renderReadinessTab() {
  const target = document.getElementById('readinessContent');
  const udp = meta.udpShortpathReadiness || {};
  const time = meta.timeSync || {};
  const proxy = meta.proxyDiagnostics || {};
  const egress = meta.publicEgress || {};
  const env = meta.environmentFingerprint || {};
  const currency = meta.endpointCurrency || {};
  const certs = meta.certificateReadiness || [];

  target.innerHTML = `
    <div class="readiness-grid">
      <div class="context-card">
        <h3>UDP and Shortpath</h3>
        <div class="context-item"><span class="k">UDP Egress</span><span class="v"><span class="badge ${readinessBadgeClass(udp.generalUdpStatus)}">${fmt(udp.generalUdpStatus)}</span></span></div>
        <div class="context-item"><span class="k">UDP RTT</span><span class="v">${udp.generalUdpRttMs >= 0 ? `${udp.generalUdpRttMs} ms` : '—'}</span></div>
        <div class="context-item"><span class="k">NAT Mapping</span><span class="v mono">${fmt(udp.natPublicEndpoint)}</span></div>
        <div class="context-item"><span class="k">Shortpath</span><span class="v"><span class="badge ${readinessBadgeClass(udp.shortpathStatus)}">${fmt(udp.shortpathStatus)}</span></span></div>
      </div>
      <div class="context-card">
        <h3>Time Sync</h3>
        <div class="context-item"><span class="k">Status</span><span class="v"><span class="badge ${readinessBadgeClass(time.status)}">${fmt(time.status)}</span></span></div>
        <div class="context-item"><span class="k">Service</span><span class="v">${fmt(time.serviceStatus)}</span></div>
        <div class="context-item"><span class="k">Source</span><span class="v">${fmt(time.source)}</span></div>
        <div class="context-item"><span class="k">Clock Offset</span><span class="v">${time.clockOffsetMs !== '' ? `${time.clockOffsetMs} ms` : '—'}</span></div>
      </div>
      <div class="context-card">
        <h3>Public Egress</h3>
        <div class="context-item"><span class="k">Route</span><span class="v"><span class="badge ${readinessBadgeClass(egress.route)}">${fmt(egress.route)}</span></span></div>
        <div class="context-item"><span class="k">IP</span><span class="v mono">${fmt(egress.ip)}</span></div>
        <div class="context-item"><span class="k">ASN</span><span class="v">${fmt(egress.asn)}</span></div>
        <div class="context-item"><span class="k">Provider</span><span class="v">${fmt(egress.organization)}</span></div>
      </div>
      <div class="context-card">
        <h3>Endpoint Currency</h3>
        <div class="context-item"><span class="k">Status</span><span class="v"><span class="badge ${readinessBadgeClass(currency.status)}">${fmt(currency.status)}</span></span></div>
        <div class="context-item"><span class="k">Reviewed On</span><span class="v">${fmt(currency.reviewedOn)}</span></div>
        <div class="context-item"><span class="k">Days Old</span><span class="v">${fmt(currency.daysSinceReview)}</span></div>
        <div class="context-item"><span class="k">Threshold</span><span class="v">${fmt(currency.staleAfterDays)} days</span></div>
      </div>
    </div>

    <div class="readiness-section">
      <h3>Environment and Proxy</h3>
      <div class="context-grid" style="margin-bottom:0">
        <div class="context-card">
          <h3>Environment</h3>
          <div class="context-item"><span class="k">Interface</span><span class="v">${fmt(env.interfaceType)}</span></div>
          <div class="context-item"><span class="k">SSID</span><span class="v">${fmt(env.connectedSsid)}</span></div>
          <div class="context-item"><span class="k">VPN</span><span class="v">${fmt(env.vpnDetected)}</span></div>
          <div class="context-item"><span class="k">VPN Adapters</span><span class="v">${fmt(env.vpnAdapters)}</span></div>
          <div class="context-item"><span class="k">Domain Joined</span><span class="v">${fmt(env.domainJoined)}</span></div>
          <div class="context-item"><span class="k">Entra Joined</span><span class="v">${fmt(env.entraJoined)}</span></div>
          <div class="context-item"><span class="k">Reboot Pending</span><span class="v">${fmt(env.rebootPending)}</span></div>
          <div class="context-item"><span class="k">Reboot Detail</span><span class="v">${fmt(env.rebootPendingDetail)}</span></div>
          <div class="context-item"><span class="k">SWG</span><span class="v">${fmt(env.secureWebGateway)}</span></div>
        </div>
        <div class="context-card">
          <h3>Proxy Diagnostics</h3>
          <div class="context-item"><span class="k">Status</span><span class="v">${fmt(proxy.status)}</span></div>
          <div class="context-item"><span class="k">Configured</span><span class="v">${fmt(proxy.proxyConfigured)}</span></div>
          <div class="context-item"><span class="k">Proxy URI</span><span class="v mono">${fmt(proxy.proxyUri)}</span></div>
          <div class="context-item"><span class="k">Proxy Auth</span><span class="v">${fmt(proxy.proxyAuthRequired)}</span></div>
          <div class="context-item"><span class="k">Authenticate</span><span class="v">${fmt(proxy.proxyAuthenticate)}</span></div>
          <div class="context-item"><span class="k">SWG Suspected</span><span class="v">${fmt(proxy.secureWebGatewaySuspected)}</span></div>
          <div class="context-item"><span class="k">Detail</span><span class="v">${fmt(proxy.detail)}</span></div>
        </div>
      </div>
    </div>

    <div class="readiness-section">
      <h3>Certificate Readiness</h3>
      <div class="table-wrap"><table>
        <thead><tr>
          <th>Host</th><th>Status</th><th>TLS</th><th>Name Match</th><th>Chain</th><th>Issuer</th><th>Inspection</th><th>Detail</th>
        </tr></thead>
        <tbody>
          ${certs.length ? certs.map(cert => `
            <tr class="${cert.status === 'Pass' ? 'row-pass' : cert.status === 'Issue' ? 'row-warn' : 'row-fail'}">
              <td class="mono">${cert.hostname}:${cert.port}</td>
              <td><span class="badge ${readinessBadgeClass(cert.status)}">${fmt(cert.status)}</span></td>
              <td>${fmt(cert.tlsProtocol)}</td>
              <td>${fmt(cert.sanMatch)}</td>
              <td>${fmt(cert.chainStatus)}</td>
              <td title="${fmt(cert.certificateSubject).replace(/"/g,'&quot;')}">${fmt(cert.certificateIssuer)}</td>
              <td>${fmt(cert.sslInspectionSuspected)}</td>
              <td title="${fmt(cert.detail).replace(/"/g,'&quot;')}">${fmt(cert.detail)}</td>
            </tr>`).join('') : '<tr class="empty-row"><td colspan="8">No certificate readiness data was collected.</td></tr>'}
        </tbody>
      </table></div>
    </div>

    <div class="readiness-section">
      <h3>Endpoint Documentation Sources</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Source</th><th>Reachable</th><th>Last Modified</th><th>ETag</th><th>URI</th><th>Detail</th></tr></thead>
        <tbody>
          ${(currency.documents || []).length ? currency.documents.map(doc => `
            <tr class="${doc.reachable === 'Yes' ? 'row-pass' : 'row-warn'}">
              <td>${fmt(doc.name)}</td>
              <td><span class="badge ${doc.reachable === 'Yes' ? 'badge-pass' : 'badge-warn'}">${fmt(doc.reachable)}</span></td>
              <td>${fmt(doc.lastModified)}</td>
              <td>${fmt(doc.etag)}</td>
              <td class="mono">${fmt(doc.uri)}</td>
              <td>${fmt(doc.detail)}</td>
            </tr>`).join('') : '<tr class="empty-row"><td colspan="6">No documentation metadata was collected.</td></tr>'}
        </tbody>
      </table></div>
    </div>`;
}

function renderRttTab() {
  const target = document.getElementById('rttContent');
  const sorted = [...azureRtt].sort((a, b) => {
    const aOk = a.status === 'Pass';
    const bOk = b.status === 'Pass';
    if (aOk !== bOk) return aOk ? -1 : 1;
    return (rttMedianValue(a) || Number.MAX_SAFE_INTEGER) - (rttMedianValue(b) || Number.MAX_SAFE_INTEGER);
  });

  const best = sorted.find(region => region.status === 'Pass');
  const requestedSamples = sorted[0]?.requestedSamples || 0;
  const defaults = getDefaultBackboneSelections();
  const liveOptions = getLiveRttOptions();
  const targetOptions = azureBackboneRtt.regions || [];
  const hasBackboneReference = !!(azureBackboneRtt.rows?.length);

  const plannerMarkup = `
    <div class="azure-rtt-section">
      <div class="azure-rtt-head">
        <div>
          <h3>Azure Backbone Reference</h3>
          <p>Static April 2026 Microsoft Azure inter-region P50 RTT data. Use this to estimate the Azure-to-Azure segment between the client-aligned Azure entry region and the Cloud PC region.</p>
        </div>
      </div>
      ${hasBackboneReference ? '' : '<div class="context-card" style="margin-bottom:12px;"><h3>Dataset Missing</h3><div class="context-item"><span class="k">Status</span><span class="v">Azure backbone reference file not found</span></div><div class="context-item"><span class="k">Effect</span><span class="v">Combined planning estimate unavailable</span></div><div class="meta" style="margin-top:8px;">Place azure-rtt-reference-apr2026.json under Azure Network RTT Stats - April 2026 to re-enable planner calculations.</div></div>'}
      <div class="azure-rtt-grid">
        <div class="azure-rtt-card">
          <h4>Azure to Azure</h4>
          <div class="loc">Select the measured Azure entry region and the target Cloud PC region.</div>
          <div class="context-item"><span class="k">Entry Region</span><span class="v"><select id="backboneSourceRegion" class="rtt-select" ${hasBackboneReference ? '' : 'disabled'}>${liveOptions.map(region => `<option value="${escapeHtml(region.displayName)}" ${region.displayName === defaults.source ? 'selected' : ''}>${escapeHtml(region.displayName)}</option>`).join('')}</select></span></div>
          <div class="context-item"><span class="k">Cloud PC Region</span><span class="v"><select id="backboneTargetRegion" class="rtt-select" ${hasBackboneReference ? '' : 'disabled'}>${targetOptions.map(region => `<option value="${escapeHtml(region)}" ${region === defaults.target ? 'selected' : ''}>${escapeHtml(region)}</option>`).join('')}</select></span></div>
          <div id="backboneReferenceValue" class="ms">—</div>
          <div id="backboneReferenceMeta" class="meta"></div>
        </div>
        <div class="azure-rtt-card">
          <h4>Combined Planning Estimate</h4>
          <div class="loc">Live client-to-Azure median RTT plus the selected Azure backbone reference.</div>
          <div id="combinedPlanningValue" class="ms">—</div>
          <div id="combinedPlanningMeta" class="meta"></div>
        </div>
        <div class="azure-rtt-card">
          <h4>Dataset</h4>
          <div class="loc">Reference data only</div>
          <div class="context-item"><span class="k">Dataset</span><span class="v">${escapeHtml(azureBackboneRtt.datasetName || '—')}</span></div>
          <div class="context-item"><span class="k">Date</span><span class="v">${escapeHtml(azureBackboneRtt.datasetDate || '—')}</span></div>
          <div class="context-item"><span class="k">Metric</span><span class="v">${escapeHtml(azureBackboneRtt.metric || '—')}</span></div>
          <div class="context-item"><span class="k">Regions</span><span class="v">${targetOptions.length}</span></div>
          <div class="meta">Published Azure backbone RTT reference from Microsoft Learn. This is not measured by the local scan.</div>
        </div>
      </div>
    </div>`;

  const liveTableMarkup = azureRtt.length ? `
    <div class="table-wrap"><table id="tbl-rtt">
      <thead><tr>
        <th>Region</th>
        <th>Location</th>
        <th>Status</th>
        <th>Median RTT (ms)</th>
        <th>Latest RTT (ms)</th>
        <th>Samples</th>
        <th>Method</th>
        <th>Target</th>
        <th>Detail</th>
      </tr></thead>
      <tbody>
        ${sorted.map(region => {
          const median = rttMedianValue(region);
          const latest = rttLatestValue(region);
          const sampleSummary = `${region.successfulSamples || 0}/${region.requestedSamples || 0}`;
          const storageText = region.storageAccountName ? `${region.storageAccountName}.blob.core.windows.net` : 'No regional target resolved';
          return `
            <tr class="${region.status === 'Pass' ? 'row-pass' : 'row-fail'}">
              <td>${region.displayName}</td>
              <td>${region.location}</td>
              <td><span class="badge ${region.status === 'Pass' ? 'badge-pass' : 'badge-fail'}">${region.status}</span></td>
              <td><span class="${region.status === 'Pass' ? latencyClass(median) : 'latency-none'}">${region.status === 'Pass' ? median : '—'}</span></td>
              <td><span class="${region.status === 'Pass' ? latencyClass(latest) : 'latency-none'}">${region.status === 'Pass' ? latest : '—'}</span></td>
              <td>${sampleSummary}</td>
              <td>${region.method || '—'}</td>
              <td class="mono">${storageText}</td>
              <td title="${(region.detail || '').replace(/"/g, '&quot;')}">${region.detail || '—'}</td>
            </tr>`;
        }).join('')}
      </tbody>
    </table></div>` : '<div class="context-card">No live Azure RTT results were collected for this scan.</div>';

  target.innerHTML = `
    <div class="context-grid" style="margin-bottom:16px;">
      <div class="context-card">
        <h3>Live Measurement Method</h3>
        <div class="context-item"><span class="k">Protocol</span><span class="v">HTTPS HEAD</span></div>
        <div class="context-item"><span class="k">Samples</span><span class="v">${requestedSamples || '—'} per region</span></div>
        <div class="context-item"><span class="k">Primary metric</span><span class="v">Median RTT</span></div>
        <div class="context-item"><span class="k">Secondary metric</span><span class="v">Latest RTT</span></div>
        <div class="context-item"><span class="k">Segment</span><span class="v">Client device to Azure</span></div>
      </div>
      <div class="context-card">
        <h3>Best Measured Region</h3>
        <div class="context-item"><span class="k">Region</span><span class="v">${best ? best.displayName : '—'}</span></div>
        <div class="context-item"><span class="k">Location</span><span class="v">${best ? best.location : '—'}</span></div>
        <div class="context-item"><span class="k">Median RTT</span><span class="v ${best ? latencyClass(rttMedianValue(best)) : 'latency-none'}">${best ? `${rttMedianValue(best)} ms` : '—'}</span></div>
        <div class="context-item"><span class="k">Latest RTT</span><span class="v ${best ? latencyClass(rttLatestValue(best)) : 'latency-none'}">${best ? `${rttLatestValue(best)} ms` : '—'}</span></div>
      </div>
      <div class="context-card">
        <h3>Two-Part RTT View</h3>
        <div class="context-item"><span class="k">Segment 1</span><span class="v">Client to Azure</span></div>
        <div class="context-item"><span class="k">Segment 2</span><span class="v">Azure to Azure</span></div>
        <div class="context-item"><span class="k">Reference</span><span class="v">Microsoft April 2026</span></div>
        <div class="context-item"><span class="k">Use</span><span class="v">Planning estimate</span></div>
      </div>
    </div>
    <div class="rtt-map-section">
      <div class="rtt-map-head">
        <div>
          <h3>Route Intelligence</h3>
          <p>Compact view of the strongest Azure paths from your detected egress. Focus on route rankings and route detail instead of a visual map.</p>
        </div>
      </div>
      <div class="rtt-intel-strip" id="rttIntelStrip"></div>
      <div class="rtt-legend">
        <span class="rtt-legend-chip"><span class="rtt-legend-dot" style="background:#3fb950"></span> Fast path</span>
        <span class="rtt-legend-chip"><span class="rtt-legend-dot" style="background:#d29922"></span> Medium path</span>
        <span class="rtt-legend-chip"><span class="rtt-legend-dot" style="background:#f85149"></span> Slow path</span>
        <span class="rtt-legend-chip">Click any route card to inspect it</span>
      </div>
      <div class="rtt-map-layout">
        <div class="rtt-route-panel" id="rttRoutePanel"></div>
        <div class="rtt-side-stack">
          <div class="rtt-route-list" id="rttRouteList"></div>
        </div>
      </div>
    </div>
    ${plannerMarkup}
    ${liveTableMarkup}`;

  renderRttFlightMap(sorted);

  if (azureBackboneRtt.rows?.length) {
    document.getElementById('backboneSourceRegion')?.addEventListener('change', renderBackbonePlanner);
    document.getElementById('backboneTargetRegion')?.addEventListener('change', renderBackbonePlanner);
    renderBackbonePlanner();
  }
}

// ── KPIs ─────────────────────────────────────────────────────────
function renderKPIs() {
  const pass  = results.filter(r=>r.result==='Pass').length;
  const fail  = results.filter(r=>isFailureResult(r.result)).length;
  const advisory  = results.filter(r=>isAdvisoryResult(r.result)).length;
  const total = results.length;
  const testable = total - advisory;
  const pct = testable > 0 ? Math.round(pass/testable*100) : 0;

  const cards = [
    { l:'Pass Rate',    v:`${pct}%`,  c: pct===100?'c-pass':pct>=80?'c-warn':'c-fail' },
    { l:'Passed',       v:pass,       c:'c-pass' },
    { l:'Failed',       v:fail,       c:fail>0?'c-fail':'c-pass' },
    { l:'Advisory',     v:advisory,   c:advisory>0?'c-warn':'c-neutral' },
    { l:'Total Tests',  v:total,      c:'c-neutral' },
    { l:'Duration',     v:`${meta.durationSeconds||0}s`, c:'c-neutral' }
  ];
  document.getElementById('kpiGrid').innerHTML = cards.map(k=>
    `<div class="kpi-card"><div class="lbl">${k.l}</div><div class="val ${k.c}">${k.v}</div></div>`
  ).join('');
}

// ── CHARTS ───────────────────────────────────────────────────────
const chartInstances = {};
function renderCharts() {
  const grid = document.getElementById('chartsGrid');
  grid.innerHTML = '';
  Object.entries(CAT_MAP).forEach(([catKey, tabId]) => {
    const rows  = results.filter(r=>r.category===catKey);
    if (!rows.length) return;
    const pass  = rows.filter(r=>r.result==='Pass').length;
    const fail  = rows.filter(r=>isFailureResult(r.result)).length;
    const wild  = rows.filter(r=>isAdvisoryResult(r.result)).length;
    const card  = document.createElement('div');
    card.className = 'chart-card';
    card.innerHTML = `
      <h3>${CAT_LABEL[tabId]}</h3>
      <canvas id="chart-${tabId}"></canvas>
      <div class="chart-legend">
        <span><span class="dot" style="background:${COLORS.Pass}"></span>${pass} Pass</span>
        <span><span class="dot" style="background:${COLORS.Fail}"></span>${fail} Fail</span>
        <span><span class="dot" style="background:${COLORS.Wildcard}"></span>${wild} Skip</span>
      </div>`;
    grid.appendChild(card);
    chartInstances[tabId] = new Chart(document.getElementById(`chart-${tabId}`), {
      type: 'doughnut',
      data: {
        labels: ['Pass','Fail','Wildcard'],
        datasets:[{ data:[pass,fail,wild], backgroundColor:[COLORS.Pass,COLORS.Fail,COLORS.Wildcard], borderWidth:0 }]
      },
      options:{
        cutout:'68%',
        plugins:{
          legend:{display:false},
          tooltip:{callbacks:{label:c=>` ${c.label}: ${c.parsed}`}}
        }
      }
    });
  });
}

function getLatencyColor(ms) {
  if (typeof ms !== 'number' || ms < 0) return '#7d8fa5';
  if (ms <= 120) return '#3fb950';
  if (ms <= 260) return '#d29922';
  return '#f85149';
}

function renderWowCharts() {
  const pulseCanvas = document.getElementById('wowPulseChart');
  const latencyCanvas = document.getElementById('wowLatencyChart');
  if (!pulseCanvas || !latencyCanvas) return;

  if (chartInstances.wowPulse) chartInstances.wowPulse.destroy();
  if (chartInstances.wowLatency) chartInstances.wowLatency.destroy();

  const labels = [];
  const passData = [];
  const failData = [];

  Object.entries(CAT_MAP).forEach(([catKey, tabId]) => {
    const rows = results.filter(r => r.category === catKey);
    if (!rows.length) return;
    labels.push(CAT_LABEL[tabId]);
    passData.push(rows.filter(r => r.result === 'Pass').length);
    failData.push(rows.filter(r => isFailureResult(r.result)).length);
  });

  chartInstances.wowPulse = new Chart(pulseCanvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'Pass', data: passData, backgroundColor: 'rgba(63,185,80,.78)', borderRadius: 6, borderSkipped: false },
        { label: 'Fail', data: failData, backgroundColor: 'rgba(248,81,73,.84)', borderRadius: 6, borderSkipped: false }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 900, easing: 'easeOutQuart' },
      plugins: { legend: { labels: { color: '#cdefff' } } },
      scales: {
        x: { ticks: { color: '#9ec6df', maxRotation: 0, autoSkip: false }, grid: { color: 'rgba(70,120,160,.2)' } },
        y: { ticks: { color: '#9ec6df', precision: 0 }, grid: { color: 'rgba(70,120,160,.2)' }, beginAtZero: true }
      }
    }
  });

  const latencies = results
    .map(r => Number(r.responseTime_ms))
    .filter(v => Number.isFinite(v) && v >= 0)
    .sort((a, b) => a - b);

  const buckets = [0, 50, 100, 200, 400, 800, 1200, 2000, 4000];
  const bucketLabels = ['0-50', '51-100', '101-200', '201-400', '401-800', '801-1200', '1201-2000', '2001-4000'];
  const counts = Array(bucketLabels.length).fill(0);

  latencies.forEach(ms => {
    for (let i = 0; i < buckets.length - 1; i++) {
      if (ms >= buckets[i] && ms <= buckets[i + 1]) { counts[i]++; break; }
    }
  });

  chartInstances.wowLatency = new Chart(latencyCanvas, {
    type: 'line',
    data: {
      labels: bucketLabels,
      datasets: [{
        label: 'Endpoints',
        data: counts,
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,.2)',
        fill: true,
        tension: .35,
        pointRadius: 3,
        pointHoverRadius: 5,
        pointBackgroundColor: '#9ef3ff'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 1100, easing: 'easeOutQuart' },
      plugins: { legend: { labels: { color: '#cdefff' } } },
      scales: {
        x: { ticks: { color: '#9ec6df' }, grid: { color: 'rgba(70,120,160,.2)' } },
        y: { ticks: { color: '#9ec6df', precision: 0 }, grid: { color: 'rgba(70,120,160,.2)' }, beginAtZero: true }
      }
    }
  });
}

function parseLatLon(value) {
  if (!value || typeof value !== 'string' || !value.includes(',')) return null;
  const [lat, lon] = value.split(',').map(v => Number(v.trim()));
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  return { lat, lon };
}

function projectEquirect(lat, lon, width, height) {
  const x = ((lon + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return { x, y };
}

function projectCompactMap(lat, lon, width, height) {
  const minLat = -42;
  const maxLat = 68;
  const padTop = 14;
  const padBottom = 12;
  const padX = 18;
  const clampedLat = Math.max(minLat, Math.min(maxLat, lat));
  const x = padX + ((lon + 180) / 360) * (width - padX * 2);
  const y = padTop + ((maxLat - clampedLat) / (maxLat - minLat)) * (height - padTop - padBottom);
  return { x, y };
}

const WORLD_SILHOUETTE_PATHS = [
  'M55 58 L88 44 L122 40 L154 45 L170 59 L164 73 L144 79 L130 94 L136 108 L120 117 L96 112 L80 98 L66 82 Z',
  'M162 116 L182 125 L194 145 L188 168 L177 192 L159 182 L152 160 L149 138 Z',
  'M420 52 L448 42 L474 44 L490 54 L486 68 L468 74 L446 71 L430 62 Z',
  'M448 78 L480 82 L512 76 L552 78 L592 74 L640 80 L676 92 L704 108 L732 124 L720 134 L688 130 L654 124 L624 128 L590 122 L560 130 L542 148 L520 154 L500 144 L492 126 L478 116 L460 112 L450 98 Z',
  'M470 114 L492 124 L505 148 L510 172 L500 194 L478 196 L464 180 L456 160 L454 136 Z',
  'M752 160 L784 154 L820 162 L842 178 L834 194 L806 198 L772 190 L748 176 Z'
];

function renderCompactWorldBackdrop(svg, width, height) {
  const backdrop = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  backdrop.setAttribute('aria-hidden', 'true');

  for (let lon = -120; lon <= 120; lon += 60) {
    const a = projectCompactMap(65, lon, width, height);
    const b = projectCompactMap(-35, lon, width, height);
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    line.setAttribute('class', 'rtt-grid-line');
    backdrop.appendChild(line);
  }

  for (let lat = -20; lat <= 60; lat += 20) {
    const a = projectCompactMap(lat, -180, width, height);
    const b = projectCompactMap(lat, 180, width, height);
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    line.setAttribute('class', 'rtt-grid-line');
    backdrop.appendChild(line);
  }

  WORLD_SILHOUETTE_PATHS.forEach(d => {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    path.setAttribute('class', 'world-silhouette');
    path.setAttribute('transform', 'translate(60 0) scale(1.08 1.02)');
    backdrop.appendChild(path);
  });

  svg.appendChild(backdrop);
}

const RTT_REGION_COORDS = {
  canadacentral: { lat: 43.6532, lon: -79.3832 },
  eastus: { lat: 37.4316, lon: -78.6569 },
  westus: { lat: 37.7749, lon: -122.4194 },
  westus2: { lat: 47.6062, lon: -122.3321 },
  uksouth: { lat: 51.5074, lon: -0.1278 },
  uaenorth: { lat: 25.2048, lon: 55.2708 },
  centralindia: { lat: 18.5204, lon: 73.8567 },
  australiaeast: { lat: -33.8688, lon: 151.2093 },
  brazilsouth: { lat: -23.5505, lon: -46.6333 }
};

function renderRttFlightMap(sortedRtt) {
  const panel = document.getElementById('rttRoutePanel');
  const list = document.getElementById('rttRouteList');
  const intel = document.getElementById('rttIntelStrip');
  if (!panel || !list || !intel) return;

  list.innerHTML = '';
  intel.innerHTML = '';

  const sourceLabelText = [meta.publicEgress?.city, meta.publicEgress?.region, meta.publicEgress?.country].filter(Boolean).join(', ') || 'Detected egress';
  const activeRegions = sortedRtt.filter(r => r.status === 'Pass').slice(0, 8);
  const best = activeRegions[0] || sortedRtt.find(r => r.status === 'Pass') || sortedRtt[0];
  const slowest = activeRegions[activeRegions.length - 1];
  const routeRegistry = new Map();

  function renderRoutePanel(region) {
    const median = rttMedianValue(region);
    panel.innerHTML = `
      <h4>Selected Route</h4>
      <div class="rtt-route-item"><span class="k">Region</span><span class="v">${escapeHtml(region.displayName)}</span></div>
      <div class="rtt-route-item"><span class="k">Status</span><span class="v">${escapeHtml(region.status || '—')}</span></div>
      <div class="rtt-route-item"><span class="k">Median RTT</span><span class="v">${typeof median === 'number' ? `${median} ms` : '—'}</span></div>
      <div class="rtt-route-item"><span class="k">Latest RTT</span><span class="v">${typeof rttLatestValue(region) === 'number' ? `${rttLatestValue(region)} ms` : '—'}</span></div>
      <div class="rtt-route-item"><span class="k">Samples</span><span class="v">${region.successfulSamples || 0}/${region.requestedSamples || 0}</span></div>
      <div class="rtt-route-item"><span class="k">Location</span><span class="v">${escapeHtml(region.location || '—')}</span></div>
      <div class="rtt-route-item"><span class="k">Target</span><span class="v mono">${escapeHtml(region.storageAccountName ? `${region.storageAccountName}.blob.core.windows.net` : '—')}</span></div>
      <div class="rtt-route-item"><span class="k">Method</span><span class="v">${escapeHtml(region.method || '—')}</span></div>
    `;
  }

  function setActiveRoute(regionId) {
    routeRegistry.forEach(entry => {
      const active = entry.region.regionId === regionId;
      entry.card.classList.toggle('active', active);
    });
    const selected = routeRegistry.get(regionId);
    if (selected) renderRoutePanel(selected.region);
  }

  intel.innerHTML = `
    <div class="rtt-mini-kpi"><div class="label">Source Egress</div><div class="value">${escapeHtml(sourceLabelText)}</div><div class="meta">Detected public route origin</div></div>
    <div class="rtt-mini-kpi"><div class="label">Fastest Region</div><div class="value">${best ? escapeHtml(best.displayName) : '—'}</div><div class="meta">${best && typeof rttMedianValue(best) === 'number' ? `${rttMedianValue(best)} ms median` : 'No measured data'}</div></div>
    <div class="rtt-mini-kpi"><div class="label">Route Spread</div><div class="value">${best && slowest && typeof rttMedianValue(best) === 'number' && typeof rttMedianValue(slowest) === 'number' ? `${rttMedianValue(slowest) - rttMedianValue(best)} ms` : '—'}</div><div class="meta">Gap between best and slowest visible route</div></div>
    <div class="rtt-mini-kpi"><div class="label">Visible Paths</div><div class="value">${activeRegions.length}</div><div class="meta">Top measured Azure routes shown</div></div>
  `;

  activeRegions.forEach((region, idx) => {
    const median = rttMedianValue(region);
    const color = getLatencyColor(median);
    const maxMedian = Math.max(...activeRegions.map(r => rttMedianValue(r) || 1), 1);
    const relativeWidth = Math.max(14, Math.min(100, Math.round((1 - (median / maxMedian)) * 100)));
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'rtt-route-card';
    card.innerHTML = `
      <div class="rtt-route-card-top">
        <div>
          <div class="rtt-route-rank">Rank ${idx + 1}</div>
          <div class="rtt-route-name">${escapeHtml(region.displayName)}</div>
        </div>
        <div class="rtt-route-ms" style="color:${color}">${typeof median === 'number' ? `${median} ms` : '—'}</div>
      </div>
      <div class="rtt-route-bar"><span style="width:${relativeWidth}%;background:${color}"></span></div>
      <div class="rtt-route-meta"><span>${escapeHtml(region.location || '—')}</span><span>${region.successfulSamples || 0}/${region.requestedSamples || 0} samples</span></div>
    `;
    card.addEventListener('click', () => setActiveRoute(region.regionId));
    list.appendChild(card);
    routeRegistry.set(region.regionId, { region, card });
  });

  if (best) setActiveRoute(best.regionId);

  if (typeof gsap !== 'undefined') {
    gsap.fromTo('.rtt-route-card', { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: .28, stagger: 0.04, ease: 'power1.out' });
  }
}

// ── CATEGORY BREAKDOWN TABLE ──────────────────────────────────────
function renderCatBreakdown() {
  const rows = Object.entries(CAT_MAP).map(([catKey, tabId]) => {
    const r = results.filter(x=>x.category===catKey);
    if (!r.length) return '';
    const pass = r.filter(x=>x.result==='Pass').length;
    const fail = r.filter(x=>isFailureResult(x.result)).length;
    const wild = r.filter(x=>isAdvisoryResult(x.result)).length;
    const tot  = r.length;
    const pct  = tot-wild > 0 ? Math.round(pass/(tot-wild)*100) : 0;
    const bar  = `<div style="background:var(--border);border-radius:4px;height:6px;overflow:hidden;width:120px">
      <div style="background:${pct===100?COLORS.Pass:pct>=80?COLORS.Wildcard:COLORS.Fail};height:100%;width:${pct}%;transition:width .4s"></div></div>`;
    return `<tr>
      <td style="padding:8px 12px;font-size:13px">${CAT_LABEL[tabId]}</td>
      <td style="padding:8px 12px;font-size:13px;color:var(--pass)">${pass}</td>
      <td style="padding:8px 12px;font-size:13px;color:var(--fail)">${fail}</td>
      <td style="padding:8px 12px;font-size:13px;color:var(--warn)">${wild}</td>
      <td style="padding:8px 12px;font-size:13px">${tot}</td>
      <td style="padding:8px 12px">${bar} <span style="font-size:11px;color:var(--muted);margin-left:6px">${pct}%</span></td>
    </tr>`;
  }).join('');
  document.getElementById('catBreakdown').innerHTML = `
    <table style="width:100%;border-collapse:collapse">
      <thead><tr style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">
        <th style="padding:6px 12px;text-align:left;font-weight:600">Category</th>
        <th style="padding:6px 12px;text-align:left;font-weight:600">Pass</th>
        <th style="padding:6px 12px;text-align:left;font-weight:600">Fail</th>
        <th style="padding:6px 12px;text-align:left;font-weight:600">Skip</th>
        <th style="padding:6px 12px;text-align:left;font-weight:600">Total</th>
        <th style="padding:6px 12px;text-align:left;font-weight:600">Pass Rate</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── TABLE RENDER ──────────────────────────────────────────────────
function getTabRows(tabId) {
  const catKey = Object.keys(CAT_MAP).find(k=>CAT_MAP[k]===tabId);
  const s = state[tabId];
  let rows = results.filter(r => {
    if (r.category !== catKey) return false;
    if (s.filter === 'FAIL' && !isFailureResult(r.result)) return false;
    if (s.filter === 'ADVISORY' && !isAdvisoryResult(r.result)) return false;
    if (s.filter !== 'ALL' && s.filter !== 'FAIL' && s.filter !== 'ADVISORY' && r.result !== s.filter) return false;
    if (s.search && !r.hostname.toLowerCase().includes(s.search)) return false;
    return true;
  });
  if (s.sortCol >= 0) {
    rows = [...rows].sort((a,b) => {
      const vals = [
        [a.hostname, b.hostname],
        [a.port, b.port],
        [a.protocol || 'TCP', b.protocol || 'TCP'],
        [a.result, b.result],
        [a.responseTime_ms, b.responseTime_ms],
        [a.description || '', b.description || ''],
        [getRemediation(a).nextAction, getRemediation(b).nextAction]
      ][s.sortCol];
      return (vals[0] > vals[1] ? 1 : vals[0] < vals[1] ? -1 : 0) * s.sortDir;
    });
  }
  return rows;
}

function isTabIncludedInScan(tabId) {
  const mode = String(meta.testMode || '').toLowerCase();
  if (mode.includes('both')) return true;
  if (mode.includes('client')) return tabId === 'w365client';
  if (mode.includes('host')) return tabId === 'w365host' || tabId === 'avd' || tabId === 'intune';
  return true;
}

function getTabEmptyMessage(tabId) {
  if (!isTabIncludedInScan(tabId)) {
    if (tabId === 'w365client') {
      return 'User Device endpoints were not included in this scan. Run in Client Network mode or Both mode to test them.';
    }
    return 'This endpoint group was not included in this scan mode. Run in Host Network mode or Both mode to test these URLs.';
  }

  const s = state[tabId];
  if (s.filter !== 'ALL' || s.search) {
    return 'No results match the current filter.';
  }

  return 'No results were recorded for this endpoint group in the current scan.';
}

function renderTable(tabId) {
  const tbody = document.querySelector(`#tbl-${tabId} tbody`);
  const rows  = getTabRows(tabId);
  const count = document.getElementById(`count-${tabId}`);
  if (count) {
    count.textContent = isTabIncludedInScan(tabId)
      ? `${rows.length} result${rows.length!==1?'s':''}`
      : 'Not included in this scan';
  }
  if (!rows.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="7">${getTabEmptyMessage(tabId)}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const rc   = r.result==='Pass' ? 'row-pass' : isFailureResult(r.result) ? 'row-fail' : 'row-warn';
    const bc   = statusClass(r.result);
    const icon = statusIcon(r.result);
    const rt   = r.responseTime_ms>=0 ? r.responseTime_ms+' ms' : '—';
    const remediation = getRemediation(r);
    const detail = [
      `DNS: ${r.dnsStatus||'—'}`,
      `TCP: ${r.tcpStatus||'—'}`,
      `TLS: ${r.tlsStatus||'—'}`,
      r.tlsCertificateIssuer ? `Issuer: ${r.tlsCertificateIssuer}` : '',
      r.tlsChainStatus ? `Chain: ${r.tlsChainStatus}` : '',
      r.tlsSanMatch ? `SAN Match: ${r.tlsSanMatch}` : '',
      r.sslInspectionSuspected ? `SSL Inspection: ${r.sslInspectionSuspected}` : '',
      r.description ? `Description: ${r.description}` : '',
      r.detail || ''
    ].filter(Boolean).join(' | ');
    return `<tr class="${rc}">
      <td class="mono">${r.hostname}</td>
      <td><span class="port-badge">${r.port}</span></td>
      <td>${r.protocol || 'TCP'}</td>
      <td><span class="badge ${bc}" title="${detail.replace(/"/g, '&quot;')}">${icon} ${r.result}</span></td>
      <td><span class="${latencyClass(r.responseTime_ms)}">${rt}</span></td>
      <td title="${(r.description || '').replace(/"/g, '&quot;')}">${r.description || '—'}</td>
      <td><span class="badge ${remediationBadgeClass(r)}" title="${remediation.category} · ${remediation.audience}">${remediation.nextAction}</span></td>
    </tr>`;
  }).join('');
}

// ── FILTER / SEARCH / SORT ────────────────────────────────────────
function doFilter(tabId, val, btn) {
  state[tabId].filter = val;
  btn.closest('.toolbar').querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  btn.classList.add('active');
  renderTable(tabId);
}
function doSearch(tabId, val) {
  state[tabId].search = val.toLowerCase();
  renderTable(tabId);
}
function sortTable(tabId, col, th) {
  const s = state[tabId];
  if (s.sortCol === col) { s.sortDir *= -1; }
  else { s.sortCol = col; s.sortDir = 1; }
  document.querySelectorAll(`#tbl-${tabId} thead th`)
    .forEach((h,i)=>{ h.classList.remove('sort-asc','sort-desc'); if(i===col) h.classList.add(s.sortDir===1?'sort-asc':'sort-desc'); });
  renderTable(tabId);
}

// ── TAB BADGES (fail counts) ──────────────────────────────────────
function updateTabBadges() {
  const allFail = results.filter(r=>isFailureResult(r.result)).length;
  TABS.forEach(tabId => {
    const catKey = Object.keys(CAT_MAP).find(k=>CAT_MAP[k]===tabId);
    const n = results.filter(r=>r.category===catKey&&isFailureResult(r.result)).length;
    const el = document.getElementById(`badge-${tabId}`);
    if (el && n>0) { el.textContent = n; el.style.display='inline'; }
  });
  const fw = document.getElementById('badge-fw');
  if (fw && allFail>0) { fw.textContent = allFail; fw.style.display='inline'; }
}

// ── TAB SWITCHING ─────────────────────────────────────────────────
function showTab(id, btn) {
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tabbar button').forEach(b=>{ b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
  document.getElementById('tab-'+id).classList.add('active');
  btn.classList.add('active');
  btn.setAttribute('aria-selected','true');
}

function bindKeyboardTabs() {
  const tabIds = ['overview','rtt','readiness','w365host','w365client','avd','intune','firewall','compare'];
  window.addEventListener('keydown', e => {
    const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable) return;
    if (!/^[1-9]$/.test(e.key)) return;
    const index = Number(e.key) - 1;
    const id = tabIds[index];
    const button = document.querySelectorAll('#tabbar button')[index];
    if (id && button) showTab(id, button);
  });
}

// ── FIREWALL RULES ────────────────────────────────────────────────
function renderFirewall() {
  const tcpFailed = results.filter(r => r.result === 'TCP Fail');
  const tlsRows = results.filter(r => r.result === 'TLS Fail');
  const wildcardRows = results.filter(r => r.result === 'Wildcard');
  const ipRangeRows = results.filter(r => r.result === 'IP Range');
  const dnsRows = results.filter(r => r.result === 'DNS Fail');
  const networkItems = tcpFailed.length + tlsRows.length + wildcardRows.length + ipRangeRows.length;

  const summaryTarget = document.getElementById('firewallSummary');
  summaryTarget.innerHTML = [
    { label: 'Open Now', value: tcpFailed.length, tone: tcpFailed.length ? 'c-fail' : 'c-pass', meta: 'Explicit outbound TCP opens required' },
    { label: 'TLS / Proxy Review', value: tlsRows.length, tone: tlsRows.length ? 'c-warn' : 'c-pass', meta: 'Inspection or proxy path needs review' },
    { label: 'Wildcard Allowlist', value: wildcardRows.length, tone: wildcardRows.length ? 'c-warn' : 'c-pass', meta: 'Manual wildcard review required' },
    { label: 'IP Range Allowlist', value: ipRangeRows.length, tone: ipRangeRows.length ? 'c-warn' : 'c-pass', meta: 'Manual IP range review required' }
  ].map(card => `
    <div class="firewall-summary-card">
      <div class="label">${card.label}</div>
      <div class="value ${card.tone}">${card.value}</div>
      <div class="meta">${card.meta}</div>
    </div>`).join('');

  document.getElementById('fwSub').textContent =
    networkItems
      ? `${networkItems} Infrastructure - Network/Firewall Team action item${networkItems !== 1 ? 's' : ''} detected - use this tab as the handoff list for opens, proxy review, and allowlist changes.`
      : 'No Infrastructure - Network/Firewall Team actions detected.';

  document.getElementById('fwIntro').textContent =
    networkItems
      ? 'This tab is organized as a single Infrastructure - Network/Firewall Team handoff. Prioritize direct TCP opens first, then review DNS, TLS inspection, wildcard allowlists, and IP range allowlists.'
      : 'All testable network paths completed successfully and no Infrastructure - Network/Firewall Team action is required from this scan.';

  const renderItem = (row, actionLabel, detailText) => `
    <div class="firewall-item">
      <div class="firewall-item-main">
        <div class="firewall-item-host">${row.hostname}:${row.port}</div>
        <div class="firewall-item-action">${actionLabel}</div>
      </div>
      <div class="firewall-item-detail"><strong>Why:</strong> ${detailText}</div>
    </div>`;

  const renderSection = (title, description, rows, actionLabel, detailFactory) => {
    if (!rows.length) return '';
    return `
      <div class="firewall-task-section">
        <h4>${title}</h4>
        <p>${description}</p>
        <div class="firewall-item-list">
          ${rows.map(row => renderItem(row, actionLabel, detailFactory(row))).join('')}
        </div>
      </div>`;
  };

  const box = document.getElementById('ruleBox');
  if (!networkItems) {
    box.innerHTML = `<div class="rule-empty">✅ No Infrastructure - Network/Firewall Team actions are required.</div>`;
  } else {
    box.innerHTML = `
      <div class="firewall-pane-head">
        <div>
          <h3>Infrastructure - Network/Firewall Team Action Queue</h3>
          <div class="meta">Use this pane as the client-ready handoff for outbound firewall changes, proxy inspection review, wildcard allowlists, and IP range allowlists.</div>
        </div>
        <div class="firewall-owner-badge">Owner: Infrastructure - Network/Firewall Team</div>
      </div>
      ${renderSection(
        '1. Open Outbound TCP Now',
        'These endpoints failed the direct TCP probe and should be submitted first as explicit outbound rule requests.',
        tcpFailed,
        'Open now',
        row => `Direct TCP connectivity failed. ${row.detail || 'The firewall path blocked this host and port.'}`
      )}
      ${renderSection(
        '2. Review TLS / Proxy Inspection',
        'These endpoints completed TCP but failed TLS negotiation, which usually points to SSL inspection, proxy interception, or certificate path interference.',
        tlsRows,
        'Review proxy path',
        row => `${row.sslInspectionSuspected === 'Yes' ? 'SSL inspection is suspected.' : 'TLS negotiation failed.'} ${row.detail || 'Review proxy interception and certificate handling for this host.'}`
      )}
      ${renderSection(
        '3. Review Wildcard Allowlist',
        'These wildcard URLs are documented requirements and still need explicit allowlist confirmation even though the scan cannot directly test wildcard coverage.',
        wildcardRows,
        'Review allowlist',
        row => row.description || 'Microsoft documents this wildcard URL as required for service reachability.'
      )}
      ${renderSection(
        '4. Review IP Range Allowlist',
        'These IP ranges are documented requirements and should be reviewed with the same change process used for outbound network allowlists.',
        ipRangeRows,
        'Review range allowlist',
        row => row.description || 'Microsoft documents this IP range as required for service connectivity.'
      )}
      ${dnsRows.length ? `<div class="firewall-support-note"><strong>Separate follow-up:</strong> ${dnsRows.length} DNS finding${dnsRows.length !== 1 ? 's were' : ' was'} detected outside the Network/Firewall action queue. Coordinate those with the endpoint or DNS owners.</div>` : ''}`;
  }

  const wildcardNote = document.getElementById('firewallWildcardNote');
  if (!wildcardRows.length && !ipRangeRows.length) {
    wildcardNote.innerHTML = '<h4>Advisory Allowlist Expectations</h4><p>No advisory wildcard URLs or IP ranges were recorded in this scan.</p>';
    return;
  }

  wildcardNote.innerHTML = `
    <h4>Advisory Allowlist Expectations</h4>
    <p>Use this lower section as a reference list after the primary Network/Firewall actions above have been reviewed. These items are advisory because the scan cannot validate them directly end to end.</p>
    ${wildcardRows.length ? `<div style="font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em;">Wildcard URLs</div><div class="wildcard-list" style="margin-bottom:16px;">${[...new Set(wildcardRows.map(item => `${item.hostname}:${item.port}`))].sort((a, b) => a.localeCompare(b)).map(item => `<span class="wildcard-chip">${item}</span>`).join('')}</div>` : ''}
    ${ipRangeRows.length ? `<div style="font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em;">IP Ranges</div><div class="wildcard-list">${[...new Set(ipRangeRows.map(item => `${item.hostname}:${item.port}`))].sort((a, b) => a.localeCompare(b)).map(item => `<span class="wildcard-chip">${item}</span>`).join('')}</div>` : ''}`;
}

function copyRules() {
  const failed = results.filter(r=>r.result==='TCP Fail');
  if (!failed.length) { alert('No TCP firewall rules to copy.'); return; }
  const txt = failed.map(r=>`Allow TCP outbound → ${r.hostname}:${r.port}`).join('\n');
  navigator.clipboard.writeText(txt)
    .then(()=>alert(`Copied ${failed.length} firewall rule${failed.length!==1?'s':''} to clipboard.`))
    .catch(()=>{ /* fallback */ const ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);alert('Copied!'); });
}

function downloadRetry() {
  const failed = results.filter(r=>isFailureResult(r.result));
  if (!failed.length) { alert('No failed endpoints to retry.'); return; }
  const entries = failed.map(r=>`    [PSCustomObject]@{ Hostname='${r.hostname}'; Port=${r.port} }`).join(",\n");
  const ps = `#Requires -Version 5.1\n# W365 Retry Script — generated ${new Date().toISOString()}\n\n$RetryList = @(\n${entries}\n)\n\nWrite-Host "W365 Endpoint Retry" -ForegroundColor Cyan\nforeach ($ep in $RetryList) {\n    Write-Host -NoNewline "  Testing $($ep.Hostname):$($ep.Port) ... "\n    try {\n        $ok = Test-NetConnection $ep.Hostname -Port $ep.Port -InformationLevel Quiet -WarningAction SilentlyContinue\n        if ($ok) { Write-Host "PASS" -ForegroundColor Green } else { Write-Host "FAIL" -ForegroundColor Red }\n    } catch { Write-Host "ERROR: $_" -ForegroundColor Red }\n}\nWrite-Host "Done." -ForegroundColor Blue\n`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([ps],{type:'text/plain'}));
  a.download = `W365-Retry-${new Date().toISOString().substring(0,10)}.ps1`;
  a.click();
}

// ── EXCEL EXPORT ──────────────────────────────────────────────────
// ── RAG cell style helper ────────────────────────────────────────
function ragStyle(result) {
  if (result === 'Pass')     return { font:{color:{rgb:'1A7F37'}}, fill:{fgColor:{rgb:'DAFBE1'}}, patternType:'solid' };
  if (/Fail$/.test(result || '')) return { font:{color:{rgb:'CF222E'}}, fill:{fgColor:{rgb:'FFEBE9'}}, patternType:'solid' };
  if (isAdvisoryResult(result)) return { font:{color:{rgb:'7D4E00'}}, fill:{fgColor:{rgb:'FFF8C5'}}, patternType:'solid' };
  return {};
}

function exportExcel() {
  const wb = XLSX.utils.book_new();
  const ts = new Date().toISOString().replace(/[:.]/g,'-').substring(0,19);
  const ctx = meta.networkContext || {};
  const os = meta.operatingSystem || {};
  const proxy = meta.proxyDiagnostics || {};
  const egress = meta.publicEgress || {};
  const env = meta.environmentFingerprint || {};
  const time = meta.timeSync || {};
  const udp = meta.udpShortpathReadiness || {};
  const currency = meta.endpointCurrency || {};
  const certs = meta.certificateReadiness || [];
  const backbonePlan = getCurrentBackbonePlan();
  const audienceSummaries = getAudienceDefinitions().map(audience => {
    const rows = getActionableRows().filter(row => getRemediation(row).audience === audience.title);
    return {
      title: audience.title,
      count: rows.length,
      topIssue: getTopRemediationCategory(rows),
      action: rows.length ? audience.defaultAction : 'No immediate action required.'
    };
  });

  // ── Summary sheet ──────────────────────────────────────────────
  const summaryRows = [
    ['W365 Endpoint Network Validator — Full Export'],
    ['Report generated', new Date().toLocaleString()],
    ['Scan host',        meta.hostname||''],
    ['Scan date',        meta.scanDate||''],
    ['Test mode',        meta.testMode||''],
    ['Duration (s)',     meta.durationSeconds||0],
    ['Script version',   meta.scriptVersion||''],
    ['Timeout (ms)',     meta.timeoutMs||0],
    ['Max parallel',     meta.maxParallel||0],
    ['OS Name',          os.name||''],
    ['OS Version',       os.version||''],
    ['OS Build',         os.build||''],
    ['Interface',        ctx.interfaceAlias||''],
    ['IPv4',             ctx.ipv4Address||''],
    ['Gateway',          ctx.defaultGateway||''],
    ['DNS Servers',      fmt(ctx.dnsServers)],
    ['WinHTTP Proxy',    ctx.winHttpProxy||''],
    ['WinINet Proxy',    ctx.winInetProxyEnabled||''],
    ['WinINet Server',   ctx.winInetProxyServer||''],
    ['PAC URL',          ctx.winInetAutoConfigUrl||''],
    ['Auto Detect',      ctx.winInetAutoDetect||''],
    ['HTTPS_PROXY',      ctx.httpsProxy||''],
    ['Proxy Route',      egress.route||''],
    ['Proxy URI',        proxy.proxyUri||''],
    ['Proxy Auth Required', proxy.proxyAuthRequired||''],
    ['Secure Web Gateway Suspected', env.secureWebGateway||egress.secureWebGatewaySuspected||''],
    ['Public IP',        egress.ip||''],
    ['Public ASN',       egress.asn||''],
    ['Public Provider',  egress.organization||''],
    ['Public Location',  [egress.city, egress.region, egress.country].filter(Boolean).join(', ')],
    ['VPN Detected',     env.vpnDetected||''],
    ['VPN Adapters',     fmt(env.vpnAdapters)],
    ['SSID',             env.connectedSsid||''],
    ['Interface Type',   env.interfaceType||''],
    ['Domain Joined',    env.domainJoined||''],
    ['Entra Joined',     env.entraJoined||''],
    ['Reboot Pending',   env.rebootPending||''],
    ['Reboot Detail',    env.rebootPendingDetail||''],
    ['Time Sync Status', time.status||''],
    ['Time Source',      time.source||''],
    ['Clock Offset (ms)', time.clockOffsetMs !== '' ? time.clockOffsetMs : ''],
    ['UDP Egress',       udp.generalUdpStatus||''],
    ['UDP RTT (ms)',     udp.generalUdpRttMs >= 0 ? udp.generalUdpRttMs : ''],
    ['Shortpath Status', udp.shortpathStatus||''],
    ['Endpoint List Currency', currency.status||''],
    ['Endpoint Lists Reviewed On', currency.reviewedOn||''],
    ['Endpoint List Age (days)', currency.daysSinceReview||''],
    [],
    ['Azure Region RTT', '', '', '', '', ''],
    ['Region', 'Location', 'Status', 'Median RTT (ms)', 'Latest RTT (ms)', 'Samples'],
    ...azureRtt.map(r => [r.displayName, r.location, r.status, rttMedianValue(r) >= 0 ? rttMedianValue(r) : '', rttLatestValue(r) >= 0 ? rttLatestValue(r) : '', `${r.successfulSamples || 0}/${r.requestedSamples || 0}`]),
    ['Category','Total','Pass','Fail','Advisory','Pass Rate']
  ];
  if ((azureBackboneRtt.rows || []).length) {
    summaryRows.push(
      [],
      ['Azure Backbone RTT Reference', '', '', '', '', ''],
      ['Dataset', azureBackboneRtt.datasetName || ''],
      ['Dataset Date', azureBackboneRtt.datasetDate || ''],
      ['Metric', azureBackboneRtt.metric || ''],
      ['Selected Entry Region', backbonePlan.source || ''],
      ['Selected Cloud PC Region', backbonePlan.target || ''],
      ['Client to Azure RTT (ms)', typeof backbonePlan.liveClientRtt === 'number' ? backbonePlan.liveClientRtt : ''],
      ['Azure to Azure RTT (ms)', typeof backbonePlan.backboneRtt === 'number' ? backbonePlan.backboneRtt : ''],
      ['Combined Planning Estimate (ms)', typeof backbonePlan.combinedRtt === 'number' ? backbonePlan.combinedRtt : ''],
      []
    );
  }
  Object.entries(CAT_MAP).forEach(([catKey,tabId])=>{
    const r    = results.filter(x=>x.category===catKey);
    const pass = r.filter(x=>x.result==='Pass').length;
    const fail = r.filter(x=>isFailureResult(x.result)).length;
    const wild = r.filter(x=>isAdvisoryResult(x.result)).length;
    const tot  = r.length;
    const pct  = tot-wild>0 ? `${Math.round(pass/(tot-wild)*100)}%` : 'N/A';
    summaryRows.push([CAT_LABEL[tabId], tot, pass, fail, wild, pct]);
  });
  summaryRows.push([]);
  summaryRows.push(['Remediation Summary', '', '', '', '', '']);
  summaryRows.push(['Audience', 'Findings', 'Top Issue', 'Action Summary']);
  audienceSummaries.forEach(summary => {
    summaryRows.push([summary.title, summary.count, summary.topIssue, summary.action]);
  });
  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);
  wsSummary['!cols'] = [{wch:36},{wch:48},{wch:8},{wch:8},{wch:14},{wch:10}];
  XLSX.utils.book_append_sheet(wb, wsSummary, 'Summary');

  // ── All Results sheet (every endpoint in one place) ────────────
  const allHeader = ['Category','Hostname','Port','Protocol','Description','Status','Remediation Category','Audience','Next Action','DNS','TCP','TLS','Response (ms)','Resolved IPs','TLS Protocol','TLS Cert Issuer','TLS Cert Subject','TLS SAN Match','TLS Chain','SSL Inspection Suspected','Detail'];
  const allData   = results.map(r=>[
    CAT_LABEL[CAT_MAP[r.category]] || r.category,
    r.hostname, r.port, r.protocol || 'TCP', r.description || '', r.result,
    r.remediationCategory || '',
    r.remediationAudience || '',
    r.nextAction || '',
    r.dnsStatus || '',
    r.tcpStatus || '',
    r.tlsStatus || '',
    r.responseTime_ms >= 0 ? r.responseTime_ms : '',
    r.resolvedAddresses || '',
    r.tlsProtocol || '',
    r.tlsCertificateIssuer || '',
    r.tlsCertificateSubject || '',
    r.tlsSanMatch || '',
    r.tlsChainStatus || '',
    r.sslInspectionSuspected || '',
    r.detail || ''
  ]);
  const combinedAllRows = [allHeader, ...allData];
  if (azureRtt.length) {
    combinedAllRows.push([]);
    combinedAllRows.push(['Azure Round Trip Times']);
    combinedAllRows.push(['Region','Location','Status','Median RTT (ms)','Latest RTT (ms)','Successful Samples','Requested Samples','Method','Target','Detail']);
    azureRtt.forEach(r => {
      combinedAllRows.push([
        r.displayName,
        r.location,
        r.status,
        rttMedianValue(r) >= 0 ? rttMedianValue(r) : '',
        rttLatestValue(r) >= 0 ? rttLatestValue(r) : '',
        r.successfulSamples || 0,
        r.requestedSamples || 0,
        r.method || '',
        r.storageAccountName ? `${r.storageAccountName}.blob.core.windows.net` : '',
        r.detail || ''
      ]);
    });
  }
  const wsAll = XLSX.utils.aoa_to_sheet(combinedAllRows);
  wsAll['!cols'] = [{wch:16},{wch:52},{wch:8},{wch:10},{wch:42},{wch:12},{wch:22},{wch:18},{wch:26},{wch:10},{wch:10},{wch:10},{wch:14},{wch:28},{wch:14},{wch:28},{wch:34},{wch:12},{wch:18},{wch:18},{wch:42}];
  // RAG colour on Status column (col index 5, F)
  allData.forEach((row, i) => {
    const cellRef = XLSX.utils.encode_cell({r: i+1, c: 5});
    if (wsAll[cellRef]) wsAll[cellRef].s = ragStyle(row[5]);
  });
  if (azureRtt.length) {
    const rttSectionStart = allData.length + 4;
    azureRtt.forEach((row, i) => {
      const cellRef = XLSX.utils.encode_cell({r: rttSectionStart + i, c: 2});
      if (wsAll[cellRef]) wsAll[cellRef].s = row.status === 'Pass' ? ragStyle('Pass') : ragStyle('DNS Fail');
    });
  }
  XLSX.utils.book_append_sheet(wb, wsAll, 'All Results');

  if ((azureBackboneRtt.rows || []).length) {
    const backboneRows = [
      ['Azure Backbone RTT Reference'],
      ['Dataset', azureBackboneRtt.datasetName || ''],
      ['Dataset Date', azureBackboneRtt.datasetDate || ''],
      ['Metric', azureBackboneRtt.metric || ''],
      ['Source', 'Target', 'P50 RTT (ms)'],
      ...azureBackboneRtt.rows.map(row => [row.source, row.target, row.p50RttMs])
    ];
    const wsBackbone = XLSX.utils.aoa_to_sheet(backboneRows);
    wsBackbone['!cols'] = [{wch:28},{wch:28},{wch:14}];
    XLSX.utils.book_append_sheet(wb, wsBackbone, 'Azure Backbone RTT Ref');

    const planningRows = [
      ['RTT Planning View'],
      ['Selected Entry Region', backbonePlan.source || ''],
      ['Selected Cloud PC Region', backbonePlan.target || ''],
      ['Client to Azure RTT (ms)', typeof backbonePlan.liveClientRtt === 'number' ? backbonePlan.liveClientRtt : ''],
      ['Azure to Azure RTT (ms)', typeof backbonePlan.backboneRtt === 'number' ? backbonePlan.backboneRtt : ''],
      ['Combined Planning Estimate (ms)', typeof backbonePlan.combinedRtt === 'number' ? backbonePlan.combinedRtt : ''],
      ['Note', 'Planning estimate only; not an observed end-to-end session RTT.']
    ];
    const wsPlanning = XLSX.utils.aoa_to_sheet(planningRows);
    wsPlanning['!cols'] = [{wch:32},{wch:42}];
    XLSX.utils.book_append_sheet(wb, wsPlanning, 'RTT Planning View');
  }

  // ── Per-category sheets ─────────────────────────────────────────
  Object.entries(CAT_MAP).forEach(([catKey,tabId])=>{
    const rows = results.filter(r=>r.category===catKey);
    if (!rows.length) return;
    const data = rows.map(r=>[
      r.hostname, r.port, r.protocol || 'TCP', r.description || '', r.result,
      r.remediationCategory || '',
      r.remediationAudience || '',
      r.nextAction || '',
      r.dnsStatus || '',
      r.tcpStatus || '',
      r.tlsStatus || '',
      r.responseTime_ms>=0 ? r.responseTime_ms : '',
      r.resolvedAddresses || '',
      r.tlsProtocol || '',
      r.tlsCertificateIssuer || '',
      r.tlsCertificateSubject || '',
      r.tlsSanMatch || '',
      r.tlsChainStatus || '',
      r.sslInspectionSuspected || '',
      r.detail || ''
    ]);
    const ws = XLSX.utils.aoa_to_sheet([
      ['Hostname','Port','Protocol','Description','Status','Remediation Category','Audience','Next Action','DNS','TCP','TLS','Response (ms)','Resolved IPs','TLS Protocol','TLS Cert Issuer','TLS Cert Subject','TLS SAN Match','TLS Chain','SSL Inspection Suspected','Detail'],
      ...data
    ]);
    ws['!cols'] = [{wch:52},{wch:8},{wch:10},{wch:42},{wch:12},{wch:22},{wch:18},{wch:26},{wch:10},{wch:10},{wch:10},{wch:14},{wch:28},{wch:14},{wch:28},{wch:34},{wch:12},{wch:18},{wch:18},{wch:42}];
    // RAG colour on Status column (col index 4, E)
    data.forEach((row, i) => {
      const cellRef = XLSX.utils.encode_cell({r: i+1, c: 4});
      if (ws[cellRef]) ws[cellRef].s = ragStyle(row[4]);
    });
    XLSX.utils.book_append_sheet(wb, ws, CAT_LABEL[tabId].substring(0,31));
  });

  const remediationRows = [
    ['Audience', 'Findings', 'Top Issue', 'Action Summary'],
    ...audienceSummaries.map(summary => [summary.title, summary.count, summary.topIssue, summary.action])
  ];
  const wsRemediation = XLSX.utils.aoa_to_sheet(remediationRows);
  wsRemediation['!cols'] = [{wch:18},{wch:12},{wch:28},{wch:70}];
  XLSX.utils.book_append_sheet(wb, wsRemediation, 'Remediation Summary');

  // ── Failed endpoints sheet ──────────────────────────────────────
  const failed = results.filter(r=>isFailureResult(r.result));
  if (failed.length) {
    const failData = failed.map(r=>[
      CAT_LABEL[CAT_MAP[r.category]] || r.category,
      r.hostname, r.port,
      r.result,
      r.result === 'TCP Fail'
        ? `Allow TCP outbound → ${r.hostname}:${r.port}`
        : r.result === 'DNS Fail'
          ? 'Review DNS resolution path / split-horizon DNS'
          : 'Review TLS inspection / proxy certificate trust',
      r.detail || ''
    ]);
    const wsFail = XLSX.utils.aoa_to_sheet([
      ['Category','Hostname','Port','Failure Type','Recommended Action','Detail'],
      ...failData
    ]);
    wsFail['!cols'] = [{wch:16},{wch:52},{wch:8},{wch:12},{wch:60},{wch:42}];
    XLSX.utils.book_append_sheet(wb, wsFail, 'Failed — Actions');
  }

  const readinessRows = [
    ['Category', 'Signal', 'Value', 'Detail'],
    ['Proxy', 'Status', proxy.status || '', proxy.detail || ''],
    ['Proxy', 'Proxy URI', proxy.proxyUri || '', proxy.proxyAuthenticate || ''],
    ['Proxy', 'Proxy Auth Required', proxy.proxyAuthRequired || '', ''],
    ['Public Egress', 'Route', egress.route || '', egress.detail || ''],
    ['Public Egress', 'Public IP', egress.ip || '', egress.organization || ''],
    ['Public Egress', 'ASN', egress.asn || '', [egress.city, egress.region, egress.country].filter(Boolean).join(', ')],
    ['Environment', 'VPN Detected', env.vpnDetected || '', fmt(env.vpnAdapters)],
    ['Environment', 'SSID', env.connectedSsid || '', env.interfaceType || ''],
    ['Environment', 'Domain Joined', env.domainJoined || '', `Entra Joined: ${env.entraJoined || ''}`],
    ['Environment', 'Reboot Pending', env.rebootPending || '', env.rebootPendingDetail || ''],
    ['Time Sync', 'Status', time.status || '', time.detail || ''],
    ['Time Sync', 'Source', time.source || '', time.clockOffsetMs !== '' ? `${time.clockOffsetMs} ms` : ''],
    ['UDP', 'General UDP', udp.generalUdpStatus || '', udp.detail || ''],
    ['UDP', 'Shortpath', udp.shortpathStatus || '', udp.shortpathRequirement || ''],
    ['Endpoint Currency', 'Status', currency.status || '', currency.detail || ''],
    ['Endpoint Currency', 'Reviewed On', currency.reviewedOn || '', currency.daysSinceReview ? `${currency.daysSinceReview} day(s)` : '']
  ];
  const wsReadiness = XLSX.utils.aoa_to_sheet(readinessRows);
  wsReadiness['!cols'] = [{wch:18},{wch:22},{wch:24},{wch:70}];
  XLSX.utils.book_append_sheet(wb, wsReadiness, 'Readiness');

  if (certs.length) {
    const wsCerts = XLSX.utils.aoa_to_sheet([
      ['Hostname','Port','Status','TLS Protocol','Subject','Issuer','Thumbprint','Names','Name Match','Chain','SSL Inspection Suspected','Detail'],
      ...certs.map(cert => [
        cert.hostname || '',
        cert.port || '',
        cert.status || '',
        cert.tlsProtocol || '',
        cert.certificateSubject || '',
        cert.certificateIssuer || '',
        cert.certificateThumbprint || '',
        fmt(cert.certificateNames),
        cert.sanMatch || '',
        cert.chainStatus || '',
        cert.sslInspectionSuspected || '',
        cert.detail || ''
      ])
    ]);
    wsCerts['!cols'] = [{wch:30},{wch:8},{wch:12},{wch:12},{wch:42},{wch:32},{wch:42},{wch:40},{wch:12},{wch:18},{wch:18},{wch:48}];
    XLSX.utils.book_append_sheet(wb, wsCerts, 'Certificate Readiness');
  }

  XLSX.writeFile(wb, `W365-Results-${ts}.xlsx`);
}

// ── COMPARE MODE ──────────────────────────────────────────────────
let cmpRows = [];
let cmpFilter = 'ALL';

function onDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) parseCompareFile(f);
}
function onFileSelect(input) {
  if (input.files[0]) parseCompareFile(input.files[0]);
}
function parseCompareFile(file) {
  const r = new FileReader();
  r.onload = e => {
    try { buildCompare(JSON.parse(e.target.result)); }
    catch { alert('Invalid JSON. Please load a W365-Results-*.json sidecar file.'); }
  };
  r.readAsText(file);
}

function buildCompare(prev) {
  const prevMap = {};
  (prev.results||[]).forEach(r=>{ prevMap[`${r.category}|${r.hostname}|${r.port}`] = r.result; });
  const currMap = {};
  results.forEach(r=>{ currMap[`${r.category}|${r.hostname}|${r.port}`] = r.result; });
  const allKeys = [...new Set([...Object.keys(prevMap),...Object.keys(currMap)])];

  cmpRows = allKeys.map(key=>{
    const [catKey, hostname, port] = key.split('|');
    const pv = prevMap[key]||'Missing';
    const cv = currMap[key]||'Missing';
    let change = 'Unchanged';
    if (pv==='Missing')                      change = 'New';
    else if (cv==='Missing')                 change = 'Removed';
    else if (isFailureResult(pv)&&cv==='Pass') change = 'Resolved';
    else if (pv==='Pass'&&isFailureResult(cv)) change = 'Regressed';
    else if (pv!==cv)                        change = 'Changed';
    return {
      hostname,
      port,
      category: CAT_LABEL[CAT_MAP[catKey] || catKey] || catKey,
      prev: pv,
      curr: cv,
      change
    };
  });

  // KPIs
  const res  = cmpRows.filter(r=>r.change==='Resolved').length;
  const reg  = cmpRows.filter(r=>r.change==='Regressed').length;
  const nw   = cmpRows.filter(r=>r.change==='New').length;
  const unch = cmpRows.filter(r=>r.change==='Unchanged').length;
  const prevDate = prev.meta?.scanDate ? new Date(prev.meta.scanDate).toLocaleDateString() : '?';
  document.getElementById('cmpKpis').innerHTML = [
    {l:'Resolved',  v:res,  c:res>0?'c-pass':'c-neutral'},
    {l:'Regressed', v:reg,  c:reg>0?'c-fail':'c-neutral'},
    {l:'New',       v:nw,   c:nw>0?'c-warn':'c-neutral'},
    {l:'Unchanged', v:unch, c:'c-neutral'},
    {l:'Prev Scan', v:prevDate, c:'c-neutral'}
  ].map(k=>`<div class="kpi-card"><div class="lbl">${k.l}</div><div class="val ${k.c}">${k.v}</div></div>`).join('');

  document.getElementById('dropZone').style.display = 'none';
  document.getElementById('compareOut').style.display = 'block';
  renderCmpTable();
}

function doCmpFilter(val, btn) {
  cmpFilter = val;
  document.querySelectorAll('#tab-compare .chip').forEach(c=>c.classList.remove('active'));
  btn.classList.add('active');
  renderCmpTable();
}

function renderCmpTable() {
  const rows = cmpFilter==='ALL' ? cmpRows : cmpRows.filter(r=>r.change.startsWith(cmpFilter));
  const tbody = document.querySelector('#tbl-compare tbody');
  tbody.innerHTML = rows.map(r=>{
    const bc = {Resolved:'badge-pass',Regressed:'badge-fail',New:'badge-warn',Removed:'badge-fail',Changed:'badge-warn',Unchanged:'badge-neutral'}[r.change]||'badge-neutral';
    const pb = statusClass(r.prev);
    const cb = statusClass(r.curr);
    return `<tr>
      <td class="mono">${r.hostname}</td>
      <td><span class="port-badge">${r.port}</span></td>
      <td style="color:var(--muted)">${r.category}</td>
      <td><span class="badge ${pb}">${r.prev}</span></td>
      <td><span class="badge ${cb}">${r.curr}</span></td>
      <td><span class="badge ${bc}">${r.change}</span></td>
    </tr>`;
  }).join('') || `<tr class="empty-row"><td colspan="6">No results for this filter.</td></tr>`;
}
</script>
</body>
</html>

'@

# ─────────────────────────────────────────────────────────────────────────────
# INJECT JSON INTO HTML
# ─────────────────────────────────────────────────────────────────────────────
$finalHtml = $htmlTemplate.Replace('##RESULTS_JSON##', $jsonData)

# ─────────────────────────────────────────────────────────────────────────────
# SAVE FILES
# ─────────────────────────────────────────────────────────────────────────────
$htmlPath  = Join-Path $OutputFolder "W365-Results-$Timestamp.html"
$jsonPath  = Join-Path $OutputFolder "W365-Results-$Timestamp.json"
$retryPath = Join-Path $OutputFolder "W365-Retry-$Timestamp.ps1"

# — HTML report
$finalHtml | Out-File -FilePath $htmlPath -Encoding UTF8 -Force

# — JSON sidecar (for Compare mode)
$jsonData  | Out-File -FilePath $jsonPath -Encoding UTF8 -Force

# — Retry script for failed endpoints
$failedEntries = $allResults | Where-Object { $_.result -like '*Fail' }
if ($failedEntries) {
    $retryEntries = ($failedEntries | ForEach-Object {
        "    [PSCustomObject]@{ Hostname = '$($_.hostname)'; Port = $($_.port) }"
    }) -join ",`n"

    $retryContent = @"
#Requires -Version 5.1
# W365 Endpoint Retry Script
# Generated: $(Get-Date -Format 'o')
# Source scan: $htmlPath
# Only re-tests endpoints that FAILED in the original scan.

`$RetryList = @(
$retryEntries
)

Write-Host "W365 Endpoint Retry" -ForegroundColor Cyan
Write-Host "Testing `$(`$RetryList.Count) previously failed endpoint(s)..." -ForegroundColor Yellow
Write-Host ""

foreach (`$ep in `$RetryList) {
    Write-Host "  Testing `$(`$ep.Hostname):`$(`$ep.Port) ... " -NoNewline
    try {
        `$ok = Test-NetConnection `$ep.Hostname -Port `$ep.Port -InformationLevel Quiet -WarningAction SilentlyContinue
        if (`$ok) { Write-Host "PASS" -ForegroundColor Green }
        else      { Write-Host "FAIL" -ForegroundColor Red }
    } catch {
        Write-Host "ERROR: `$_" -ForegroundColor Red
    }
}
Write-Host ""
Write-Host "Done." -ForegroundColor Blue
"@
    $retryContent | Out-File -FilePath $retryPath -Encoding UTF8 -Force
}

# ─────────────────────────────────────────────────────────────────────────────
# REPORT PATHS
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "Files saved:" -ForegroundColor Blue
Write-Host "  HTML Report : " -NoNewline; Write-Host $htmlPath  -ForegroundColor Green
Write-Host "  JSON Data   : " -NoNewline; Write-Host $jsonPath  -ForegroundColor Green
if ($failedEntries) {
    Write-Host "  Retry Script: " -NoNewline; Write-Host $retryPath -ForegroundColor Green
}
Write-Host ""

if (-not $SkipBrowser) {
    Start-Process $htmlPath
}

Write-Host ""
Write-Host "Done." -ForegroundColor Blue

