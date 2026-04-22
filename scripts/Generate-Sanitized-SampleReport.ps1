param(
    [string]$SourceJson = "..\..\W365-Endpoints-Network-Connectivity\W365-Results-20260417-095807.json",
    [string]$SourceHtml = "..\..\W365-Endpoints-Network-Connectivity\W365-Results-20260417-095807.html",
    [string]$OutputJson = "..\sample-output\W365-Results-sanitized-sample.json",
    [string]$OutputHtml = "..\sample-output\W365-Results-sanitized-sample.html"
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoPath {
    param([string]$RelativePath)
    return [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $RelativePath))
}

function Set-IfPresent {
    param(
        [object]$Object,
        [string]$Property,
        [object]$Value
    )

    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Property) {
        $Object.$Property = $Value
    }
}

function Sanitize-AddressList {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    if ($Value -match '^\d+\.\d+\.\d+\.\d+$') {
        return '203.0.113.10'
    }

    return $Value
}

$sourceJsonPath = Resolve-RepoPath $SourceJson
$sourceHtmlPath = Resolve-RepoPath $SourceHtml
$outputJsonPath = Resolve-RepoPath $OutputJson
$outputHtmlPath = Resolve-RepoPath $OutputHtml

$null = New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($outputJsonPath))

$rawJson = Get-Content -Raw -Path $sourceJsonPath
$report = $rawJson | ConvertFrom-Json -Depth 100

Set-IfPresent $report.meta 'hostname' 'PUBLIC-SAMPLE-DEVICE'
Set-IfPresent $report.meta 'scanDate' '2026-04-22T12:00:00Z'
Set-IfPresent $report.meta 'scriptVersion' 'v10.0-public-sample'

if ($null -ne $report.meta.operatingSystem) {
    Set-IfPresent $report.meta.operatingSystem 'build' '26100'
}

if ($null -ne $report.meta.networkContext) {
    Set-IfPresent $report.meta.networkContext 'interfaceAlias' 'Corporate Wi-Fi'
    Set-IfPresent $report.meta.networkContext 'interfaceDescription' 'Sample Wireless Adapter'
    Set-IfPresent $report.meta.networkContext 'ipv4Address' '192.0.2.10'
    Set-IfPresent $report.meta.networkContext 'defaultGateway' '192.0.2.1'
    Set-IfPresent $report.meta.networkContext 'dnsServers' @('192.0.2.53', '198.51.100.53')
    Set-IfPresent $report.meta.networkContext 'dnsSuffix' 'corp.example'
}

if ($null -ne $report.meta.publicEgress) {
    Set-IfPresent $report.meta.publicEgress 'ip' '203.0.113.10'
    Set-IfPresent $report.meta.publicEgress 'asn' 'AS64500'
    Set-IfPresent $report.meta.publicEgress 'organization' 'Contoso Telecom'
    Set-IfPresent $report.meta.publicEgress 'city' 'Sample City'
    Set-IfPresent $report.meta.publicEgress 'region' 'Sample Region'
    Set-IfPresent $report.meta.publicEgress 'country' 'US'
    Set-IfPresent $report.meta.publicEgress 'location' '37.0000,-122.0000'
    Set-IfPresent $report.meta.publicEgress 'timezone' 'UTC'
    Set-IfPresent $report.meta.publicEgress 'detail' 'Public egress anonymized for repository sample.'
}

if ($null -ne $report.meta.environmentFingerprint) {
    Set-IfPresent $report.meta.environmentFingerprint 'connectedSsid' 'CorpWiFi-Sample'
    Set-IfPresent $report.meta.environmentFingerprint 'deviceId' '00000000-0000-0000-0000-000000000000'
    Set-IfPresent $report.meta.environmentFingerprint 'secureWebGatewayHint' 'None'
    Set-IfPresent $report.meta.environmentFingerprint 'rebootPending' 'No'
    Set-IfPresent $report.meta.environmentFingerprint 'rebootPendingDetail' ''
}

if ($null -ne $report.meta.timeSync) {
    Set-IfPresent $report.meta.timeSync 'lastSync' '2026-04-22 11:55:00 AM'
    Set-IfPresent $report.meta.timeSync 'clockOffsetMs' 120
    Set-IfPresent $report.meta.timeSync 'detail' 'Approximate UTC drift: 120 ms.'
}

foreach ($propertyName in 'certificateReadiness', 'results') {
    $collection = $report.meta.$propertyName
    if ($null -ne $collection) {
        foreach ($item in $collection) {
            if ($item.PSObject.Properties.Name -contains 'resolvedAddresses') {
                $item.resolvedAddresses = Sanitize-AddressList $item.resolvedAddresses
            }
        }
    }
}

$sanitizedJson = $report | ConvertTo-Json -Depth 100 -Compress
Set-Content -Path $outputJsonPath -Value $sanitizedJson -Encoding UTF8

$html = Get-Content -Raw -Path $sourceHtmlPath
$html = [regex]::Replace(
    $html,
    'const RAW = .*?;\r?\n',
    "const RAW = $sanitizedJson;`r`n",
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

$html = $html.Replace('AVAPC-266106024', 'PUBLIC-SAMPLE-DEVICE')
$html = $html.Replace('Bell Canada', 'Contoso Telecom')
$html = $html.Replace('FinalFrontier 2', 'corp.example')
$html = $html.Replace('FinalFrontier', 'CorpWiFi-Sample')
$html = $html.Replace('142.189.105.98', '203.0.113.10')
$html = $html.Replace('192.168.2.23', '192.0.2.10')
$html = $html.Replace('192.168.2.1', '192.0.2.1')
$html = $html.Replace('207.164.234.193', '198.51.100.53')
$html = $html.Replace('fc8953da-0048-4984-94e2-662a2e3c3ac5', '00000000-0000-0000-0000-000000000000')
$html = $html.Replace('Willowdale', 'Sample City')
$html = $html.Replace('Ontario', 'Sample Region')
$html = $html.Replace('43.7667,-79.3991', '37.0000,-122.0000')
$html = $html.Replace('America/Toronto', 'UTC')

Set-Content -Path $outputHtmlPath -Value $html -Encoding UTF8

Write-Host "Created sanitized sample JSON: $outputJsonPath"
Write-Host "Created sanitized sample HTML: $outputHtmlPath"