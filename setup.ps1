$ErrorActionPreference = 'Stop'

$Repo = "usenwep/nwep"

# Detect OS — respect GOOS when cross-compiling, otherwise assume windows
if ($env:GOOS) {
    $OS = $env:GOOS
} else {
    $OS = "windows"
}

# Detect architecture — respect GOARCH when cross-compiling
if ($env:GOARCH) {
    $OS_ARCH = switch ($env:GOARCH) {
        "arm64" { "aarch64" }
        "arm"   { "arm" }
        "amd64" { "x86_64" }
        "386"   { "x86" }
        default { $env:GOARCH }
    }
} else {
    $OS_ARCH = switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "x86_64" }
        "ARM64" { "aarch64" }
        "x86"   { "x86" }
        default { $env:PROCESSOR_ARCHITECTURE.ToLower() }
    }
}

# Fetch latest release
Write-Host "Fetching latest release from $Repo..."
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Tag = $Release.tag_name

# Find matching asset (prefer gcc variant for linux)
$AssetUrl  = $null
$AssetName = $null

foreach ($Asset in $Release.assets) {
    $Name = $Asset.name
    if ($Name -match [regex]::Escape($OS) -and $Name -match [regex]::Escape($OS_ARCH)) {
        if (-not $AssetUrl) {
            $AssetUrl  = $Asset.browser_download_url
            $AssetName = $Name
        }
        if ($Name -match "gcc") {
            $AssetUrl  = $Asset.browser_download_url
            $AssetName = $Name
            break
        }
    }
}

if (-not $AssetUrl) {
    Write-Error "No matching asset found for $OS-$OS_ARCH in release $Tag"
    Write-Host "Available assets:"
    $Release.assets | ForEach-Object { Write-Host "  $($_.name)" }
    exit 1
}

$Dir = "third_party\nwep"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Push-Location $Dir

# Record existing directories before extraction
$Before = Get-ChildItem -Directory -Filter "nwep-*" | Select-Object -ExpandProperty Name

Write-Host "Downloading $AssetName ($Tag)..."
Invoke-WebRequest -Uri $AssetUrl -OutFile $AssetName

if ($AssetName -match '\.zip$') {
    Expand-Archive -Path $AssetName -DestinationPath . -Force
} else {
    tar -xzf $AssetName
}
Remove-Item $AssetName

# Find the newly extracted directory
$After  = Get-ChildItem -Directory -Filter "nwep-*" | Select-Object -ExpandProperty Name
$Target = $After | Where-Object { $_ -notin $Before } | Select-Object -First 1

# Fallback: match by OS and arch
if (-not $Target) {
    $Target = Get-ChildItem -Directory -Filter "nwep-*$OS*$OS_ARCH*" |
              Select-Object -First 1 -ExpandProperty Name
}
# Fallback: any nwep directory
if (-not $Target) {
    $Target = Get-ChildItem -Directory -Filter "nwep-*" |
              Select-Object -First 1 -ExpandProperty Name
}
if (-not $Target) {
    Write-Error "No nwep build found in $Dir"
    exit 1
}

# Create/update a junction named 'current' (no admin rights required)
$CurrentPath = Join-Path (Get-Location) "current"
if (Test-Path $CurrentPath) {
    Remove-Item $CurrentPath -Recurse -Force
}
New-Item -ItemType Junction -Path $CurrentPath -Target (Join-Path (Get-Location) $Target) | Out-Null

Pop-Location
Write-Host "nwep ready ($Target)"
