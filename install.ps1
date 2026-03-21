# AccuKnox Asset Check — Windows installer
# Run: iwr -useb https://raw.githubusercontent.com/accuknox/ak-asset-check/main/install.ps1 | iex
# Or:  $env:VERSION="v1.2.3"; .\install.ps1

param(
  [string]$Version  = $env:VERSION,
  [string]$InstallDir = "$env:LOCALAPPDATA\Programs\ak-asset-check"
)

$Repo   = "accuknox/ak-asset-check"
$Binary = "ak-asset-check.exe"
$ErrorActionPreference = "Stop"

# ── Detect architecture ───────────────────────────────────────────────────────
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else {
  Write-Error "32-bit Windows is not supported."; exit 1
}

# ── Resolve latest version ────────────────────────────────────────────────────
if (-not $Version) {
  $meta    = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $meta.tag_name
}

if (-not $Version) {
  Write-Error "Could not determine latest version. Set `$env:VERSION to override."
  exit 1
}

$Archive = "ak-asset-check-windows-$Arch.zip"
$Url     = "https://github.com/$Repo/releases/download/$Version/$Archive"

# ── Download & install ────────────────────────────────────────────────────────
$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
  Write-Host "Downloading ak-asset-check $Version (windows/$Arch)..."
  $ZipPath = Join-Path $Tmp $Archive
  Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
  Expand-Archive -Path $ZipPath -DestinationPath $Tmp -Force

  $Exe = Get-ChildItem -Path $Tmp -Filter $Binary -Recurse | Select-Object -First 1
  if (-not $Exe) {
    Write-Error "Binary not found in archive."
    exit 1
  }

  if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
  }

  Copy-Item -Path $Exe.FullName -Destination (Join-Path $InstallDir $Binary) -Force
} finally {
  Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# ── Add to PATH for current user if not already present ───────────────────────
$UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
  [System.Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
  Write-Host "Added $InstallDir to your PATH (restart your terminal to apply)."
}

Write-Host "Installed: $InstallDir\$Binary"
