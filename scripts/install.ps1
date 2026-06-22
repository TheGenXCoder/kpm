<#
KPM Windows Quick Install

Usage:
  iwr https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.ps1 -UseBasicParsing | iex

Environment variables:
  KPM_INSTALL_DIR   Install directory. Default: $env:LOCALAPPDATA\Programs\kpm
  KPM_RELEASE_TAG   Release tag. Default: v0.5.0
#>

$ErrorActionPreference = 'Stop'

$ReleaseTag = if ($env:KPM_RELEASE_TAG) { $env:KPM_RELEASE_TAG } else { 'v0.5.0' }
$InstallDir = if ($env:KPM_INSTALL_DIR) { $env:KPM_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\kpm' }
$BinaryUrl = "https://github.com/TheGenXCoder/kpm/releases/download/$ReleaseTag/kpm-windows-amd64.exe"
$Dest = Join-Path $InstallDir 'kpm.exe'

Write-Host "==> Installing kpm $ReleaseTag for windows/amd64"
New-Item -ItemType Directory -Force $InstallDir | Out-Null

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("kpm-{0}.exe" -f ([System.Guid]::NewGuid()))
try {
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $Tmp -UseBasicParsing
    Move-Item -Force $Tmp $Dest
} finally {
    Remove-Item -Force $Tmp -ErrorAction SilentlyContinue
}

$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($UserPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', ($UserPath.TrimEnd(';') + ';' + $InstallDir).TrimStart(';'), 'User')
    Write-Host "==> Added $InstallDir to the user PATH. Open a new PowerShell session to pick it up."
}

& $Dest version
Write-Host ""
Write-Host "Next steps:"
Write-Host "  kpm quickstart"
Write-Host "  kpm tree"
