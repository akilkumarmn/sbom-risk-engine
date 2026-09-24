# Download syft and trivy (Windows, no admin needed) into tools\ and put them on
# PATH for this PowerShell session.
#
#   powershell -ExecutionPolicy Bypass -File scripts\get_tools.ps1
#
# In a NEW window, put them back on PATH with:
#   $env:Path = "$PWD\tools;$env:Path"

$ErrorActionPreference = "Stop"
$repo  = Split-Path -Parent $PSScriptRoot
$tools = [System.IO.Path]::Combine($repo, "tools")
[System.IO.Directory]::CreateDirectory($tools) | Out-Null
Write-Host "tools folder: $tools"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-Tool($repoPath, $pattern, $exe) {
  $dest = [System.IO.Path]::Combine($tools, $exe)
  if ([System.IO.File]::Exists($dest)) { Write-Host "$exe already present"; return }

  Write-Host "looking up the latest $exe release..."
  $rel = Invoke-RestMethod "https://api.github.com/repos/$repoPath/releases/latest" -Headers @{ "User-Agent" = "sbom-risk-engine" }
  $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
  if (-not $asset) { throw "no Windows asset matching '$pattern' in $repoPath $($rel.tag_name)" }

  $zip = [System.IO.Path]::Combine($env:TEMP, $asset.name)
  Write-Host "  downloading $($asset.name) ($([math]::Round($asset.size/1MB,1)) MB)"
  Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing

  $tmp = [System.IO.Path]::Combine($env:TEMP, "sre-" + [guid]::NewGuid().ToString("N"))
  [System.IO.Directory]::CreateDirectory($tmp) | Out-Null
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $tmp)

  $src = Get-ChildItem -LiteralPath $tmp -Recurse -File | Where-Object { $_.Name -ieq $exe } | Select-Object -First 1
  if (-not $src) {
    Write-Host "  archive contents:"
    Get-ChildItem -LiteralPath $tmp -Recurse -File | ForEach-Object { Write-Host "    $($_.Name)" }
    throw "$exe was not found inside $($asset.name)"
  }
  [System.IO.File]::Copy($src.FullName, $dest, $true)
  Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "  installed $dest"
}

Get-Tool "anchore/syft"       'windows_amd64\.zip$'  "syft.exe"
Get-Tool "aquasecurity/trivy" 'windows-64bit\.zip$'  "trivy.exe"

$env:Path = "$tools;$env:Path"
Write-Host ""
& ([System.IO.Path]::Combine($tools, "syft.exe")) version
& ([System.IO.Path]::Combine($tools, "trivy.exe")) --version
Write-Host ""
Write-Host "tools\ is on PATH for THIS window only. Next:"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\build_kev_fixture.ps1"
