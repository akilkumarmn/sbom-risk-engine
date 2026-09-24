# Turn the generated manifests into a real SBOM + scan with Syft and Trivy (Windows).
#
#   python -m scripts.make_backtest_fixture --freeze 2025-01-01
#   powershell -ExecutionPolicy Bypass -File scripts\build_kev_fixture.ps1
#   python -m scripts.make_backtest_fixture --verify
#
# Uses syft.exe and trivy.exe if they are on PATH; otherwise falls back to Docker
# (Docker Desktop must be running). Force Docker with:  -UseDocker
param([switch]$UseDocker)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$fix = Join-Path $repo "backtest\fixtures\kev-2025-app"
if (-not (Test-Path (Join-Path $fix "src"))) {
  throw "run 'python -m scripts.make_backtest_fixture' first - $fix\src does not exist"
}

$local = Join-Path $repo "tools"
if (Test-Path $local) { $env:Path = "$local;$env:Path" }   # tools\ from scripts\get_tools.ps1
$haveSyft  = [bool](Get-Command syft  -ErrorAction SilentlyContinue)
$haveTrivy = [bool](Get-Command trivy -ErrorAction SilentlyContinue)
$useDocker = $UseDocker -or -not ($haveSyft -and $haveTrivy)

if ($useDocker) {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw @"
Neither syft/trivy nor docker was found.

Options:
  1. Run:             powershell -ExecutionPolicy Bypass -File scripts\get_tools.ps1
                      (downloads both into tools\ , no admin needed) and re-run this script
                      in the SAME window, or add tools\ to your PATH.
  2. Docker Desktop:  https://www.docker.com/products/docker-desktop/  (then re-run this script)
  3. Binaries:        download syft and trivy for Windows from
                      https://github.com/anchore/syft/releases and
                      https://github.com/aquasecurity/trivy/releases,
                      unzip them somewhere on your PATH, then re-run.
"@
  }
  Write-Host "using Docker images (anchore/syft, aquasec/trivy)"
  docker run --rm -v "${fix}:/w" anchore/syft:latest dir:/w/src -o cyclonedx-json |
    Out-File -Encoding utf8 (Join-Path $fix "sbom.cdx.json")
  docker run --rm -v "${fix}:/w" aquasec/trivy:latest sbom /w/sbom.cdx.json --format json --output /w/trivy.json
} else {
  Write-Host "using local syft and trivy"
  syft "dir:$fix\src" -o cyclonedx-json | Out-File -Encoding utf8 (Join-Path $fix "sbom.cdx.json")
  trivy sbom "$fix\sbom.cdx.json" --format json --output "$fix\trivy.json"
}

python -c @"
import json
sb = json.load(open(r'$fix\sbom.cdx.json', encoding='utf-8-sig'))
sc = json.load(open(r'$fix\trivy.json', encoding='utf-8-sig'))
n = len(sb.get('components', []))
v = sum(len(r.get('Vulnerabilities') or []) for r in sc.get('Results', []))
print(f'SBOM: {n} components | scan: {v} findings')
raise SystemExit(0 if n and v else 'empty SBOM or scan - check the manifests in src/')
"@

Write-Host ""
Write-Host "next: python -m scripts.make_backtest_fixture --verify"
Write-Host "then: python -m backtest.run_backtest --features data\features.parquet --freeze 2025-01-01 --out site\backtest.json --primary kev-2025-app"
