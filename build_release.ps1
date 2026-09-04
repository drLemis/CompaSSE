$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$BundleDir = Join-Path $Root 'release'
$Spec = Join-Path $Root 'CompaSSE.spec'
$env:SOURCE_DATE_EPOCH = $(git log -1 --format='%ct' -- CompaSSE.spec build_release.ps1)
if (-not $env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH = '0' }
$env:PYTHONHASHSEED = '12345'

foreach ($p in @('build', $BundleDir)) {
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
}

Write-Host '== PyInstaller build =='
$ErrorActionPreference = 'Continue'
python -m PyInstaller --noconfirm --clean --log-level WARN --distpath $BundleDir $Spec
$rc = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($rc -ne 0) { throw 'PyInstaller failed' }

$DataDir = Join-Path $BundleDir 'Data\SKSE\Plugins'
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $Root 'DLL\build\!CompaSSE.dll') -Destination $DataDir

$Ver = & python -c "import compasse; print(compasse.VERSION)"
$Zip = Join-Path $BundleDir "CompaSSE-$Ver.zip"
Compress-Archive -Path (Join-Path $BundleDir '*') -DestinationPath $Zip -Force

Write-Host "`n== Done. Bundle: $BundleDir =="
Get-ChildItem -LiteralPath $BundleDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($BundleDir.Length + 1)
    "{0,-40} {1,10} bytes" -f $rel, $_.Length
}
