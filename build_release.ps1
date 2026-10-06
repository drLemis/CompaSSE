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
$CompaSSEDir = Join-Path $DataDir 'CompaSSE'
New-Item -ItemType Directory -Path $CompaSSEDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $Root 'DLL\build\!CompaSSE.dll') -Destination $DataDir
$RecipesSrc = Join-Path $Root 'recipes'
if (Test-Path -LiteralPath $RecipesSrc) {
    $RecipesDir = Join-Path $CompaSSEDir 'recipes'
    New-Item -ItemType Directory -Path $RecipesDir -Force | Out-Null
    Copy-Item -Path (Join-Path $RecipesSrc '*.json') -Destination $RecipesDir -Force
    Write-Host '   Copied recipes to bundle'
}

# Build translation table against installed game's old bins (best effort, skipped without a game)
$DefaultPluginsDir = $env:COMPASSE_PLUGINS_DIR
if (-not $DefaultPluginsDir) {
    $roots = @()
    foreach ($hive in @('HKCU:\Software\Valve\Steam', 'HKLM:\SOFTWARE\Wow6432Node\Valve\Steam', 'HKLM:\SOFTWARE\Valve\Steam')) {
        try {
            $sp = (Get-ItemProperty -LiteralPath $hive -Name SteamPath -ErrorAction Stop).SteamPath
            if ($sp) { $roots += $sp }
        } catch { }
    }
    $libs = @()
    foreach ($root in ($roots | Select-Object -Unique)) {
        $libs += (Join-Path $root 'steamapps')
        $vdf = Join-Path $root 'steamapps\libraryfolders.vdf'
        if (Test-Path -LiteralPath $vdf) {
            $raw = Get-Content -LiteralPath $vdf -Raw -ErrorAction SilentlyContinue
            if ($raw) {
                foreach ($m in [regex]::Matches($raw, '"path"\s+"([^"]+)"')) {
                    $libs += (Join-Path ($m.Groups[1].Value -replace '\\\\', '\') 'steamapps')
                }
            }
        }
    }
    foreach ($lib in ($libs | Select-Object -Unique)) {
        $cand = Join-Path $lib 'common\Skyrim Special Edition\Data\SKSE\Plugins'
        if (Test-Path -LiteralPath $cand) { $DefaultPluginsDir = $cand; break }
    }
}
$GameExe = $null
if ($DefaultPluginsDir) {
    $GameExe = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $DefaultPluginsDir))) 'SkyrimSE.exe'
}
if ($GameExe -and (Test-Path -LiteralPath $GameExe)) {
    Write-Host '== Building translation table =='
    python -c "import sys, core.translations as T, core.versions as V; from pathlib import Path; game, plug = sys.argv[1], Path(sys.argv[2]); T.build_translations(game, plug, game_version=V.runtime_version_from_exe(game))" $GameExe $DefaultPluginsDir
    if ($LASTEXITCODE -ne 0) { Write-Warning "Translation build failed (exit code $LASTEXITCODE)" }
    # Copy result to bundle
    $srcBin = Join-Path $DefaultPluginsDir 'CompaSSE\translation_table.bin'
    if (Test-Path -LiteralPath $srcBin) {
        Copy-Item -LiteralPath $srcBin -Destination $CompaSSEDir
        Write-Host "   Copied translation_table.bin to bundle"
    }
} else {
    Write-Warning "Game exe not found - skipping translation table build"
    Write-Warning "Rebuild helper data from the Therapist tab instead"
}

$Ver = & python -c "import core; print(core.VERSION)"
$Zip = Join-Path $BundleDir "CompaSSE-$Ver.zip"
Compress-Archive -Path (Join-Path $BundleDir '*') -DestinationPath $Zip -Force

Write-Host "`n== Done. Bundle: $BundleDir =="
Get-ChildItem -LiteralPath $BundleDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($BundleDir.Length + 1)
    "{0,-40} {1,10} bytes" -f $rel, $_.Length
}
