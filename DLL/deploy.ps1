<#
.SYNOPSIS
    Build, deploy, and optionally launch Skyrim with the CompaSSE shim.

.DESCRIPTION
    Compiles the shim DLL from source, builds CompaSSE.exe via PyInstaller,
    generates the translation table, and deploys everything to the Skyrim SE
    Plugins folder.

    ASCII sort order matters: "!" (0x21) sorts before "A" (0x41), so
    !CompaSSE.dll loads FIRST and installs hooks before any other plugin
    tries to open the address library.

.PARAMETER NoBuild
    Skip compilation. Deploy the last build output.

.PARAMETER NoTranslations
    Skip translation table generation.

.PARAMETER Launch
    After deployment, launch Skyrim SE via skse64_loader.exe.

.PARAMETER Kill
    Kill any running Skyrim SE or skse64_loader processes before deploying.

.PARAMETER Wait
    Seconds to wait after launch before returning (default: 5).

.PARAMETER PluginsDir
    Override the plugins folder path. Defaults to the standard Steam path.

.PARAMETER DryRun
    Show what would happen without making changes.

.EXAMPLE
    .\deploy.ps1
    # Build + deploy (kill nothing, don't launch)

.EXAMPLE
    .\deploy.ps1 -Kill -Launch -Wait 20
    # Kill running game, build, deploy, launch, wait 20s

.EXAMPLE
    .\deploy.ps1 -NoBuild -Kill -Launch
    # Skip build, kill old game, deploy last build, launch

.EXAMPLE
    .\deploy.ps1 -DryRun
    # Preview what the script would do
#>
[CmdletBinding()]
param(
    [switch]$NoBuild,
    [switch]$NoTranslations,
    [switch]$Launch,
    [switch]$Kill,
    [int]$Wait = 5,
    [string]$PluginsDir,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ---- Paths ----
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BuildBat = Join-Path $ScriptDir 'build_shim.bat'
$BuildOutput = Join-Path $ScriptDir 'build\!CompaSSE.dll'

# Locate the SKSE plugins folder: explicit arg, env var, then Steam
# libraries from the registry + libraryfolders.vdf. No hardcoded paths.
function Find-SkyrimPluginsDir {
    if ($env:COMPASSE_PLUGINS_DIR -and (Test-Path -LiteralPath $env:COMPASSE_PLUGINS_DIR)) {
        return $env:COMPASSE_PLUGINS_DIR
    }
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
        if (Test-Path -LiteralPath $cand) {
            return $cand
        }
    }
    return $null
}

if (-not $PluginsDir) {
    $PluginsDir = Find-SkyrimPluginsDir
}
if (-not $PluginsDir -or -not (Test-Path -LiteralPath $PluginsDir)) {
    Write-Host "   FAIL: Plugins folder not found: ${PluginsDir}. Pass -PluginsDir <path> or set COMPASSE_PLUGINS_DIR." -ForegroundColor Red
    exit 1
}
$SkyrimDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PluginsDir))
$GameExe = Join-Path $SkyrimDir 'SkyrimSE.exe'

$Target = Join-Path $PluginsDir '!CompaSSE.dll'
$CompaSSEDir = Join-Path $PluginsDir 'CompaSSE'

# ---- Helpers ----
function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "   OK: $msg" -ForegroundColor Green }
function Write-Skip($msg) { Write-Host "   SKIP: $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "   FAIL: $msg" -ForegroundColor Red }
function Invoke-Dry($desc, $scriptblock) {
    if ($DryRun) {
        Write-Host "   [DRY RUN] $desc" -ForegroundColor DarkGray
        return
    }
    & $scriptblock
}

# ---- Kill running game ----
if ($Kill) {
    Write-Step 'Killing running game processes'
    $procs = Get-Process -Name 'SkyrimSE','skse64_loader' -ErrorAction SilentlyContinue
    if ($procs) {
        Invoke-Dry "Stop-Process ($($procs.Count) process(es))" {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        Write-Ok "Killed $($procs.Count) process(es)"
    } else {
        Write-Skip 'No running game processes found'
    }
}

# ---- Build DLL ----
if ($NoBuild) {
    Write-Step 'Build DLL'
    Write-Skip 'Skipped (-NoBuild)'
    if (-not (Test-Path -LiteralPath $BuildOutput)) {
        Write-Fail "Build output not found: $BuildOutput"
        Write-Host "   Run without -NoBuild, or build manually:" -ForegroundColor Yellow
        Write-Host "   cmd /c `"$BuildBat`"" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Step 'Building shim DLL'
    if (-not (Test-Path -LiteralPath $BuildBat)) {
        Write-Fail "Build script not found: $BuildBat"
        exit 1
    }
    if ($DryRun) {
        Write-Host "   [DRY RUN] cmd /c `"$BuildBat`"" -ForegroundColor DarkGray
    } else {
        Write-Host "   Running: cmd /c `"$BuildBat`"" -ForegroundColor Gray
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Push-Location $ScriptDir
        cmd /c "`"$BuildBat`"" 2>&1 | ForEach-Object { Write-Host "   $_" }
        $rc = $LASTEXITCODE
        Pop-Location
        $ErrorActionPreference = $prev
        if ($rc -ne 0) {
            Write-Fail "Build failed (exit code $rc)"
            exit 1
        }
    }
    if (-not (Test-Path -LiteralPath $BuildOutput)) {
        Write-Fail "Build output not found after successful build: $BuildOutput"
        exit 1
    }
    $sz = (Get-Item -LiteralPath $BuildOutput).Length
    Write-Ok "Built: $BuildOutput ($sz bytes)"
}

# ---- Build CompaSSE.exe (PyInstaller) ----
$ExeOutput = Join-Path $ProjectRoot 'dist\CompaSSE.exe'
if ($NoBuild) {
    Write-Step 'Build CompaSSE.exe'
    Write-Skip 'Skipped (-NoBuild)'
    if (-not (Test-Path -LiteralPath $ExeOutput)) {
        Write-Skip "CompaSSE.exe not found: $ExeOutput"
    }
} else {
    Write-Step 'Building CompaSSE.exe'
    $Spec = Join-Path $ProjectRoot 'CompaSSE.spec'
    if ($DryRun) {
        Write-Host "   [DRY RUN] python -m PyInstaller --noconfirm --clean --distpath dist $Spec" -ForegroundColor DarkGray
    } else {
        Write-Host "   Running: python -m PyInstaller" -ForegroundColor Gray
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Push-Location $ProjectRoot
        python -m PyInstaller --noconfirm --clean --log-level WARN --distpath dist $Spec 2>&1 | ForEach-Object { Write-Host "   $_" }
        $rc = $LASTEXITCODE
        Pop-Location
        $ErrorActionPreference = $prev
        if ($rc -ne 0) {
            Write-Fail "PyInstaller failed (exit code $rc)"
            exit 1
        }
    }
    if (Test-Path -LiteralPath $ExeOutput) {
        $sz = (Get-Item -LiteralPath $ExeOutput).Length
        Write-Ok "Built: $ExeOutput ($sz bytes)"
    } else {
        Write-Fail "CompaSSE.exe not found after build"
    }
}

# ---- Deploy DLL ----
Write-Step 'Deploying DLL to plugins folder'

$name = Split-Path -Leaf $Target
Invoke-Dry "Copy -> $name" {
    try {
        Copy-Item -LiteralPath $BuildOutput -Destination $Target -Force
    } catch {
        Write-Fail "Failed to copy to ${name}: $_"
        exit 1
    }
}
if (-not $DryRun) {
    $deplSz = (Get-Item -LiteralPath $Target).Length
    Write-Ok "$name ($deplSz bytes)"
} else {
    Write-Ok "$name (dry run)"
}

# ---- Deploy CompaSSE.exe ----
if (Test-Path -LiteralPath $ExeOutput) {
    Write-Step 'Deploying CompaSSE.exe'
    $ExeTarget = Join-Path $PluginsDir '..\..\..\..\..\..'
    $ExeTarget = Join-Path $SkyrimDir 'CompaSSE.exe'
    Invoke-Dry "Copy -> CompaSSE.exe" {
        Copy-Item -LiteralPath $ExeOutput -Destination $ExeTarget -Force
    }
    if (-not $DryRun) {
        $exSz = (Get-Item -LiteralPath $ExeTarget).Length
        Write-Ok "CompaSSE.exe ($exSz bytes)"
    } else {
        Write-Ok "CompaSSE.exe (dry run)"
    }
}

# ---- Ensure CompaSSE subfolder exists ----
if (-not (Test-Path -LiteralPath $CompaSSEDir)) {
    Invoke-Dry "Create CompaSSE subfolder" { New-Item -ItemType Directory -Path $CompaSSEDir -Force | Out-Null }
    Write-Ok "Created CompaSSE subfolder"
}

# ---- Build translation table ----
if (-not $NoTranslations) {
    Write-Step 'Building translation table'
    if (-not (Test-Path -LiteralPath $GameExe)) {
        Write-Skip "Game exe not found: $GameExe - skipping translation build"
    } else {
        if ($DryRun) {
            Write-Host "   [DRY RUN] compasse.exe --build-translations" -ForegroundColor DarkGray
        } else {
            $pyArgs = @(
                'compasse.py', '--build-translations',
                '--game', $GameExe,
                '--plugins-dir', $PluginsDir
            )
            Write-Host "   Running: python $($pyArgs -join ' ')" -ForegroundColor Gray
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            Push-Location $ProjectRoot
            python @pyArgs 2>&1 | ForEach-Object { Write-Host "   $_" }
            $rc = $LASTEXITCODE
            Pop-Location
            $ErrorActionPreference = $prev
            if ($rc -ne 0) {
                Write-Fail "Translation build failed (exit code $rc)"
                exit 1
            }
        }
        $transBin = Join-Path $CompaSSEDir 'translation_table.bin'
        if (Test-Path -LiteralPath $transBin) {
            $sz = (Get-Item -LiteralPath $transBin).Length
            Write-Ok "translation_table.bin ($sz bytes)"
        } else {
            Write-Skip "translation_table.bin not found after build"
        }
    }
} else {
    Write-Step 'Build translation table'
    Write-Skip 'Skipped (-NoTranslations)'
}

# ---- Clear old log ----
$logPath = Join-Path $CompaSSEDir '!CompaSSE.log'
if (Test-Path -LiteralPath $logPath) {
    Invoke-Dry "Remove old log" { Remove-Item -LiteralPath $logPath -Force }
    Write-Ok 'Cleared old log'
}

# ---- Launch ----
if ($Launch) {
    Write-Step 'Launching Skyrim SE'
    $exe = Join-Path $SkyrimDir 'skse64_loader.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        Write-Fail "skse64_loader.exe not found: $exe"
        exit 1
    }
    Invoke-Dry "Start-Process $exe" {
        Start-Process -FilePath $exe -WorkingDirectory $SkyrimDir
    }
    if ($Wait -gt 0) {
        Write-Host "   Waiting ${Wait}s for plugin loading..." -ForegroundColor Gray
        if (-not $DryRun) { Start-Sleep -Seconds $Wait }
    }

    if (-not $DryRun -and (Test-Path -LiteralPath $logPath)) {
        Write-Step 'Log output (last 30 lines)'
        Get-Content -LiteralPath $logPath -Tail 30 | ForEach-Object {
            if ($_ -match 'error|fail|MessageBox|Unsupported|must be recompiled') {
                Write-Host $_ -ForegroundColor Red
            } elseif ($_ -match 'CRASH|exception|CRASHED') {
                Write-Host $_ -ForegroundColor Magenta
            } elseif ($_ -match 'patched|serve.*format') {
                Write-Host $_ -ForegroundColor Green
            } else {
                Write-Host $_
            }
        }
    }
}

# ---- Summary ----
Write-Step 'Done'
if ($DryRun) {
    Write-Host "   Dry run complete. No changes were made." -ForegroundColor Yellow
} else {
    Write-Host "   Deployed:" -ForegroundColor Green
    Write-Host "     $Target"
    if (Test-Path -LiteralPath $ExeTarget) {
        Write-Host "     $ExeTarget"
    }
    $transBin = Join-Path $CompaSSEDir 'translation_table.bin'
    if (Test-Path -LiteralPath $transBin) {
        Write-Host "     $transBin"
    }
    if ($Launch) {
        Write-Host "   Game launched. Check log at:" -ForegroundColor Green
        Write-Host "     $logPath"
    }
}
