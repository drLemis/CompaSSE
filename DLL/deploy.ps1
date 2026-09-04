<#
.SYNOPSIS
    Build, deploy, and optionally launch Skyrim with the CompaSSE shim.

.DESCRIPTION
    Compiles the shim DLL from source, copies it to the Skyrim SE Plugins
    folder, and optionally launches the game via skse64_loader.

    ASCII sort order matters: "!" (0x21) sorts before "A" (0x41), so
    !CompaSSE.dll loads FIRST and installs hooks before any other plugin
    tries to open the address library.

.PARAMETER NoBuild
    Skip compilation. Deploy the last build output.

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

if (-not $PluginsDir) {
    $PluginsDir = 'D:\SteamLibrary\steamapps\common\Skyrim Special Edition\Data\SKSE\Plugins'
}
$SkyrimDir = Split-Path -Parent (Split-Path -Parent $PluginsDir)

$Target = Join-Path $PluginsDir '!CompaSSE.dll'

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

# ---- Build ----
if ($NoBuild) {
    Write-Step 'Build'
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
        cmd /c "`"$BuildBat`"" 2>&1 | ForEach-Object { Write-Host "   $_" }
        $rc = $LASTEXITCODE
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

# ---- Verify target folder exists ----
if (-not (Test-Path -LiteralPath $PluginsDir)) {
    Write-Fail "Plugins folder not found: $PluginsDir"
    Write-Host "   Check your Skyrim SE install path." -ForegroundColor Yellow
    exit 1
}

# ---- Deploy ----
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

# ---- Clear old log ----
$logPath = Join-Path $PluginsDir '!CompaSSE.log'
if (Test-Path -LiteralPath $logPath) {
    Invoke-Dry "Remove old log" { Remove-Item -LiteralPath $logPath -Force }
    Write-Ok 'Cleared old log'
}

# ---- Launch ----
if ($Launch) {
    Write-Step 'Launching Skyrim SE'
    $exe = Join-Path $SkyrimDir '../skse64_loader.exe'
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
    Write-Host "   DLL deployed to:" -ForegroundColor Green
    Write-Host "     $Target"
    if ($Launch) {
        Write-Host "   Game launched. Check log at:" -ForegroundColor Green
        Write-Host "     $logPath"
    }
}
