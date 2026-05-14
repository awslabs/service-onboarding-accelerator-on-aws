# Service Approval plugin installer — Windows PowerShell version.
# Detects installed AI clients and wires them up. Idempotent.
#
# Prerequisite: Windows Developer Mode ON (enables symlinks without admin).
#   Settings -> Update & Security -> For developers -> Developer Mode: On
#
# Modes:
#   .\install.ps1              Initial install (runs sync afterward)
#   .\install.ps1 -Sync        Re-sync only (safe after git pull; copies Kiro
#                              files, regenerates client manifests + agent
#                              mirrors)
#   .\install.ps1 -Update      git pull + -Sync (one-shot "get latest")
#   .\install.ps1 -Check       Dry-run (report what would be installed)
#   .\install.ps1 -Quiet       Suppress non-error output

param(
    [switch]$Check,
    [switch]$Sync,
    [switch]$Update,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSCommandPath

function Log  { if (-not $Quiet) { Write-Host $args } }
function Ok   { Log "  [OK] $args" }
function Skip { Log "  [..] $args" }
function Warn { Write-Host "  [!!] $args" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# -Update: git pull first, then fall through to -Sync
# ---------------------------------------------------------------------------
if ($Update) {
    Log ""
    Log "Pulling latest changes..."
    try {
        git -C $RepoDir pull --ff-only
    } catch {
        Warn "git pull failed - fix conflicts and rerun"
        exit 1
    }
    $Sync = $true
}

$mode = if ($Check) { "check" } elseif ($Sync) { "sync" } else { "install" }

Log ""
Log "Service Approval installer - mode: $mode"
Log "Repo:   $RepoDir"
Log ""

# ---------------------------------------------------------------------------
# Sync-KiroIde: copy Power files into .kiro\ workspace paths.
# ---------------------------------------------------------------------------
function Sync-KiroIde {
    $src      = Join-Path $RepoDir "powers\service-approval"
    $dstKiro  = Join-Path $RepoDir ".kiro"

    if (-not (Test-Path $src)) {
        Skip "powers\service-approval\ missing - Kiro IDE sync skipped"
        return
    }

    foreach ($sub in @("agents", "hooks", "steering", "settings")) {
        $p = Join-Path $dstKiro $sub
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }

    # Steering — every *.md from powers/.../steering/
    $steering = Join-Path $src "steering"
    if (Test-Path $steering) {
        Copy-Item "$steering\*.md" "$dstKiro\steering\" -Force -ErrorAction SilentlyContinue
    }

    # IDE agents (.md) — from powers/.../ide/agents/
    $ideAgents = Join-Path $src "ide\agents"
    if (Test-Path $ideAgents) {
        Copy-Item "$ideAgents\*.md" "$dstKiro\agents\" -Force -ErrorAction SilentlyContinue
    }

    # IDE hooks (.kiro.hook) — from powers/.../ide/hooks/
    $ideHooks = Join-Path $src "ide\hooks"
    if (Test-Path $ideHooks) {
        Copy-Item "$ideHooks\*.kiro.hook" "$dstKiro\hooks\" -Force -ErrorAction SilentlyContinue
    }

    # MCP config — overwrite (source of truth is the manifest)
    $mcpJson = Join-Path $src "mcp.json"
    if (Test-Path $mcpJson) {
        Copy-Item $mcpJson "$dstKiro\settings\mcp.json" -Force
    }
}

# ---------------------------------------------------------------------------
# Sync-Configs: regenerate client-specific manifests from manifest.yaml AND
# regenerate Kiro CLI/IDE agent mirrors from agents-src/*.yaml.
# ---------------------------------------------------------------------------
function Sync-Configs {
    $manifest = Join-Path $RepoDir "manifest.yaml"
    if (-not (Test-Path $manifest)) {
        Skip "manifest.yaml missing - skipping config sync"
        return $false
    }
    try {
        & python3 -c "import yaml" 2>$null
        if ($LASTEXITCODE -ne 0) { throw "no yaml" }
    } catch {
        Warn "PyYAML not installed - run: pip3 install pyyaml"
        return $false
    }
    & python3 (Join-Path $RepoDir "tools\sync-ide-configs.py")
    if ($LASTEXITCODE -ne 0) { return $false }
    & python3 (Join-Path $RepoDir "tools\generate-kiro-agents.py")
    if ($LASTEXITCODE -ne 0) { return $false }
    return $true
}

# ===========================================================================
# Sync mode — copy Kiro IDE files, regenerate client manifests, stop.
# ===========================================================================
if ($Sync) {
    Log "Kiro IDE sync"
    Sync-KiroIde
    Ok "workspace .kiro\ synced from powers\service-approval\"

    Log ""
    Log "Client manifest sync"
    if (Sync-Configs) {
        Ok "manifests + agent mirrors regenerated from manifest.yaml + agents-src\"
    }

    Log ""
    Log "Done. Re-run any time after editing manifest.yaml, agents-src\*.yaml, powers\, or steering."
    exit 0
}

# ---------------------------------------------------------------------------
# Windows Developer Mode check (required for symlinks without admin).
# ---------------------------------------------------------------------------
$devMode = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
if (-not $devMode -or $devMode.AllowDevelopmentWithoutDevLicense -ne 1) {
    Warn "Windows Developer Mode is OFF. Symlink installs will require admin."
    Warn "Enable: Settings -> Update & Security -> For developers -> Developer Mode"
    Log ""
}

# ---------------------------------------------------------------------------
# Claude Code — auto-discovers.
# ---------------------------------------------------------------------------
Log "Claude Code"
if (Test-Path "$RepoDir\.claude-plugin\plugin.json") {
    Ok "plugin.json present - Claude Code will auto-load"
} else {
    Warn ".claude-plugin\plugin.json missing"
}

# ---------------------------------------------------------------------------
# GitHub Copilot (VS Code) — auto-discovers .github/.
# ---------------------------------------------------------------------------
Log ""
Log "GitHub Copilot"
if (Test-Path "$RepoDir\.github") {
    Ok ".github\ present - VS Code + Copilot auto-discovers"
} else {
    Warn ".github\ missing"
}

# ---------------------------------------------------------------------------
# Kiro CLI 2.0 — install the Power.
# ---------------------------------------------------------------------------
Log ""
Log "Kiro CLI"
if (Get-Command kiro-cli -ErrorAction SilentlyContinue) {
    $powerPath = Join-Path $RepoDir "powers\service-approval"
    if (Test-Path $powerPath) {
        if ($Check) {
            Skip "would run: kiro-cli power install --local $powerPath"
        } else {
            try {
                & kiro-cli power install --local $powerPath 2>&1 | Out-Null
                Ok "Power installed (symlink - git pull auto-updates)"
            } catch {
                Skip "Power already installed or install failed"
            }
        }
    } else {
        Skip "powers\service-approval\ missing"
    }
} else {
    Skip "kiro-cli not installed"
}

# ---------------------------------------------------------------------------
# Kiro IDE — manual UI install, but pre-copy workspace files to .kiro\.
# ---------------------------------------------------------------------------
Log ""
Log "Kiro IDE"
$kiroApp = "C:\Program Files\Kiro"
if ((Test-Path $kiroApp) -or (Test-Path "$env:USERPROFILE\.kiro")) {
    if ($Check) {
        Skip "would copy powers\service-approval\{steering,ide\*} -> .kiro\"
    } else {
        Sync-KiroIde
        Ok "workspace .kiro\ populated - open Kiro and Powers -> Add from Local Path"
        Ok "                              -> select $RepoDir\powers\service-approval"
    }
} else {
    Skip "Kiro IDE not detected"
}

# ---------------------------------------------------------------------------
# Run sync after install
# ---------------------------------------------------------------------------
if (-not $Check) {
    Log ""
    Log "Running sync to regenerate client manifests + agent mirrors..."
    if (Sync-Configs) {
        Ok "manifests + agent mirrors in sync with sources"
    }
}

Log ""
Log "Done. Update with: .\install.ps1 -Update  (or: git pull; .\install.ps1 -Sync)"
