# Service Approval plugin installer — Windows PowerShell version.
# Detects installed AI clients and wires them up. Idempotent.
#
# Prerequisite: Windows Developer Mode ON (enables symlinks without admin).
#   Settings -> Update & Security -> For developers -> Developer Mode: On
#
# Usage:
#   .\install.ps1                  # install for all detected clients
#   .\install.ps1 -Check           # report what would be installed
#   .\install.ps1 -Quiet           # suppress non-error output

param(
    [switch]$Check,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$RepoDir = Split-Path -Parent $PSCommandPath

function Log  { if (-not $Quiet) { Write-Host $args } }
function Ok   { Log "  [OK] $args" }
function Skip { Log "  [..] $args" }
function Warn { Write-Host "  [!!] $args" -ForegroundColor Yellow }

Log ""
Log "Service Approval installer - mode: $(if ($Check) { 'check' } else { 'install' })"
Log "Repo:   $RepoDir"
Log ""

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
# Cursor — auto-discovers .cursor/.
# ---------------------------------------------------------------------------
Log ""
Log "Cursor"
if (Test-Path "$RepoDir\.cursor") {
    Ok ".cursor\ present - Cursor auto-discovers"
} else {
    Skip ".cursor\ not in repo - Cursor users can still read AGENTS.md"
}

# ---------------------------------------------------------------------------
# Codex CLI — reads AGENTS.md.
# ---------------------------------------------------------------------------
Log ""
Log "Codex CLI"
if (Test-Path "$RepoDir\AGENTS.md") {
    Ok "AGENTS.md present - Codex CLI auto-reads"
} else {
    Warn "AGENTS.md missing"
}

# ---------------------------------------------------------------------------
# Gemini CLI — needs `gemini extensions link`.
# ---------------------------------------------------------------------------
Log ""
Log "Gemini CLI"
if (Get-Command gemini -ErrorAction SilentlyContinue) {
    $extPath = Join-Path $RepoDir "gemini-extension"
    if (Test-Path $extPath) {
        if ($Check) {
            Skip "would run: gemini extensions link $extPath"
        } else {
            try {
                & gemini extensions link $extPath 2>&1 | Out-Null
                Ok "extension linked (symlink - git pull auto-updates)"
            } catch {
                Skip "extension already linked or link failed"
            }
        }
    } else {
        Skip "gemini-extension\ not yet created (awaiting PR3)"
    }
} else {
    Skip "gemini CLI not installed"
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
        Skip "powers\service-approval\ not yet created (awaiting PR2)"
    }
} else {
    Skip "kiro-cli not installed"
}

Log ""
Log "Done. To update: git pull (symlinked installs refresh automatically)."
