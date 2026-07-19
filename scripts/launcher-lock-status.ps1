<#
.SYNOPSIS
    Read-only process-identity classification for an Astrolabe launcher lock.

.DESCRIPTION
    Exposes the authoritative launcher-lock parser to non-PowerShell callers such as Git for
    Windows hooks. It never creates, removes, or changes a file and never stops a process.

    Exit 0: absent or stale exact owner (classification only; stale never authorizes claim/removal)
    Exit 20: exact owner held/live
    Exit 21: lock schema unreadable
    Exit 22: owner process identity unevaluable
    Exit 24: interrupted claim/cleanup transition present
    Exit 23: classifier fault

.NOTES
    Refs #611, #519, #197. Runtime helper; this is not a test or gate.
#>
[CmdletBinding()]
param([string]$LockPath = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    if ([string]::IsNullOrWhiteSpace($LockPath)) {
        throw [ArgumentException]::new('LockPath is required')
    }
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
    $state = Read-AstroLauncherLock -LockPath ([IO.Path]::GetFullPath($LockPath))
    $state | ConvertTo-Json -Depth 5 -Compress | Write-Output
    switch ($state.State) {
        'absent' { exit 0 }
        'stale' { exit 0 }
        'held' { exit 20 }
        'unreadable' { exit 21 }
        'unevaluable' { exit 22 }
        'transition' { exit 24 }
        default { exit 23 }
    }
}
catch {
    $payload = [ordered]@{
        State = 'fault'
        Code = 'ASTRO_LAUNCHER_LOCK_STATUS_FAULT'
        Message = $_.Exception.Message
        Remediation = 'preserve the lock and repair the authoritative process-identity classifier'
    } | ConvertTo-Json -Compress
    [Console]::Error.WriteLine($payload)
    exit 23
}
