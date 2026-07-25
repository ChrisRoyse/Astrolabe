<#
.SYNOPSIS
Runs native Windows GNU toolchain work through Astrolabe's canonical launcher authority.

.DESCRIPTION
Dispatches an issue-bound bootstrap, diagnostic, single command, or contiguous command batch
to the hash-verified canonical protocol authority. Native Cargo and C work must enter through
this trampoline so the launcher owns its toolchain, process tree, temporary state, and target
lifecycle.

.EXAMPLE
PS> $drivingIssue = Read-Host 'Driving GitHub issue number'
PS> $cargoArgs = '["check","--workspace"]'
PS> .\scripts\windows-gnu-toolchain.ps1 -Issue $drivingIssue -Command cargo -CommandArgsJson $cargoArgs

Runs a native Cargo workspace check under the positive GitHub issue that drives the run.

.EXAMPLE
PS> $drivingIssue = Read-Host 'Driving GitHub issue number'
PS> $batch = '[["cargo","check","--workspace"],["cargo","build","--workspace"]]'
PS> .\scripts\windows-gnu-toolchain.ps1 -Issue $drivingIssue -BatchCommandsJson $batch

Runs a native check and build as one fail-fast contiguous batch under one launcher owner.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# #613: this file is the only launcher entrypoint tracked into registered
# worktrees. It contains no build, lock, cleanup, Git, TEMP, target, or
# shared-tool mutation capability. Every invocation transfers control to the
# canonical authority implementation in the main checkout, which independently
# verifies these exact trampoline bytes before doing any mutating work.
$protocolAuthorityVersion = 3
$canonicalRoot = 'C:\code\Astrolabe'
$authorityPath = Join-Path `
    (Join-Path $canonicalRoot 'scripts') `
    'windows-gnu-toolchain-authority.ps1'
$entryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..')
).TrimEnd('\', '/')

if (-not [IO.File]::Exists($authorityPath)) {
    throw (
        'LAUNCHER_AUTHORITY[ASTRO_LAUNCHER_AUTHORITY_MISSING]: ' +
        "{code=ASTRO_LAUNCHER_AUTHORITY_MISSING; " +
        "message=`"canonical launcher protocol authority v$protocolAuthorityVersion " +
        "is absent at '$authorityPath'`"; " +
        "remediation=`"restore and verify the canonical checkout at " +
        "'$canonicalRoot', then rerun this exact trampoline`"}"
    )
}

Write-Output (
    'LAUNCHER_AUTHORITY[ASTRO_LAUNCHER_CANONICAL_DISPATCH]: ' +
    "protocol_version=$protocolAuthorityVersion; " +
    "entrypoint=$PSCommandPath; authority=$authorityPath; " +
    "workspace_root=$entryRoot"
)
& $authorityPath -WorkspaceRoot $entryRoot @args
$authorityExitCode = $LASTEXITCODE
if ($null -eq $authorityExitCode) {
    throw (
        'LAUNCHER_AUTHORITY[ASTRO_LAUNCHER_AUTHORITY_EXIT_MISSING]: ' +
        "{code=ASTRO_LAUNCHER_AUTHORITY_EXIT_MISSING; " +
        "message=`"canonical launcher protocol authority v$protocolAuthorityVersion " +
        "returned without an explicit process exit code`"; " +
        "remediation=`"preserve all launcher state, inspect the canonical " +
        "authority terminal path at '$authorityPath', and repair its explicit " +
        "exit contract before retrying`"}"
    )
}
exit [int]$authorityExitCode
