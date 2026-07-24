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
