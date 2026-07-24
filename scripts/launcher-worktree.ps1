[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Inspect', 'Provision', 'Retire')]
    [string]$Operation,
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9._-]*$')]
    [string]$Name,
    [string]$Commitish = 'HEAD',
    [string]$NewBranch = '',
    [ValidateSet('Supported', 'Retired')]
    [string]$Location = 'Supported'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$canonicalRoot = 'C:\code\Astrolabe'
$canonicalEntrypoint = Join-Path `
    (Join-Path $canonicalRoot 'scripts') `
    'windows-gnu-toolchain.ps1'
$lockHelper = Join-Path `
    (Join-Path $canonicalRoot 'scripts') `
    'launcher-lock.ps1'
$gitExe = 'C:\Program Files\Git\cmd\git.exe'
$supportedParent = Join-Path `
    (Join-Path $canonicalRoot '.claude') `
    'worktrees'
$retiredParent = Join-Path `
    (Join-Path $canonicalRoot '.claude') `
    'retired-worktrees'

foreach ($requiredFile in @(
        $canonicalEntrypoint,
        $lockHelper,
        $gitExe
    )) {
    if (-not [IO.File]::Exists($requiredFile)) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_AUTHORITY_INCOMPLETE]: ' +
            "{code=ASTRO_WORKTREE_AUTHORITY_INCOMPLETE; " +
            "message=`"required canonical authority file is absent: " +
            "$requiredFile`"; remediation=`"restore the exact canonical " +
            "checkout/tool before managing registered worktrees`"}"
        )
    }
}
. $lockHelper

function Invoke-AstroWorktreeGit {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Arguments
    )

    $global:LASTEXITCODE = 0
    $output = @(
        & $gitExe @Arguments 2>&1 |
            ForEach-Object { $_.ToString() }
    )
    $exitCode = [int]$LASTEXITCODE
    if ($exitCode -ne 0) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_GIT_FAILED]: ' +
            "{code=ASTRO_WORKTREE_GIT_FAILED; " +
            "message=`"git exited $exitCode for arguments " +
            "'$($Arguments -join ' ')': $($output -join ' | ')`"; " +
            "remediation=`"preserve every worktree and protocol path; " +
            "resolve the reported Git failure before retrying`"}"
        )
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = [string[]]$output
    }
}

function Get-AstroFileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (
            [BitConverter]::ToString(
                $sha.ComputeHash($stream)
            ) -replace '-', ''
        ).ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-AstroLauncherWorktreeState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedParent,
        [Parameter(Mandatory)][bool]$RequireRegistered
    )

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not [string]::Equals(
            $parent,
            $ExpectedParent,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_PATH_INVALID]: ' +
            "{code=ASTRO_WORKTREE_PATH_INVALID; message=`"worktree " +
            "'$full' is not one direct child of '$ExpectedParent'`"; " +
            "remediation=`"use the exact managed worktree name and parent`"}"
        )
    }
    if (-not [IO.Directory]::Exists($full)) {
        return [pscustomobject]@{
            Path = $full
            Exists = $false
            Registered = $false
            RegistrationMatchesCanonical = $false
            RootFileId = $null
            Head = $null
            Status = @()
            LockState = 'absent'
            LockTransitions = @()
            TempEntryCount = 0
            TargetExists = $false
            TargetPaths = @()
            FsvLockExists = $false
            DirectAttributionCount = 0
            DirectTempCount = 0
            EntrypointExists = $false
            EntrypointSha256 = $null
            CanonicalEntrypointSha256 =
                Get-AstroFileSha256 $canonicalEntrypoint
            AuthorityMatch = $false
        }
    }

    $gitMarker = Join-Path $full '.git'
    $rootLease = Open-AstroLauncherPinnedDirectoryLease $full
    try {
        $rootFileId = [string]$rootLease.FileId
    }
    finally {
        $rootLease.SafeFileHandle.Dispose()
    }
    $registered = [IO.File]::Exists($gitMarker)
    if ($RequireRegistered -and -not $registered) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_NOT_REGISTERED]: ' +
            "{code=ASTRO_WORKTREE_NOT_REGISTERED; message=`"managed " +
            "path is not a registered Git worktree: '$full'`"; " +
            "remediation=`"repair the Git worktree registration before " +
            "any launcher admission or retirement`"}"
        )
    }
    $head = if ($registered) {
        (
            Invoke-AstroWorktreeGit @(
                '-C', $full, 'rev-parse', 'HEAD'
            )
        ).Output[0].Trim()
    }
    else {
        $null
    }
    $registrationMatchesCanonical = $false
    if ($registered) {
        $topLevel = (
            Invoke-AstroWorktreeGit @(
                '-C', $full, 'rev-parse', '--show-toplevel'
            )
        ).Output[0].Trim()
        $commonDirectory = (
            Invoke-AstroWorktreeGit @(
                '-C', $full, 'rev-parse', '--git-common-dir'
            )
        ).Output[0].Trim()
        $registrationMatchesCanonical =
            [string]::Equals(
                [IO.Path]::GetFullPath($topLevel).TrimEnd('\', '/'),
                $full,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [string]::Equals(
                [IO.Path]::GetFullPath($commonDirectory).TrimEnd('\', '/'),
                [IO.Path]::GetFullPath(
                    (Join-Path $canonicalRoot '.git')
                ).TrimEnd('\', '/'),
                [StringComparison]::OrdinalIgnoreCase
            )
    }
    $status = if ($registered) {
        @(
            (
                Invoke-AstroWorktreeGit @(
                    '-C', $full, 'status', '--short'
                )
            ).Output
        )
    }
    else {
        @()
    }
    $lockPath = Join-Path $full '.tmp\astrolabe-launcher.lock'
    $lockState = Read-AstroLauncherLock -LockPath $lockPath
    $entrypoint = Join-Path $full 'scripts\windows-gnu-toolchain.ps1'
    $canonicalSha = Get-AstroFileSha256 $canonicalEntrypoint
    $entrypointExists = [IO.File]::Exists($entrypoint)
    $entrypointSha = if ($entrypointExists) {
        Get-AstroFileSha256 $entrypoint
    }
    else {
        $null
    }
    $temporaryRoot = Join-Path $full '.tmp'
    $tempEntries = @(
        Get-ChildItem `
            -LiteralPath $temporaryRoot `
            -Force `
            -ErrorAction SilentlyContinue
    )
    $targetPaths = [Collections.Generic.List[string]]::new()
    $rootTarget = Join-Path $full 'target'
    if ([IO.Directory]::Exists($rootTarget) -or
        [IO.File]::Exists($rootTarget)) {
        $targetPaths.Add([IO.Path]::GetFullPath($rootTarget))
    }
    foreach ($child in @(
            Get-ChildItem `
                -LiteralPath $full `
                -Directory `
                -Force `
                -ErrorAction SilentlyContinue
        )) {
        if ($child.Name.StartsWith('.') -or
            ($child.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not [IO.File]::Exists(
                (Join-Path $child.FullName 'Cargo.toml')
            )) {
            continue
        }
        $childTarget = Join-Path $child.FullName 'target'
        if ([IO.Directory]::Exists($childTarget) -or
            [IO.File]::Exists($childTarget)) {
            $targetPaths.Add([IO.Path]::GetFullPath($childTarget))
        }
    }
    return [pscustomobject]@{
        Path = $full
        Exists = $true
        Registered = $registered
        RegistrationMatchesCanonical = $registrationMatchesCanonical
        RootFileId = $rootFileId
        Head = $head
        Status = @($status)
        LockState = $lockState.State
        LockSchema = $lockState.Schema
        LockOwnerPid = $lockState.OwnerPid
        LockOwnerProcessStartUtcTicks =
            $lockState.OwnerProcessStartUtcTicks
        LockTransitions = @($lockState.TransitionPaths)
        TempEntryCount = $tempEntries.Count
        TargetExists = $targetPaths.Count -ne 0
        TargetPaths = @($targetPaths)
        FsvLockExists =
            [IO.File]::Exists((Join-Path $full '.tmp\astrolabe-fsv.lock'))
        DirectAttributionCount = @(
            Get-ChildItem `
                -LiteralPath (Join-Path $full '.tmp') `
                -Filter 'no-escape-attribution-v*.json' `
                -File `
                -ErrorAction SilentlyContinue
        ).Count
        DirectTempCount = @(
            Get-ChildItem `
                -LiteralPath (Join-Path $full '.tmp') `
                -Filter 'windows-gnu-toolchain-*' `
                -Directory `
                -ErrorAction SilentlyContinue
        ).Count
        EntrypointExists = $entrypointExists
        EntrypointSha256 = $entrypointSha
        CanonicalEntrypointSha256 = $canonicalSha
        AuthorityMatch =
            $entrypointExists -and $entrypointSha -ceq $canonicalSha
    }
}

function Assert-AstroWorktreeMovable {
    param([Parameter(Mandatory)]$State)

    $reasons = [Collections.Generic.List[string]]::new()
    if (-not $State.Exists -or -not $State.Registered) {
        $reasons.Add('worktree is absent or unregistered')
    }
    if (-not $State.RegistrationMatchesCanonical) {
        $reasons.Add(
            'worktree Git registration does not bind the exact root to the ' +
            'canonical common directory'
        )
    }
    if ($State.Status.Count -ne 0) {
        $reasons.Add(
            "tracked/visible-untracked status is nonempty: " +
            ($State.Status -join ' | ')
        )
    }
    if ($State.LockState -cne 'absent' -or
        $State.LockTransitions.Count -ne 0) {
        $reasons.Add(
            "launcher protocol is state=$($State.LockState), " +
            "transitions=$($State.LockTransitions -join '; ')"
        )
    }
    if ($State.FsvLockExists) {
        $reasons.Add('native FSV lock exists')
    }
    if ($State.DirectAttributionCount -ne 0 -or
        $State.DirectTempCount -ne 0) {
        $reasons.Add(
            "direct attribution/TEMP state exists " +
            "(attribution=$($State.DirectAttributionCount), " +
            "temp=$($State.DirectTempCount))"
        )
    }
    if ($reasons.Count -ne 0) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_RETIREMENT_REFUSED]: ' +
            "{code=ASTRO_WORKTREE_RETIREMENT_REFUSED; " +
            "message=`"worktree retirement preconditions failed for " +
            "'$($State.Path)': $($reasons -join '; ')`"; " +
            "remediation=`"preserve the complete worktree; only its exact " +
            "owner/recovery lifecycle may clean protocol state before retry`"}"
        )
    }
}

function Assert-AstroNoWorktreeProcessReferences {
    param([Parameter(Mandatory)][string]$Path)

    try {
        $rows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    }
    catch {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_PROCESS_PROBE_UNEVALUABLE]: ' +
            "{code=ASTRO_WORKTREE_PROCESS_PROBE_UNEVALUABLE; " +
            "message=`"Windows process inventory failed before worktree " +
            "mutation: $($_.Exception.Message)`"; remediation=`"preserve the " +
            "complete worktree and repair process-query capability`"}"
        )
    }
    $references = [Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        if ([int]$row.ProcessId -eq $PID) {
            continue
        }
        $executablePath = [string]$row.ExecutablePath
        $commandLine = [string]$row.CommandLine
        $referencesPath = [bool](
            (
                -not [string]::IsNullOrWhiteSpace(
                    $executablePath
                ) -and
                $executablePath.StartsWith(
                    $Path,
                    [StringComparison]::OrdinalIgnoreCase
                )
            ) -or
            (
                -not [string]::IsNullOrWhiteSpace(
                    $commandLine
                ) -and
                $commandLine.IndexOf(
                    $Path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -ge 0
            )
        )
        if (-not $referencesPath) {
            continue
        }
        $probe = Get-AstroProcessIdentityProbe ([int]$row.ProcessId)
        $references.Add([pscustomobject]@{
                pid = [int]$row.ProcessId
                creation_date = [string]$row.CreationDate
                exact_probe_state = $probe.State
                process_start_utc_ticks = $probe.ProcessStartUtcTicks
                executable_path = $executablePath
                command_line = $commandLine
            })
    }
    if ($references.Count -ne 0) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_PROCESS_REFERENCE_HELD]: ' +
            "{code=ASTRO_WORKTREE_PROCESS_REFERENCE_HELD; message=`"one or " +
            "more live/unevaluable processes reference '$Path': " +
            "$($references | ConvertTo-Json -Depth 6 -Compress)`"; " +
            "remediation=`"do not move or mutate the worktree; wait for its " +
            "exact owners to terminate, then re-read the tracker and probe again`"}"
        )
    }
    return [pscustomobject]@{
        path = $Path
        observed_process_count = $rows.Count
        matching_reference_count = 0
    }
}

function Assert-AstroCanonicalManagerClean {
    $canonicalStatus = @(
        (
            Invoke-AstroWorktreeGit @(
                '-C', $canonicalRoot, 'status', '--short'
            )
        ).Output
    )
    if ($canonicalStatus.Count -ne 0) {
        throw (
            'LAUNCHER_WORKTREE[ASTRO_WORKTREE_CANONICAL_DIRTY]: ' +
            "{code=ASTRO_WORKTREE_CANONICAL_DIRTY; message=`"canonical " +
            "checkout has status: $($canonicalStatus -join ' | ')`"; " +
            "remediation=`"commit and verify the canonical authority " +
            "before mutating registered worktrees`"}"
        )
    }
}

$supportedPath = Join-Path $supportedParent $Name
$retiredPath = Join-Path $retiredParent $Name

switch ($Operation) {
    'Inspect' {
        $parent = if ($Location -ceq 'Supported') {
            $supportedParent
        }
        else {
            $retiredParent
        }
        $path = if ($Location -ceq 'Supported') {
            $supportedPath
        }
        else {
            $retiredPath
        }
        $state = Get-AstroLauncherWorktreeState `
            -Path $path `
            -ExpectedParent $parent `
            -RequireRegistered $false
        [pscustomobject]@{
            operation = 'inspect'
            location = $Location.ToLowerInvariant()
            state = $state
        } | ConvertTo-Json -Depth 12 -Compress
        exit 0
    }
    'Provision' {
        if ($Location -cne 'Supported') {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_ARGUMENT_INVALID]: ' +
                'Provision requires -Location Supported'
            )
        }
        if ([IO.Directory]::Exists($supportedPath) -or
            [IO.File]::Exists($supportedPath)) {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_DESTINATION_EXISTS]: ' +
                "{code=ASTRO_WORKTREE_DESTINATION_EXISTS; message=`"supported " +
                "destination already exists: '$supportedPath'`"; " +
                "remediation=`"inspect the registered worktree; never " +
                "overwrite or reuse an existing destination`"}"
            )
        }
        Assert-AstroCanonicalManagerClean
        $commitSha = (
            Invoke-AstroWorktreeGit @(
                '-C',
                $canonicalRoot,
                'rev-parse',
                '--verify',
                "$Commitish^{commit}"
            )
        ).Output[0].Trim()
        $canonicalBlob = (
            Invoke-AstroWorktreeGit @(
                '-C',
                $canonicalRoot,
                'rev-parse',
                'HEAD:scripts/windows-gnu-toolchain.ps1'
            )
        ).Output[0].Trim()
        $candidateBlob = (
            Invoke-AstroWorktreeGit @(
                '-C',
                $canonicalRoot,
                'rev-parse',
                "$commitSha`:scripts/windows-gnu-toolchain.ps1"
            )
        ).Output[0].Trim()
        if ($candidateBlob -cne $canonicalBlob) {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH]: ' +
                "{code=ASTRO_LAUNCHER_PROTOCOL_VERSION_MISMATCH; " +
                "message=`"commit $commitSha launcher trampoline blob " +
                "$candidateBlob does not match canonical blob " +
                "$canonicalBlob`"; remediation=`"update the candidate commit " +
                "to canonical main authority before admitting it under " +
                "'$supportedParent'; historical worktrees belong under " +
                "'$retiredParent'`"}"
            )
        }
        [IO.Directory]::CreateDirectory($supportedParent) | Out-Null
        $arguments = [Collections.Generic.List[string]]::new()
        foreach ($arg in @(
                '-C',
                $canonicalRoot,
                'worktree',
                'add'
            )) {
            $arguments.Add($arg)
        }
        if ([string]::IsNullOrWhiteSpace($NewBranch)) {
            $arguments.Add('--detach')
        }
        else {
            if ($NewBranch -cnotmatch '^[A-Za-z0-9._/-]+$') {
                throw (
                    'LAUNCHER_WORKTREE[ASTRO_WORKTREE_BRANCH_INVALID]: ' +
                    "new branch name is invalid: '$NewBranch'"
                )
            }
            $arguments.Add('-b')
            $arguments.Add($NewBranch)
        }
        $arguments.Add($supportedPath)
        $arguments.Add($commitSha)
        $gitResult = Invoke-AstroWorktreeGit `
            ([string[]]$arguments.ToArray())
        $state = Get-AstroLauncherWorktreeState `
            -Path $supportedPath `
            -ExpectedParent $supportedParent `
            -RequireRegistered $true
        if ($state.Head -cne $commitSha -or
            $state.Status.Count -ne 0 -or
            -not $state.RegistrationMatchesCanonical -or
            -not $state.AuthorityMatch -or
            $state.LockState -cne 'absent' -or
            $state.TempEntryCount -ne 0 -or
            $state.TargetExists -or
            $state.FsvLockExists -or
            $state.DirectAttributionCount -ne 0 -or
            $state.DirectTempCount -ne 0) {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_PROVISION_READBACK_FAILED]: ' +
                "{code=ASTRO_WORKTREE_PROVISION_READBACK_FAILED; " +
                "message=`"new worktree readback does not match the " +
                "admission contract: $($state | ConvertTo-Json -Depth 8 -Compress)`"; " +
                "remediation=`"preserve the new worktree and investigate " +
                "the exact Git/filesystem state; never auto-delete it`"}"
            )
        }
        [pscustomobject]@{
            operation = 'provision'
            git_output = $gitResult.Output
            state = $state
        } | ConvertTo-Json -Depth 12 -Compress
        exit 0
    }
    'Retire' {
        if ($Location -cne 'Supported') {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_ARGUMENT_INVALID]: ' +
                'Retire requires -Location Supported'
            )
        }
        Assert-AstroCanonicalManagerClean
        $before = Get-AstroLauncherWorktreeState `
            -Path $supportedPath `
            -ExpectedParent $supportedParent `
            -RequireRegistered $true
        Assert-AstroWorktreeMovable $before
        $firstProcessProbe =
            Assert-AstroNoWorktreeProcessReferences $supportedPath
        if ([IO.Directory]::Exists($retiredPath) -or
            [IO.File]::Exists($retiredPath)) {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_DESTINATION_EXISTS]: ' +
                "{code=ASTRO_WORKTREE_DESTINATION_EXISTS; message=`"retired " +
                "destination already exists: '$retiredPath'`"; " +
                "remediation=`"inspect both exact paths; never overwrite " +
                "or merge worktree bytes`"}"
            )
        }
        [IO.Directory]::CreateDirectory($retiredParent) | Out-Null
        $secondProcessProbe =
            Assert-AstroNoWorktreeProcessReferences $supportedPath
        $gitResult = Invoke-AstroWorktreeGit @(
            '-C',
            $canonicalRoot,
            'worktree',
            'move',
            $supportedPath,
            $retiredPath
        )
        $after = Get-AstroLauncherWorktreeState `
            -Path $retiredPath `
            -ExpectedParent $retiredParent `
            -RequireRegistered $true
        if ($after.RootFileId -cne $before.RootFileId -or
            $after.Head -cne $before.Head -or
            $after.Status.Count -ne 0 -or
            -not $after.RegistrationMatchesCanonical -or
            $after.LockState -cne 'absent' -or
            $after.TempEntryCount -ne $before.TempEntryCount -or
            $after.TargetExists -ne $before.TargetExists -or
            $after.TargetPaths.Count -ne $before.TargetPaths.Count -or
            $after.FsvLockExists -or
            $after.DirectAttributionCount -ne 0 -or
            $after.DirectTempCount -ne 0 -or
            [IO.Directory]::Exists($supportedPath)) {
            throw (
                'LAUNCHER_WORKTREE[ASTRO_WORKTREE_RETIRE_READBACK_FAILED]: ' +
                "{code=ASTRO_WORKTREE_RETIRE_READBACK_FAILED; " +
                "message=`"retired worktree readback differs from the " +
                "pre-move identity: before=$($before | ConvertTo-Json -Depth 8 -Compress); " +
                "after=$($after | ConvertTo-Json -Depth 8 -Compress)`"; " +
                "remediation=`"preserve both paths and repair Git worktree " +
                "registration before any further action`"}"
            )
        }
        [pscustomobject]@{
            operation = 'retire'
            git_output = $gitResult.Output
            process_probes = @(
                $firstProcessProbe,
                $secondProcessProbe
            )
            before = $before
            after = $after
        } | ConvertTo-Json -Depth 12 -Compress
        exit 0
    }
}
