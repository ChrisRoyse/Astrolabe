<#
.SYNOPSIS
    Atomically retire obsolete CUDA 13 runtime bundle roots (#559, #614).

.DESCRIPTION
    Launcher admission and retirement share one Global mutex derived from the retained
    canonical-workspace FILE_ID. Retirement publishes an exact-owner transition while it
    inventories every Git-registered worktree and the content-addressed bundle store.
    Exactly one supplied active launcher lease may be classified as caller-self; every
    foreign, stale, malformed, redirected, aliased, missing, or unevaluable root/lease is a
    fail-closed blocker.

    Each obsolete owned bundle is inventoried twice under the transition, identity-preserving
    renamed to a transaction tombstone, deleted without following reparses, and represented by
    durable intent/completion records. The records bind the owner, both pre-delete inventories,
    candidate FILE_ID and content hash, exact source/tombstone paths, and post-delete readback.

    This file is dot-sourceable and performs no top-level mutation.
#>

Set-StrictMode -Version Latest

if (-not (Get-Command -Name 'Read-AstroLauncherLock' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
}

function Write-RetireDiag {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    [Console]::Error.WriteLine("CUDA13_RETIRE[$Code]: $Message")
}

function Throw-AstroCuda13Retirement {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )
    throw "CUDA13_RETIRE[$Code]: {code=$Code; message=`"$Message`"; remediation=`"$Remediation`"}"
}

function Get-AstroCuda13Sha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
                $sha.ComputeHash($Bytes)
            ) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-AstroCuda13Sha256File {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
                $sha.ComputeHash($stream)
            ) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function ConvertTo-AstroCuda13CanonicalJsonSnapshot {
    param([Parameter(Mandatory)]$Value)

    $json = $Value | ConvertTo-Json -Depth 40 -Compress
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    return [pscustomobject]@{
        Json = $json
        Bytes = $bytes
        Length = [uint64]$bytes.LongLength
        Sha256 = Get-AstroCuda13Sha256Bytes $bytes
    }
}

function Write-NewAstroCuda13DurableFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $full = [IO.Path]::GetFullPath($Path)
    $state = Get-AstroPathEntryState $full
    if ($state.State -ne 'absent') {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_RECORD_COLLISION' `
            "durable no-replace publication path is not absent (state=$($state.State); error=$($state.Error)): $full" `
            'preserve the existing bytes and investigate the transaction identity collision'
    }
    $stream = [IO.FileStream]::new(
        (ConvertTo-AstroExtendedLengthPath $full),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read,
        4096,
        [IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $readback = [IO.File]::ReadAllBytes(
        (ConvertTo-AstroExtendedLengthPath $full)
    )
    if ($readback.LongLength -ne $Bytes.LongLength -or
        [Convert]::ToBase64String($readback) -cne
            [Convert]::ToBase64String($Bytes)) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_RECORD_READBACK' `
            "durable publication readback differs from intended bytes: $full" `
            'preserve the file and inspect the storage/filesystem fault'
    }
    return [pscustomobject]@{
        Path = $full
        Length = [uint64]$readback.LongLength
        Sha256 = Get-AstroCuda13Sha256Bytes $readback
    }
}

function Ensure-AstroCuda13OrdinaryDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $state = Get-AstroPathEntryState $full
    if ($state.State -eq 'absent') {
        [AstroLauncherLockNative]::CreateDirectoryNoReplace($full)
        $state = Get-AstroPathEntryState $full
    }
    if ($state.State -ne 'present' -or
        ($state.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_DIRECTORY_INVALID' `
            "protocol directory is not one ordinary non-reparse directory (state=$($state.State); attributes=$($state.Attributes); error=$($state.Error)): $full" `
            'restore the canonical ordinary directory and retry'
    }
    return $full
}

function Invoke-AstroCuda13GitWorktreeList {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$WorkspaceRoot
    )

    $git = [IO.Path]::GetFullPath($GitExe)
    $workspace = [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\', '/')
    if ($workspace.IndexOf('"') -ge 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_ARGUMENT' `
            "workspace path contains a quote and cannot be represented by this native Git boundary: $workspace" `
            'use the canonical ordinary workspace path'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $git
    $start.Arguments =
        "-C `"$workspace`" worktree list --porcelain -z"
    $start.WorkingDirectory = $workspace
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw 'native process creation returned false'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $exitCode = [int]$process.ExitCode
    }
    catch {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_FAILED' `
            "could not execute registered-worktree inventory: $($_.Exception.Message)" `
            'repair native Git for Windows and retry'
    }
    finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_FAILED' `
            "git worktree list --porcelain -z exited ${exitCode}: $stderr" `
            'repair the Git worktree registry before bundle retirement'
    }

    $records = @()
    $current = $null
    foreach ($token in $stdout.Split([char]0)) {
        if ($token.Length -eq 0) {
            if ($null -ne $current) {
                $records += [pscustomobject]$current
                $current = $null
            }
            continue
        }
        if ($token.StartsWith('worktree ', [StringComparison]::Ordinal)) {
            if ($null -ne $current) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_GIT_FORMAT' `
                    'Git emitted a worktree record without its NUL record terminator' `
                    'repair or upgrade native Git for Windows'
            }
            $current = [ordered]@{
                Path = $token.Substring('worktree '.Length)
                Attributes = @()
            }
            continue
        }
        if ($null -eq $current) {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_GIT_FORMAT' `
                "Git emitted an attribute before a worktree field: $token" `
                'repair or upgrade native Git for Windows'
        }
        $current.Attributes += $token
    }
    if ($null -ne $current) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_FORMAT' `
            'Git output ended inside a registered-worktree record' `
            'repair or upgrade native Git for Windows'
    }
    if ($records.Count -eq 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_EMPTY' `
            'Git returned no registered worktree, including no main worktree' `
            'repair the canonical repository worktree registry'
    }
    return @($records)
}

function Get-AstroCuda13RegisteredLockInventory {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        $CallerSelf
    )

    $roots = @()
    $blockers = @()
    $selfMatches = 0
    $identities = @{}
    $registered = @(
        Invoke-AstroCuda13GitWorktreeList `
            -GitExe $GitExe `
            -WorkspaceRoot $WorkspaceRoot
    )
    foreach ($record in $registered) {
        $path = $null
        try {
            if (-not [IO.Path]::IsPathRooted([string]$record.Path)) {
                throw 'registered path is not absolute'
            }
            $path = [IO.Path]::GetFullPath(
                ([string]$record.Path).Replace('/', '\')
            ).TrimEnd('\', '/')
        }
        catch {
            $blockers += [ordered]@{
                code = 'registered-root-path-invalid'
                path = [string]$record.Path
                detail = $_.Exception.Message
            }
            continue
        }
        $state = Get-AstroPathEntryState $path
        if ($state.State -ne 'present' -or
            ($state.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $blockers += [ordered]@{
                code = 'registered-root-unevaluable-or-reparse'
                path = $path
                detail = "state=$($state.State); attributes=$($state.Attributes); error=$($state.Error)"
            }
            continue
        }
        try {
            Assert-AstroLauncherRootCanonical $path
            $rootHandle =
                [AstroLauncherLockNative]::OpenExactRenameDirectory($path)
            try {
                $identity =
                    [AstroLauncherLockNative]::GetDirectoryLockIdentity(
                        $rootHandle
                    )
                $finalPath = ConvertFrom-AstroNativeFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
                )
                $finalPath = [IO.Path]::GetFullPath(
                    $finalPath
                ).TrimEnd('\', '/')
            }
            finally {
                $rootHandle.Dispose()
            }
        }
        catch {
            $blockers += [ordered]@{
                code = 'registered-root-alias-or-query-fault'
                path = $path
                detail = $_.Exception.Message
            }
            continue
        }
        if ($identities.ContainsKey($identity)) {
            $blockers += [ordered]@{
                code = 'registered-root-identity-alias'
                path = $path
                detail = "FILE_ID $identity is already registered as $($identities[$identity])"
            }
            continue
        }
        $identities[$identity] = $path
        if (-not [string]::Equals(
                $path,
                $finalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $blockers += [ordered]@{
                code = 'registered-root-final-path-alias'
                path = $path
                detail = "retained final path is $finalPath"
            }
            continue
        }

        $lockPath = [IO.Path]::Combine(
            $path,
            '.tmp',
            'astrolabe-launcher.lock'
        )
        $lock = Read-AstroLauncherLock -LockPath $lockPath
        $isSelfPath = $null -ne $CallerSelf -and
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$CallerSelf.LockPath),
                $lockPath,
                [StringComparison]::OrdinalIgnoreCase
            )
        $disposition = 'absent'
        if ($isSelfPath) {
            if ($lock.State -cne 'held' -or
                $lock.OwnerPid -ne [int]$CallerSelf.Pid -or
                $lock.OwnerProcessStartUtcTicks -ne
                    [long]$CallerSelf.OwnerProcessStartUtcTicks -or
                $lock.Issue -ne [int]$CallerSelf.Issue -or
                $lock.Sha256 -cne [string]$CallerSelf.LockSha256) {
                $blockers += [ordered]@{
                    code = 'caller-self-lease-mismatch'
                    path = $lockPath
                    detail = "state=$($lock.State); pid=$($lock.OwnerPid); ticks=$($lock.OwnerProcessStartUtcTicks); issue=$($lock.Issue); sha256=$($lock.Sha256)"
                }
                $disposition = 'blocked-self-mismatch'
            }
            else {
                $selfMatches++
                $disposition = 'accepted-exact-caller-self'
            }
        }
        elseif ($lock.State -ne 'absent') {
            $blockers += [ordered]@{
                code = 'foreign-or-unevaluable-launcher-state'
                path = $lockPath
                detail = "state=$($lock.State); pid=$($lock.OwnerPid); ticks=$($lock.OwnerProcessStartUtcTicks); issue=$($lock.Issue); sha256=$($lock.Sha256); error=$(if ($lock.ReadError) { $lock.ReadError } elseif ($lock.ValidationError) { $lock.ValidationError } else { $lock.ProbeError })"
            }
            $disposition = 'blocked-foreign'
        }
        $roots += [ordered]@{
            root_path = $path
            root_file_id = $identity
            lock_path = $lockPath
            lock_state = [string]$lock.State
            lock_disposition = $disposition
            lock_pid = $lock.OwnerPid
            lock_owner_process_start_utc_ticks =
                $lock.OwnerProcessStartUtcTicks
            lock_issue = $lock.Issue
            lock_sha256 = $lock.Sha256
        }
    }
    if ($null -ne $CallerSelf -and $selfMatches -ne 1) {
        $blockers += [ordered]@{
            code = 'caller-self-cardinality'
            path = [string]$CallerSelf.LockPath
            detail = "expected exactly one registered exact self lease; observed $selfMatches"
        }
    }
    return [pscustomobject]@{
        Roots = @($roots | Sort-Object -Property { $_.root_path })
        Blockers = @($blockers)
        RegisteredCount = $registered.Count
        SelfMatchCount = $selfMatches
    }
}

function Get-AstroCuda13OwnershipProbe {
    param(
        [Parameter(Mandatory)][string]$CandidatePath,
        [Parameter(Mandatory)][string]$NameDigest
    )

    $shaPath = Join-Path $CandidatePath 'bundle.lock.sha256'
    $receiptPath = Join-Path $CandidatePath 'bundle.receipt.json'
    $shaState = Get-AstroPathEntryState $shaPath
    $receiptState = Get-AstroPathEntryState $receiptPath
    if ($shaState.State -ne 'present' -or
        ($shaState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($shaState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $receiptState.State -ne 'present' -or
        ($receiptState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($receiptState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return [pscustomobject]@{
            Owned = $false
            Detail = 'ownership leaves are absent, redirected, non-files, or unevaluable'
            LockLeafSha256 = $null
            ReceiptSha256 = $null
        }
    }
    try {
        $shaBytes = [IO.File]::ReadAllBytes(
            (ConvertTo-AstroExtendedLengthPath $shaPath)
        )
        $receiptBytes = [IO.File]::ReadAllBytes(
            (ConvertTo-AstroExtendedLengthPath $receiptPath)
        )
        $shaText = [Text.UTF8Encoding]::new(
            $false,
            $true
        ).GetString($shaBytes).Trim()
        $receiptText = [Text.UTF8Encoding]::new(
            $false,
            $true
        ).GetString($receiptBytes)
        $receipt = ConvertFrom-Json -InputObject $receiptText -ErrorAction Stop
        if ($shaText -cne $NameDigest -or
            -not $receipt.PSObject.Properties['schema'] -or
            -not $receipt.PSObject.Properties['lock_sha256'] -or
            [string]$receipt.schema -cnotmatch
                '^astrolabe\.windows-ort-cuda-runtime-receipt\.v[0-9]+$' -or
            [string]$receipt.lock_sha256 -cne $NameDigest) {
            throw 'name/lock-leaf/receipt ownership triple does not agree'
        }
        return [pscustomobject]@{
            Owned = $true
            Detail = $null
            LockLeafSha256 = Get-AstroCuda13Sha256Bytes $shaBytes
            ReceiptSha256 = Get-AstroCuda13Sha256Bytes $receiptBytes
        }
    }
    catch {
        return [pscustomobject]@{
            Owned = $false
            Detail = $_.Exception.Message
            LockLeafSha256 = $null
            ReceiptSha256 = $null
        }
    }
}

function Test-AstroCudaRootOwned {
    param(
        [Parameter(Mandatory)][string]$CandidatePath,
        [Parameter(Mandatory)][string]$NameDigest
    )
    return [bool](Get-AstroCuda13OwnershipProbe `
            -CandidatePath $CandidatePath `
            -NameDigest $NameDigest).Owned
}

function Get-AstroCuda13BundleInventory {
    param(
        [Parameter(Mandatory)][string]$ToolchainsRoot,
        [Parameter(Mandatory)][string]$RootPrefix,
        [Parameter(Mandatory)][string]$ActiveDigest
    )

    $root = [IO.Path]::GetFullPath($ToolchainsRoot).TrimEnd('\', '/')
    $pattern = '^' + [Regex]::Escape($RootPrefix) + '-([0-9a-f]{64})$'
    $bundles = @()
    $blockers = @()
    foreach ($entry in Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop) {
        $match = [Regex]::Match($entry.Name, $pattern)
        if (-not $match.Success) { continue }
        $digest = $match.Groups[1].Value
        $path = [IO.Path]::GetFullPath($entry.FullName).TrimEnd('\', '/')
        $state = Get-AstroPathEntryState $path
        if ($state.State -ne 'present' -or
            ($state.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
            ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            $blockers += [ordered]@{
                code = 'bundle-root-unevaluable-or-reparse'
                path = $path
                detail = "state=$($state.State); attributes=$($state.Attributes); error=$($state.Error)"
            }
            continue
        }
        try {
            Assert-AstroLauncherRootCanonical $path
            $handle =
                [AstroLauncherLockNative]::OpenExactRenameDirectory($path)
            try {
                $identity =
                    [AstroLauncherLockNative]::GetDirectoryLockIdentity($handle)
                $finalPath = ConvertFrom-AstroNativeFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath($handle)
                )
                $finalPath = [IO.Path]::GetFullPath(
                    $finalPath
                ).TrimEnd('\', '/')
            }
            finally {
                $handle.Dispose()
            }
            if (-not [string]::Equals(
                    $path,
                    $finalPath,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetDirectoryName($finalPath),
                    $root,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "candidate final path/parent differs: final=$finalPath parent=$([IO.Path]::GetDirectoryName($finalPath))"
            }
        }
        catch {
            $blockers += [ordered]@{
                code = 'bundle-root-alias-or-query-fault'
                path = $path
                detail = $_.Exception.Message
            }
            continue
        }
        $ownership = Get-AstroCuda13OwnershipProbe `
            -CandidatePath $path `
            -NameDigest $digest
        if (-not $ownership.Owned) {
            $blockers += [ordered]@{
                code = 'bundle-root-ownership-mismatch'
                path = $path
                detail = $ownership.Detail
            }
        }
        $bundles += [ordered]@{
            path = $path
            digest = $digest
            active = $digest -ceq $ActiveDigest
            root_file_id = $identity
            owned = [bool]$ownership.Owned
            lock_leaf_sha256 = $ownership.LockLeafSha256
            receipt_sha256 = $ownership.ReceiptSha256
        }
    }
    $active = @($bundles | Where-Object { $_.active })
    if ($active.Count -ne 1) {
        $blockers += [ordered]@{
            code = 'active-bundle-cardinality'
            path = Join-Path $root ($RootPrefix + '-' + $ActiveDigest)
            detail = "expected exactly one active bundle root; observed $($active.Count)"
        }
    }
    return [pscustomobject]@{
        Bundles = @($bundles | Sort-Object -Property { $_.path })
        Blockers = @($blockers)
    }
}

function Get-AstroCuda13StateInventory {
    param(
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$ToolchainsRoot,
        [Parameter(Mandatory)][string]$RootPrefix,
        [Parameter(Mandatory)][string]$ActiveDigest,
        $CallerSelf
    )

    $locks = Get-AstroCuda13RegisteredLockInventory `
        -GitExe $GitExe `
        -WorkspaceRoot $WorkspaceRoot `
        -CallerSelf $CallerSelf
    $bundles = Get-AstroCuda13BundleInventory `
        -ToolchainsRoot $ToolchainsRoot `
        -RootPrefix $RootPrefix `
        -ActiveDigest $ActiveDigest
    $value = [ordered]@{
        schema = 'astrolabe.cuda13-retirement-inventory.v1'
        canonical_workspace_root =
            [IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\', '/')
        toolchains_root =
            [IO.Path]::GetFullPath($ToolchainsRoot).TrimEnd('\', '/')
        root_prefix = $RootPrefix
        active_digest = $ActiveDigest
        registered_roots = @($locks.Roots)
        bundle_roots = @($bundles.Bundles)
    }
    $snapshot = ConvertTo-AstroCuda13CanonicalJsonSnapshot $value
    return [pscustomobject]@{
        Value = $value
        Json = $snapshot.Json
        Bytes = $snapshot.Bytes
        Length = $snapshot.Length
        Sha256 = $snapshot.Sha256
        Blockers = @($locks.Blockers) + @($bundles.Blockers)
        SelfMatchCount = $locks.SelfMatchCount
    }
}

function Assert-AstroCuda13InventoryUnblocked {
    param([Parameter(Mandatory)]$Inventory)

    if (@($Inventory.Blockers).Count -eq 0) { return }
    foreach ($blocker in @($Inventory.Blockers)) {
        Write-RetireDiag `
            'ASTRO_CUDA13_RETIRE_INVENTORY_BLOCKER' `
            "code=$($blocker.code); path=$($blocker.path); detail=$($blocker.detail)"
    }
    $blockerSummary = @(
        $Inventory.Blockers | ForEach-Object {
            "code=$($_.code),path=$($_.path),detail=$($_.detail)"
        }
    ) -join ' | '
    Throw-AstroCuda13Retirement `
        'ASTRO_CUDA13_RETIRE_INVENTORY_BLOCKED' `
        "$(@($Inventory.Blockers).Count) registered-root, launcher-state, or bundle-attestation blocker(s) preserved the entire store; inventory_sha256=$($Inventory.Sha256); blockers=$blockerSummary" `
        'repair the named blocker; never delete a bundle or launcher state manually'
}

function Get-AstroCuda13BundleTreeSnapshot {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$RootHandle,
        [Parameter(Mandatory)][string]$ExpectedFileId
    )

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $fileIdBefore =
        [AstroLauncherLockNative]::GetFileIdentity($RootHandle)
    $finalBefore = ConvertFrom-AstroNativeFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath($RootHandle)
    )
    $finalBefore = [IO.Path]::GetFullPath($finalBefore).TrimEnd('\', '/')
    if ($fileIdBefore -cne $ExpectedFileId -or
        -not [string]::Equals(
            $finalBefore,
            $rootFull,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_CANDIDATE_IDENTITY_CHANGED' `
            "retained candidate identity/path differs before tree inventory (expected_file_id=$ExpectedFileId; observed_file_id=$fileIdBefore; expected_path=$rootFull; observed_path=$finalBefore)" `
            'preserve the candidate and investigate the concurrent filesystem mutation'
    }
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('D`t.')
    [long]$totalBytes = 0
    $stack = [Collections.Generic.Stack[string]]::new()
    $stack.Push($rootFull)
    while ($stack.Count -gt 0) {
        $directory = $stack.Pop()
        $entries = @(
            Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop |
                Sort-Object -Property Name -Descending
        )
        foreach ($entry in $entries) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_REPARSE_BLOCKED' `
                    "candidate tree contains a reparse point: $($entry.FullName)" `
                    'restore the immutable ordinary bundle from its checked-in lock'
            }
            $relative = $entry.FullName.Substring(
                $rootFull.Length
            ).TrimStart('\', '/').Replace('/', '\')
            if ($entry.PSIsContainer) {
                $lines.Add("D`t$relative")
                $stack.Push($entry.FullName)
            }
            else {
                $lengthBefore = [long]$entry.Length
                $hash = Get-AstroCuda13Sha256File $entry.FullName
                $fileAfter = Get-Item -LiteralPath $entry.FullName -Force `
                    -ErrorAction Stop
                if ($fileAfter.PSIsContainer -or
                    ($fileAfter.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    [long]$fileAfter.Length -ne $lengthBefore) {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_TREE_CHANGED' `
                        "candidate entry changed during content hashing: $($entry.FullName)" `
                        'preserve the candidate and investigate the concurrent writer'
                }
                if ($lengthBefore -lt 0 -or
                    $totalBytes -gt ([long]::MaxValue - $lengthBefore)) {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_TREE_SIZE_OVERFLOW' `
                        "candidate byte total exceeds signed 64-bit range at $($entry.FullName)" `
                        'preserve the candidate and inspect its filesystem metadata'
                }
                $totalBytes += $lengthBefore
                $lines.Add("F`t$relative`t$lengthBefore`t$hash")
            }
        }
    }
    $fileIdAfter =
        [AstroLauncherLockNative]::GetFileIdentity($RootHandle)
    $finalAfter = ConvertFrom-AstroNativeFinalPath (
        [AstroLauncherLockNative]::GetFileFinalPath($RootHandle)
    )
    $finalAfter = [IO.Path]::GetFullPath($finalAfter).TrimEnd('\', '/')
    if ($fileIdAfter -cne $fileIdBefore -or
        -not [string]::Equals(
            $finalAfter,
            $finalBefore,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_CANDIDATE_IDENTITY_CHANGED' `
            'retained candidate root identity/path changed during tree inventory' `
            'preserve the candidate and investigate the concurrent filesystem mutation'
    }
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($lines -join "`n") + "`n")
    )
    return [pscustomobject]@{
        Root = $rootFull
        RootFileId = $fileIdAfter
        EntryCount = $lines.Count
        TotalBytes = $totalBytes
        InventorySha256 = Get-AstroCuda13Sha256Bytes $bytes
    }
}

function Remove-AstroDirectoryTreeNoFollow {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$RootHandle,
        [Parameter(Mandatory)][string]$ExpectedFileId
    )

    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ([AstroLauncherLockNative]::GetFileIdentity($RootHandle) -cne
        $ExpectedFileId) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_DELETE_IDENTITY' `
            "retained delete root FILE_ID no longer matches $ExpectedFileId" `
            'preserve the tombstone and investigate the filesystem mutation'
    }
    $order = [Collections.Generic.Stack[string]]::new()
    $walk = [Collections.Generic.Stack[string]]::new()
    $walk.Push($rootFull)
    while ($walk.Count -gt 0) {
        $directory = $walk.Pop()
        $order.Push($directory)
        $directoryItem = Get-Item -LiteralPath $directory -Force `
            -ErrorAction Stop
        if (($directoryItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_REPARSE_BLOCKED' `
                "reparse point appeared during delete traversal: $directory" `
                'preserve the tombstone and investigate the concurrent writer'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop) {
            if (($entry.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_REPARSE_BLOCKED' `
                    "reparse point appeared during delete traversal: $($entry.FullName)" `
                    'preserve the tombstone and investigate the concurrent writer'
            }
            if ($entry.PSIsContainer) { $walk.Push($entry.FullName) }
        }
    }
    while ($order.Count -gt 0) {
        $directory = $order.Pop()
        $directoryItem = Get-Item -LiteralPath $directory -Force `
            -ErrorAction Stop
        if (($directoryItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_REPARSE_BLOCKED' `
                "reparse point appeared immediately before deletion: $directory" `
                'preserve the tombstone and investigate the concurrent writer'
        }
        foreach ($entry in Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop) {
            if (($entry.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_REPARSE_BLOCKED' `
                    "reparse point appeared immediately before deletion: $($entry.FullName)" `
                    'preserve the tombstone and investigate the concurrent writer'
            }
            if (-not $entry.PSIsContainer) {
                [IO.File]::Delete(
                    (ConvertTo-AstroExtendedLengthPath $entry.FullName)
                )
            }
        }
        if ([string]::Equals(
                $directory,
                $rootFull,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            [AstroLauncherLockNative]::DeleteExactDirectoryHandle(
                $RootHandle
            )
        }
        else {
            [IO.Directory]::Delete(
                (ConvertTo-AstroExtendedLengthPath $directory),
                $false
            )
        }
    }
}

function Read-AstroCuda13RetirementRecord {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $state = Get-AstroPathEntryState $full
    if ($state.State -ne 'present' -or
        ($state.Attributes -band
            ([IO.FileAttributes]::Directory -bor
                [IO.FileAttributes]::ReparsePoint)) -ne 0) {
        throw "record is absent, redirected, non-file, or unevaluable (state=$($state.State); attributes=$($state.Attributes); error=$($state.Error)): $full"
    }
    $bytes = [IO.File]::ReadAllBytes(
        (ConvertTo-AstroExtendedLengthPath $full)
    )
    try {
        $text = [Text.UTF8Encoding]::new(
            $false,
            $true
        ).GetString($bytes)
        $value = ConvertFrom-Json -InputObject $text -ErrorAction Stop
    }
    catch {
        throw "record is not strict UTF-8 JSON: $full; $($_.Exception.Message)"
    }
    return [pscustomobject]@{
        Path = $full
        Length = [uint64]$bytes.LongLength
        Sha256 = Get-AstroCuda13Sha256Bytes $bytes
        Bytes = $bytes
        Value = $value
    }
}

function Assert-AstroCuda13ExactRecordProperties {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string[]]$Required,
        [Parameter(Mandatory)][string]$Context
    )

    $observed = @($Value.PSObject.Properties.Name)
    if ($observed.Count -ne $Required.Count) {
        throw "$Context property count is $($observed.Count), expected $($Required.Count)"
    }
    foreach ($name in $Required) {
        if ($name -cnotin $observed) {
            throw "$Context is missing exact property '$name'"
        }
    }
    foreach ($name in $observed) {
        if ($name -cnotin $Required) {
            throw "$Context contains unexpected property '$name'"
        }
    }
}

function Assert-AstroCuda13RecoveryStateClear {
    param(
        [Parameter(Mandatory)][string]$RecordsRoot,
        [Parameter(Mandatory)][string]$TombstonesRoot
    )

    foreach ($entry in Get-ChildItem -LiteralPath $TombstonesRoot -Force `
            -ErrorAction Stop) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_RECOVERY_REQUIRED' `
            "an interrupted retirement tombstone is present unchanged: $($entry.FullName)" `
            'post its exact path, FILE_ID, inventory hash, and bound intent record to the driving issue before recovery'
    }
    foreach ($transaction in Get-ChildItem -LiteralPath $RecordsRoot -Force `
            -ErrorAction Stop) {
        if (-not $transaction.PSIsContainer -or
            ($transaction.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $transaction.Name -cnotmatch '^tx-v1\.[0-9a-f]{32}$') {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_RECOVERY_REQUIRED' `
                "retirement record entry has an invalid or redirected shape: $($transaction.FullName)" `
                'preserve the entry and investigate its provenance'
        }
        $transactionEntries = @(
            Get-ChildItem -LiteralPath $transaction.FullName -Force `
                -ErrorAction Stop
        )
        if ($transactionEntries.Count -ne 2 -or
            'intent.json' -cnotin @($transactionEntries.Name) -or
            'completion.json' -cnotin @($transactionEntries.Name)) {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_RECOVERY_REQUIRED' `
                "retirement record transaction does not contain exactly intent.json + completion.json: $($transaction.FullName)" `
                'preserve the transaction and post its exact inventory/hash before recovery'
        }
        try {
            $intent = Read-AstroCuda13RetirementRecord (
                Join-Path $transaction.FullName 'intent.json'
            )
            $completion = Read-AstroCuda13RetirementRecord (
                Join-Path $transaction.FullName 'completion.json'
            )
            $intentProperties = @(
                'schema',
                'transaction_id',
                'transition_transaction_id',
                'owner',
                'source_path',
                'source_file_id',
                'tombstone_path',
                'root_prefix',
                'active_digest',
                'candidate_digest',
                'candidate_tree',
                'first_inventory',
                'first_inventory_sha256',
                'second_inventory',
                'second_inventory_sha256',
                'authorized_utc'
            )
            $completionProperties = @(
                'schema',
                'transaction_id',
                'transition_transaction_id',
                'owner',
                'intent_path',
                'intent_sha256',
                'source_path',
                'source_file_id',
                'tombstone_path',
                'candidate_tree_inventory_sha256',
                'first_inventory_sha256',
                'second_inventory_sha256',
                'post_inventory',
                'post_inventory_sha256',
                'source_post_state',
                'tombstone_post_state',
                'completed_utc'
            )
            Assert-AstroCuda13ExactRecordProperties `
                -Value $intent.Value `
                -Required $intentProperties `
                -Context "$($transaction.FullName) intent"
            Assert-AstroCuda13ExactRecordProperties `
                -Value $completion.Value `
                -Required $completionProperties `
                -Context "$($transaction.FullName) completion"
            $transactionId = $transaction.Name.Substring('tx-v1.'.Length)
            if ([string]$intent.Value.schema -cne
                    'astrolabe.cuda13-retirement-intent.v1' -or
                [string]$completion.Value.schema -cne
                    'astrolabe.cuda13-retirement-completion.v1' -or
                [string]$intent.Value.transaction_id -cne $transactionId -or
                [string]$completion.Value.transaction_id -cne
                    $transactionId -or
                [string]$completion.Value.transition_transaction_id -cne
                    [string]$intent.Value.transition_transaction_id -or
                [long]$completion.Value.owner.pid -ne
                    [long]$intent.Value.owner.pid -or
                [long]$completion.Value.owner.owner_process_start_utc_ticks -ne
                    [long]$intent.Value.owner.owner_process_start_utc_ticks -or
                [long]$completion.Value.owner.issue -ne
                    [long]$intent.Value.owner.issue -or
                -not [string]::Equals(
                    [string]$completion.Value.intent_path,
                    $intent.Path,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [string]$completion.Value.intent_sha256 -cne
                    $intent.Sha256 -or
                [string]$completion.Value.source_path -cne
                    [string]$intent.Value.source_path -or
                [string]$completion.Value.source_file_id -cne
                    [string]$intent.Value.source_file_id -or
                [string]$completion.Value.tombstone_path -cne
                    [string]$intent.Value.tombstone_path -or
                [string]$completion.Value.candidate_tree_inventory_sha256 -cne
                    [string]$intent.Value.candidate_tree.inventory_sha256 -or
                [string]$completion.Value.first_inventory_sha256 -cne
                    [string]$intent.Value.first_inventory_sha256 -or
                [string]$completion.Value.second_inventory_sha256 -cne
                    [string]$intent.Value.second_inventory_sha256 -or
                [string]$completion.Value.source_post_state -cne 'absent' -or
                [string]$completion.Value.tombstone_post_state -cne
                    'absent') {
                throw 'intent/completion schema, transaction, hash, source, tree, or post-state binding differs'
            }
            if ([long]$intent.Value.owner.pid -le 0 -or
                [long]$intent.Value.owner.pid -gt [int]::MaxValue -or
                [long]$intent.Value.owner.owner_process_start_utc_ticks -le
                    0 -or
                [long]$intent.Value.owner.owner_process_start_utc_ticks -gt
                    [DateTime]::MaxValue.Ticks -or
                [long]$intent.Value.owner.issue -le 0 -or
                [long]$intent.Value.owner.issue -gt [int]::MaxValue -or
                [string]$intent.Value.active_digest -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$intent.Value.candidate_digest -cnotmatch
                    '^[0-9a-f]{64}$') {
                throw 'intent owner or bundle digest fields are not canonical'
            }
            foreach ($field in @(
                    'intent_sha256',
                    'source_file_id',
                    'candidate_tree_inventory_sha256',
                    'first_inventory_sha256',
                    'second_inventory_sha256',
                    'post_inventory_sha256'
                )) {
                $pattern = if ($field -ceq 'source_file_id') {
                    '^[0-9a-f]{16}:[0-9a-f]{32}$'
                }
                else {
                    '^[0-9a-f]{64}$'
                }
                if ([string]$completion.Value.$field -cnotmatch $pattern) {
                    throw "completion field '$field' is not canonical"
                }
            }
        }
        catch {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_RECOVERY_REQUIRED' `
                "retirement record transaction failed exact durable readback: $($transaction.FullName); $($_.Exception.Message)" `
                'preserve the transaction and post its exact inventory/hash before recovery'
        }
    }
}

function New-AstroCuda13TransitionLease {
    param(
        [Parameter(Mandatory)][string]$CanonicalWorkspaceRoot,
        [Parameter(Mandatory)]$Manifest
    )

    $path = Get-AstroCuda13RetirementTransitionPath `
        $CanonicalWorkspaceRoot
    $snapshot = ConvertTo-AstroCuda13CanonicalJsonSnapshot $Manifest
    $published = Write-NewAstroCuda13DurableFile `
        -Path $path `
        -Bytes $snapshot.Bytes
    $handle = $null
    try {
        $handle =
            [AstroLauncherLockNative]::OpenExactRenameSource($path)
        $readback = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $path `
            -MaximumBytes 65536
        if ($readback.Sha256 -cne $snapshot.Sha256 -or
            $readback.Length -ne $snapshot.Length -or
            [Convert]::ToBase64String($readback.Bytes) -cne
                [Convert]::ToBase64String($snapshot.Bytes)) {
            throw 'retained transition bytes differ from durable publication'
        }
        $classified = Read-AstroCuda13RetirementTransition `
            -CanonicalWorkspaceRoot $CanonicalWorkspaceRoot
        if ($classified.State -cne 'held' -or
            $classified.OwnerPid -ne [int]$Manifest.pid -or
            $classified.OwnerProcessStartUtcTicks -ne
                [long]$Manifest.owner_process_start_utc_ticks -or
            $classified.Issue -ne [int]$Manifest.issue -or
            $classified.TransactionId -cne
                [string]$Manifest.transaction_id -or
            $classified.Sha256 -cne $snapshot.Sha256) {
            throw "transition classifier readback is not the exact held owner (state=$($classified.State); sha256=$($classified.Sha256))"
        }
        return [pscustomobject]@{
            Path = $path
            SafeFileHandle = $handle
            Snapshot = $readback
            Classified = $classified
            Published = $published
        }
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_TRANSITION_PUBLICATION' `
            "transition publication/readback failed and its exact bytes were preserved: $path; $($_.Exception.Message)" `
            'post the path/hash and exact owner probe before any recovery'
    }
}

function Remove-AstroCuda13TransitionLease {
    param([Parameter(Mandatory)]$Lease)

    [AstroLauncherLockNative]::DeleteExactFileHandle(
        $Lease.SafeFileHandle
    )
    $Lease.SafeFileHandle.Dispose()
    $state = Get-AstroPathEntryState $Lease.Path
    if ($state.State -ne 'absent') {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_TRANSITION_CLEANUP' `
            "exact transition disposition did not end absent (state=$($state.State); error=$($state.Error)): $($Lease.Path)" `
            'preserve the protocol state and investigate the filesystem fault'
    }
}

function Remove-AstroObsoleteCudaRuntimeRoots {
    param(
        [Parameter(Mandatory)][string]$ToolchainsRoot,
        [Parameter(Mandatory)][string]$RootPrefix,
        [Parameter(Mandatory)][string]$ActiveDigest,
        [Parameter(Mandatory)][string]$WorkspaceRoot,
        [Parameter(Mandatory)][string]$GitExe,
        [Parameter(Mandatory)][int]$DrivingIssue,
        $CallerSelf
    )

    if ($ActiveDigest -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($RootPrefix) -or
        $RootPrefix.IndexOfAny([char[]]@('\', '/')) -ge 0 -or
        $DrivingIssue -le 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_PRECONDITION' `
            "active digest, root prefix, or driving issue is invalid (digest=$ActiveDigest; prefix=$RootPrefix; issue=$DrivingIssue)" `
            'pass the checked-in lock digest/prefix and positive driving issue'
    }
    $workspace = [IO.Path]::GetFullPath(
        $WorkspaceRoot
    ).TrimEnd('\', '/')
    $toolchains = [IO.Path]::GetFullPath(
        $ToolchainsRoot
    ).TrimEnd('\', '/')
    Assert-AstroLauncherRootCanonical $workspace
    $toolchainsState = Get-AstroPathEntryState $toolchains
    if ($toolchainsState.State -ne 'present' -or
        ($toolchainsState.Attributes -band
            [IO.FileAttributes]::Directory) -eq 0 -or
        ($toolchainsState.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [string]::Equals(
            [IO.Path]::GetDirectoryName($toolchains),
            $workspace,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [IO.Path]::GetFileName($toolchains) -cne '.toolchains') {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_PRECONDITION' `
            "toolchains root is not the exact ordinary canonical .toolchains child: $toolchains" `
            'pass the canonical workspace .toolchains directory'
    }
    Assert-AstroLauncherRootCanonical $toolchains
    $git = [IO.Path]::GetFullPath($GitExe)
    $gitState = Get-AstroPathEntryState $git
    if ($gitState.State -ne 'present' -or
        ($gitState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
        ($gitState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_GIT_INVALID' `
            "native Git path is absent, redirected, non-file, or unevaluable: $git" `
            'repair native Git for Windows and retry'
    }
    $ownerProcess = Get-Process -Id $PID -ErrorAction Stop
    try {
        $ownerTicks =
            [long]$ownerProcess.StartTime.ToUniversalTime().Ticks
    }
    finally {
        $ownerProcess.Dispose()
    }
    if ($null -ne $CallerSelf -and
        ([int]$CallerSelf.Pid -ne $PID -or
            [long]$CallerSelf.OwnerProcessStartUtcTicks -ne $ownerTicks -or
            [int]$CallerSelf.Issue -ne $DrivingIssue)) {
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_SELF_INVALID' `
            "caller-self identity is not the current exact retirement owner (current_pid=$PID; current_ticks=$ownerTicks; self_pid=$($CallerSelf.Pid); self_ticks=$($CallerSelf.OwnerProcessStartUtcTicks); issue=$DrivingIssue; self_issue=$($CallerSelf.Issue))" `
            'invoke retirement only from the exact active launcher owner'
    }

    $mutex = Enter-AstroCuda13RetirementMutex $workspace
    if (-not $mutex.Acquired) {
        Exit-AstroCuda13RetirementMutex $mutex
        Throw-AstroCuda13Retirement `
            'ASTRO_CUDA13_RETIRE_BUSY' `
            "another launcher admission or retirement owns shared mutex $($mutex.Name); no state changed" `
            'retry after the bounded owner releases the shared transition'
    }
    $transitionLease = $null
    $result = $null
    $fault = $null
    try {
        $existing = Read-AstroCuda13RetirementTransition `
            -CanonicalWorkspaceRoot $workspace
        if ($existing.State -ne 'absent') {
            Throw-AstroCuda13Retirement `
                'ASTRO_CUDA13_RETIRE_TRANSITION_BLOCKED' `
                "existing transition state '$($existing.State)' was preserved: $($existing.Path); owner_pid=$($existing.OwnerPid); owner_ticks=$($existing.OwnerProcessStartUtcTicks); issue=$($existing.Issue); sha256=$($existing.Sha256)" `
                'post exact bytes and owner probe to the driving issue before recovery'
        }
        if ($mutex.WasAbandoned) {
            Write-RetireDiag `
                'ASTRO_CUDA13_RETIRE_MUTEX_ABANDONED_RECLASSIFIED' `
                "mutex=$($mutex.Name); durable_transition_state=absent"
        }
        $tmp = Ensure-AstroCuda13OrdinaryDirectory (
            Join-Path $workspace '.tmp'
        )
        $transactionId = [Guid]::NewGuid().ToString('N')
        $transition = [ordered]@{
            schema = 'astrolabe.cuda13-retirement-transition.v1'
            canonical_workspace_root = $workspace
            canonical_workspace_file_id = $mutex.RootIdentity
            pid = $PID
            owner_process_start_utc_ticks = $ownerTicks
            issue = $DrivingIssue
            transaction_id = $transactionId
            started_utc = [DateTime]::UtcNow.ToString('o')
        }
        $transitionLease = New-AstroCuda13TransitionLease `
            -CanonicalWorkspaceRoot $workspace `
            -Manifest $transition
        Write-RetireDiag `
            'ASTRO_CUDA13_RETIRE_TRANSITION_HELD' `
            "path=$($transitionLease.Path); sha256=$($transitionLease.Snapshot.Sha256); mutex=$($mutex.Name); pid=$PID; owner_process_start_utc_ticks=$ownerTicks; issue=#$DrivingIssue; transaction=$transactionId"

        $recordsRoot = Ensure-AstroCuda13OrdinaryDirectory (
            Join-Path $toolchains '.cuda13-retirement-records'
        )
        $tombstonesRoot = Ensure-AstroCuda13OrdinaryDirectory (
            Join-Path $toolchains '.cuda13-retirement-tombstones'
        )
        Assert-AstroCuda13RecoveryStateClear `
            -RecordsRoot $recordsRoot `
            -TombstonesRoot $tombstonesRoot

        $baseline = Get-AstroCuda13StateInventory `
            -GitExe $git `
            -WorkspaceRoot $workspace `
            -ToolchainsRoot $toolchains `
            -RootPrefix $RootPrefix `
            -ActiveDigest $ActiveDigest `
            -CallerSelf $CallerSelf
        Assert-AstroCuda13InventoryUnblocked $baseline
        $candidates = @(
            $baseline.Value.bundle_roots |
                Where-Object { -not $_.active } |
                Sort-Object -Property { $_.path }
        )
        $records = @()
        foreach ($originalCandidate in $candidates) {
            $candidate = @(
                $baseline.Value.bundle_roots |
                    Where-Object {
                        [string]::Equals(
                            [string]$_.path,
                            [string]$originalCandidate.path,
                            [StringComparison]::OrdinalIgnoreCase
                        ) -and
                        [string]$_.root_file_id -ceq
                            [string]$originalCandidate.root_file_id
                    }
            )
            if ($candidate.Count -ne 1 -or $candidate[0].active -or
                -not $candidate[0].owned) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_CANDIDATE_CHANGED' `
                    "candidate is no longer one exact owned non-active root in the baseline: $($originalCandidate.path)" `
                    'preserve the store and investigate the inventory change'
            }
            $candidate = $candidate[0]
            $firstSnapshotHandle =
                [AstroLauncherLockNative]::OpenExactRenameDirectory(
                    [string]$candidate.path
                )
            try {
                $treeFirst = Get-AstroCuda13BundleTreeSnapshot `
                    -Root ([string]$candidate.path) `
                    -RootHandle $firstSnapshotHandle `
                    -ExpectedFileId ([string]$candidate.root_file_id)
            }
            finally {
                $firstSnapshotHandle.Dispose()
            }
            $second = Get-AstroCuda13StateInventory `
                -GitExe $git `
                -WorkspaceRoot $workspace `
                -ToolchainsRoot $toolchains `
                -RootPrefix $RootPrefix `
                -ActiveDigest $ActiveDigest `
                -CallerSelf $CallerSelf
            Assert-AstroCuda13InventoryUnblocked $second
            if ($second.Sha256 -cne $baseline.Sha256 -or
                [Convert]::ToBase64String($second.Bytes) -cne
                    [Convert]::ToBase64String($baseline.Bytes)) {
                Throw-AstroCuda13Retirement `
                    'ASTRO_CUDA13_RETIRE_SECOND_INVENTORY_CHANGED' `
                    "registered-root/lock/bundle inventory changed under the transition (first=$($baseline.Sha256); second=$($second.Sha256))" `
                    'preserve the store and investigate the concurrent state change'
            }
            $sourceHandle =
                [AstroLauncherLockNative]::OpenExactDeleteDirectory(
                    [string]$candidate.path
                )
            $sourceHandleOwned = $true
            try {
                $treeSecond = Get-AstroCuda13BundleTreeSnapshot `
                    -Root ([string]$candidate.path) `
                    -RootHandle $sourceHandle `
                    -ExpectedFileId ([string]$candidate.root_file_id)
                if ($treeSecond.InventorySha256 -cne
                        $treeFirst.InventorySha256 -or
                    $treeSecond.EntryCount -ne $treeFirst.EntryCount -or
                    $treeSecond.TotalBytes -ne $treeFirst.TotalBytes) {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_TREE_CHANGED' `
                        "candidate tree changed between inventories (first=$($treeFirst.InventorySha256); second=$($treeSecond.InventorySha256)): $($candidate.path)" `
                        'preserve the store and investigate the concurrent writer'
                }

                $candidateTransactionId =
                    [Guid]::NewGuid().ToString('N')
                $transactionDirectory = Ensure-AstroCuda13OrdinaryDirectory (
                    Join-Path $recordsRoot (
                        'tx-v1.' + $candidateTransactionId
                    )
                )
                $tombstonePath = Join-Path `
                    $tombstonesRoot `
                    ('tx-v1.' + $candidateTransactionId)
                if ((Get-AstroPathEntryState $tombstonePath).State -ne
                    'absent') {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_TOMBSTONE_COLLISION' `
                        "candidate tombstone destination is not absent: $tombstonePath" `
                        'preserve the colliding entry and investigate its provenance'
                }
                $intentValue = [ordered]@{
                    schema = 'astrolabe.cuda13-retirement-intent.v1'
                    transaction_id = $candidateTransactionId
                    transition_transaction_id = $transactionId
                    owner = [ordered]@{
                        pid = $PID
                        owner_process_start_utc_ticks = $ownerTicks
                        issue = $DrivingIssue
                    }
                    source_path = [string]$candidate.path
                    source_file_id = [string]$candidate.root_file_id
                    tombstone_path = $tombstonePath
                    root_prefix = $RootPrefix
                    active_digest = $ActiveDigest
                    candidate_digest = [string]$candidate.digest
                    candidate_tree = [ordered]@{
                        inventory_sha256 =
                            $treeSecond.InventorySha256
                        entry_count = $treeSecond.EntryCount
                        total_bytes = $treeSecond.TotalBytes
                    }
                    first_inventory = $baseline.Value
                    first_inventory_sha256 = $baseline.Sha256
                    second_inventory = $second.Value
                    second_inventory_sha256 = $second.Sha256
                    authorized_utc = [DateTime]::UtcNow.ToString('o')
                }
                $intentSnapshot =
                    ConvertTo-AstroCuda13CanonicalJsonSnapshot $intentValue
                $intentRecord = Write-NewAstroCuda13DurableFile `
                    -Path (Join-Path $transactionDirectory 'intent.json') `
                    -Bytes $intentSnapshot.Bytes

                $tombstoneParentLease =
                    Open-AstroLauncherPinnedDirectoryLease $tombstonesRoot
                try {
                    [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
                        $sourceHandle,
                        $tombstoneParentLease.SafeFileHandle,
                        ('tx-v1.' + $candidateTransactionId)
                    )
                }
                finally {
                    $tombstoneParentLease.SafeFileHandle.Dispose()
                }
                $renamedFileId =
                    [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
                $renamedFinal = ConvertFrom-AstroNativeFinalPath (
                    [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
                )
                $renamedFinal = [IO.Path]::GetFullPath(
                    $renamedFinal
                ).TrimEnd('\', '/')
                $sourceState =
                    Get-AstroPathEntryState ([string]$candidate.path)
                if ($renamedFileId -cne
                        [string]$candidate.root_file_id -or
                    -not [string]::Equals(
                        $renamedFinal,
                        $tombstonePath,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -or
                    $sourceState.State -ne 'absent') {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_RENAME_READBACK' `
                        "exact tombstone rename readback failed (file_id=$renamedFileId; final_path=$renamedFinal; source_state=$($sourceState.State))" `
                        'preserve the transition, intent, and tombstone for tracker-bound recovery'
                }
                Remove-AstroDirectoryTreeNoFollow `
                    -Root $tombstonePath `
                    -RootHandle $sourceHandle `
                    -ExpectedFileId ([string]$candidate.root_file_id)
                $sourceHandle.Dispose()
                $sourceHandleOwned = $false
                $sourceAfter =
                    Get-AstroPathEntryState ([string]$candidate.path)
                $tombstoneAfter =
                    Get-AstroPathEntryState $tombstonePath
                if ($sourceAfter.State -ne 'absent' -or
                    $tombstoneAfter.State -ne 'absent') {
                    Throw-AstroCuda13Retirement `
                        'ASTRO_CUDA13_RETIRE_DELETE_READBACK' `
                        "delete readback is not absent (source=$($sourceAfter.State); tombstone=$($tombstoneAfter.State))" `
                        'preserve all records and investigate the filesystem fault'
                }
                $post = Get-AstroCuda13StateInventory `
                    -GitExe $git `
                    -WorkspaceRoot $workspace `
                    -ToolchainsRoot $toolchains `
                    -RootPrefix $RootPrefix `
                    -ActiveDigest $ActiveDigest `
                    -CallerSelf $CallerSelf
                Assert-AstroCuda13InventoryUnblocked $post
                $completionValue = [ordered]@{
                    schema = 'astrolabe.cuda13-retirement-completion.v1'
                    transaction_id = $candidateTransactionId
                    transition_transaction_id = $transactionId
                    owner = [ordered]@{
                        pid = $PID
                        owner_process_start_utc_ticks = $ownerTicks
                        issue = $DrivingIssue
                    }
                    intent_path = $intentRecord.Path
                    intent_sha256 = $intentRecord.Sha256
                    source_path = [string]$candidate.path
                    source_file_id = [string]$candidate.root_file_id
                    tombstone_path = $tombstonePath
                    candidate_tree_inventory_sha256 =
                        $treeSecond.InventorySha256
                    first_inventory_sha256 = $baseline.Sha256
                    second_inventory_sha256 = $second.Sha256
                    post_inventory = $post.Value
                    post_inventory_sha256 = $post.Sha256
                    source_post_state = $sourceAfter.State
                    tombstone_post_state = $tombstoneAfter.State
                    completed_utc = [DateTime]::UtcNow.ToString('o')
                }
                $completionSnapshot =
                    ConvertTo-AstroCuda13CanonicalJsonSnapshot `
                        $completionValue
                $completionRecord = Write-NewAstroCuda13DurableFile `
                    -Path (
                        Join-Path $transactionDirectory 'completion.json'
                    ) `
                    -Bytes $completionSnapshot.Bytes
                $records += [ordered]@{
                    intent_path = $intentRecord.Path
                    intent_sha256 = $intentRecord.Sha256
                    completion_path = $completionRecord.Path
                    completion_sha256 = $completionRecord.Sha256
                    source_path = [string]$candidate.path
                    source_file_id = [string]$candidate.root_file_id
                    tree_inventory_sha256 =
                        $treeSecond.InventorySha256
                    total_bytes = $treeSecond.TotalBytes
                }
                Write-RetireDiag `
                    'ASTRO_CUDA13_RETIRE_RETIRED' `
                    "source=$($candidate.path); file_id=$($candidate.root_file_id); tree_sha256=$($treeSecond.InventorySha256); bytes=$($treeSecond.TotalBytes); intent_sha256=$($intentRecord.Sha256); completion_sha256=$($completionRecord.Sha256); source_absent=True; tombstone_absent=True"
                $baseline = $post
            }
            finally {
                if ($sourceHandleOwned) {
                    $sourceHandle.Dispose()
                }
            }
        }
        $activeRoot = @(
            $baseline.Value.bundle_roots |
                Where-Object { $_.active }
        )[0]
        Write-RetireDiag `
            'ASTRO_CUDA13_RETIRE_ACTIVE_PRESERVED' `
            "root=$($activeRoot.path); file_id=$($activeRoot.root_file_id); digest=$ActiveDigest"
        Write-RetireDiag `
            'ASTRO_CUDA13_RETIRE_SUMMARY' `
            "candidates=$($candidates.Count); retired=$($records.Count); final_inventory_sha256=$($baseline.Sha256); transition=$transactionId"
        $result = [pscustomobject]@{
            State = 'completed'
            TransitionTransactionId = $transactionId
            TransitionPath = $transitionLease.Path
            TransitionSha256 = $transitionLease.Snapshot.Sha256
            InitialCandidateCount = $candidates.Count
            RetiredCount = $records.Count
            Records = @($records)
            FinalInventorySha256 = $baseline.Sha256
            FinalInventory = $baseline.Value
        }
    }
    catch {
        $fault = $_
    }
    finally {
        try {
            if ($null -ne $transitionLease) {
                Remove-AstroCuda13TransitionLease $transitionLease
            }
        }
        catch {
            if ($null -eq $fault) {
                $fault = $_
            }
            else {
                $fault = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($fault.Exception.Message); transition_cleanup_error=$($_.Exception.Message)"
                    ),
                    'AstroCuda13RetirementAndCleanupFailed',
                    [Management.Automation.ErrorCategory]::InvalidOperation,
                    $workspace
                )
            }
        }
        Exit-AstroCuda13RetirementMutex $mutex
    }
    if ($null -ne $fault) {
        throw $fault
    }
    return $result
}
