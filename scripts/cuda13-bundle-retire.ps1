<#
.SYNOPSIS
    Retire obsolete CUDA13/ORT runtime bundle roots left behind by lock revisions (#559).

.DESCRIPTION
    The CUDA13 runtime provisioner (scripts/windows-cuda13-runtime.ps1) materializes the
    ONNX Runtime CUDA bundle into a hash-addressed root
    `<.toolchains>\<root_prefix>-<lockSha256>`. Every checked-in lock revision changes the
    digest, so each revision births a *new* root and orphans the previous one -- a ~1.8 GB
    leak per revision that accumulates forever inside the canonical workspace.

    This module retires those obsolete sibling roots. It is the Nix-GC model applied to the
    bundle store: discover the single live root (the active lock digest), prove no session is
    using the store (launcher session locks), then delete only provably-obsolete,
    provably-owned roots. Retirement can never lose unreproducible state -- the provisioner
    re-materializes any root from the checked-in lock, exactly like a cache miss falling back
    to re-provisioning.

    SAFETY DOCTRINE (all fail-closed -- when in doubt, delete NOTHING):
      * Lock gate. Any launcher session lock (canonical `.tmp` + every registered worktree
        `.claude\worktrees\*\.tmp`) blocks the entire pass until it is absent. We never guess
        and never remove even a stale lock; a crashed launcher may have detached descendants
        still using the shared toolchain, and #197 requires tracker-evidenced explicit reclaim.
      * Ownership proof. A candidate is retired only when its directory-name digest, its
        `bundle.lock.sha256` leaf content, and its `bundle.receipt.json` (schema of the
        receipt version family, matching lock_sha256) all agree on the same 64-hex digest.
        Only the provisioner writes that triple, so agreement is proof of ownership. The
        active digest is always preserved. Non-grammar siblings (gcc, staging dirs) never
        match.
      * Reparse safety. PowerShell's `Remove-Item -Recurse -Force` FOLLOWS NTFS junctions and
        symlinks into their targets and deletes real files OUTSIDE the tree (PowerShell bug
        #26913 -- catastrophic out-of-tree data loss). This module NEVER uses that. It
        pre-scans with a non-following manual walk, skips any root that contains a reparse
        point anywhere, and deletes bottom-up with non-following primitives
        ([System.IO.File]::Delete / [System.IO.Directory]::Delete($dir,$false)), re-checking
        the ReparsePoint attribute immediately before every descent (TOCTOU guard).

    DIAGNOSTICS: every decision is emitted as a named `CUDA13_RETIRE[ASTRO_CUDA13_RETIRE_*]`
    record on stderr via [Console]::Error.WriteLine -- NOT Write-Error (the provisioner runs
    under $ErrorActionPreference='Stop', which would make Write-Error THROW), and NOT
    Write-Output (which would break the launcher-enforced one-line stdout contract in
    scripts/windows-gnu-toolchain.ps1). stdout is left entirely to the provisioner.

    This file is dot-sourceable and has no top-level execution. Its FSV drives
    Remove-AstroObsoleteCudaRuntimeRoots against an isolated fixture `.toolchains` root, never
    the live shared runtime store (#197).
#>

Set-StrictMode -Version Latest

# Dot-source the shared launcher-lock semantics if not already present. The retirer only
# ever READS locks (classification); it never removes even a stale lock.
if (-not (Get-Command -Name 'Read-AstroLauncherLock' -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
}

function Write-RetireDiag {
    # Emit one named retirement decision record to stderr (never stdout, never a throw).
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message
    )
    [Console]::Error.WriteLine("CUDA13_RETIRE[$Code]: $Message")
}

function Get-AstroLiveCuda13LockBlockers {
    <#
    .SYNOPSIS
        Enumerate launcher session locks that must block bundle retirement.

    .DESCRIPTION
        Returns a blocker record for every present launcher protocol state under
        $WorkspaceRoot. Held, stale/PID-reused, unreadable, unevaluable, and interrupted
        transition states all block destructive retirement. Only authoritative 'absent'
        is safe.

        Locks inspected: the canonical `<WorkspaceRoot>\.tmp\astrolabe-launcher.lock` and,
        for each direct child of `<WorkspaceRoot>\.claude\worktrees` that exists and is not a
        reparse point, `<child>\.tmp\astrolabe-launcher.lock`. No recursion; a reparse-point
        or unevaluable worktree entry is itself a blocker and is never followed.

        This function is strictly read-only: it never mutates or removes any lock file.

    .PARAMETER WorkspaceRoot
        Absolute path to the workspace whose launcher locks gate retirement.
    #>
    param([Parameter(Mandatory = $true)][string]$WorkspaceRoot)

    $blockers = @()

    $lockPaths = @()
    $lockPaths += (Join-Path (Join-Path $WorkspaceRoot '.tmp') 'astrolabe-launcher.lock')

    $worktreesParent = Join-Path (Join-Path $WorkspaceRoot '.claude') 'worktrees'
    $worktreesState = Get-AstroPathEntryState $worktreesParent
    if ($worktreesState.State -eq 'present' -and
        ($worktreesState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -and
        ($worktreesState.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        try {
            $worktreeChildren = @(
                Get-ChildItem `
                    -LiteralPath $worktreesParent `
                    -Force `
                    -Directory `
                    -ErrorAction Stop
            )
        }
        catch {
            $blockers += [pscustomobject]@{
                Path = $worktreesParent
                State = 'unevaluable'
                OwnerPid = $null
                Detail = $_.Exception.Message
            }
            $worktreeChildren = @()
        }
        foreach ($child in $worktreeChildren) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $blockers += [pscustomobject]@{
                    Path = $child.FullName
                    State = 'unevaluable'
                    OwnerPid = $null
                    Detail = 'registered worktree root is a reparse point'
                }
                continue
            }
            $lockPaths += (Join-Path (Join-Path $child.FullName '.tmp') 'astrolabe-launcher.lock')
        }
    }
    elseif ($worktreesState.State -ne 'absent') {
        $blockers += [pscustomobject]@{
            Path = $worktreesParent
            State = 'unevaluable'
            OwnerPid = $null
            Detail = "worktree-parent state=$($worktreesState.State) attributes=$($worktreesState.Attributes) error=$($worktreesState.Error)"
        }
    }

    foreach ($lockPath in $lockPaths) {
        $lock = Read-AstroLauncherLock -LockPath $lockPath
        if ($lock.State -ne 'absent') {
            $blockers += [pscustomobject]@{
                Path     = $lockPath
                State    = $lock.State
                OwnerPid = $lock.OwnerPid
                Detail   = if ($lock.ReadError) {
                    $lock.ReadError
                } elseif ($lock.ValidationError) {
                    $lock.ValidationError
                } else {
                    $lock.ProbeError
                }
            }
        }
    }

    return $blockers
}

function Test-AstroPathContainsReparse {
    # Non-following manual walk: returns the first reparse-point path found at or under $Root
    # (inclusive), or $null if none. NEVER descends into a reparse-point directory and NEVER
    # uses Get-ChildItem -Recurse (which would follow reparse points). Also accumulates the
    # total byte size of regular files into the [ref]$TotalBytes accumulator.
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ref]$TotalBytes
    )

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $Root
    }

    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($entry in Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $entry.FullName
            }
            if ($entry.PSIsContainer) {
                $stack.Push($entry.FullName)
            }
            else {
                $TotalBytes.Value += [long]$entry.Length
            }
        }
    }
    return $null
}

function Remove-AstroDirectoryTreeNoFollow {
    # Bottom-up manual deletion that NEVER follows reparse points. Re-checks the ReparsePoint
    # attribute immediately before descending into any directory (TOCTOU guard). Files are
    # removed with [System.IO.File]::Delete and directories with
    # [System.IO.Directory]::Delete($dir,$false) (non-recursive). Throws on any reparse
    # discovery or IO fault so the caller can record a named FAULT and preserve the root.
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "reparse point discovered at delete time: $Root"
    }

    # Post-order traversal: push dirs onto an order stack, delete deepest-first.
    $orderStack = [System.Collections.Generic.Stack[string]]::new()
    $walkStack = [System.Collections.Generic.Stack[string]]::new()
    $walkStack.Push($Root)
    while ($walkStack.Count -gt 0) {
        $dir = $walkStack.Pop()
        $orderStack.Push($dir)
        foreach ($entry in Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "reparse point discovered at delete time: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) {
                $walkStack.Push($entry.FullName)
            }
        }
    }

    # orderStack now holds directories root..deepest top-to-bottom; popping yields
    # deepest-first. Delete each directory's files, then the (now-empty) directory itself.
    while ($orderStack.Count -gt 0) {
        $dir = $orderStack.Pop()
        # TOCTOU guard: re-verify the directory is not a reparse point before touching it.
        $dirItem = Get-Item -LiteralPath $dir -Force -ErrorAction Stop
        if (($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "reparse point discovered at delete time: $dir"
        }
        foreach ($entry in Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "reparse point discovered at delete time: $($entry.FullName)"
            }
            if (-not $entry.PSIsContainer) {
                [System.IO.File]::Delete($entry.FullName)
            }
        }
        [System.IO.Directory]::Delete($dir, $false)
    }
}

function Test-AstroCudaRootOwned {
    # Ownership proof for a candidate bundle root: the directory-name digest, the
    # `bundle.lock.sha256` leaf content, and the `bundle.receipt.json` (schema of the receipt
    # version family, lock_sha256 field) must all agree on the same 64-hex $NameDigest. Only
    # the provisioner writes that consistent triple. Returns $true iff all hold.
    param(
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string]$NameDigest
    )

    $sha256Leaf = Join-Path $CandidatePath 'bundle.lock.sha256'
    if (-not (Test-Path -LiteralPath $sha256Leaf -PathType Leaf)) { return $false }
    $sha256Content = ([System.IO.File]::ReadAllText($sha256Leaf, [Text.Encoding]::UTF8)).Trim()
    if ($sha256Content -cne $NameDigest) { return $false }

    $receiptLeaf = Join-Path $CandidatePath 'bundle.receipt.json'
    if (-not (Test-Path -LiteralPath $receiptLeaf -PathType Leaf)) { return $false }
    $receipt = $null
    try {
        $receipt = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($receiptLeaf, [Text.Encoding]::UTF8))
    }
    catch {
        return $false
    }
    if ($null -eq $receipt) { return $false }
    if (-not $receipt.PSObject.Properties['schema']) { return $false }
    if (-not $receipt.PSObject.Properties['lock_sha256']) { return $false }
    # Accept the receipt-schema version FAMILY, so pre-existing v1 receipts written by older
    # provisioner revisions (the actual leaked root this issue targets) are recognized as
    # launcher-owned and remain retirable.
    if (([string]$receipt.schema) -cnotmatch '^astrolabe\.windows-ort-cuda-runtime-receipt\.v[0-9]+$') { return $false }
    if (([string]$receipt.lock_sha256) -cne $NameDigest) { return $false }

    return $true
}

function Remove-AstroObsoleteCudaRuntimeRoots {
    <#
    .SYNOPSIS
        Retire every obsolete, launcher-owned CUDA13/ORT bundle root under a toolchains store.

    .DESCRIPTION
        Deletes each direct child of $ToolchainsRoot named `<RootPrefix>-<64hex>` whose digest
        is NOT $ActiveDigest, provided (a) no launcher lock across the workspace blocks the
        pass, (b) the root carries the digest-consistent ownership triple
        (name digest == bundle.lock.sha256 == receipt.lock_sha256, receipt schema in the
        family), and (c) the root contains no reparse point. Deletion is bottom-up and never
        follows reparse points. Every decision is logged to stderr; stdout is untouched.

        Policy is "retire ALL non-active owned roots" -- deterministic, with no retention-count
        or age knobs, so it introduces no new measurement constants. Fail-closed everywhere:
        on any precondition violation, lock block, ownership doubt, reparse discovery, or IO
        fault, the affected root (or the whole pass) is preserved, never partially destroyed.

        Candidates are independent: a fault on one root does not abort the others.

    .PARAMETER ToolchainsRoot
        The `.toolchains` container whose direct children are the bundle roots.

    .PARAMETER RootPrefix
        The bundle root name prefix (lock.bundle.root_prefix), e.g. ort-cuda13.3-windows-x86_64.

    .PARAMETER ActiveDigest
        The 64-hex lock digest of the currently active bundle root, which is always preserved.

    .PARAMETER WorkspaceRoot
        The workspace whose launcher session locks gate the pass.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ToolchainsRoot,
        [Parameter(Mandatory = $true)][string]$RootPrefix,
        [Parameter(Mandatory = $true)][string]$ActiveDigest,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    # --- Preconditions (fail-closed: nothing deleted) --------------------------------------
    if ($ActiveDigest -cnotmatch '^[0-9a-f]{64}$') {
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_PRECONDITION' "{code=ASTRO_CUDA13_RETIRE_PRECONDITION; message=`"ActiveDigest is not a 64-hex lowercase digest: $ActiveDigest`"; remediation=`"pass the active lock sha256 digest`"}"
        return
    }
    if ([string]::IsNullOrWhiteSpace($RootPrefix) -or $RootPrefix.IndexOfAny([char[]]@('\', '/')) -ge 0) {
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_PRECONDITION' "{code=ASTRO_CUDA13_RETIRE_PRECONDITION; message=`"RootPrefix is blank or contains a path separator: $RootPrefix`"; remediation=`"pass lock.bundle.root_prefix`"}"
        return
    }
    if (-not (Test-Path -LiteralPath $ToolchainsRoot -PathType Container)) {
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_PRECONDITION' "{code=ASTRO_CUDA13_RETIRE_PRECONDITION; message=`"ToolchainsRoot does not resolve to a container: $ToolchainsRoot`"; remediation=`"pass the canonical .toolchains root`"}"
        return
    }
    $resolvedToolchains = (Resolve-Path -LiteralPath $ToolchainsRoot).ProviderPath.TrimEnd('\')
    $toolchainsItem = Get-Item -LiteralPath $resolvedToolchains -Force
    if (($toolchainsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_PRECONDITION' "{code=ASTRO_CUDA13_RETIRE_PRECONDITION; message=`"ToolchainsRoot is a reparse point: $resolvedToolchains`"; remediation=`"remove the redirected .toolchains path and retry`"}"
        return
    }

    # --- Lock gate (fail-closed: every non-absent protocol/root state blocks) ----------------
    $blockers = @(Get-AstroLiveCuda13LockBlockers -WorkspaceRoot $WorkspaceRoot)
    if ($blockers.Count -gt 0) {
        foreach ($blocker in $blockers) {
            if ($blocker.State -eq 'held') {
                Write-RetireDiag 'ASTRO_CUDA13_RETIRE_BLOCKED_LIVE_LOCK' "state=held pid=$($blocker.OwnerPid) lock=$($blocker.Path)"
            }
            else {
                Write-RetireDiag 'ASTRO_CUDA13_RETIRE_BLOCKED_LOCK_STATE' "state=$($blocker.State) lock=$($blocker.Path) detail=$($blocker.Detail)"
            }
        }
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SUMMARY' "candidates=0 retired=0 skipped_unowned=0 skipped_reparse=0 faults=0 (blocked by launcher lock)"
        return
    }

    # --- Candidate enumeration (direct grammar-matching children, active digest preserved) --
    $namePattern = '^' + [Regex]::Escape($RootPrefix) + '-([0-9a-f]{64})$'
    $candidateCount = 0
    $retiredCount = 0
    $skippedUnowned = 0
    $skippedReparse = 0
    $faultCount = 0

    foreach ($child in Get-ChildItem -LiteralPath $resolvedToolchains -Force -Directory -ErrorAction Stop) {
        $match = [Regex]::Match($child.Name, $namePattern)
        if (-not $match.Success) {
            # Non-grammar siblings (gcc-14.1) and staging dirs (.installing-ort-cuda13-*) are
            # not bundle roots; silently ignored.
            continue
        }
        $childDigest = $match.Groups[1].Value
        if ($childDigest -ceq $ActiveDigest) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_ACTIVE_PRESERVED' "root=$($child.FullName)"
            continue
        }

        # Containment re-check: resolved candidate's parent must be exactly the toolchains root.
        $resolvedChild = (Resolve-Path -LiteralPath $child.FullName).ProviderPath.TrimEnd('\')
        $childParent = [System.IO.Path]::GetDirectoryName($resolvedChild)
        if (-not [string]::Equals($childParent, $resolvedToolchains, [StringComparison]::OrdinalIgnoreCase)) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SKIPPED_UNOWNED' "root=$resolvedChild reason=containment-failed parent=$childParent"
            $candidateCount++
            $skippedUnowned++
            continue
        }

        $candidateCount++

        # Ownership proof: the candidate dir must not itself be a reparse point, and the
        # name/sha256/receipt digest triple must agree.
        $candidateItem = Get-Item -LiteralPath $resolvedChild -Force
        if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SKIPPED_REPARSE' "path=$resolvedChild"
            $skippedReparse++
            continue
        }
        if (-not (Test-AstroCudaRootOwned -CandidatePath $resolvedChild -NameDigest $childDigest)) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SKIPPED_UNOWNED' "root=$resolvedChild reason=ownership-triple-mismatch"
            $skippedUnowned++
            continue
        }

        # Reparse scan (non-following) over the whole tree; also accumulates byte size.
        $totalBytes = [long]0
        $reparseHit = $null
        try {
            $reparseHit = Test-AstroPathContainsReparse -Root $resolvedChild -TotalBytes ([ref]$totalBytes)
        }
        catch {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_FAULT' "{code=ASTRO_CUDA13_RETIRE_FAULT; message=`"reparse scan failed for $resolvedChild : $($_.Exception.Message)`"; remediation=`"inspect the root manually and remove it if safe`"}"
            $faultCount++
            continue
        }
        if ($null -ne $reparseHit) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SKIPPED_REPARSE' "path=$reparseHit"
            $skippedReparse++
            continue
        }

        # Deletion (bottom-up, non-following).
        try {
            Remove-AstroDirectoryTreeNoFollow -Root $resolvedChild
        }
        catch {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_FAULT' "{code=ASTRO_CUDA13_RETIRE_FAULT; message=`"deletion faulted for $resolvedChild : $($_.Exception.Message)`"; remediation=`"inspect the root manually and remove it if safe`"}"
            $faultCount++
            continue
        }

        # Post-delete readback (independent Test-Path).
        if (Test-Path -LiteralPath $resolvedChild) {
            Write-RetireDiag 'ASTRO_CUDA13_RETIRE_FAULT' "{code=ASTRO_CUDA13_RETIRE_FAULT; message=`"readback failed: root still present after deletion: $resolvedChild`"; remediation=`"inspect the root manually and remove it if safe`"}"
            $faultCount++
            continue
        }
        Write-RetireDiag 'ASTRO_CUDA13_RETIRE_RETIRED' "root=$resolvedChild bytes~=$totalBytes readback_absent=True"
        $retiredCount++
    }

    Write-RetireDiag 'ASTRO_CUDA13_RETIRE_SUMMARY' "candidates=$candidateCount retired=$retiredCount skipped_unowned=$skippedUnowned skipped_reparse=$skippedReparse faults=$faultCount"
}
