<#
.SYNOPSIS
    Exact owner-bound compiler scratch lifecycle for detached PowerShell roles.

.DESCRIPTION
    Creates one compiler scope inside an already-created detached run, persists
    its exact process/principal/security intent before changing TEMP, and after
    imports double-inventories, handle-renames, and deletes only that bound
    ordinary tree. Any compiler or cleanup fault is persisted outside the scope
    and leaves the remaining namespace bytes untouched. Refs #717.
#>

Set-StrictMode -Version Latest

function Get-AstroDetachedPrincipalSnapshot {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $integritySids = @(
        $identity.Groups |
            ForEach-Object { $_.Value } |
            Where-Object { $_ -cmatch '^S-1-16-[0-9]+$' } |
            Sort-Object -Unique
    )
    return [ordered]@{
        name = [string]$identity.Name
        sid = [string]$identity.User.Value
        authentication_type = [string]$identity.AuthenticationType
        is_authenticated = [bool]$identity.IsAuthenticated
        is_system = [bool]$identity.IsSystem
        is_elevated_administrator = [bool]$principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
        integrity_sids = [string[]]$integritySids
    }
}

function Get-AstroDetachedSecuritySnapshot {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    try {
        $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Group -bor
            [Security.AccessControl.AccessControlSections]::Access
        $sddl = $acl.GetSecurityDescriptorSddlForm($sections)
        return [ordered]@{
            state = 'readable'
            path = $full
            owner = [string]$acl.Owner
            group = [string]$acl.Group
            access_sddl = $sddl
            access_sddl_sha256 = Get-AstroDetachedSha256Bytes (
                Get-AstroDetachedUtf8Bytes $sddl
            )
            error = $null
        }
    }
    catch {
        return [ordered]@{
            state = 'unreadable'
            path = $full
            owner = $null
            group = $null
            access_sddl = $null
            access_sddl_sha256 = $null
            error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
        }
    }
}

function Write-AstroDetachedCompilerRecord {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)]
        [ValidateSet('coordinator', 'runner')]
        [string]$Role,
        [Parameter(Mandatory)]
        [ValidateSet('intent', 'authorization', 'renamed', 'completion', 'fault')]
        [string]$Stage,
        [Parameter(Mandatory)]$Payload
    )

    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    $name = "compiler-$Role-$Stage.json"
    $path = Join-Path $run $name
    $writer = Get-AstroDetachedCurrentIdentity
    $payloadJson = $Payload | ConvertTo-Json -Depth 40 -Compress
    $payloadBytes = Get-AstroDetachedUtf8Bytes $payloadJson
    $document = [ordered]@{
        schema = 'astrolabe.detached.compiler-state.v1'
        run_id = [IO.Path]::GetFileName($run)
        role = $Role
        stage = $Stage
        written_utc_ticks = [DateTime]::UtcNow.Ticks
        writer = $writer
        payload_sha256 = Get-AstroDetachedSha256Bytes $payloadBytes
        payload_bytes = [long]$payloadBytes.Length
        payload = $Payload
    }
    $bytes = Get-AstroDetachedUtf8Bytes (
        $document | ConvertTo-Json -Depth 48 -Compress
    )
    if ($bytes.Length -gt $script:AstroDetachedRecordMaximumBytes) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_RECORD_TOO_LARGE]: {code=ASTRO_DETACH_COMPILER_RECORD_TOO_LARGE; message=`"$name is $($bytes.Length) bytes`"; remediation=`"preserve compiler state and investigate the unexpectedly large evidence payload`"}"
    }
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $readback = Read-AstroDetachedOrdinaryFile $path
    $expectedHash = Get-AstroDetachedSha256Bytes $bytes
    if ($readback.Length -ne $bytes.Length -or
        $readback.Sha256 -cne $expectedHash) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_RECORD_READBACK]: {code=ASTRO_DETACH_COMPILER_RECORD_READBACK; message=`"create-new record readback differs for $path`"; remediation=`"preserve the run and inspect the immutable record bytes`"}"
    }
    return [pscustomobject]@{
        Name = $name
        Path = $path
        Sha256 = $readback.Sha256
        Length = $readback.Length
        Document = [pscustomobject]$document
    }
}

function Start-AstroDetachedCompilerScope {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)]
        [ValidateSet('coordinator', 'runner')]
        [string]$Role,
        [Parameter(Mandatory)][int]$Issue
    )

    if ($Issue -le 0) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_ISSUE_INVALID]: {code=ASTRO_DETACH_COMPILER_ISSUE_INVALID; message=`"Issue must be positive`"; remediation=`"bind compiler preparation to the driving tracker issue`"}"
    }
    $run = Assert-AstroDetachedRunDirectory $RunDirectory
    $owner = Get-AstroDetachedCurrentIdentity
    $principal = Get-AstroDetachedPrincipalSnapshot
    $leaf = 'compiler-state-{0}.pid-{1}.ticks-{2}.dir' -f
        $Role, $owner.pid, $owner.process_start_utc_ticks
    $scopePath = Join-Path $run $leaf
    [void](New-AstroDetachedDirectoryNoReplace $scopePath)
    try {
        $security = Get-AstroDetachedSecuritySnapshot $scopePath
        if ($security.state -cne 'readable') {
            throw "new compiler scope security is unreadable: $($security.error)"
        }
        $intent = Write-AstroDetachedCompilerRecord `
            -RunDirectory $run `
            -Role $Role `
            -Stage intent `
            -Payload ([ordered]@{
                issue = $Issue
                exact_owner = $owner
                principal = $principal
                scope_path = $scopePath
                scope_leaf = $leaf
                security_before = $security
                environment_before = [ordered]@{
                    TEMP = [string]$env:TEMP
                    TMP = [string]$env:TMP
                    TMPDIR = [string]$env:TMPDIR
                }
                policy = [ordered]@{
                    compiler_temp_authority = 'exact-scope-only'
                    normal_cleanup_authority = 'exact-live-owner-only'
                    unreadable_or_unevaluable = 'preserve-with-fault'
                }
            })
    }
    catch {
        $startFailure = $_
        try {
            [void](Write-AstroDetachedCompilerRecord `
                -RunDirectory $run `
                -Role $Role `
                -Stage fault `
                -Payload ([ordered]@{
                    issue = $Issue
                    code = 'ASTRO_DETACH_COMPILER_START_FAILED'
                    message = $startFailure.Exception.Message
                    remediation =
                        'preserve the newly created scope and fault record; ' +
                        'inspect security/storage before tracker-bound recovery'
                    failed_stage = 'scope-intent-publication'
                    exact_owner = $owner
                    principal = $principal
                    scope_path = $scopePath
                    security_readback =
                        Get-AstroDetachedSecuritySnapshot $scopePath
                    policy = 'preserve-all-observed-compiler-state'
                }))
        }
        catch {
            throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_START_FAULT_PUBLISH_FAILED]: {code=ASTRO_DETACH_COMPILER_START_FAULT_PUBLISH_FAILED; message=`"compiler scope start failed ('$($startFailure.Exception.Message)') and fault publication failed ('$($_.Exception.Message)')`"; remediation=`"preserve the run and scope; inspect both failures before recovery`"}"
        }
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_START_FAILED]: {code=ASTRO_DETACH_COMPILER_START_FAILED; message=`"$($startFailure.Exception.Message)`"; remediation=`"preserve the scope and immutable fault record; do not compile`"}"
    }

    $env:TEMP = $scopePath
    $env:TMP = $scopePath
    $env:TMPDIR = $scopePath
    return [pscustomobject]@{
        RunDirectory = $run
        Role = $Role
        Issue = $Issue
        Owner = $owner
        Principal = $principal
        ScopePath = $scopePath
        ScopeLeaf = $leaf
        TombstoneLeaf = ($leaf -replace '\.dir$', '.tombstone')
        TombstonePath = Join-Path $run ($leaf -replace '\.dir$', '.tombstone')
        Intent = $intent
        EnvironmentBefore = [ordered]@{
            TEMP = [string]$intent.Document.payload.environment_before.TEMP
            TMP = [string]$intent.Document.payload.environment_before.TMP
            TMPDIR = [string]$intent.Document.payload.environment_before.TMPDIR
        }
    }
}

function Restore-AstroDetachedCompilerEnvironment {
    param([Parameter(Mandatory)]$State)

    $env:TEMP = [string]$State.RunDirectory
    $env:TMP = [string]$State.RunDirectory
    $env:TMPDIR = [string]$State.RunDirectory
}

function Write-AstroDetachedCompilerFault {
    param(
        [Parameter(Mandatory)]$State,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation,
        [Parameter(Mandatory)][string]$Stage
    )

    Restore-AstroDetachedCompilerEnvironment $State
    $scopePresent = [IO.Directory]::Exists([string]$State.ScopePath)
    $tombstonePresent = [IO.Directory]::Exists([string]$State.TombstonePath)
    $observedPath = if ($scopePresent) {
        [string]$State.ScopePath
    }
    elseif ($tombstonePresent) {
        [string]$State.TombstonePath
    }
    else {
        [string]$State.ScopePath
    }
    return Write-AstroDetachedCompilerRecord `
        -RunDirectory ([string]$State.RunDirectory) `
        -Role ([string]$State.Role) `
        -Stage fault `
        -Payload ([ordered]@{
            issue = [int]$State.Issue
            code = $Code
            message = $Message
            remediation = $Remediation
            failed_stage = $Stage
            exact_owner = $State.Owner
            principal = $State.Principal
            intent_path = [string]$State.Intent.Path
            intent_sha256 = [string]$State.Intent.Sha256
            scope_path = [string]$State.ScopePath
            tombstone_path = [string]$State.TombstonePath
            scope_present = $scopePresent
            tombstone_present = $tombstonePresent
            security_readback = Get-AstroDetachedSecuritySnapshot $observedPath
            policy = 'preserve-all-observed-compiler-state'
        })
}

function Complete-AstroDetachedCompilerScope {
    param([Parameter(Mandatory)]$State)

    Restore-AstroDetachedCompilerEnvironment $State
    $current = Get-AstroDetachedCurrentIdentity
    if ($current.pid -ne [int]$State.Owner.pid -or
        $current.process_start_utc_ticks -ne
            [long]$State.Owner.process_start_utc_ticks -or
        $current.session_id -ne [int]$State.Owner.session_id) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_OWNER_CHANGED]: {code=ASTRO_DETACH_COMPILER_OWNER_CHANGED; message=`"compiler cleanup caller is not the exact intent owner`"; remediation=`"preserve scope state and recover only through a tracker-bound dead-owner transaction`"}"
    }
    if (-not ('AstroLauncherLockNative' -as [type]) -or
        -not (Test-Path Function:\Get-AstroOrdinaryDirectoryTreeInventoryLongPath) -or
        -not (Test-Path Function:\Remove-AstroOrdinaryDirectoryTreeLongPath)) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_NATIVE_UNAVAILABLE]: {code=ASTRO_DETACH_COMPILER_NATIVE_UNAVAILABLE; message=`"launcher native inventory/handle helpers did not load`"; remediation=`"preserve the compiler scope and inspect the recorded Add-Type failure`"}"
    }

    $scope = [IO.Path]::GetFullPath([string]$State.ScopePath).TrimEnd('\', '/')
    $run = Assert-AstroDetachedRunDirectory ([string]$State.RunDirectory)
    if ([IO.Path]::GetDirectoryName($scope).TrimEnd('\', '/') -cne $run -or
        [IO.Path]::GetFileName($scope) -cne [string]$State.ScopeLeaf) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_SCOPE_ESCAPE]: {code=ASTRO_DETACH_COMPILER_SCOPE_ESCAPE; message=`"compiler scope escaped its exact run/leaf binding: $scope`"; remediation=`"preserve the namespace and inspect the immutable compiler intent`"}"
    }
    $tombstone = [IO.Path]::GetFullPath(
        [string]$State.TombstonePath
    ).TrimEnd('\', '/')
    $destinationState = Get-AstroPathEntryState $tombstone
    if ($destinationState.State -cne 'absent') {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_TOMBSTONE_COLLISION]: {code=ASTRO_DETACH_COMPILER_TOMBSTONE_COLLISION; message=`"compiler tombstone is not absent (state=$($destinationState.State), error=$($destinationState.Error)): $tombstone`"; remediation=`"preserve both paths and use tracker-bound recovery`"}"
    }

    $first = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
    $second = Get-AstroOrdinaryDirectoryTreeInventoryLongPath $scope
    if ($first.schema -cne $second.schema -or
        $first.encoding -cne $second.encoding -or
        $first.entry_count -ne $second.entry_count -or
        $first.sha256 -cne $second.sha256) {
        throw "compiler scope inventory changed between exact observations: first=$($first.sha256) second=$($second.sha256)"
    }
    $expectedRootFileId = [string]@(
        $second.entries |
            Where-Object { [string]$_.relative_path -ceq '.' }
    )[0].file_id
    if ($expectedRootFileId -cnotmatch '^[0-9a-f]+:[0-9a-f]+$') {
        throw "compiler scope inventory lacks one canonical root FILE_ID"
    }
    $security = Get-AstroDetachedSecuritySnapshot $scope
    if ($security.state -cne 'readable') {
        throw "compiler scope security became unreadable: $($security.error)"
    }

    $sourceHandle = $null
    $parentHandle = $null
    try {
        $sourceHandle = [AstroLauncherLockNative]::OpenExactDeleteDirectory($scope)
        $parentHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($run)
        $fileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        if ($fileId -cne $expectedRootFileId) {
            throw "compiler scope FILE_ID changed after double inventory: expected=$expectedRootFileId observed=$fileId"
        }
        $final = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
        )
        $final = [IO.Path]::GetFullPath($final).TrimEnd('\', '/')
        if (-not [string]::Equals(
                $final,
                $scope,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "retained compiler scope resolved to '$final', expected '$scope'"
        }
        $authorization = Write-AstroDetachedCompilerRecord `
            -RunDirectory $run `
            -Role ([string]$State.Role) `
            -Stage authorization `
            -Payload ([ordered]@{
                issue = [int]$State.Issue
                exact_owner = $State.Owner
                principal = $State.Principal
                intent_path = [string]$State.Intent.Path
                intent_sha256 = [string]$State.Intent.Sha256
                scope_path = $scope
                scope_file_id = $fileId
                tombstone_path = $tombstone
                security = $security
                first_inventory = [ordered]@{
                    schema = [string]$first.schema
                    encoding = [string]$first.encoding
                    entry_count = [int]$first.entry_count
                    canonical_bytes_length =
                        [uint64]$first.canonical_bytes_length
                    sha256 = [string]$first.sha256
                }
                second_inventory = [ordered]@{
                    schema = [string]$second.schema
                    encoding = [string]$second.encoding
                    entry_count = [int]$second.entry_count
                    canonical_bytes_length =
                        [uint64]$second.canonical_bytes_length
                    sha256 = [string]$second.sha256
                }
                mutation_authority =
                    'same-volume-handle-rename-then-exact-inventory-delete'
            })

        [AstroLauncherLockNative]::RenameDirectoryHandleNoReplace(
            $sourceHandle,
            $parentHandle,
            [string]$State.TombstoneLeaf
        )
        $renamedFileId = [AstroLauncherLockNative]::GetFileIdentity($sourceHandle)
        $renamedFinal = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($sourceHandle)
        )
        $renamedFinal = [IO.Path]::GetFullPath($renamedFinal).TrimEnd('\', '/')
        $sourceState = Get-AstroPathEntryState $scope
        if ($renamedFileId -cne $fileId -or
            -not [string]::Equals(
                $renamedFinal,
                $tombstone,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $sourceState.State -cne 'absent') {
            throw "handle-bound compiler rename readback failed: file_id=$renamedFileId final=$renamedFinal source_state=$($sourceState.State)"
        }
        $renamed = Write-AstroDetachedCompilerRecord `
            -RunDirectory $run `
            -Role ([string]$State.Role) `
            -Stage renamed `
            -Payload ([ordered]@{
                issue = [int]$State.Issue
                authorization_path = $authorization.Path
                authorization_sha256 = $authorization.Sha256
                source_path = $scope
                source_state = $sourceState.State
                tombstone_path = $tombstone
                tombstone_file_id = $renamedFileId
                inventory_sha256 = [string]$second.sha256
            })
    }
    finally {
        if ($null -ne $parentHandle) { $parentHandle.Dispose() }
        if ($null -ne $sourceHandle) { $sourceHandle.Dispose() }
    }

    $tombstoneInventory =
        Get-AstroOrdinaryDirectoryTreeInventoryLongPath $tombstone
    if ($tombstoneInventory.sha256 -cne $second.sha256 -or
        $tombstoneInventory.entry_count -ne $second.entry_count) {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_TOMBSTONE_DRIFT]: {code=ASTRO_DETACH_COMPILER_TOMBSTONE_DRIFT; message=`"compiler tombstone inventory differs after rename: expected=$($second.sha256) observed=$($tombstoneInventory.sha256)`"; remediation=`"preserve the tombstone and immutable authorization/rename records`"}"
    }
    Remove-AstroOrdinaryDirectoryTreeLongPath `
        -LiteralPath $tombstone `
        -ExpectedInventorySchema ([string]$second.schema) `
        -ExpectedInventoryEncoding ([string]$second.encoding) `
        -ExpectedInventorySha256 ([string]$second.sha256)
    $sourceTerminal = Get-AstroPathEntryState $scope
    $tombstoneTerminal = Get-AstroPathEntryState $tombstone
    if ($sourceTerminal.State -cne 'absent' -or
        $tombstoneTerminal.State -cne 'absent') {
        throw "DETACH_COMPILER[ASTRO_DETACH_COMPILER_TERMINAL_STATE]: {code=ASTRO_DETACH_COMPILER_TERMINAL_STATE; message=`"compiler cleanup terminal state is source=$($sourceTerminal.State) tombstone=$($tombstoneTerminal.State)`"; remediation=`"preserve run evidence and inspect the exact namespace states`"}"
    }
    $completion = Write-AstroDetachedCompilerRecord `
        -RunDirectory $run `
        -Role ([string]$State.Role) `
        -Stage completion `
        -Payload ([ordered]@{
            issue = [int]$State.Issue
            exact_owner = $State.Owner
            intent_path = [string]$State.Intent.Path
            intent_sha256 = [string]$State.Intent.Sha256
            authorization_path = $authorization.Path
            authorization_sha256 = $authorization.Sha256
            renamed_path = $renamed.Path
            renamed_sha256 = $renamed.Sha256
            scope_path = $scope
            scope_file_id = $fileId
            scope_state = $sourceTerminal.State
            tombstone_path = $tombstone
            tombstone_state = $tombstoneTerminal.State
            inventory_sha256 = [string]$second.sha256
            security = $security
        })
    return [pscustomobject]@{
        Intent = $State.Intent
        Authorization = $authorization
        Renamed = $renamed
        Completion = $completion
        ScopePath = $scope
        ScopeFileId = $fileId
        InventorySha256 = [string]$second.sha256
        ScopeState = $sourceTerminal.State
        TombstoneState = $tombstoneTerminal.State
    }
}
