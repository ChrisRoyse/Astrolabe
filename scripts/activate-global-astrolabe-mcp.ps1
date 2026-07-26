<#
.SYNOPSIS
    Atomically activate one verified immutable Astrolabe generation for Codex and Claude Code.

.DESCRIPTION
    Publication and activation are separate durable transactions. This command accepts only an
    immutable astrolabe.global-mcp-publication.v3 receipt whose artifact bytes still match its
    receipt and whose frozen tree matches the live issue-owned launcher generation.

    It snapshots both real user configuration files, validates the complete Codex TOML through
    the installed Codex CLI, strictly parses the complete Claude JSON with duplicate-key
    rejection, and builds both candidates before changing either Source of Truth. Candidate and
    before-image bytes plus intent/candidate/completion or fault records remain in an append-only
    activation transaction. Each config is replaced with metadata-preserving ReplaceFileW,
    explicitly flushed, and read back. Any partial failure attempts exact before-image rollback and reports the
    independently read physical end state; it never reports global activation unless both files
    agree on the exact immutable executable.

.NOTES
    Manual FSV/activation tooling for #773. This is not a fallback installer or a test harness.
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PublicationReceiptPath,
    [Parameter(Mandatory)][string]$ExpectedPublicationReceiptSha256,
    [Parameter(Mandatory)][int]$Issue,
    [Parameter(Mandatory)][string]$ExpectedTreeSha,
    [string]$CodexConfigPath = '',
    [string]$ClaudeConfigPath = '',
    [string]$TransactionRoot = '',
    [string]$CodexCliPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. (Join-Path $PSScriptRoot 'launcher-lock.ps1')

function Fail-AstroGlobalActivation {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Remediation
    )

    $exception = [InvalidOperationException]::new($Message)
    $exception.Data['AstroCode'] = $Code
    $exception.Data['AstroRemediation'] = $Remediation
    throw $exception
}

function Get-StringSha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    return Get-AstroByteSha256 (
        [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
    )
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return (
            [BitConverter]::ToString($hasher.ComputeHash($stream)) -replace '-', ''
        ).ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Assert-OrdinaryFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $state = Get-AstroPathEntryState $Path
    if ($state.State -cne 'present' -or
        ($state.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_FILE_UNAVAILABLE' `
            "$Description is not one evaluable present file: $Path (state=$($state.State); error=$($state.Error))" `
            'restore the exact ordinary config or publication file and retry unchanged'
    }
    if (($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_REPARSE_REFUSED' `
            "$Description is a reparse point: $Path" `
            'use one ordinary local file as the configuration Source of Truth'
    }
}

function Read-ConfigSnapshot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-OrdinaryFile $Path $Description
    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $memory = [IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        }
        finally { $memory.Dispose() }
        $identity = [AstroLauncherLockNative]::GetFileIdentity($stream.SafeFileHandle)
    }
    finally { $stream.Dispose() }

    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    catch {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_UTF8_INVALID' `
            "$Description is not strict UTF-8: $Path ($($_.Exception.Message))" `
            'repair the exact configuration encoding without discarding any setting, then retry'
    }
    return [pscustomobject]@{
        path = [IO.Path]::GetFullPath($Path)
        bytes_value = $bytes
        text = $text
        bytes = [uint64]$bytes.LongLength
        sha256 = Get-AstroByteSha256 $bytes
        file_id = $identity
        last_write_utc = [IO.File]::GetLastWriteTimeUtc($Path).ToString('o')
    }
}

function Write-NewDurableBytes {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Flush-ExistingDurableFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $stream = [IO.File]::Open(
        (ConvertTo-AstroExtendedLengthPath $Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read
    )
    try { $stream.Flush($true) }
    catch {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_FLUSH_FAILED' `
            "$Description could not be flushed after replacement: $($_.Exception.Message)" `
            'preserve the transaction; exact rollback will restore the before image'
    }
    finally { $stream.Dispose() }
}

function Write-NewDurableText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    Write-NewDurableBytes $Path ([Text.UTF8Encoding]::new($false).GetBytes($Text))
}

function Write-NewDurableJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )

    Write-NewDurableText $Path ($Value | ConvertTo-Json -Depth 40)
}

function Test-DescendantOf {
    param(
        [Parameter(Mandatory)][int]$CandidatePid,
        [Parameter(Mandatory)][int]$AncestorPid
    )

    $seen = @{}
    $current = $CandidatePid
    while ($current -gt 0 -and -not $seen.ContainsKey($current)) {
        if ($current -eq $AncestorPid) { return $true }
        $seen[$current] = $true
        $row = Get-CimInstance Win32_Process -Filter "ProcessId=$current" -ErrorAction Stop
        if ($null -eq $row) { return $false }
        $current = [int]$row.ParentProcessId
    }
    return $false
}

function Assert-NoDuplicateJsonKeys {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$JsonPath
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_JSON_DUPLICATE_KEY' `
                    "Claude JSON contains duplicate key '$($property.Name)' at $JsonPath" `
                    'repair the ambiguous JSON object explicitly; no client config was changed'
            }
            Assert-NoDuplicateJsonKeys $property.Value "$JsonPath.$($property.Name)"
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonKeys $item "$JsonPath[$index]"
            $index++
        }
    }
}

function Assert-StrictJsonText {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Description,
        [switch]$RequireObject
    )

    try {
        $document = [Text.Json.JsonDocument]::Parse(
            $Text,
            [Text.Json.JsonDocumentOptions]@{
                AllowTrailingCommas = $false
                CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
                MaxDepth = 128
            }
        )
    }
    catch {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_JSON_MALFORMED' `
            "$Description is malformed JSON: $($_.Exception.Message)" `
            'repair the complete JSON document; no client config was changed'
    }
    try {
        if ($RequireObject -and
            $document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_JSON_ROOT_INVALID' `
                "$Description root is $($document.RootElement.ValueKind), not an object" `
                'restore one JSON object as the complete Claude user configuration'
        }
        Assert-NoDuplicateJsonKeys $document.RootElement '$'
    }
    finally { $document.Dispose() }
}

function ConvertTo-CanonicalJsonElement {
    param(
        [Parameter(Mandatory)][Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)][string]$JsonPath,
        [switch]$ExcludeClaudeTarget
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $properties = @($Element.EnumerateObject())
        $keys = [string[]]@($properties | ForEach-Object { $_.Name })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $members = [Collections.Generic.List[string]]::new()
        foreach ($key in $keys) {
            if ($ExcludeClaudeTarget -and
                $JsonPath -ceq '$.mcpServers' -and
                $key -ceq 'astrolabe') {
                continue
            }
            $encodedKey = [Text.Json.JsonSerializer]::Serialize(
                [string]$key,
                [type][string]
            )
            $property = $properties | Where-Object { $_.Name -ceq $key } |
                Select-Object -First 1
            $encodedValue = ConvertTo-CanonicalJsonElement `
                $property.Value "$JsonPath.$key" `
                -ExcludeClaudeTarget:$ExcludeClaudeTarget
            if ($ExcludeClaudeTarget -and
                $JsonPath -ceq '$' -and
                $key -ceq 'mcpServers' -and
                $encodedValue -ceq '{}') {
                continue
            }
            $members.Add("$encodedKey`:$encodedValue")
        }
        return '{' + ($members -join ',') + '}'
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $items = [Collections.Generic.List[string]]::new()
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            $items.Add((ConvertTo-CanonicalJsonElement `
                        $item "$JsonPath[$index]" `
                        -ExcludeClaudeTarget:$ExcludeClaudeTarget))
            $index++
        }
        return '[' + ($items -join ',') + ']'
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::String) {
        return [Text.Json.JsonSerializer]::Serialize(
            [string]$Element.GetString(),
            [type][string]
        )
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Number) {
        return $Element.GetRawText()
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::True) {
        return 'true'
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::False) {
        return 'false'
    }
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Null) {
        return 'null'
    }
    Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_JSON_KIND_INVALID' `
        "Claude JSON contains unsupported value kind $($Element.ValueKind) at $JsonPath" `
        'repair the complete JSON document; no client config was changed'
}

function Get-StrictJsonHashtable {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-StrictJsonText $Text $Description -RequireObject
    return $Text | ConvertFrom-Json -AsHashtable -Depth 128
}

function Get-ClaudeConfigInspection {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-StrictJsonText $Text $Description -RequireObject
    $document = [Text.Json.JsonDocument]::Parse(
        $Text,
        [Text.Json.JsonDocumentOptions]@{
            AllowTrailingCommas = $false
            CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
            MaxDepth = 128
        }
    )
    try {
        $root = $document.RootElement
        $unrelatedCanonical = ConvertTo-CanonicalJsonElement `
            $root '$' -ExcludeClaudeTarget
        $serversFound = $false
        [Text.Json.JsonElement]$servers = $root
        foreach ($property in $root.EnumerateObject()) {
            if ($property.Name -ceq 'mcpServers') {
                $serversFound = $true
                $servers = $property.Value
                break
            }
        }
        if ($serversFound -and
            $servers.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_SERVERS_INVALID' `
                'Claude root mcpServers value is not a JSON object' `
                'repair the complete mcpServers object before activation'
        }

        $targetFound = $false
        [Text.Json.JsonElement]$target = $root
        if ($serversFound) {
            foreach ($property in $servers.EnumerateObject()) {
                if ($property.Name -ceq 'astrolabe') {
                    $targetFound = $true
                    $target = $property.Value
                }
                elseif ([string]::Equals(
                        $property.Name,
                        'astrolabe',
                        [StringComparison]::OrdinalIgnoreCase
                    )) {
                    Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_TARGET_AMBIGUOUS' `
                        "Claude mcpServers contains case-ambiguous target '$($property.Name)'" `
                        'rename or remove the ambiguous target explicitly before activation'
                }
            }
        }
        if ($targetFound -and
            $target.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
            Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_TARGET_INVALID' `
                'Claude mcpServers.astrolabe exists but is not a JSON object' `
                'repair or remove the invalid target explicitly before activation'
        }

        $type = $null
        $command = $null
        $argsCount = -1
        $envCount = -1
        $targetPropertyCount = 0
        if ($targetFound) {
            foreach ($property in $target.EnumerateObject()) {
                $targetPropertyCount++
                if ($property.Name -ceq 'type' -and
                    $property.Value.ValueKind -eq [Text.Json.JsonValueKind]::String) {
                    $type = $property.Value.GetString()
                }
                elseif ($property.Name -ceq 'command' -and
                    $property.Value.ValueKind -eq [Text.Json.JsonValueKind]::String) {
                    $command = $property.Value.GetString()
                }
                elseif ($property.Name -ceq 'args' -and
                    $property.Value.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
                    $argsCount = $property.Value.GetArrayLength()
                }
                elseif ($property.Name -ceq 'env' -and
                    $property.Value.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
                    $envCount = @($property.Value.EnumerateObject()).Count
                }
            }
        }
        return [pscustomobject]@{
            unrelated_canonical = $unrelatedCanonical
            unrelated_sha256 = Get-StringSha256 $unrelatedCanonical
            target_present = $targetFound
            target_valid = ($targetFound -and
                $targetPropertyCount -eq 4 -and
                $type -ceq 'stdio' -and
                $null -ne $command -and
                $argsCount -eq 0 -and
                $envCount -eq 0)
            command = $command
            args_count = $argsCount
            env_count = $envCount
        }
    }
    finally { $document.Dispose() }
}

function New-ClaudeCandidate {
    param(
        [Parameter(Mandatory)][string]$BeforeText,
        [Parameter(Mandatory)][string]$ArtifactPath
    )

    $before = Get-ClaudeConfigInspection `
        $BeforeText 'Claude user configuration'
    $root = [Text.Json.Nodes.JsonNode]::Parse($BeforeText)
    if ($root -isnot [Text.Json.Nodes.JsonObject]) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_JSON_ROOT_INVALID' `
            'Claude user configuration root is not a mutable JSON object' `
            'restore one JSON object as the complete Claude user configuration'
    }
    if (-not $root.ContainsKey('mcpServers')) {
        $root['mcpServers'] = [Text.Json.Nodes.JsonObject]::new()
    }
    $servers = $root['mcpServers']
    if ($servers -isnot [Text.Json.Nodes.JsonObject]) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_SERVERS_INVALID' `
            'Claude root mcpServers value is not a mutable JSON object' `
            'repair the complete mcpServers object before activation'
    }
    $target = [Text.Json.Nodes.JsonObject]::new()
    $target['type'] = [Text.Json.Nodes.JsonValue]::Create([string]'stdio')
    $target['command'] = [Text.Json.Nodes.JsonValue]::Create($ArtifactPath)
    $target['args'] = [Text.Json.Nodes.JsonArray]::new()
    $target['env'] = [Text.Json.Nodes.JsonObject]::new()
    $servers['astrolabe'] = $target
    $jsonOptions = [Text.Json.JsonSerializerOptions]::new()
    $jsonOptions.WriteIndented = $true
    $candidate = $root.ToJsonString($jsonOptions)
    $candidateInspection = Get-ClaudeConfigInspection `
        $candidate 'Claude activation candidate'
    if ($candidateInspection.unrelated_sha256 -cne $before.unrelated_sha256) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_UNRELATED_DRIFT' `
            'Claude activation candidate changes JSON state outside mcpServers.astrolabe' `
            'preserve the transaction and inspect the exact before/candidate documents'
    }
    if (-not $candidateInspection.target_valid -or
        $candidateInspection.command -cne $ArtifactPath) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_CANDIDATE_INVALID' `
            'Claude candidate does not contain the exact stdio command/args/env contract' `
            'preserve the transaction and inspect candidate construction'
    }
    return [pscustomobject]@{
        text = $candidate
        unrelated_sha256 = $candidateInspection.unrelated_sha256
    }
}

function Get-CodexTargetSpan {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $targetPattern = '(?m)^[\t ]*\[mcp_servers\.astrolabe\][\t ]*(?:#[^\r\n]*)?(?:\r\n|\n|$)'
    $targetMatches = [regex]::Matches(
        $Text,
        $targetPattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($targetMatches.Count -gt 1) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_TARGET_DUPLICATE' `
            'Codex configuration contains more than one canonical astrolabe table' `
            'repair the duplicate TOML definition explicitly before activation'
    }
    if ($targetMatches.Count -eq 0) {
        return [pscustomobject]@{ found = $false; start = 0; length = 0 }
    }
    $target = $targetMatches[0]
    $afterHeader = $target.Index + $target.Length
    $nextPattern = '(?m)^[\t ]*\[\[?[^\r\n]+\]\]?[\t ]*(?:#[^\r\n]*)?(?:\r\n|\n|$)'
    $next = [regex]::Match(
        $Text.Substring($afterHeader),
        $nextPattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $end = if ($next.Success) { $afterHeader + $next.Index } else { $Text.Length }
    return [pscustomobject]@{
        found = $true
        start = $target.Index
        length = $end - $target.Index
    }
}

function Invoke-CodexMcp {
    param(
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][string]$CandidateHome,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $prior = [Environment]::GetEnvironmentVariable('CODEX_HOME', 'Process')
    $hadPrior = $null -ne $prior
    Push-Location $CandidateHome
    try {
        [Environment]::SetEnvironmentVariable('CODEX_HOME', $CandidateHome, 'Process')
        $output = @(& $CliPath @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
        [Environment]::SetEnvironmentVariable(
            'CODEX_HOME',
            $(if ($hadPrior) { $prior } else { $null }),
            'Process'
        )
    }
    return [pscustomobject]@{
        exit_code = [int]$exitCode
        output = @($output)
        text = @($output) -join "`n"
    }
}

function Assert-CodexConfigParses {
    param(
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][string]$CandidateHome,
        [Parameter(Mandatory)][string]$Description
    )

    $list = Invoke-CodexMcp $CliPath $CandidateHome @('mcp', 'list', '--json')
    if ($list.exit_code -ne 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_TOML_MALFORMED' `
            "$Description was rejected by Codex (exit=$($list.exit_code); output=$($list.text))" `
            'repair the complete Codex TOML document; no client config was changed'
    }
    Assert-StrictJsonText $list.text "$Description Codex list readback"
}

function Get-CodexTargetReadback {
    param(
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][string]$CandidateHome
    )

    $get = Invoke-CodexMcp $CliPath $CandidateHome @('mcp', 'get', 'astrolabe', '--json')
    if ($get.exit_code -ne 0) {
        return [pscustomobject]@{
            found = $false
            exit_code = $get.exit_code
            output = $get.text
            value = $null
        }
    }
    return [pscustomobject]@{
        found = $true
        exit_code = 0
        output = $get.text
        value = Get-StrictJsonHashtable $get.text 'Codex astrolabe target readback'
    }
}

function New-CodexCandidate {
    param(
        [Parameter(Mandatory)][string]$BeforeText,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][string]$BeforeHome,
        [Parameter(Mandatory)][string]$CandidateHome
    )

    Assert-CodexConfigParses $CliPath $BeforeHome 'Codex user configuration'
    $beforeReadback = Get-CodexTargetReadback $CliPath $BeforeHome
    $span = Get-CodexTargetSpan $BeforeText
    if ($beforeReadback.found -ne $span.found) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_TARGET_AMBIGUOUS' `
            "Codex semantic target presence ($($beforeReadback.found)) disagrees with one canonical [mcp_servers.astrolabe] table ($($span.found))" `
            'canonicalize the target as exactly one unquoted table before activation'
    }

    $newline = if ($BeforeText.Contains("`r`n")) { "`r`n" } else { "`n" }
    $encodedCommand = [Text.Json.JsonSerializer]::Serialize(
        $ArtifactPath,
        [type][string]
    )
    $block = @(
        '[mcp_servers.astrolabe]'
        "command = $encodedCommand"
        'args = []'
        'enabled = true'
        'required = true'
        'default_tools_approval_mode = "approve"'
        ''
    ) -join $newline

    if ($span.found) {
        $prefix = $BeforeText.Substring(0, $span.start)
        $suffix = $BeforeText.Substring($span.start + $span.length)
        $candidate = $prefix + $block + $suffix
    }
    else {
        $separator = if ($BeforeText.Length -eq 0 -or
            $BeforeText.EndsWith("`n")) { '' } else { $newline }
        $prefix = $BeforeText
        $suffix = ''
        $candidate = $BeforeText + $separator + $block
    }

    Write-NewDurableText (Join-Path $CandidateHome 'config.toml') $candidate
    Assert-CodexConfigParses $CliPath $CandidateHome 'Codex activation candidate'
    $after = Get-CodexTargetReadback $CliPath $CandidateHome
    if (-not $after.found -or
        [string]$after.value['name'] -cne 'astrolabe' -or
        [bool]$after.value['enabled'] -ne $true -or
        [string]$after.value['transport']['type'] -cne 'stdio' -or
        [string]$after.value['transport']['command'] -cne $ArtifactPath -or
        @($after.value['transport']['args']).Count -ne 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_CANDIDATE_INVALID' `
            "Codex rejected or reinterpreted the exact activation candidate: $($after.output)" `
            'preserve the candidate and inspect the installed Codex configuration contract'
    }
    $candidateSpan = Get-CodexTargetSpan $candidate
    if (-not $candidateSpan.found) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_CANDIDATE_INVALID' `
            'Codex candidate lacks its canonical astrolabe table after construction' `
            'preserve the transaction and inspect candidate construction'
    }
    $targetText = $candidate.Substring($candidateSpan.start, $candidateSpan.length)
    foreach ($requiredLine in @(
            'args = []',
            'enabled = true',
            'required = true',
            'default_tools_approval_mode = "approve"'
        )) {
        if (-not $targetText.Contains($requiredLine, [StringComparison]::Ordinal)) {
            Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_CANDIDATE_INVALID' `
                "Codex candidate target lacks exact line '$requiredLine'" `
                'preserve the transaction and inspect candidate construction'
        }
    }
    return [pscustomobject]@{
        text = $candidate
        unrelated_prefix_sha256 = Get-StringSha256 $prefix
        unrelated_suffix_sha256 = Get-StringSha256 $suffix
        target_was_present = [bool]$span.found
    }
}

function Test-SnapshotEquals {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual
    )

    return (
        [uint64]$Actual.bytes -eq [uint64]$Expected.bytes -and
        [string]$Actual.sha256 -ceq [string]$Expected.sha256 -and
        [string]$Actual.file_id -ceq [string]$Expected.file_id
    )
}

function Assert-SnapshotEquals {
    param(
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Description
    )

    if (-not (Test-SnapshotEquals $Expected $Actual)) {
        Fail-AstroGlobalActivation $Code `
            "$Description drifted (expected_bytes=$($Expected.bytes); actual_bytes=$($Actual.bytes); expected_sha256=$($Expected.sha256); actual_sha256=$($Actual.sha256); expected_file_id=$($Expected.file_id); actual_file_id=$($Actual.file_id))" `
            'preserve the transaction, reconcile the exact concurrent config change, and retry from fresh snapshots'
    }
}

function Restore-ConfigBeforeImage {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)][string]$ReplacementBackupPath,
        [Parameter(Mandatory)][string]$TransactionPath,
        [Parameter(Mandatory)][string]$Role
    )

    $backup = Read-ConfigSnapshot `
        $ReplacementBackupPath "$Role replacement backup"
    Assert-SnapshotEquals $Before $backup `
        'ASTRO_GLOBAL_ACTIVATION_BACKUP_MISMATCH' "$Role replacement backup"
    $failedAfter = $null
    $targetState = Get-AstroPathEntryState $Before.path
    if ($targetState.State -ceq 'present') {
        $failedAfter = Join-Path $TransactionPath (
            "$Role.failed-after-" + [Guid]::NewGuid().ToString('N')
        )
        [AstroLauncherLockNative]::ReplaceFilePreserveMetadata(
            $Before.path,
            $ReplacementBackupPath,
            $failedAfter
        )
    }
    elseif ($targetState.State -ceq 'absent') {
        [AstroLauncherLockNative]::MoveFileWriteThroughNoReplace(
            $ReplacementBackupPath,
            $Before.path
        )
    }
    else {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_ROLLBACK_TARGET_UNEVALUABLE' `
            "$Role rollback target is unevaluable (state=$($targetState.State); error=$($targetState.Error))" `
            'preserve every transaction byte and repair the exact target namespace before recovery'
    }
    Flush-ExistingDurableFile $Before.path "$Role rollback"
    $readback = Read-ConfigSnapshot $Before.path "$Role rollback readback"
    Assert-SnapshotEquals $Before $readback `
        'ASTRO_GLOBAL_ACTIVATION_ROLLBACK_MISMATCH' "$Role rollback"
    return [pscustomobject]@{
        snapshot = $readback
        failed_after_path = $failedAfter
        failed_after_sha256 = $(if ($null -ne $failedAfter) {
                Get-FileSha256 $failedAfter
            } else { $null })
    }
}

function Restore-ConfigIfChanged {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)][string]$ReplacementBackupPath,
        [Parameter(Mandatory)][string]$TransactionPath,
        [Parameter(Mandatory)][string]$Role
    )

    try {
        $current = Read-ConfigSnapshot $Before.path "$Role post-fault readback"
        if (Test-SnapshotEquals $Before $current) {
            return [ordered]@{
                role = $Role
                verdict = 'unchanged'
                sha256 = $current.sha256
                file_id = $current.file_id
                failed_after_path = $null
                failed_after_sha256 = $null
            }
        }
    }
    catch {
        # An absent/unevaluable target is handled by the exact backup restore
        # below; its own diagnostic remains authoritative if recovery fails.
    }

    $restored = Restore-ConfigBeforeImage `
        $Before $ReplacementBackupPath $TransactionPath $Role
    return [ordered]@{
        role = $Role
        verdict = 'restored'
        sha256 = $restored.snapshot.sha256
        file_id = $restored.snapshot.file_id
        failed_after_path = $restored.failed_after_path
        failed_after_sha256 = $restored.failed_after_sha256
    }
}

function Assert-NoIncompleteActivationTransaction {
    param([Parameter(Mandatory)][string]$Root)

    foreach ($child in @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop)) {
        if (-not $child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-AstroGlobalActivation `
                'ASTRO_GLOBAL_ACTIVATION_TRANSACTION_ROOT_ENTRY_INVALID' `
                "activation transaction root contains a non-ordinary child: $($child.FullName)" `
                'preserve the entry and reconcile the dedicated transaction root explicitly'
        }
        $intentState = Get-AstroPathEntryState `
            (Join-Path $child.FullName 'intent.json')
        $completionState = Get-AstroPathEntryState `
            (Join-Path $child.FullName 'completion.json')
        $faultState = Get-AstroPathEntryState `
            (Join-Path $child.FullName 'fault.json')
        $completionReadbackFaultState = Get-AstroPathEntryState `
            (Join-Path $child.FullName 'completion-readback-fault.json')
        $intentPresent = $intentState.State -ceq 'present' -and
            ($intentState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -and
            ($intentState.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        $completionPresent = $completionState.State -ceq 'present' -and
            ($completionState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -and
            ($completionState.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        $faultPresent = $faultState.State -ceq 'present' -and
            ($faultState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -and
            ($faultState.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
        $completionReadbackFaultPresent =
            $completionReadbackFaultState.State -ceq 'present' -and
            ($completionReadbackFaultState.Attributes -band
                [IO.FileAttributes]::Directory) -eq 0 -and
            ($completionReadbackFaultState.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -eq 0
        $terminalCount = [int]$completionPresent + [int]$faultPresent
        if (-not $intentPresent -or $terminalCount -ne 1 -or
            $completionReadbackFaultPresent) {
            Fail-AstroGlobalActivation `
                'ASTRO_GLOBAL_ACTIVATION_INCOMPLETE_TRANSACTION' `
                "prior activation transaction is nonterminal, ambiguous, or has a terminal readback fault: $($child.FullName) (intent=$($intentState.State); completion=$($completionState.State); fault=$($faultState.State); completion_readback_fault=$($completionReadbackFaultState.State))" `
                'preserve every transaction byte and reconcile the exact prior config state before another activation'
        }
    }
}

$transactionPath = $null
$activationMutex = $null
$mutexHeld = $false
$codexBefore = $null
$claudeBefore = $null
$codexCommitted = $false
$claudeCommitted = $false
$codexCommitAttempted = $false
$claudeCommitAttempted = $false
$codexReplacementBackupPath = $null
$claudeReplacementBackupPath = $null
$completionPath = $null
$completionSha256 = $null
$completionPublished = $false
$rollback = [Collections.Generic.List[object]]::new()

try {
    if ($Issue -le 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_ISSUE_INVALID' `
            "Issue must be positive; received $Issue" `
            'pass the active GitHub issue number'
    }
    if ($ExpectedTreeSha -cnotmatch '^[0-9a-fA-F]{40}$') {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_TREE_INVALID' `
            "ExpectedTreeSha is not a full Git object id: '$ExpectedTreeSha'" `
            'pass the exact clean commit held by the native launcher'
    }
    if ($ExpectedPublicationReceiptSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_RECEIPT_HASH_INVALID' `
            'ExpectedPublicationReceiptSha256 is not one SHA-256 digest' `
            'pass the exact hash read independently from publication.json'
    }
    $ExpectedTreeSha = $ExpectedTreeSha.ToLowerInvariant()
    $ExpectedPublicationReceiptSha256 =
        $ExpectedPublicationReceiptSha256.ToLowerInvariant()

    $workspace = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
    $launcher = Read-AstroLauncherLock `
        -LockPath (Join-Path $workspace '.tmp\astrolabe-launcher.lock')
    if ($launcher.State -cne 'held' -or
        [int]$launcher.Issue -ne $Issue -or
        [string]$launcher.HeadSha -cne $ExpectedTreeSha) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_LAUNCHER_INVALID' `
            "launcher does not hold issue #$Issue at tree $ExpectedTreeSha (state=$($launcher.State); issue=$($launcher.Issue); head=$($launcher.HeadSha); pid=$($launcher.OwnerPid); ticks=$($launcher.OwnerProcessStartUtcTicks))" `
            'activate synchronously inside the exact issue-owned native launcher generation'
    }
    $launcherProbe = Get-AstroExactProcessIdentityProbe `
        -Pid ([int]$launcher.OwnerPid) `
        -ProcessStartUtcTicks ([long]$launcher.OwnerProcessStartUtcTicks)
    if ($launcherProbe.State -cne 'exact-live' -or
        -not (Test-DescendantOf $PID ([int]$launcher.OwnerPid))) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_OWNER_MISMATCH' `
            "activation caller PID $PID is not an exact owned descendant of launcher ($($launcher.OwnerPid),$($launcher.OwnerProcessStartUtcTicks)); owner_state=$($launcherProbe.State)" `
            'invoke activation synchronously from the exact launcher-owned command plan'
    }

    $receiptPath = [IO.Path]::GetFullPath($PublicationReceiptPath)
    Assert-OrdinaryFile $receiptPath 'immutable publication receipt'
    $receiptHash = Get-FileSha256 $receiptPath
    if ($receiptHash -cne $ExpectedPublicationReceiptSha256) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_RECEIPT_DRIFT' `
            "publication receipt hash differs (expected=$ExpectedPublicationReceiptSha256; actual=$receiptHash; path=$receiptPath)" `
            'preserve the generation and pass its exact independently read receipt hash'
    }
    $receiptText = Read-AstroUtf8FileLongPath $receiptPath
    $receipt = Get-StrictJsonHashtable $receiptText 'immutable publication receipt'
    if ([string]$receipt['schema'] -cne 'astrolabe.global-mcp-publication.v3' -or
        [string]$receipt['tree_sha'] -cne $ExpectedTreeSha -or
        [string]$receipt['client_activation']['status'] -cne 'not_attempted' -or
        [bool]$receipt['client_activation']['required'] -ne $true -or
        [string]$receipt['client_activation']['server_name'] -cne 'astrolabe') {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_RECEIPT_INVALID' `
            'publication receipt schema/tree/activation contract does not authorize activation' `
            'publish one v3 immutable generation from this exact tree before activation'
    }
    $artifactPath = [IO.Path]::GetFullPath(
        [string]$receipt['artifact']['installed_path']
    )
    $generationPath = [IO.Path]::GetFullPath(
        [string]$receipt['generation']['root']
    )
    if ([IO.Path]::GetFullPath((Split-Path -Parent $receiptPath)) -cne
            $generationPath -or
        [IO.Path]::GetFullPath((Split-Path -Parent $artifactPath)) -cne
            $generationPath -or
        [string]$receipt['client_activation']['command'] -cne $artifactPath) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_GENERATION_MISMATCH' `
            'receipt, generation root, artifact path, and activation command are not one exact directory' `
            'preserve the generation and inspect its immutable publication receipt'
    }
    Assert-OrdinaryFile $artifactPath 'immutable published Astrolabe artifact'
    $artifactHash = Get-FileSha256 $artifactPath
    $artifactBytes = [uint64](Get-AstroFileLengthLongPath $artifactPath)
    if ($artifactHash -cne [string]$receipt['artifact']['sha256'] -or
        $artifactBytes -ne [uint64]$receipt['artifact']['bytes'] -or
        -not (Get-AstroFileInfoLongPath $artifactPath).IsReadOnly -or
        -not (Get-AstroFileInfoLongPath $receiptPath).IsReadOnly) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_ARTIFACT_DRIFT' `
            'immutable artifact or receipt physical readback differs from publication authority' `
            'preserve the generation and investigate its exact bytes before activation'
    }

    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_USERPROFILE_MISSING' `
            'USERPROFILE is absent; Claude user configuration is undefined' `
            'run from the intended interactive Windows user profile'
    }
    if ([string]::IsNullOrWhiteSpace($CodexConfigPath)) {
        $codexRoot = [Environment]::GetEnvironmentVariable('CODEX_HOME', 'Process')
        if ([string]::IsNullOrWhiteSpace($codexRoot)) {
            $codexRoot = Join-Path $env:USERPROFILE '.codex'
        }
        $CodexConfigPath = Join-Path $codexRoot 'config.toml'
    }
    if ([string]::IsNullOrWhiteSpace($ClaudeConfigPath)) {
        $ClaudeConfigPath = Join-Path $env:USERPROFILE '.claude.json'
    }
    $CodexConfigPath = [IO.Path]::GetFullPath($CodexConfigPath)
    $ClaudeConfigPath = [IO.Path]::GetFullPath($ClaudeConfigPath)
    Assert-OrdinaryFile $CodexConfigPath 'Codex user configuration'
    Assert-OrdinaryFile $ClaudeConfigPath 'Claude user configuration'

    if ([string]::IsNullOrWhiteSpace($TransactionRoot)) {
        $installRoot = Split-Path -Parent (Split-Path -Parent $generationPath)
        $TransactionRoot = Join-Path $installRoot 'activation-transactions'
    }
    $TransactionRoot = [IO.Path]::GetFullPath($TransactionRoot)
    $configVolume = [IO.Path]::GetPathRoot($CodexConfigPath)
    $claudeVolume = [IO.Path]::GetPathRoot($ClaudeConfigPath)
    $transactionVolume = [IO.Path]::GetPathRoot($TransactionRoot)
    if (-not [string]::Equals($configVolume, $claudeVolume,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($configVolume, $transactionVolume,
            [StringComparison]::OrdinalIgnoreCase)) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_VOLUME_MISMATCH' `
            "Codex, Claude, and transaction roots are not on one volume (codex=$configVolume; claude=$claudeVolume; transaction=$transactionVolume)" `
            'choose a transaction root on the shared config volume so both replacements and rollbacks are atomic'
    }
    $rootState = Get-AstroPathEntryState $TransactionRoot
    if ($rootState.State -ceq 'absent') {
        New-AstroDirectoryLongPath $TransactionRoot | Out-Null
    }
    elseif ($rootState.State -cne 'present' -or
        ($rootState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($rootState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_TRANSACTION_ROOT_INVALID' `
            "transaction root is not one ordinary directory: $TransactionRoot (state=$($rootState.State))" `
            'repair or select one ordinary same-volume transaction root'
    }

    if ([string]::IsNullOrWhiteSpace($CodexCliPath)) {
        try {
            $CodexCliPath = [IO.Path]::GetFullPath(
                [string](Get-Command codex -CommandType Application -ErrorAction Stop |
                    Select-Object -First 1).Path
            )
        }
        catch {
            Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_CLI_MISSING' `
                "installed Codex CLI is unavailable: $($_.Exception.Message)" `
                'install or repair the intended global Codex CLI before activation'
        }
    }
    $CodexCliPath = [IO.Path]::GetFullPath($CodexCliPath)
    Assert-OrdinaryFile $CodexCliPath 'installed Codex CLI entrypoint'
    $codexCliHash = Get-FileSha256 $CodexCliPath

    $mutexMaterial = @(
        $CodexConfigPath.ToLowerInvariant(),
        $ClaudeConfigPath.ToLowerInvariant()
    ) -join "`n"
    $mutexName = 'Global\Astrolabe.GlobalMcpActivation.' +
        (Get-StringSha256 $mutexMaterial)
    $activationMutex = [Threading.Mutex]::new($false, $mutexName)
    try { $mutexHeld = $activationMutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $mutexHeld = $true }
    if (-not $mutexHeld) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_HELD' `
            "another exact config activation owns $mutexName" `
            'wait for that transaction to publish completion or fault, then re-read both configs'
    }
    Assert-NoIncompleteActivationTransaction $TransactionRoot

    $codexBefore = Read-ConfigSnapshot $CodexConfigPath 'Codex user configuration'
    $claudeBefore = Read-ConfigSnapshot $ClaudeConfigPath 'Claude user configuration'
    $transactionId = (
        [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') +
        "-issue-$Issue-" + [Guid]::NewGuid().ToString('N')
    )
    $transactionPath = Join-Path $TransactionRoot $transactionId
    New-AstroDirectoryNoClobberLongPath $transactionPath | Out-Null

    $codexBeforePath = Join-Path $transactionPath 'codex.before.toml'
    $claudeBeforePath = Join-Path $transactionPath 'claude.before.json'
    $codexReplacementBackupPath = Join-Path `
        $transactionPath 'codex.replaced-original.toml'
    $claudeReplacementBackupPath = Join-Path `
        $transactionPath 'claude.replaced-original.json'
    Write-NewDurableBytes $codexBeforePath $codexBefore.bytes_value
    Write-NewDurableBytes $claudeBeforePath $claudeBefore.bytes_value
    $intent = [ordered]@{
        schema = 'astrolabe.global-mcp-activation-intent.v1'
        transaction_id = $transactionId
        issue = $Issue
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        tree_sha = $ExpectedTreeSha
        launcher = [ordered]@{
            pid = [int]$launcher.OwnerPid
            process_start_utc_ticks = [long]$launcher.OwnerProcessStartUtcTicks
            lock_sha256 = [string]$launcher.Sha256
        }
        publication = [ordered]@{
            receipt_path = $receiptPath
            receipt_sha256 = $receiptHash
            publication_issue = [int]$receipt['issue']
            generation_path = $generationPath
        }
        artifact = [ordered]@{
            path = $artifactPath
            bytes = $artifactBytes
            sha256 = $artifactHash
        }
        clients = [ordered]@{
            codex = [ordered]@{
                config_path = $CodexConfigPath
                before_path = $codexBeforePath
                before_bytes = $codexBefore.bytes
                before_sha256 = $codexBefore.sha256
                before_file_id = $codexBefore.file_id
                replacement_backup_path = $codexReplacementBackupPath
                cli_path = $CodexCliPath
                cli_sha256 = $codexCliHash
            }
            claude_code = [ordered]@{
                config_path = $ClaudeConfigPath
                before_path = $claudeBeforePath
                before_bytes = $claudeBefore.bytes
                before_sha256 = $claudeBefore.sha256
                before_file_id = $claudeBefore.file_id
                replacement_backup_path = $claudeReplacementBackupPath
            }
        }
        commit_protocol =
            'candidate-both-first; exact precommit drift read; ReplaceFileW metadata-preserving commit with original-file backup; explicit file flush/readback; reverse exact backup rollback on any partial failure'
    }
    Write-NewDurableJson (Join-Path $transactionPath 'intent.json') $intent

    $beforeHome = Join-Path $transactionPath 'codex-before-home'
    $candidateHome = Join-Path $transactionPath 'codex-candidate-home'
    New-AstroDirectoryNoClobberLongPath $beforeHome | Out-Null
    New-AstroDirectoryNoClobberLongPath $candidateHome | Out-Null
    Write-NewDurableBytes (Join-Path $beforeHome 'config.toml') $codexBefore.bytes_value

    $codexCandidate = New-CodexCandidate `
        $codexBefore.text $artifactPath $CodexCliPath $beforeHome $candidateHome
    $codexCandidatePath = Join-Path $transactionPath 'codex.candidate.toml'
    $codexCommitStagePath = Join-Path $transactionPath 'codex.commit-stage.toml'
    $candidateHomePath = Join-Path $candidateHome 'config.toml'
    $codexCandidateBytes = [IO.File]::ReadAllBytes($candidateHomePath)
    Write-NewDurableBytes $codexCandidatePath $codexCandidateBytes
    Write-NewDurableBytes $codexCommitStagePath $codexCandidateBytes
    $codexCommitStage = Read-ConfigSnapshot `
        $codexCommitStagePath 'Codex activation commit stage'

    $claudeCandidate = New-ClaudeCandidate $claudeBefore.text $artifactPath
    $claudeCandidatePath = Join-Path $transactionPath 'claude.candidate.json'
    $claudeCommitStagePath = Join-Path $transactionPath 'claude.commit-stage.json'
    Write-NewDurableText $claudeCandidatePath $claudeCandidate.text
    Write-NewDurableText $claudeCommitStagePath $claudeCandidate.text
    $claudeCommitStage = Read-ConfigSnapshot `
        $claudeCommitStagePath 'Claude activation commit stage'
    $candidateRecord = [ordered]@{
        schema = 'astrolabe.global-mcp-activation-candidates.v1'
        transaction_id = $transactionId
        intent_sha256 = Get-FileSha256 (Join-Path $transactionPath 'intent.json')
        created_at_utc = [DateTime]::UtcNow.ToString('o')
        codex = [ordered]@{
            path = $codexCandidatePath
            bytes = [uint64](Get-AstroFileLengthLongPath $codexCandidatePath)
            sha256 = Get-FileSha256 $codexCandidatePath
            commit_stage_path = $codexCommitStagePath
            commit_stage_file_id = $codexCommitStage.file_id
            target_was_present = $codexCandidate.target_was_present
            unrelated_prefix_sha256 = $codexCandidate.unrelated_prefix_sha256
            unrelated_suffix_sha256 = $codexCandidate.unrelated_suffix_sha256
            cli_semantic_readback = 'stdio/exact-command/empty-args/enabled'
        }
        claude_code = [ordered]@{
            path = $claudeCandidatePath
            bytes = [uint64](Get-AstroFileLengthLongPath $claudeCandidatePath)
            sha256 = Get-FileSha256 $claudeCandidatePath
            commit_stage_path = $claudeCommitStagePath
            commit_stage_file_id = $claudeCommitStage.file_id
            unrelated_semantic_sha256 = $claudeCandidate.unrelated_sha256
            semantic_readback = 'user mcpServers.astrolabe stdio/exact-command/empty-args/empty-env'
        }
    }
    Write-NewDurableJson (Join-Path $transactionPath 'candidates.json') $candidateRecord

    $codexPrecommit = Read-ConfigSnapshot $CodexConfigPath 'Codex precommit readback'
    $claudePrecommit = Read-ConfigSnapshot $ClaudeConfigPath 'Claude precommit readback'
    Assert-SnapshotEquals $codexBefore $codexPrecommit `
        'ASTRO_GLOBAL_ACTIVATION_CODEX_CONCURRENT_DRIFT' 'Codex config before commit'
    Assert-SnapshotEquals $claudeBefore $claudePrecommit `
        'ASTRO_GLOBAL_ACTIVATION_CLAUDE_CONCURRENT_DRIFT' 'Claude config before commit'
    Assert-SnapshotEquals $codexCommitStage `
        (Read-ConfigSnapshot $codexCommitStagePath 'Codex commit-stage readback') `
        'ASTRO_GLOBAL_ACTIVATION_CODEX_STAGE_DRIFT' 'Codex commit stage'
    Assert-SnapshotEquals $claudeCommitStage `
        (Read-ConfigSnapshot $claudeCommitStagePath 'Claude commit-stage readback') `
        'ASTRO_GLOBAL_ACTIVATION_CLAUDE_STAGE_DRIFT' 'Claude commit stage'

    $codexCommitAttempted = $true
    [AstroLauncherLockNative]::ReplaceFilePreserveMetadata(
        $CodexConfigPath,
        $codexCommitStagePath,
        $codexReplacementBackupPath
    )
    $codexCommitted = $true
    Flush-ExistingDurableFile $CodexConfigPath 'Codex activation config'
    $codexBackup = Read-ConfigSnapshot `
        $codexReplacementBackupPath 'Codex replacement backup'
    Assert-SnapshotEquals $codexBefore $codexBackup `
        'ASTRO_GLOBAL_ACTIVATION_CODEX_BACKUP_MISMATCH' `
        'Codex replacement backup'
    $codexAfter = Read-ConfigSnapshot $CodexConfigPath 'Codex activation readback'
    Assert-SnapshotEquals $codexCommitStage $codexAfter `
        'ASTRO_GLOBAL_ACTIVATION_CODEX_READBACK_MISMATCH' `
        'Codex config after replacement'
    $codexLiveHome = Join-Path $transactionPath 'codex-live-readback-home'
    New-AstroDirectoryNoClobberLongPath $codexLiveHome | Out-Null
    Write-NewDurableBytes (Join-Path $codexLiveHome 'config.toml') $codexAfter.bytes_value
    Assert-CodexConfigParses $CodexCliPath $codexLiveHome 'persisted Codex activation readback'
    $codexLive = Get-CodexTargetReadback $CodexCliPath $codexLiveHome
    if (-not $codexLive.found -or
        [string]$codexLive.value['transport']['command'] -cne $artifactPath -or
        @($codexLive.value['transport']['args']).Count -ne 0 -or
        [bool]$codexLive.value['enabled'] -ne $true) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CODEX_SEMANTIC_MISMATCH' `
            "persisted Codex config does not resolve the exact artifact: $($codexLive.output)" `
            'preserve the transaction; exact rollback will restore the before image'
    }

    $claudeCommitAttempted = $true
    [AstroLauncherLockNative]::ReplaceFilePreserveMetadata(
        $ClaudeConfigPath,
        $claudeCommitStagePath,
        $claudeReplacementBackupPath
    )
    $claudeCommitted = $true
    Flush-ExistingDurableFile $ClaudeConfigPath 'Claude activation config'
    $claudeBackup = Read-ConfigSnapshot `
        $claudeReplacementBackupPath 'Claude replacement backup'
    Assert-SnapshotEquals $claudeBefore $claudeBackup `
        'ASTRO_GLOBAL_ACTIVATION_CLAUDE_BACKUP_MISMATCH' `
        'Claude replacement backup'
    $claudeAfter = Read-ConfigSnapshot $ClaudeConfigPath 'Claude activation readback'
    Assert-SnapshotEquals $claudeCommitStage $claudeAfter `
        'ASTRO_GLOBAL_ACTIVATION_CLAUDE_READBACK_MISMATCH' `
        'Claude config after replacement'
    $claudeLive = Get-ClaudeConfigInspection $claudeAfter.text `
        'persisted Claude activation readback'
    if ($claudeLive.unrelated_sha256 -cne
            [string]$candidateRecord.claude_code.unrelated_semantic_sha256 -or
        -not $claudeLive.target_valid -or
        $claudeLive.command -cne $artifactPath) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_CLAUDE_SEMANTIC_MISMATCH' `
            'persisted Claude config does not preserve unrelated state plus the exact stdio target' `
            'preserve the transaction; exact rollback will restore both before images'
    }

    $completion = [ordered]@{
        schema = 'astrolabe.global-mcp-activation.v1'
        verdict = 'activated'
        transaction_id = $transactionId
        completed_at_utc = [DateTime]::UtcNow.ToString('o')
        issue = $Issue
        tree_sha = $ExpectedTreeSha
        intent_sha256 = Get-FileSha256 (Join-Path $transactionPath 'intent.json')
        candidates_sha256 = Get-FileSha256 (Join-Path $transactionPath 'candidates.json')
        publication_receipt_sha256 = $receiptHash
        artifact = [ordered]@{
            path = $artifactPath
            bytes = $artifactBytes
            sha256 = $artifactHash
        }
        codex = [ordered]@{
            config_path = $CodexConfigPath
            before_sha256 = $codexBefore.sha256
            replacement_backup_path = $codexReplacementBackupPath
            replacement_backup_sha256 = $codexBackup.sha256
            replacement_backup_file_id = $codexBackup.file_id
            after_bytes = $codexAfter.bytes
            after_sha256 = $codexAfter.sha256
            after_file_id = $codexAfter.file_id
            semantic_readback = $codexLive.value
            candidate_evidence_sha256 = Get-FileSha256 $codexCandidatePath
            commit_stage_absent =
                -not (Test-AstroPathLongPath -LiteralPath $codexCommitStagePath)
        }
        claude_code = [ordered]@{
            config_path = $ClaudeConfigPath
            before_sha256 = $claudeBefore.sha256
            replacement_backup_path = $claudeReplacementBackupPath
            replacement_backup_sha256 = $claudeBackup.sha256
            replacement_backup_file_id = $claudeBackup.file_id
            after_bytes = $claudeAfter.bytes
            after_sha256 = $claudeAfter.sha256
            after_file_id = $claudeAfter.file_id
            unrelated_semantic_sha256 = $claudeLive.unrelated_sha256
            command = $claudeLive.command
            args_count = $claudeLive.args_count
            env_count = $claudeLive.env_count
            candidate_evidence_sha256 = Get-FileSha256 $claudeCandidatePath
            commit_stage_absent =
                -not (Test-AstroPathLongPath -LiteralPath $claudeCommitStagePath)
        }
        source_of_truth = @($CodexConfigPath, $ClaudeConfigPath)
    }
    $completionPath = Join-Path $transactionPath 'completion.json'
    $completionStagePath = Join-Path $transactionPath 'completion.stage.json'
    Write-NewDurableJson $completionStagePath $completion
    $completionReadback = Get-StrictJsonHashtable `
        (Read-AstroUtf8FileLongPath $completionStagePath) `
        'activation completion stage readback'
    if ([string]$completionReadback['verdict'] -cne 'activated' -or
        [string]$completionReadback['codex']['after_sha256'] -cne
            $codexAfter.sha256 -or
        [string]$completionReadback['claude_code']['after_sha256'] -cne
            $claudeAfter.sha256) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_COMPLETION_MISMATCH' `
            'durable activation completion record differs from physical config readback' `
            'preserve the transaction and both configs; do not claim global activation'
    }
    $completionSha256 = Get-FileSha256 $completionStagePath
    [AstroLauncherLockNative]::MoveFileWriteThroughNoReplace(
        $completionStagePath,
        $completionPath
    )
    $completionPublished = $true
    $completionFinalReadback = Get-StrictJsonHashtable `
        (Read-AstroUtf8FileLongPath $completionPath) `
        'activation completion final readback'
    if ((Get-FileSha256 $completionPath) -cne $completionSha256 -or
        [string]$completionFinalReadback['verdict'] -cne 'activated' -or
        [string]$completionFinalReadback['codex']['after_sha256'] -cne
            $codexAfter.sha256 -or
        [string]$completionFinalReadback['claude_code']['after_sha256'] -cne
            $claudeAfter.sha256) {
        Fail-AstroGlobalActivation 'ASTRO_GLOBAL_ACTIVATION_COMPLETION_MISMATCH' `
            'published completion differs from its validated stage or physical config readback' `
            'preserve the terminal transaction and both activated configs for exact readback'
    }

    [ordered]@{
        code = 'ASTRO_GLOBAL_MCP_ACTIVATED'
        transaction_path = $transactionPath
        completion_path = $completionPath
        completion_sha256 = $completionSha256
        issue = $Issue
        tree_sha = $ExpectedTreeSha
        artifact_path = $artifactPath
        artifact_sha256 = $artifactHash
        codex = [ordered]@{
            config_path = $CodexConfigPath
            bytes = $codexAfter.bytes
            sha256 = $codexAfter.sha256
            command = [string]$codexLive.value['transport']['command']
        }
        claude_code = [ordered]@{
            config_path = $ClaudeConfigPath
            bytes = $claudeAfter.bytes
            sha256 = $claudeAfter.sha256
            command = $claudeLive.command
        }
    } | ConvertTo-Json -Depth 12 -Compress | Write-Output
}
catch {
    $original = $_.Exception
    if ($null -ne $transactionPath) {
        if (-not $completionPublished) {
            if ($claudeCommitAttempted -and $null -ne $claudeBefore) {
                try {
                    $outcome = Restore-ConfigIfChanged `
                        $claudeBefore $claudeReplacementBackupPath `
                        $transactionPath 'claude'
                    $outcome.role = 'claude_code'
                    $rollback.Add($outcome)
                    $claudeCommitted = $false
                }
                catch {
                    $rollback.Add([ordered]@{
                            role = 'claude_code'
                            verdict = 'failed'
                            error = $_.Exception.Message
                        })
                }
            }
            if ($codexCommitAttempted -and $null -ne $codexBefore) {
                try {
                    $outcome = Restore-ConfigIfChanged `
                        $codexBefore $codexReplacementBackupPath `
                        $transactionPath 'codex'
                    $rollback.Add($outcome)
                    $codexCommitted = $false
                }
                catch {
                    $rollback.Add([ordered]@{
                            role = 'codex'
                            verdict = 'failed'
                            error = $_.Exception.Message
                        })
                }
            }
        }

        $finalStates = [ordered]@{}
        foreach ($entry in @(
                [pscustomobject]@{ role = 'codex'; path = $CodexConfigPath },
                [pscustomobject]@{ role = 'claude_code'; path = $ClaudeConfigPath }
            )) {
            try {
                $snapshot = Read-ConfigSnapshot $entry.path "$($entry.role) fault readback"
                $finalStates[$entry.role] = [ordered]@{
                    path = $snapshot.path
                    bytes = $snapshot.bytes
                    sha256 = $snapshot.sha256
                    file_id = $snapshot.file_id
                }
            }
            catch {
                $finalStates[$entry.role] = [ordered]@{
                    path = $entry.path
                    state = 'unevaluable'
                    error = $_.Exception.Message
                }
            }
        }
        $fault = [ordered]@{
            schema = $(if ($completionPublished) {
                    'astrolabe.global-mcp-activation-completion-readback-fault.v1'
                } else { 'astrolabe.global-mcp-activation-fault.v1' })
            verdict = $(if ($completionPublished) {
                    'activated_terminal_readback_fault'
                } else { 'not_activated' })
            recorded_at_utc = [DateTime]::UtcNow.ToString('o')
            issue = $Issue
            completion = $(if ($completionPublished) {
                    [ordered]@{
                        path = $completionPath
                        sha256 = $completionSha256
                    }
                } else { $null })
            error = [ordered]@{
                code = $(if ($original.Data['AstroCode']) {
                        [string]$original.Data['AstroCode']
                    } else { 'ASTRO_GLOBAL_ACTIVATION_FAILED' })
                message = $original.Message
                remediation = $(if ($original.Data['AstroRemediation']) {
                        [string]$original.Data['AstroRemediation']
                    } else {
                        'preserve the transaction and inspect its exact config readback'
                    })
            }
            rollback = @($rollback)
            final_config_state = $finalStates
        }
        try {
            $faultName = if ($completionPublished) {
                'completion-readback-fault.json'
            } else { 'fault.json' }
            Write-NewDurableJson (Join-Path $transactionPath $faultName) $fault
        }
        catch {
            [Console]::Error.WriteLine(
                "ASTRO_GLOBAL_ACTIVATION_FAULT_RECORD_FAILED: $($_.Exception.Message)"
            )
        }
    }
    $errorPayload = [ordered]@{
        code = $(if ($original.Data['AstroCode']) {
                [string]$original.Data['AstroCode']
            } else { 'ASTRO_GLOBAL_ACTIVATION_FAILED' })
        message = $original.Message
        remediation = $(if ($original.Data['AstroRemediation']) {
                [string]$original.Data['AstroRemediation']
            } else {
                'preserve the transaction and inspect its exact config readback'
            })
        transaction_path = $transactionPath
        rollback = @($rollback)
    }
    [Console]::Error.WriteLine(($errorPayload | ConvertTo-Json -Depth 12 -Compress))
    exit 1
}
finally {
    if ($mutexHeld -and $null -ne $activationMutex) {
        try { $activationMutex.ReleaseMutex() } catch {}
    }
    if ($null -ne $activationMutex) { $activationMutex.Dispose() }
}
