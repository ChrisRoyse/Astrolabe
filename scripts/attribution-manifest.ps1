<#
.SYNOPSIS
    Strict exact-generation lifecycle for launcher attribution manifests (#617).

.DESCRIPTION
    The v3 attribution manifest is diagnostic history plus the binding to one unique
    machine-wide launcher-tree Job Object configured with KILL_ON_JOB_CLOSE. Persisted
    PID intervals never authorize deletion. Cleanup authority requires all of the
    following from independently read state: an exact canonical v3 filename/document
    pair, the exact 0x2000 limit binding, the exact owner generation absent or PID-reused,
    and the exact named Job Object absent. Strict v2 manifests remain readable only for
    diagnosis; their dead-owner/absent-name state is never cleanup authority. Missing,
    legacy, malformed, mismatched, observed, or unevaluable state is preserving.

    This helper never stops a process. It imports launcher-lock.ps1 only for its exact
    retained-file, process-identity, root-identity, and query-only Job Object primitives.
#>

if (-not (Get-Command Get-AstroLauncherJobObjectProbe -ErrorAction SilentlyContinue) -or
    -not ('AstroLauncherLockNative' -as [type])) {
    . (Join-Path $PSScriptRoot 'launcher-lock.ps1')
}
if (-not (Get-Command Get-AstroLauncherTreeJobObjectName -ErrorAction SilentlyContinue) -or
    -not (Get-Command Get-AstroExactRetainedFileSnapshot -ErrorAction SilentlyContinue)) {
    throw 'attribution lifecycle requires the exact launcher-lock v2 native helpers'
}

$script:AstroAttributionManifestMaxBytes = 65536
$script:AstroAttributionManifestReservedPrefix = 'no-escape-attribution-'
$script:AstroAttributionManifestPattern = 'no-escape-attribution-*'
$script:AstroAttributionManifestPidRegex =
    '^no-escape-attribution-v(?<version>[23])\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.json\z'
$script:AstroAttributionKillOnJobCloseLimit = [uint32]0x00002000
$script:AstroLauncherTempV2Regex =
    '^windows-gnu-toolchain-v2\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\z'
$script:AstroAttributionStageReservedPrefix = '.astro-attribution-stage-'
$script:AstroAttributionStageV2Regex =
    '^\.astro-attribution-stage-v2\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.(?<nonce>[0-9a-f]{32})\.bin\z'
$script:AstroAttributionCleanupReservedPrefix = '.astro-attribution-cleanup.'
$script:AstroAttributionCleanupV2Regex =
    '^\.astro-attribution-cleanup\.v2\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.nonce-(?<nonce>[0-9a-f]{32})\.bin\z'
$script:AstroAttributionRefreshReservedPrefix = '.astro-attribution-refresh.'
$script:AstroAttributionRefreshV1Regex =
    '^\.astro-attribution-refresh\.v1\.(?<phase>prepared|old-disposition-set)\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.nonce-(?<nonce>[0-9a-f]{32})\.json\z'
$script:AstroAttributionRefreshOldReservedPrefix = '.astro-attribution-refresh-old.'
$script:AstroAttributionRefreshOldV1Regex =
    '^\.astro-attribution-refresh-old\.v1\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.nonce-(?<nonce>[0-9a-f]{32})\.bin\z'
$script:AstroAttributionRefreshScratchV1Regex =
    '^\.astro-manifest-refresh-scratch-v1\.pid-(?<pid>[1-9][0-9]*)\.ticks-(?<ticks>[1-9][0-9]*)\.lock-sha256-(?<sha>[0-9a-f]{64})\.nonce-(?<nonce>[0-9a-f]{32})\.tmp\z'

function ConvertTo-AstroAttributionCanonicalJsonString {
    param([AllowEmptyString()][Parameter(Mandatory)][string]$Value)

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int]$character
        if ($code -eq 0x22) {
            [void]$builder.Append('\"')
            continue
        }
        if ($code -eq 0x5c) {
            [void]$builder.Append('\\')
            continue
        }
        if ($code -eq 0x0a) {
            [void]$builder.Append('\n')
            continue
        }
        if ($code -eq 0x0d) {
            [void]$builder.Append('\r')
            continue
        }
        if ($code -eq 0x09) {
            [void]$builder.Append('\t')
            continue
        }
        if ($code -lt 0x20) {
            [void]$builder.Append('\u')
            [void]$builder.Append(
                $code.ToString(
                    'x4',
                    [Globalization.CultureInfo]::InvariantCulture
                )
            )
        }
        else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Assert-AstroAttributionUnicodeScalars {
    param(
        [AllowEmptyString()][Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$JsonPath
    )

    for ($index = 0; $index -lt $Value.Length; $index++) {
        $code = [int]$Value[$index]
        if ($code -ge 0xd800 -and $code -le 0xdbff) {
            if ($index + 1 -ge $Value.Length) {
                throw "$JsonPath ends with an unpaired high surrogate"
            }
            $low = [int]$Value[$index + 1]
            if ($low -lt 0xdc00 -or $low -gt 0xdfff) {
                throw "$JsonPath contains an unpaired high surrogate"
            }
            $index++
            continue
        }
        if ($code -ge 0xdc00 -and $code -le 0xdfff) {
            throw "$JsonPath contains an unpaired low surrogate"
        }
    }
}

function Read-AstroAttributionJsonValueNode {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex,
        [int]$Depth = 0,
        [string]$JsonPath = '$'
    )

    if ($Depth -gt 32) {
        throw "$JsonPath exceeds the 32-level attribution JSON nesting bound"
    }
    $index = Get-AstroJsonNextTokenIndex $Json $StartIndex
    if ($index -ge $Json.Length) {
        throw "$JsonPath is missing a JSON value"
    }
    $character = $Json[$index]
    if ($character -eq '"') {
        $token = Read-AstroJsonStringToken $Json $index
        Assert-AstroAttributionUnicodeScalars `
            ([string]$token.Value) `
            $JsonPath
        return [pscustomobject]@{
            Kind = 'string'
            Value = $token.Value
            Raw = $token.Raw
            NextIndex = $token.NextIndex
        }
    }
    if ($character -eq '{') {
        $properties = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        $names = [Collections.Generic.List[string]]::new()
        $rawNames = [Collections.Generic.List[string]]::new()
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -lt $Json.Length -and $Json[$index] -eq '}') {
            return [pscustomobject]@{
                Kind = 'object'
                Properties = $properties
                Names = @()
                RawNames = @()
                NextIndex = $index + 1
            }
        }
        while ($true) {
            $nameToken = Read-AstroJsonStringToken $Json $index
            $name = [string]$nameToken.Value
            Assert-AstroAttributionUnicodeScalars $name "$JsonPath property name"
            if ($properties.ContainsKey($name)) {
                throw "$JsonPath contains duplicate decoded property '$name'"
            }
            $index = Get-AstroJsonNextTokenIndex $Json $nameToken.NextIndex
            if ($index -ge $Json.Length -or $Json[$index] -ne ':') {
                throw "$JsonPath property '$name' is missing ':'"
            }
            $value = Read-AstroAttributionJsonValueNode `
                $Json `
                ($index + 1) `
                ($Depth + 1) `
                "$JsonPath.$name"
            $properties.Add($name, $value)
            $names.Add($name)
            $rawNames.Add([string]$nameToken.Raw)
            $index = Get-AstroJsonNextTokenIndex $Json $value.NextIndex
            if ($index -ge $Json.Length) {
                throw "$JsonPath object is unterminated"
            }
            if ($Json[$index] -eq '}') {
                return [pscustomobject]@{
                    Kind = 'object'
                    Properties = $properties
                    Names = @($names)
                    RawNames = @($rawNames)
                    NextIndex = $index + 1
                }
            }
            if ($Json[$index] -ne ',') {
                throw "$JsonPath expected ',' or '}' at character $index"
            }
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        }
    }
    if ($character -eq '[') {
        $items = [Collections.Generic.List[object]]::new()
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -lt $Json.Length -and $Json[$index] -eq ']') {
            return [pscustomobject]@{
                Kind = 'array'
                Items = @()
                NextIndex = $index + 1
            }
        }
        while ($true) {
            $value = Read-AstroAttributionJsonValueNode `
                $Json `
                $index `
                ($Depth + 1) `
                "$JsonPath[$($items.Count)]"
            $items.Add($value)
            $index = Get-AstroJsonNextTokenIndex $Json $value.NextIndex
            if ($index -ge $Json.Length) {
                throw "$JsonPath array is unterminated"
            }
            if ($Json[$index] -eq ']') {
                return [pscustomobject]@{
                    Kind = 'array'
                    Items = @($items)
                    NextIndex = $index + 1
                }
            }
            if ($Json[$index] -ne ',') {
                throw "$JsonPath expected ',' or ']' at character $index"
            }
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        }
    }
    if ($character -eq '-' -or
        ($character -ge '0' -and $character -le '9')) {
        $numberRegex = [Regex]::new(
            '\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        $match = $numberRegex.Match($Json, $index)
        if (-not $match.Success) {
            throw "$JsonPath contains an invalid JSON number"
        }
        $raw = $match.Value
        return [pscustomobject]@{
            Kind = if ($raw -cmatch '^-?(?:0|[1-9][0-9]*)\z') {
                'integer'
            } else {
                'number'
            }
            Value = $raw
            Raw = $raw
            NextIndex = $index + $raw.Length
        }
    }
    foreach ($literal in @(
            @('true', 'boolean', $true),
            @('false', 'boolean', $false),
            @('null', 'null', $null)
        )) {
        $literalText = [string]$literal[0]
        if ($index + $literalText.Length -le $Json.Length -and
            [string]::CompareOrdinal(
                $Json,
                $index,
                $literalText,
                0,
                $literalText.Length
            ) -eq 0) {
            return [pscustomobject]@{
                Kind = [string]$literal[1]
                Value = $literal[2]
                Raw = $literalText
                NextIndex = $index + $literalText.Length
            }
        }
    }
    throw "$JsonPath begins with an unsupported JSON token at character $index"
}

function ConvertTo-AstroAttributionCanonicalJsonNode {
    param([Parameter(Mandatory)]$Node)

    switch ([string]$Node.Kind) {
        'string' {
            return ConvertTo-AstroAttributionCanonicalJsonString `
                ([string]$Node.Value)
        }
        'integer' { return [string]$Node.Raw }
        'number' { return [string]$Node.Raw }
        'null' { return 'null' }
        'boolean' {
            return if ([bool]$Node.Value) { 'true' } else { 'false' }
        }
        'array' {
            $parts = [Collections.Generic.List[string]]::new()
            foreach ($item in [object[]]@($Node.Items)) {
                $parts.Add((ConvertTo-AstroAttributionCanonicalJsonNode $item))
            }
            return '[' + ($parts -join ',') + ']'
        }
        'object' {
            $parts = [Collections.Generic.List[string]]::new()
            foreach ($name in [string[]]@($Node.Names)) {
                $parts.Add(
                    (ConvertTo-AstroAttributionCanonicalJsonString $name) + ':' +
                    (ConvertTo-AstroAttributionCanonicalJsonNode (
                            $Node.Properties[$name]
                        ))
                )
            }
            return '{' + ($parts -join ',') + '}'
        }
        default {
            throw "unsupported attribution JSON node kind '$($Node.Kind)'"
        }
    }
}

function ConvertFrom-AstroAttributionUnsignedNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [Parameter(Mandatory)][uint64]$Maximum,
        [switch]$Positive
    )

    $value = [uint64]0
    if ($Node.Kind -cne 'integer' -or
        [string]$Node.Raw -cnotmatch '^(?:0|[1-9][0-9]*)\z' -or
        -not [uint64]::TryParse(
            [string]$Node.Raw,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$value
        ) -or
        $value -gt $Maximum -or
        ($Positive -and $value -eq 0)) {
        throw "$JsonPath must be a canonical$(if ($Positive) { ' positive' } else { '' }) invariant integer no greater than $Maximum"
    }
    return $value
}

function Assert-AstroAttributionExactObjectFields {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$JsonPath
    )

    if ($Node.Kind -cne 'object' -or @($Node.Names).Count -ne $Names.Count) {
        throw "$JsonPath must contain exactly $($Names.Count) ordered fields"
    }
    for ($index = 0; $index -lt $Names.Count; $index++) {
        $name = $Names[$index]
        if (-not $Node.Properties.ContainsKey($name) -or
            [string]$Node.Names[$index] -cne $name -or
            [string]$Node.RawNames[$index] -cne ('"' + $name + '"')) {
            throw "$JsonPath field $index must be the exact canonical '$name' property"
        }
    }
}

function ConvertFrom-AstroAttributionStringNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath,
        [switch]$Nonblank
    )

    if ($Node.Kind -cne 'string' -or
        ($Nonblank -and [string]::IsNullOrWhiteSpace([string]$Node.Value))) {
        throw "$JsonPath must be a$(if ($Nonblank) { ' nonblank' } else { '' }) JSON string"
    }
    return [string]$Node.Value
}

function ConvertFrom-AstroAttributionAbsolutePathNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )

    $value = ConvertFrom-AstroAttributionStringNode $Node $JsonPath -Nonblank
    if ($value.IndexOf([char]0) -ge 0 -or -not [IO.Path]::IsPathRooted($value)) {
        throw "$JsonPath must be one absolute NUL-free path"
    }
    $full = [IO.Path]::GetFullPath($value)
    if ($value -cne $full) {
        throw "$JsonPath must use the producer's exact normalized absolute spelling"
    }
    return $full
}

function ConvertFrom-AstroAttributionTimeNode {
    param(
        [Parameter(Mandatory)]$Node,
        [Parameter(Mandatory)][string]$JsonPath
    )

    $value = ConvertFrom-AstroAttributionUnsignedNode `
        $Node `
        $JsonPath `
        ([uint64][long]::MaxValue) `
        -Positive
    if (($value % 100) -ne 0) {
        throw "$JsonPath must be a Windows-100ns-aligned Unix nanosecond timestamp"
    }
    return [long]$value
}

function ConvertFrom-AstroAttributionManifestName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroAttributionManifestReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroAttributionManifestPidRegex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            SchemaVersion = $null
            LauncherPid = $null
            LauncherProcessStartUtcTicks = $null
            LauncherLockSha256 = $null
            Error = 'reserved attribution basename is not the exact canonical v2/v3 grammar'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        SchemaVersion = [int]$match.Groups['version'].Value
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Error = $null
    }
}

function Get-AstroAttributionManifestLeaf {
    param(
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [ValidateSet(2, 3)][int]$SchemaVersion = 3
    )

    if ($LauncherPid -le 0 -or
        $LauncherProcessStartUtcTicks -le 0 -or
        $LauncherProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks -or
        $LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'cannot derive attribution basename from noncanonical owner identity/hash'
    }
    return 'no-escape-attribution-v{0}.pid-{1}.ticks-{2}.lock-sha256-{3}.json' -f @(
        $SchemaVersion,
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256
    )
}

function Get-AstroLauncherTempLeaf {
    param(
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256
    )

    if ($LauncherPid -le 0 -or
        $LauncherProcessStartUtcTicks -le 0 -or
        $LauncherProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks -or
        $LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'cannot derive launcher TEMP basename from noncanonical owner identity/hash'
    }
    return 'windows-gnu-toolchain-v2.pid-{0}.ticks-{1}.lock-sha256-{2}' -f @(
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256
    )
}

function Get-AstroAttributionRefreshEnvelopeLeaf {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('prepared', 'old-disposition-set')]
        [string]$Phase,
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)][string]$Nonce
    )

    if ($LauncherPid -le 0 -or
        $LauncherProcessStartUtcTicks -le 0 -or
        $LauncherProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks -or
        $LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Nonce -cnotmatch '^[0-9a-f]{32}$') {
        throw 'cannot derive attribution refresh-envelope basename from noncanonical generation/nonce'
    }
    return '.astro-attribution-refresh.v1.{0}.pid-{1}.ticks-{2}.lock-sha256-{3}.nonce-{4}.json' -f @(
        $Phase,
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256,
        $Nonce
    )
}

function Get-AstroAttributionRefreshOldLeaf {
    param(
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)][string]$Nonce
    )

    if ($LauncherPid -le 0 -or
        $LauncherProcessStartUtcTicks -le 0 -or
        $LauncherProcessStartUtcTicks -gt [DateTime]::MaxValue.Ticks -or
        $LauncherLockSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $Nonce -cnotmatch '^[0-9a-f]{32}$') {
        throw 'cannot derive attribution refresh-old basename from noncanonical generation/nonce'
    }
    return '.astro-attribution-refresh-old.v1.pid-{0}.ticks-{1}.lock-sha256-{2}.nonce-{3}.bin' -f @(
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256,
        $Nonce
    )
}

function Get-AstroAttributionRefreshScratchLeaf {
    param(
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$LauncherLockSha256,
        [Parameter(Mandatory)][string]$Nonce
    )

    return '.astro-manifest-refresh-scratch-v1.pid-{0}.ticks-{1}.lock-sha256-{2}.nonce-{3}.tmp' -f @(
        $LauncherPid,
        $LauncherProcessStartUtcTicks,
        $LauncherLockSha256,
        $Nonce
    )
}

function Assert-AstroAttributionRetainedProtocolPath {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ExpectedLeaf,
        [Parameter(Mandatory)][string]$Description
    )

    if ($null -eq $Snapshot -or
        [string]::IsNullOrWhiteSpace([string]$Snapshot.FinalPath)) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_RETAINED_PATH_UNEVALUABLE]: $Description has no retained native final path"
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedLeaf) -or
        $ExpectedLeaf -cne [IO.Path]::GetFileName($ExpectedLeaf)) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_EXPECTED_LEAF_INVALID]: $Description expected leaf is not one canonical basename: '$ExpectedLeaf'"
    }

    $actual = [IO.Path]::GetFullPath([string]$Snapshot.FinalPath)
    $actualLeaf = [IO.Path]::GetFileName($actual)
    $actualParent = [IO.Path]::GetDirectoryName($actual)
    $actualParentLeaf = if ([string]::IsNullOrEmpty($actualParent)) {
        ''
    } else {
        [IO.Path]::GetFileName($actualParent.TrimEnd('\', '/'))
    }
    if ($actualParentLeaf -cne '.tmp' -or $actualLeaf -cne $ExpectedLeaf) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_RETAINED_PATH_CASE_DRIFT]: $Description retained native path does not have the exact protocol components (expected_parent=.tmp, observed_parent=$actualParentLeaf, expected_leaf=$ExpectedLeaf, observed_leaf=$actualLeaf, final_path=$actual)"
    }
}

function Convert-AstroAttributionBytesToState {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$ExpectedLauncherPid,
        [Parameter(Mandatory)][long]$ExpectedLauncherProcessStartUtcTicks,
        [Parameter(Mandatory)][string]$ExpectedLauncherLockSha256,
        [Parameter(Mandatory)][string]$Path
    )

    try {
        if ($Bytes.Length -eq 0 -or
            $Bytes.Length -gt $script:AstroAttributionManifestMaxBytes) {
            throw "attribution bytes must contain 1-$script:AstroAttributionManifestMaxBytes bytes"
        }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($json.Length -gt 0 -and $json[0] -eq [char]0xfeff) {
            throw 'UTF-8 BOM is not permitted'
        }
        $root = Read-AstroAttributionJsonValueNode $json 0 0 '$'
        $end = Get-AstroJsonNextTokenIndex $json $root.NextIndex
        if ($end -ne $json.Length) {
            throw "unexpected trailing JSON data at character $end"
        }
        if ($root.Kind -cne 'object') {
            throw 'attribution JSON root must be one object'
        }
        $canonical = ConvertTo-AstroAttributionCanonicalJsonNode $root
        if ($json -cne $canonical) {
            throw 'attribution JSON is not the exact minified producer encoding (whitespace, escapes, or token spelling differs)'
        }

        $properties = $root.Properties
        if (-not $properties.ContainsKey('schema') -or
            $properties['schema'].Kind -cne 'string') {
            throw 'attribution schema must be one exact JSON string'
        }
        $schemaVersion = switch ([string]$properties['schema'].Value) {
            'astrolabe.no_escape_attribution.v2' { 2; break }
            'astrolabe.no_escape_attribution.v3' { 3; break }
            default {
                throw 'schema must be astrolabe.no_escape_attribution.v2 or astrolabe.no_escape_attribution.v3'
            }
        }
        $required = [Collections.Generic.List[string]]::new()
        foreach ($field in @(
                'schema',
                'launcher_pid',
                'launcher_process_start_utc_ticks',
                'launcher_lock_sha256',
                'launcher_lease_start_utc_ticks',
                'job_object_name'
            )) {
            $required.Add($field)
        }
        if ($schemaVersion -eq 3) {
            $required.Add('job_limit_flags')
        }
        foreach ($field in @(
                'run_started_unix_ns',
                'written_at',
                'tree_pids',
                'pid_first_seen',
                'pid_intervals',
                'owned_paths'
            )) {
            $required.Add($field)
        }
        if (@($root.Names).Count -ne $required.Count) {
            throw "attribution root must contain exactly the $($required.Count) v$schemaVersion fields"
        }
        for ($index = 0; $index -lt $required.Count; $index++) {
            $name = $required[$index]
            if (-not $root.Properties.ContainsKey($name)) {
                throw "attribution root is missing '$name'"
            }
            if ([string]$root.Names[$index] -cne $name -or
                [string]$root.RawNames[$index] -cne ('"' + $name + '"')) {
                throw "attribution root property $index must be the exact canonical '$name' field"
            }
        }
        $pathName = ConvertFrom-AstroAttributionManifestName $Path
        if ($pathName.Candidate -and
            (-not $pathName.Valid -or
                $pathName.SchemaVersion -ne $schemaVersion)) {
            throw "manifest filename schema does not match document v$schemaVersion"
        }
        $launcherPid = ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_pid'] `
            '$.launcher_pid' `
            ([uint64][int]::MaxValue) `
            -Positive
        if ([int]$launcherPid -ne $ExpectedLauncherPid) {
            throw "launcher_pid $launcherPid does not match filename PID $ExpectedLauncherPid"
        }
        $launcherTicks = ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_process_start_utc_ticks'] `
            '$.launcher_process_start_utc_ticks' `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive
        if ([long]$launcherTicks -ne $ExpectedLauncherProcessStartUtcTicks) {
            throw "launcher_process_start_utc_ticks $launcherTicks does not match filename ticks $ExpectedLauncherProcessStartUtcTicks"
        }
        if ($properties['launcher_lock_sha256'].Kind -cne 'string' -or
            [string]$properties['launcher_lock_sha256'].Value -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$properties['launcher_lock_sha256'].Value -cne
                $ExpectedLauncherLockSha256) {
            throw 'launcher_lock_sha256 must exactly match the lowercase filename SHA-256'
        }
        $leaseTicks = ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_lease_start_utc_ticks'] `
            '$.launcher_lease_start_utc_ticks' `
            ([uint64][DateTime]::MaxValue.Ticks) `
            -Positive
        if ($leaseTicks -lt $launcherTicks) {
            throw 'launcher_lease_start_utc_ticks precedes launcher process creation'
        }
        $unixEpochTicks = [DateTime]::new(
            1970,
            1,
            1,
            0,
            0,
            0,
            [DateTimeKind]::Utc
        ).Ticks
        # floor(Int64.MaxValue / 100), the exact inverse of the producer's checked
        # Windows-tick -> Unix-nanosecond multiplication.
        $maximumUnixNanosecondDeltaTicks = [long]92233720368547758
        $maximumUnixNanosecondTicks = [long](
            $unixEpochTicks + $maximumUnixNanosecondDeltaTicks
        )
        if ($launcherTicks -lt $unixEpochTicks -or
            $launcherTicks -gt $maximumUnixNanosecondTicks -or
            $leaseTicks -lt $unixEpochTicks -or
            $leaseTicks -gt $maximumUnixNanosecondTicks) {
            throw 'launcher process/lease ticks lie outside the positive signed-Int64 Unix-nanosecond producer window'
        }
        if ($properties['job_object_name'].Kind -cne 'string' -or
            [string]$properties['job_object_name'].Value -cnotmatch
                '^Global\\Astrolabe\.LauncherTree\.[0-9a-f]{64}$') {
            throw 'job_object_name must be one exact canonical Global Astrolabe launcher-tree name'
        }
        $jobLimitFlags = if ($schemaVersion -eq 3) {
            [uint32](ConvertFrom-AstroAttributionUnsignedNode `
                $properties['job_limit_flags'] `
                '$.job_limit_flags' `
                ([uint64][uint32]::MaxValue) `
                -Positive)
        } else { [uint32]0 }
        if ($schemaVersion -eq 3 -and
            $jobLimitFlags -ne $script:AstroAttributionKillOnJobCloseLimit) {
            throw "job_limit_flags must be exactly JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (8192), observed $jobLimitFlags"
        }
        $runStarted = ConvertFrom-AstroAttributionTimeNode `
            $properties['run_started_unix_ns'] `
            '$.run_started_unix_ns'
        $writtenAt = ConvertFrom-AstroAttributionTimeNode `
            $properties['written_at'] `
            '$.written_at'
        if ($writtenAt -lt $runStarted) {
            throw 'written_at precedes run_started_unix_ns'
        }
        $launcherProcessUnixNs = [long](
            ([long]$launcherTicks - $unixEpochTicks) * 100
        )
        $launcherLeaseUnixNs = [long](
            ([long]$leaseTicks - $unixEpochTicks) * 100
        )
        if ($runStarted -lt $launcherProcessUnixNs -or
            $runStarted -lt $launcherLeaseUnixNs) {
            throw 'run_started_unix_ns precedes the bound launcher process or lease start'
        }

        $treeNode = $properties['tree_pids']
        if ($treeNode.Kind -cne 'array' -or @($treeNode.Items).Count -eq 0) {
            throw '$.tree_pids must be a nonempty array'
        }
        $treePids = [Collections.Generic.List[int]]::new()
        $seenPids = [Collections.Generic.HashSet[int]]::new()
        $priorPid = 0
        for ($index = 0; $index -lt @($treeNode.Items).Count; $index++) {
            $pidValue = ConvertFrom-AstroAttributionUnsignedNode `
                $treeNode.Items[$index] `
                "$.tree_pids[$index]" `
                ([uint64][int]::MaxValue) `
                -Positive
            if (-not $seenPids.Add([int]$pidValue)) {
                throw "$.tree_pids contains duplicate PID $pidValue"
            }
            if ($index -gt 0 -and [int]$pidValue -le $priorPid) {
                throw '$.tree_pids must be strictly ascending like the producer snapshot'
            }
            $treePids.Add([int]$pidValue)
            $priorPid = [int]$pidValue
        }

        $firstSeenNode = $properties['pid_first_seen']
        $intervalsNode = $properties['pid_intervals']
        if ($firstSeenNode.Kind -cne 'object' -or
            $intervalsNode.Kind -cne 'object' -or
            @($firstSeenNode.Names).Count -ne $treePids.Count -or
            @($intervalsNode.Names).Count -ne $treePids.Count) {
            throw 'PID object shapes must exactly match tree_pids'
        }
        $openPids = [Collections.Generic.List[int]]::new()
        for ($pidIndex = 0; $pidIndex -lt $treePids.Count; $pidIndex++) {
            $pidValue = $treePids[$pidIndex]
            $pidName = $pidValue.ToString(
                [Globalization.CultureInfo]::InvariantCulture
            )
            if ([string]$firstSeenNode.Names[$pidIndex] -cne $pidName -or
                [string]$intervalsNode.Names[$pidIndex] -cne $pidName -or
                [string]$firstSeenNode.RawNames[$pidIndex] -cne
                    ('"' + $pidName + '"') -or
                [string]$intervalsNode.RawNames[$pidIndex] -cne
                    ('"' + $pidName + '"')) {
                throw "PID key sequence differs from tree_pids at index $pidIndex"
            }
            $firstSeen = ConvertFrom-AstroAttributionTimeNode `
                $firstSeenNode.Properties[$pidName] `
                "$.pid_first_seen['$pidName']"
            if ($firstSeen -lt $runStarted -or $firstSeen -gt $writtenAt) {
                throw "first-seen timestamp for PID $pidValue lies outside the run window"
            }
            $spansNode = $intervalsNode.Properties[$pidName]
            if ($spansNode.Kind -cne 'array' -or
                @($spansNode.Items).Count -eq 0) {
                throw "pid_intervals['$pidName'] must be a nonempty array"
            }
            $priorEnd = $null
            $lastOpen = $false
            for ($spanIndex = 0;
                $spanIndex -lt @($spansNode.Items).Count;
                $spanIndex++) {
                $spanNode = $spansNode.Items[$spanIndex]
                if ($spanNode.Kind -cne 'array' -or
                    @($spanNode.Items).Count -ne 2) {
                    throw "pid_intervals['$pidName'][$spanIndex] must contain exactly [start,end]"
                }
                $start = ConvertFrom-AstroAttributionTimeNode `
                    $spanNode.Items[0] `
                    "$.pid_intervals['$pidName'][$spanIndex][0]"
                if ($start -lt $runStarted -or $start -gt $writtenAt) {
                    throw "PID $pidValue interval start lies outside the run window"
                }
                if ($spanIndex -eq 0 -and $start -ne $firstSeen) {
                    throw "PID $pidValue first-seen does not equal its first interval start"
                }
                if ($null -ne $priorEnd -and $start -le [long]$priorEnd) {
                    throw "PID $pidValue reused-generation interval must start strictly after the prior closed interval"
                }
                $endNode = $spanNode.Items[1]
                if ($endNode.Kind -ceq 'null') {
                    if ($spanIndex -ne @($spansNode.Items).Count - 1) {
                        throw "PID $pidValue has a nonterminal open interval"
                    }
                    $lastOpen = $true
                    $priorEnd = $null
                }
                else {
                    $endValue = ConvertFrom-AstroAttributionTimeNode `
                        $endNode `
                        "$.pid_intervals['$pidName'][$spanIndex][1]"
                    if ($endValue -lt $start -or $endValue -gt $writtenAt) {
                        throw "PID $pidValue interval end is before its start or after written_at"
                    }
                    $priorEnd = $endValue
                    $lastOpen = $false
                }
            }
            if ($lastOpen) {
                $openPids.Add($pidValue)
            }
            if ($pidValue -eq [int]$launcherPid) {
                $launcherSpans = @($spansNode.Items)
                if ($firstSeen -ne $runStarted -or
                    $launcherSpans.Count -ne 1 -or
                    (ConvertFrom-AstroAttributionTimeNode `
                        $launcherSpans[0].Items[0] `
                        "$.pid_intervals['$pidName'][0][0]") -ne $runStarted -or
                    $launcherSpans[0].Items[1].Kind -cne 'null') {
                    throw 'launcher PID must have the single open [run_started_unix_ns,null] interval'
                }
            }
        }
        if (-not $seenPids.Contains([int]$launcherPid)) {
            throw 'tree_pids does not contain launcher_pid'
        }

        $ownedNode = $properties['owned_paths']
        if ($ownedNode.Kind -cne 'array') {
            throw '$.owned_paths must be an array; null is not a valid v2 producer state'
        }
        $owned = [Collections.Generic.List[string]]::new()
        $ownedIgnoreCase = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        for ($index = 0; $index -lt @($ownedNode.Items).Count; $index++) {
            $item = $ownedNode.Items[$index]
            if ($item.Kind -cne 'string' -or
                [string]::IsNullOrWhiteSpace([string]$item.Value) -or
                ([string]$item.Value).IndexOf([char]0) -ge 0) {
                throw "$.owned_paths[$index] must be a nonblank NUL-free string"
            }
            $ownedPath = [string]$item.Value
            if (-not [IO.Path]::IsPathRooted($ownedPath) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath($ownedPath),
                    $ownedPath,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "$.owned_paths[$index] must be one normalized absolute path"
            }
            if ($index -gt 0 -and
                [StringComparer]::Ordinal.Compare(
                    $owned[$index - 1],
                    $ownedPath
                ) -ge 0) {
                throw '$.owned_paths must be strictly sorted under the producer Ordinal comparer'
            }
            if (-not $ownedIgnoreCase.Add($ownedPath)) {
                throw '$.owned_paths must be unique under Windows OrdinalIgnoreCase identity'
            }
            $owned.Add($ownedPath)
        }
        $ownedPaths = @($owned)

        return [pscustomobject]@{
            Valid = $true
            Readable = $true
            Error = $null
            Path = [IO.Path]::GetFullPath($Path)
            SchemaVersion = [int]$schemaVersion
            LauncherPid = [int]$launcherPid
            LauncherProcessStartUtcTicks = [long]$launcherTicks
            LauncherLockSha256 =
                [string]$properties['launcher_lock_sha256'].Value
            LauncherLeaseStartUtcTicks = [long]$leaseTicks
            JobObjectName = [string]$properties['job_object_name'].Value
            JobLimitFlags = [uint32]$jobLimitFlags
            KillOnJobCloseBound = [bool]($schemaVersion -eq 3 -and
                $jobLimitFlags -eq $script:AstroAttributionKillOnJobCloseLimit)
            RunStartedUnixNs = $runStarted
            WrittenAt = $writtenAt
            LauncherProcessStartUnixNs = $launcherProcessUnixNs
            LauncherLeaseStartUnixNs = $launcherLeaseUnixNs
            TreePids = [int[]]@($treePids)
            OpenPids = [int[]]@($openPids)
            OwnedPathsUnevaluable = $false
            OwnedPaths = $ownedPaths
            RawJson = $json
        }
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            Readable = $false
            Error = $_.Exception.Message
            Path = [IO.Path]::GetFullPath($Path)
            TreePids = [int[]]@()
            OpenPids = [int[]]@()
        }
    }
}

function Convert-AstroAttributionRefreshBytesToState {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [Parameter(Mandatory)]$Name,
        [Parameter(Mandatory)][string]$Path
    )

    try {
        if ($null -eq $Name -or -not $Name.Valid) {
            throw 'refresh envelope filename is not one exact canonical v1 name'
        }
        if ($Bytes.Length -eq 0 -or
            $Bytes.Length -gt $script:AstroAttributionManifestMaxBytes) {
            throw "refresh envelope must contain 1-$script:AstroAttributionManifestMaxBytes bytes"
        }
        $json = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        if ($json.Length -gt 0 -and $json[0] -eq [char]0xfeff) {
            throw 'refresh envelope must not contain a UTF-8 BOM'
        }
        $root = Read-AstroAttributionJsonValueNode $json 0 0 '$'
        $end = Get-AstroJsonNextTokenIndex $json $root.NextIndex
        if ($end -ne $json.Length -or $root.Kind -cne 'object') {
            throw 'refresh envelope must be exactly one JSON object with no trailing data'
        }
        if ((ConvertTo-AstroAttributionCanonicalJsonNode $root) -cne $json) {
            throw 'refresh envelope JSON is not the exact minified producer encoding'
        }
        $required = @(
            'schema',
            'launcher_pid',
            'launcher_process_start_utc_ticks',
            'launcher_lock_sha256',
            'launcher_lease_start_utc_ticks',
            'job_object_name',
            'transaction_nonce',
            'final_path',
            'old_final_path',
            'old_final_file_identity',
            'old_final_length',
            'old_final_sha256',
            'new_scratch_path',
            'new_scratch_file_identity',
            'new_manifest_length',
            'new_manifest_sha256',
            'old_tombstone_path',
            'prepared_envelope_path',
            'disposition_proof_path'
        )
        Assert-AstroAttributionExactObjectFields $root $required '$'
        $properties = $root.Properties
        if ((ConvertFrom-AstroAttributionStringNode `
                $properties['schema'] '$.schema' -Nonblank) -cne
            'astrolabe.no_escape_attribution.refresh.v1') {
            throw 'refresh envelope schema must be astrolabe.no_escape_attribution.refresh.v1'
        }
        $launcherPid = [int](ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_pid'] '$.launcher_pid' `
            ([uint64][int]::MaxValue) -Positive)
        $launcherTicks = [long](ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_process_start_utc_ticks'] `
            '$.launcher_process_start_utc_ticks' `
            ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        $launcherSha = ConvertFrom-AstroAttributionStringNode `
            $properties['launcher_lock_sha256'] `
            '$.launcher_lock_sha256' -Nonblank
        $leaseTicks = [long](ConvertFrom-AstroAttributionUnsignedNode `
            $properties['launcher_lease_start_utc_ticks'] `
            '$.launcher_lease_start_utc_ticks' `
            ([uint64][DateTime]::MaxValue.Ticks) -Positive)
        $jobName = ConvertFrom-AstroAttributionStringNode `
            $properties['job_object_name'] '$.job_object_name' -Nonblank
        $nonce = ConvertFrom-AstroAttributionStringNode `
            $properties['transaction_nonce'] '$.transaction_nonce' -Nonblank
        if ($launcherPid -ne $Name.LauncherPid -or
            $launcherTicks -ne $Name.LauncherProcessStartUtcTicks -or
            $launcherSha -cne $Name.LauncherLockSha256 -or
            $nonce -cne $Name.Nonce -or
            $launcherSha -cnotmatch '^[0-9a-f]{64}$' -or
            $nonce -cnotmatch '^[0-9a-f]{32}$' -or
            $leaseTicks -lt $launcherTicks -or
            $jobName -cnotmatch '^Global\\Astrolabe\.LauncherTree\.[0-9a-f]{64}$') {
            throw 'refresh envelope generation/nonce/lease/Job fields do not match its canonical filename identity'
        }

        $actual = [IO.Path]::GetFullPath($Path)
        $directory = [IO.Path]::GetDirectoryName($actual)
        $finalPath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['final_path'] '$.final_path'
        $oldFinalPath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['old_final_path'] '$.old_final_path'
        $newScratchPath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['new_scratch_path'] '$.new_scratch_path'
        $oldTombstonePath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['old_tombstone_path'] '$.old_tombstone_path'
        $preparedEnvelopePath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['prepared_envelope_path'] '$.prepared_envelope_path'
        $dispositionProofPath = ConvertFrom-AstroAttributionAbsolutePathNode `
            $properties['disposition_proof_path'] '$.disposition_proof_path'
        $finalName = ConvertFrom-AstroAttributionManifestName $finalPath
        if (-not $finalName.Candidate -or -not $finalName.Valid -or
            $finalName.LauncherPid -ne $launcherPid -or
            $finalName.LauncherProcessStartUtcTicks -ne $launcherTicks -or
            $finalName.LauncherLockSha256 -cne $launcherSha) {
            throw 'refresh envelope final_path is not one exact v2/v3 manifest identity for its launcher generation'
        }
        $expectedFinalPath = [IO.Path]::GetFullPath((Join-Path $directory (
                Get-AstroAttributionManifestLeaf `
                    $launcherPid $launcherTicks $launcherSha `
                    -SchemaVersion $finalName.SchemaVersion
            )))
        $expectedOldPath = [IO.Path]::GetFullPath((Join-Path $directory (
                Get-AstroAttributionRefreshOldLeaf `
                    $launcherPid $launcherTicks $launcherSha $nonce
            )))
        $expectedPreparedPath = [IO.Path]::GetFullPath((Join-Path $directory (
                Get-AstroAttributionRefreshEnvelopeLeaf `
                    'prepared' $launcherPid $launcherTicks $launcherSha $nonce
            )))
        $expectedProofPath = [IO.Path]::GetFullPath((Join-Path $directory (
                Get-AstroAttributionRefreshEnvelopeLeaf `
                    'old-disposition-set' $launcherPid $launcherTicks `
                    $launcherSha $nonce
            )))
        $expectedScratchPath = [IO.Path]::GetFullPath((Join-Path $directory (
                Get-AstroAttributionRefreshScratchLeaf `
                    $launcherPid $launcherTicks $launcherSha $nonce
            )))
        if ($finalPath -cne $expectedFinalPath -or
            $oldFinalPath -cne $expectedFinalPath -or
            $newScratchPath -cne $expectedScratchPath -or
            $oldTombstonePath -cne $expectedOldPath -or
            $preparedEnvelopePath -cne $expectedPreparedPath -or
            $dispositionProofPath -cne $expectedProofPath -or
            $actual -cne $(if ($Name.Phase -ceq 'prepared') {
                    $expectedPreparedPath
                } else { $expectedProofPath })) {
            throw 'refresh envelope paths do not exactly cross-bind its generation/nonce/phase'
        }

        $oldIdentity = ConvertFrom-AstroAttributionStringNode `
            $properties['old_final_file_identity'] `
            '$.old_final_file_identity' -Nonblank
        $newIdentity = ConvertFrom-AstroAttributionStringNode `
            $properties['new_scratch_file_identity'] `
            '$.new_scratch_file_identity' -Nonblank
        $oldLength = [uint64](ConvertFrom-AstroAttributionUnsignedNode `
            $properties['old_final_length'] '$.old_final_length' `
            ([uint64]$script:AstroAttributionManifestMaxBytes) -Positive)
        $newLength = [uint64](ConvertFrom-AstroAttributionUnsignedNode `
            $properties['new_manifest_length'] '$.new_manifest_length' `
            ([uint64]$script:AstroAttributionManifestMaxBytes) -Positive)
        $oldSha = ConvertFrom-AstroAttributionStringNode `
            $properties['old_final_sha256'] '$.old_final_sha256' -Nonblank
        $newSha = ConvertFrom-AstroAttributionStringNode `
            $properties['new_manifest_sha256'] '$.new_manifest_sha256' -Nonblank
        if ($oldIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or
            $newIdentity -cnotmatch '^[0-9a-f]{16}:[0-9a-f]{32}$' -or
            $oldIdentity -ceq $newIdentity -or
            $oldSha -cnotmatch '^[0-9a-f]{64}$' -or
            $newSha -cnotmatch '^[0-9a-f]{64}$') {
            throw 'refresh envelope FILE_ID/hash fields are not canonical distinct old/new bindings'
        }
        return [pscustomobject]@{
            Valid = $true
            Error = $null
            Path = $actual
            ManifestSchemaVersion = [int]$finalName.SchemaVersion
            Phase = $Name.Phase
            LauncherPid = $launcherPid
            LauncherProcessStartUtcTicks = $launcherTicks
            LauncherLockSha256 = $launcherSha
            LauncherLeaseStartUtcTicks = $leaseTicks
            JobObjectName = $jobName
            Nonce = $nonce
            FinalPath = $finalPath
            OldFinalPath = $oldFinalPath
            OldFinalFileId = $oldIdentity
            OldFinalLength = $oldLength
            OldFinalSha256 = $oldSha
            NewScratchPath = $newScratchPath
            NewScratchFileId = $newIdentity
            NewManifestLength = $newLength
            NewManifestSha256 = $newSha
            OldTombstonePath = $oldTombstonePath
            PreparedEnvelopePath = $preparedEnvelopePath
            DispositionProofPath = $dispositionProofPath
            RawJson = $json
        }
    }
    catch {
        return [pscustomobject]@{
            Valid = $false
            Error = $_.Exception.Message
            Path = [IO.Path]::GetFullPath($Path)
        }
    }
}

function Get-AstroAttributionProtocolContext {
    param([Parameter(Mandatory)][string]$Directory)

    $temporary = [IO.Path]::GetFullPath($Directory).TrimEnd('\', '/')
    if ([IO.Path]::GetFileName($temporary) -cne '.tmp') {
        throw "attribution protocol directory must be one exact '.tmp' child: $temporary"
    }
    $state = Get-AstroPathEntryState $temporary
    if ($state.State -ne 'present' -or
        ($state.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
        ($state.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "attribution protocol directory is not one evaluable ordinary directory (state=$($state.State), attributes=$($state.Attributes), error=$($state.Error)): $temporary"
    }
    $root = [IO.Path]::GetDirectoryName($temporary)
    Assert-AstroLauncherRootCanonical $root
    $rootHandle = [AstroLauncherLockNative]::OpenExactRenameDirectory($root)
    try {
        $rootIdentity = [AstroLauncherLockNative]::GetDirectoryLockIdentity(
            $rootHandle
        )
        $rootFinalPath = ConvertFrom-AstroNativeFinalPath (
            [AstroLauncherLockNative]::GetFileFinalPath($rootHandle)
        )
        $rootFinalPath = [IO.Path]::GetFullPath($rootFinalPath).TrimEnd('\', '/')
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath($root).TrimEnd('\', '/'),
                $rootFinalPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "attribution root final path changed while deriving its filesystem identity: $root"
        }
        return [pscustomobject]@{
            Directory = $temporary
            Root = [IO.Path]::GetFullPath($root).TrimEnd('\', '/')
            RootFinalPath = $rootFinalPath
            RootIdentity = $rootIdentity
        }
    }
    finally {
        $rootHandle.Dispose()
    }
}

function Get-AstroAttributionOwnerGenerationProbe {
    param(
        [Parameter(Mandatory)][int]$LauncherPid,
        [Parameter(Mandatory)][long]$LauncherProcessStartUtcTicks
    )

    $native = Get-AstroProcessIdentityProbe -OwnerPid $LauncherPid
    $state = if ($native.State -eq 'absent') {
        'absent'
    } elseif ($native.State -eq 'unevaluable') {
        'unevaluable'
    } elseif ([long]$native.ProcessStartUtcTicks -eq
        $LauncherProcessStartUtcTicks) {
        'exact-live'
    } else {
        'pid-reused'
    }
    return [pscustomobject]@{
        State = $state
        LauncherPid = $LauncherPid
        ExpectedProcessStartUtcTicks = $LauncherProcessStartUtcTicks
        ObservedProcessStartUtcTicks = if ($native.State -eq 'observed') {
            [long]$native.ProcessStartUtcTicks
        } else {
            $null
        }
        Error = $native.Error
    }
}

function Get-AstroAttributionManifestProbe {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [string]$RootIdentity = $null
    )

    $full = [IO.Path]::GetFullPath($ManifestPath)
    $name = ConvertFrom-AstroAttributionManifestName $full
    if (-not $name.Candidate -or -not $name.Valid) {
        return [pscustomobject]@{
            Kind = 'manifest'
            State = 'unevaluable'
            Valid = $false
            Readable = $false
            Path = $full
            Error = $name.Error
            Name = $name
            Parsed = $null
            Snapshot = $null
            OwnerProbe = $null
            JobObjectProbe = $null
            ExpectedTempPath = $null
        }
    }

    $handle = $null
    try {
        $context = Get-AstroAttributionProtocolContext (
            [IO.Path]::GetDirectoryName($full)
        )
        if ([string]::IsNullOrEmpty($RootIdentity)) {
            $RootIdentity = $context.RootIdentity
        }
        elseif ($RootIdentity -cne $context.RootIdentity) {
            throw "caller root identity '$RootIdentity' differs from retained root identity '$($context.RootIdentity)'"
        }
        $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile($full)
        $initial = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $initial $name.Leaf 'attribution manifest probe'
        $parsed = Convert-AstroAttributionBytesToState `
            -Bytes $initial.Bytes `
            -ExpectedLauncherPid $name.LauncherPid `
            -ExpectedLauncherProcessStartUtcTicks `
                $name.LauncherProcessStartUtcTicks `
            -ExpectedLauncherLockSha256 $name.LauncherLockSha256 `
            -Path $full
        if (-not $parsed.Valid) {
            throw $parsed.Error
        }
        $expectedJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $RootIdentity `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks `
            -LauncherLeaseStartUtcTicks $parsed.LauncherLeaseStartUtcTicks `
            -LauncherLockSha256 $parsed.LauncherLockSha256
        if ($parsed.JobObjectName -cne $expectedJobName) {
            throw 'manifest Job Object name does not match its exact root/PID/ticks/lease/hash derivation'
        }
        $ownerProbe = Get-AstroAttributionOwnerGenerationProbe `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks
        $jobProbe = Get-AstroLauncherJobObjectProbe -Name $parsed.JobObjectName
        $final = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $final $name.Leaf 'attribution manifest probe readback'
        if ($final.FileId -cne $initial.FileId -or
            $final.Length -ne $initial.Length -or
            $final.Sha256 -cne $initial.Sha256 -or
            [Convert]::ToBase64String($final.Bytes) -cne
                [Convert]::ToBase64String($initial.Bytes)) {
            throw 'retained attribution manifest changed across its owner/Job Object probes'
        }
        return [pscustomobject]@{
            Kind = 'manifest'
            State = 'valid'
            Valid = $true
            Readable = $true
            Path = $full
            Error = $null
            Name = $name
            Parsed = $parsed
            Snapshot = $final
            OwnerProbe = $ownerProbe
            JobObjectProbe = $jobProbe
            RootIdentity = $RootIdentity
            ExpectedTempPath = Join-Path $context.Directory (
                Get-AstroLauncherTempLeaf `
                    -LauncherPid $parsed.LauncherPid `
                    -LauncherProcessStartUtcTicks `
                        $parsed.LauncherProcessStartUtcTicks `
                    -LauncherLockSha256 $parsed.LauncherLockSha256
            )
        }
    }
    catch {
        return [pscustomobject]@{
            Kind = 'manifest'
            State = 'unevaluable'
            Valid = $false
            Readable = $false
            Path = $full
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
            Name = $name
            Parsed = $null
            Snapshot = $null
            OwnerProbe = $null
            JobObjectProbe = $null
            ExpectedTempPath = $null
        }
    }
    finally {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
    }
}

function Get-AstroAttributionTreePids {
    param([Parameter(Mandatory)][string]$ManifestPath)

    $probe = Get-AstroAttributionManifestProbe -ManifestPath $ManifestPath
    if (-not $probe.Valid) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_MANIFEST_UNEVALUABLE]: $($probe.Error): $($probe.Path)"
    }
    return [pscustomobject]@{
        Readable = $true
        OpenPids = [int[]]@($probe.Parsed.OpenPids)
        TreePids = [int[]]@($probe.Parsed.TreePids)
        LauncherPid = $probe.Parsed.LauncherPid
        LauncherProcessStartUtcTicks =
            $probe.Parsed.LauncherProcessStartUtcTicks
        LauncherLeaseStartUtcTicks =
            $probe.Parsed.LauncherLeaseStartUtcTicks
        LauncherLockSha256 = $probe.Parsed.LauncherLockSha256
        JobObjectName = $probe.Parsed.JobObjectName
        OwnerProbe = $probe.OwnerProbe
        JobObjectProbe = $probe.JobObjectProbe
    }
}

function Test-AstroPidAlive {
    param([Parameter(Mandatory)][int]$OwnerPid)

    return (Get-AstroProcessIdentityProbe -OwnerPid $OwnerPid).State -eq
        'observed'
}

function Get-AstroLiveAttributedPids {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][int]$SelfPid
    )

    $probe = Get-AstroAttributionManifestProbe -ManifestPath $ManifestPath
    if (-not $probe.Valid) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_MANIFEST_UNEVALUABLE]: $($probe.Error): $($probe.Path)"
    }
    if ($probe.OwnerProbe.State -eq 'unevaluable' -or
        $probe.JobObjectProbe.State -eq 'unevaluable') {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_TREE_UNEVALUABLE]: owner_state=$($probe.OwnerProbe.State), owner_error=$($probe.OwnerProbe.Error), job_state=$($probe.JobObjectProbe.State), job_error=$($probe.JobObjectProbe.Error)"
    }

    [int[]]$jobPids = @($probe.JobObjectProbe.ProcessIds)
    if ($probe.OwnerProbe.State -eq 'exact-live') {
        if ($probe.Parsed.LauncherPid -ne $SelfPid) {
            throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWNER_NOT_SELF]: live manifest owner PID $($probe.Parsed.LauncherPid) is not cleanup caller PID $SelfPid"
        }
        if ($probe.JobObjectProbe.State -cne 'observed' -or
            $jobPids -notcontains $SelfPid) {
            throw 'ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_JOB_OWNER_MISMATCH]: exact live launcher is not an observed member of its named Job Object'
        }
        [int[]]$protecting = @($jobPids | Where-Object { $_ -ne $SelfPid })
        return [pscustomobject]@{
            ManifestReadable = $true
            LivePids = $protecting
            NonProtecting = @()
            OwnerProbe = $probe.OwnerProbe
            JobObjectProbe = $probe.JobObjectProbe
            CleanupAuthorizedForExactSelf = $protecting.Count -eq 0
        }
    }

    if ($probe.OwnerProbe.State -notin @('absent', 'pid-reused')) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWNER_STATE_INVALID]: unsupported owner state '$($probe.OwnerProbe.State)'"
    }
    if ($probe.JobObjectProbe.State -cne 'absent') {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_JOB_STILL_EXISTS]: exact dead/reused owner has Job Object state '$($probe.JobObjectProbe.State)'; observed is preserving even with zero members"
    }
    return [pscustomobject]@{
        ManifestReadable = $true
        LivePids = [int[]]@()
        NonProtecting = @()
        OwnerProbe = $probe.OwnerProbe
        JobObjectProbe = $probe.JobObjectProbe
        CleanupAuthorizedForExactSelf = $false
    }
}

function Remove-AstroAttributionManifest {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$ExpectedBytes
    )

    $full = [IO.Path]::GetFullPath($Path)
    if ($ExpectedBytes.Length -eq 0 -or
        $ExpectedBytes.Length -gt $script:AstroAttributionManifestMaxBytes) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_EXPECTED_BYTES_INVALID]: expected producer readback must contain 1-$script:AstroAttributionManifestMaxBytes bytes"
    }
    $expectedSha256 = Get-AstroByteSha256 $ExpectedBytes
    $preflight = Get-AstroAttributionManifestProbe -ManifestPath $full
    if (-not $preflight.Valid) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_UNEVALUABLE]: $($preflight.Error): $full"
    }
    if ($preflight.Parsed.SchemaVersion -ne 3 -or
        -not $preflight.Parsed.KillOnJobCloseBound) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_JOB_CONTRACT_UNTRUSTWORTHY]: own cleanup requires one exact v3 KILL_ON_JOB_CLOSE manifest; observed schema=v$($preflight.Parsed.SchemaVersion), flags=$($preflight.Parsed.JobLimitFlags)"
    }
    if ($preflight.Snapshot.Length -ne $ExpectedBytes.Length -or
        $preflight.Snapshot.Sha256 -cne $expectedSha256 -or
        [Convert]::ToBase64String($preflight.Snapshot.Bytes) -cne
            [Convert]::ToBase64String($ExpectedBytes)) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_PRODUCER_READBACK_MISMATCH]: final manifest differs from the recorder's exact post-Stop durable bytes (expected_sha256=$expectedSha256, observed_sha256=$($preflight.Snapshot.Sha256)): $full"
    }
    $selfProbe = Get-AstroProcessIdentityProbe -OwnerPid $PID
    if ($preflight.OwnerProbe.State -cne 'exact-live' -or
        $preflight.Parsed.LauncherPid -ne $PID -or
        $selfProbe.State -ne 'observed' -or
        [long]$selfProbe.ProcessStartUtcTicks -ne
            $preflight.Parsed.LauncherProcessStartUtcTicks) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_OWNER_MISMATCH]: caller is not the exact live manifest generation (owner_state=$($preflight.OwnerProbe.State), pid=$PID, expected_ticks=$($preflight.Parsed.LauncherProcessStartUtcTicks), observed_ticks=$($selfProbe.ProcessStartUtcTicks))"
    }
    [int[]]$preflightJobPids = @($preflight.JobObjectProbe.ProcessIds)
    if ($preflight.JobObjectProbe.State -cne 'observed' -or
        $preflightJobPids.Count -ne 1 -or
        $preflightJobPids[0] -ne $PID) {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_JOB_OCCUPIED]: normal own cleanup requires the exact named Job Object to contain only launcher PID $PID (state=$($preflight.JobObjectProbe.State), pids=$($preflightJobPids -join ','), error=$($preflight.JobObjectProbe.Error))"
    }

    $handle = $null
    $dispositionSet = $false
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($full)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $snapshot $preflight.Name.Leaf `
            'attribution manifest immediately before own-cleanup disposition'
        if ($snapshot.FileId -cne $preflight.Snapshot.FileId -or
            $snapshot.Length -ne $preflight.Snapshot.Length -or
            $snapshot.Sha256 -cne $preflight.Snapshot.Sha256 -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($preflight.Snapshot.Bytes)) {
            throw 'manifest changed between own-cleanup preflight and retained mutation lease'
        }
        $name = $preflight.Name
        $parsed = Convert-AstroAttributionBytesToState `
            -Bytes $snapshot.Bytes `
            -ExpectedLauncherPid $name.LauncherPid `
            -ExpectedLauncherProcessStartUtcTicks `
                $name.LauncherProcessStartUtcTicks `
            -ExpectedLauncherLockSha256 $name.LauncherLockSha256 `
            -Path $full
        if (-not $parsed.Valid) {
            throw $parsed.Error
        }
        $expectedJob = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $preflight.RootIdentity `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks `
            -LauncherLeaseStartUtcTicks $parsed.LauncherLeaseStartUtcTicks `
            -LauncherLockSha256 $parsed.LauncherLockSha256
        if ($parsed.JobObjectName -cne $expectedJob) {
            throw 'retained manifest Job Object binding changed before own cleanup'
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe -Name $parsed.JobObjectName
        [int[]]$jobFinalPids = @($jobFinal.ProcessIds)
        if ($ownerFinal.State -cne 'exact-live' -or
            $jobFinal.State -cne 'observed' -or
            $jobFinalPids.Count -ne 1 -or
            $jobFinalPids[0] -ne $PID) {
            throw "own-cleanup owner/Job Object state changed before exact deletion (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$($jobFinalPids -join ','))"
        }
        [AstroLauncherLockNative]::FlushExactFile($handle)
        [AstroLauncherLockNative]::DeleteExactFileHandle($handle)
        # FILE_DISPOSITION_INFORMATION(TRUE) permits only CloseHandle afterward.
        # Every identity/byte/owner probe is complete above; close immediately and
        # prove the namespace terminal state through an independent path read.
        $handle.Dispose()
        $handle = $null
        $dispositionSet = $true
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $handle) {
            $handle.Dispose()
            $handle = $null
        }
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_FAILED]: disposition_set=$dispositionSet; $message"
    }
    finally {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
    }

    $terminal = Get-AstroPathEntryState $full
    if ($terminal.State -ne 'absent') {
        throw "ASTRO_ATTRIBUTION[ASTRO_ATTRIBUTION_OWN_CLEANUP_NOT_ABSENT]: exact disposition was set but terminal path state is '$($terminal.State)' ($($terminal.Error)): $full"
    }
    return [pscustomobject]@{
        Path = $full
        State = 'absent'
        FileId = $preflight.Snapshot.FileId
        Length = $preflight.Snapshot.Length
        Sha256 = $preflight.Snapshot.Sha256
        ExpectedSha256 = $expectedSha256
        DispositionSet = $dispositionSet
        OwnerProbe = $preflight.OwnerProbe
        JobObjectProbe = $preflight.JobObjectProbe
        TerminalPathState = $terminal.State
    }
}

function Get-AstroReservedAttributionEntries {
    param([Parameter(Mandatory)][string]$Directory)

    $context = Get-AstroAttributionProtocolContext $Directory
    try {
        $entries = [Collections.Generic.List[string]]::new()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries(
                $context.Directory,
                '*',
                [IO.SearchOption]::TopDirectoryOnly
            )) {
            $leaf = [IO.Path]::GetFileName($entry)
            if ($leaf.StartsWith(
                    $script:AstroAttributionManifestReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    $script:AstroAttributionStageReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    $script:AstroAttributionCleanupReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    $script:AstroAttributionRefreshReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                $leaf.StartsWith(
                    $script:AstroAttributionRefreshOldReservedPrefix,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $entries.Add([IO.Path]::GetFullPath($entry))
            }
        }
        [string[]]$ordered = @($entries)
        [Array]::Sort($ordered, [StringComparer]::OrdinalIgnoreCase)
        return [pscustomobject]@{
            Context = $context
            Paths = $ordered
        }
    }
    catch {
        throw "could not enumerate every reserved attribution/stage/refresh entry below '$($context.Directory)': $($_.Exception.Message)"
    }
}

function ConvertFrom-AstroAttributionStageName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroAttributionStageReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroAttributionStageV2Regex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            Error = 'reserved attribution stage basename is not the exact canonical v2 grammar'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $match.Groups['nonce'].Value
        Error = $null
    }
}

function ConvertFrom-AstroAttributionCleanupName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroAttributionCleanupReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroAttributionCleanupV2Regex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            Error = 'reserved attribution cleanup basename is not the exact canonical v2 grammar'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $match.Groups['nonce'].Value
        Error = $null
    }
}

function ConvertFrom-AstroAttributionRefreshName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroAttributionRefreshReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroAttributionRefreshV1Regex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            Error = 'reserved attribution refresh envelope basename is not the exact canonical v1 grammar'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        Phase = $match.Groups['phase'].Value
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $match.Groups['nonce'].Value
        Error = $null
    }
}

function ConvertFrom-AstroAttributionRefreshOldName {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $leaf = [IO.Path]::GetFileName($full)
    $candidate = $leaf.StartsWith(
        $script:AstroAttributionRefreshOldReservedPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )
    $match = [Regex]::Match(
        $leaf,
        $script:AstroAttributionRefreshOldV1Regex,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $pidValue = 0
    $ticksValue = 0L
    if (-not $match.Success -or
        -not [int]::TryParse(
            $match.Groups['pid'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$pidValue
        ) -or $pidValue -le 0 -or
        -not [long]::TryParse(
            $match.Groups['ticks'].Value,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$ticksValue
        ) -or $ticksValue -le 0 -or
        $ticksValue -gt [DateTime]::MaxValue.Ticks) {
        return [pscustomobject]@{
            Path = $full
            Leaf = $leaf
            Candidate = $candidate
            Valid = $false
            Error = 'reserved attribution refresh-old tombstone basename is not the exact canonical v1 grammar'
        }
    }
    return [pscustomobject]@{
        Path = $full
        Leaf = $leaf
        Candidate = $true
        Valid = $true
        LauncherPid = $pidValue
        LauncherProcessStartUtcTicks = $ticksValue
        LauncherLockSha256 = $match.Groups['sha'].Value
        Nonce = $match.Groups['nonce'].Value
        Error = $null
    }
}

function Get-AstroAttributionStageProbe {
    param(
        [Parameter(Mandatory)][string]$StagePath,
        [string]$RootIdentity = $null
    )

    $full = [IO.Path]::GetFullPath($StagePath)
    $leaf = [IO.Path]::GetFileName($full)
    $kind = if ($leaf.StartsWith(
            $script:AstroAttributionCleanupReservedPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        'cleanup-tombstone'
    } else {
        'stage'
    }
    $name = if ($kind -ceq 'cleanup-tombstone') {
        ConvertFrom-AstroAttributionCleanupName $full
    } else {
        ConvertFrom-AstroAttributionStageName $full
    }
    if (-not $name.Candidate -or -not $name.Valid) {
        return [pscustomobject]@{
            Kind = $kind
            State = 'unevaluable'
            Valid = $false
            Path = $full
            Error = $name.Error
            Name = $name
            Parsed = $null
            Snapshot = $null
            OwnerProbe = $null
            JobObjectProbe = $null
        }
    }

    $handle = $null
    try {
        $context = Get-AstroAttributionProtocolContext (
            [IO.Path]::GetDirectoryName($full)
        )
        if ([string]::IsNullOrEmpty($RootIdentity)) {
            $RootIdentity = $context.RootIdentity
        }
        elseif ($RootIdentity -cne $context.RootIdentity) {
            throw "caller root identity '$RootIdentity' differs from retained root identity '$($context.RootIdentity)'"
        }
        $handle = [AstroLauncherLockNative]::OpenExactProtectedReadFile($full)
        $initial = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $initial $name.Leaf "$kind probe"
        $parsed = Convert-AstroAttributionBytesToState `
            $initial.Bytes `
            $name.LauncherPid `
            $name.LauncherProcessStartUtcTicks `
            $name.LauncherLockSha256 `
            $full
        if (-not $parsed.Valid) {
            throw $parsed.Error
        }
        $expectedJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $RootIdentity `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks `
            -LauncherLeaseStartUtcTicks $parsed.LauncherLeaseStartUtcTicks `
            -LauncherLockSha256 $parsed.LauncherLockSha256
        if ($parsed.JobObjectName -cne $expectedJobName) {
            throw 'stage Job Object name does not match its exact root/PID/ticks/lease/hash derivation'
        }
        $ownerProbe = Get-AstroAttributionOwnerGenerationProbe `
            $parsed.LauncherPid `
            $parsed.LauncherProcessStartUtcTicks
        $jobProbe = Get-AstroLauncherJobObjectProbe $parsed.JobObjectName
        $final = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $final $name.Leaf "$kind probe readback"
        if ($final.FileId -cne $initial.FileId -or
            $final.Length -ne $initial.Length -or
            $final.Sha256 -cne $initial.Sha256 -or
            [Convert]::ToBase64String($final.Bytes) -cne
                [Convert]::ToBase64String($initial.Bytes)) {
            throw 'retained attribution stage changed across owner/Job Object probes'
        }
        return [pscustomobject]@{
            Kind = $kind
            State = 'valid'
            Valid = $true
            Path = $full
            Error = $null
            Name = $name
            Parsed = $parsed
            Snapshot = $final
            OwnerProbe = $ownerProbe
            JobObjectProbe = $jobProbe
            RootIdentity = $RootIdentity
            ExpectedManifestPath = Join-Path $context.Directory (
                Get-AstroAttributionManifestLeaf `
                    $parsed.LauncherPid `
                    $parsed.LauncherProcessStartUtcTicks `
                    $parsed.LauncherLockSha256 `
                    -SchemaVersion $parsed.SchemaVersion
            )
            ExpectedTempPath = Join-Path $context.Directory (
                Get-AstroLauncherTempLeaf `
                    $parsed.LauncherPid `
                    $parsed.LauncherProcessStartUtcTicks `
                    $parsed.LauncherLockSha256
            )
        }
    }
    catch {
        return [pscustomobject]@{
            Kind = $kind
            State = 'unevaluable'
            Valid = $false
            Path = $full
            Error = "$($_.FullyQualifiedErrorId): $($_.Exception.Message)"
            Name = $name
            Parsed = $null
            Snapshot = $null
            OwnerProbe = $null
            JobObjectProbe = $null
        }
    }
    finally {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
    }
}

function Get-AstroAttributionRefreshTransactions {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths,
        [Parameter(Mandatory)][string]$RootIdentity,
        [switch]$AllowMalformedRenameSuffixQuarantine
    )

    $context = Get-AstroAttributionProtocolContext $Directory
    if ($context.RootIdentity -cne $RootIdentity) {
        throw "refresh inventory root identity '$RootIdentity' differs from retained root identity '$($context.RootIdentity)'"
    }
    $envelopes = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    $oldByKey = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($path in $Paths) {
        $leaf = [IO.Path]::GetFileName($path)
        if ($leaf.StartsWith(
                $script:AstroAttributionRefreshReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
        )) {
            $name = ConvertFrom-AstroAttributionRefreshName $path
            $canonicalEnvelopePath = $path
            $recoverableRenameSuffix = $false
            if (-not $name.Valid) {
                # #624: one shipped FILE_RENAME_INFO publisher omitted the explicit
                # UTF-16 terminator/alignment padding.  The real kernel call could
                # consequently append exactly one stray code unit to the proof leaf.
                # Ordinary inventory remains strictly preserving.  The explicit
                # tracker-bound quarantine path may recognize only the one-code-unit
                # shape whose canonical prefix is an exact proof-envelope name; the
                # envelope bytes and all transaction objects are still validated below.
                $actualLeaf = [IO.Path]::GetFileName($path)
                $candidateLeaf = if ($actualLeaf.Length -gt 1) {
                    $actualLeaf.Substring(0, $actualLeaf.Length - 1)
                } else { '' }
                $candidatePath = if ([string]::IsNullOrEmpty($candidateLeaf)) {
                    ''
                } else {
                    Join-Path ([IO.Path]::GetDirectoryName($path)) $candidateLeaf
                }
                $candidateName = if ([string]::IsNullOrEmpty($candidatePath)) {
                    $null
                } else {
                    ConvertFrom-AstroAttributionRefreshName $candidatePath
                }
                if (-not $AllowMalformedRenameSuffixQuarantine -or
                    $null -eq $candidateName -or
                    -not $candidateName.Valid -or
                    $candidateName.Phase -cne 'old-disposition-set' -or
                    $actualLeaf -cne ($candidateName.Leaf +
                        $actualLeaf[$actualLeaf.Length - 1]) -or
                    (Get-AstroPathEntryState $candidatePath).State -cne 'absent') {
                    $errors.Add("refresh envelope '$path': $($name.Error)")
                    continue
                }
                $name = $candidateName
                $canonicalEnvelopePath = [IO.Path]::GetFullPath($candidatePath)
                $recoverableRenameSuffix = $true
            }
            $key = '{0}|{1}|{2}|{3}' -f @(
                $name.LauncherPid,
                $name.LauncherProcessStartUtcTicks,
                $name.LauncherLockSha256,
                $name.Nonce
            )
            if ($envelopes.ContainsKey($key)) {
                $errors.Add("refresh transaction '$key' has more than one phase envelope")
            }
            else {
                $envelopes.Add($key, [pscustomobject]@{
                        Path = $path
                        CanonicalPath = $canonicalEnvelopePath
                        Name = $name
                        RecoverableRenameSuffix = $recoverableRenameSuffix
                    })
            }
            continue
        }
        if ($leaf.StartsWith(
                $script:AstroAttributionRefreshOldReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $name = ConvertFrom-AstroAttributionRefreshOldName $path
            if (-not $name.Valid) {
                $errors.Add("refresh-old tombstone '$path': $($name.Error)")
                continue
            }
            $key = '{0}|{1}|{2}|{3}' -f @(
                $name.LauncherPid,
                $name.LauncherProcessStartUtcTicks,
                $name.LauncherLockSha256,
                $name.Nonce
            )
            if ($oldByKey.ContainsKey($key)) {
                $errors.Add("refresh transaction '$key' has more than one old tombstone")
            }
            else {
                $oldByKey.Add($key, [pscustomobject]@{ Path = $path; Name = $name })
            }
        }
    }
    foreach ($key in $oldByKey.Keys) {
        if (-not $envelopes.ContainsKey($key)) {
            $errors.Add("orphan refresh-old tombstone has no exact generation/nonce envelope: $($oldByKey[$key].Path)")
        }
    }
    $refreshGenerationCounts = [Collections.Generic.Dictionary[string, int]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($entry in $envelopes.Values) {
        $generationKey = '{0}|{1}|{2}' -f @(
            $entry.Name.LauncherPid,
            $entry.Name.LauncherProcessStartUtcTicks,
            $entry.Name.LauncherLockSha256
        )
        if ($refreshGenerationCounts.ContainsKey($generationKey)) {
            $refreshGenerationCounts[$generationKey]++
        }
        else {
            $refreshGenerationCounts.Add($generationKey, 1)
        }
    }
    foreach ($generationKey in $refreshGenerationCounts.Keys) {
        if ($refreshGenerationCounts[$generationKey] -ne 1) {
            $errors.Add("launcher generation '$generationKey' has more than one concurrent refresh transaction")
        }
    }

    $transactions = [Collections.Generic.List[object]]::new()
    foreach ($key in @($envelopes.Keys | Sort-Object)) {
        $entry = $envelopes[$key]
        $envelopeHandle = $null
        $oldHandle = $null
        $finalHandle = $null
        try {
            $envelopeHandle = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
                $entry.Path
            )
            $envelopeInitial = Get-AstroExactRetainedFileSnapshot `
                -Handle $envelopeHandle `
                -ExpectedPath $entry.Path `
                -MaximumBytes $script:AstroAttributionManifestMaxBytes
            Assert-AstroAttributionRetainedProtocolPath `
                $envelopeInitial ([IO.Path]::GetFileName($entry.Path)) `
                'attribution refresh envelope probe'
            $parsedEnvelope = Convert-AstroAttributionRefreshBytesToState `
                -Bytes $envelopeInitial.Bytes `
                -Name $entry.Name `
                -Path $entry.CanonicalPath
            if (-not $parsedEnvelope.Valid) {
                throw $parsedEnvelope.Error
            }
            $expectedJob = Get-AstroLauncherTreeJobObjectName `
                -RootIdentity $RootIdentity `
                -LauncherPid $parsedEnvelope.LauncherPid `
                -LauncherProcessStartUtcTicks `
                    $parsedEnvelope.LauncherProcessStartUtcTicks `
                -LauncherLeaseStartUtcTicks `
                    $parsedEnvelope.LauncherLeaseStartUtcTicks `
                -LauncherLockSha256 $parsedEnvelope.LauncherLockSha256
            if ($parsedEnvelope.JobObjectName -cne $expectedJob) {
                throw 'refresh envelope Job Object name differs from its exact root/generation/lease derivation'
            }
            $ownerProbe = Get-AstroAttributionOwnerGenerationProbe `
                $parsedEnvelope.LauncherPid `
                $parsedEnvelope.LauncherProcessStartUtcTicks
            $jobProbe = Get-AstroLauncherJobObjectProbe $parsedEnvelope.JobObjectName

            $oldEntry = if ($oldByKey.ContainsKey($key)) { $oldByKey[$key] } else { $null }
            $oldSnapshot = $null
            $oldParsed = $null
            if ($null -ne $oldEntry) {
                if ($oldEntry.Path -cne $parsedEnvelope.OldTombstonePath) {
                    throw 'refresh-old tombstone actual path differs from the envelope exact path binding'
                }
                $oldHandle = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
                    $oldEntry.Path
                )
                $oldSnapshot = Get-AstroExactRetainedFileSnapshot `
                    -Handle $oldHandle `
                    -ExpectedPath $oldEntry.Path `
                    -MaximumBytes $script:AstroAttributionManifestMaxBytes
                Assert-AstroAttributionRetainedProtocolPath `
                    $oldSnapshot $oldEntry.Name.Leaf `
                    'attribution refresh-old tombstone probe'
                if ($oldSnapshot.FileId -cne $parsedEnvelope.OldFinalFileId -or
                    $oldSnapshot.Length -ne $parsedEnvelope.OldFinalLength -or
                    $oldSnapshot.Sha256 -cne $parsedEnvelope.OldFinalSha256) {
                    throw 'refresh-old tombstone FILE_ID/length/hash differs from its envelope binding'
                }
                $oldParsed = Convert-AstroAttributionBytesToState `
                    $oldSnapshot.Bytes `
                    $parsedEnvelope.LauncherPid `
                    $parsedEnvelope.LauncherProcessStartUtcTicks `
                    $parsedEnvelope.LauncherLockSha256 `
                    $oldEntry.Path
                if (-not $oldParsed.Valid -or
                    $oldParsed.SchemaVersion -ne
                        $parsedEnvelope.ManifestSchemaVersion -or
                    $oldParsed.LauncherLeaseStartUtcTicks -ne
                        $parsedEnvelope.LauncherLeaseStartUtcTicks -or
                    $oldParsed.JobObjectName -cne $parsedEnvelope.JobObjectName) {
                    throw "refresh-old tombstone manifest bytes do not cross-bind the envelope generation/lease/Job: $($oldParsed.Error)"
                }
            }

            $finalState = Get-AstroPathEntryState $parsedEnvelope.FinalPath
            if ($finalState.State -eq 'unevaluable' -or
                ($finalState.State -eq 'present' -and
                    (($finalState.Attributes -band [IO.FileAttributes]::Directory) -ne 0 -or
                     ($finalState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))) {
                throw "refresh final is not an evaluable ordinary file/absence state (state=$($finalState.State), attributes=$($finalState.Attributes), error=$($finalState.Error))"
            }
            $finalSnapshot = $null
            $finalParsed = $null
            $finalBinding = 'absent'
            if ($finalState.State -eq 'present') {
                $finalHandle = [AstroLauncherLockNative]::OpenExactProtectedReadFile(
                    $parsedEnvelope.FinalPath
                )
                $finalSnapshot = Get-AstroExactRetainedFileSnapshot `
                    -Handle $finalHandle `
                    -ExpectedPath $parsedEnvelope.FinalPath `
                    -MaximumBytes $script:AstroAttributionManifestMaxBytes
                $expectedFinalLeaf = Get-AstroAttributionManifestLeaf `
                    $parsedEnvelope.LauncherPid `
                    $parsedEnvelope.LauncherProcessStartUtcTicks `
                    $parsedEnvelope.LauncherLockSha256 `
                    -SchemaVersion $parsedEnvelope.ManifestSchemaVersion
                Assert-AstroAttributionRetainedProtocolPath `
                    $finalSnapshot $expectedFinalLeaf `
                    'attribution refresh final-manifest probe'
                $finalParsed = Convert-AstroAttributionBytesToState `
                    $finalSnapshot.Bytes `
                    $parsedEnvelope.LauncherPid `
                    $parsedEnvelope.LauncherProcessStartUtcTicks `
                    $parsedEnvelope.LauncherLockSha256 `
                    $parsedEnvelope.FinalPath
                if (-not $finalParsed.Valid -or
                    $finalParsed.SchemaVersion -ne
                        $parsedEnvelope.ManifestSchemaVersion -or
                    $finalParsed.LauncherLeaseStartUtcTicks -ne
                        $parsedEnvelope.LauncherLeaseStartUtcTicks -or
                    $finalParsed.JobObjectName -cne $parsedEnvelope.JobObjectName) {
                    throw "refresh final manifest bytes do not cross-bind the envelope generation/lease/Job: $($finalParsed.Error)"
                }
                if ($finalSnapshot.FileId -ceq $parsedEnvelope.OldFinalFileId -and
                    $finalSnapshot.Length -eq $parsedEnvelope.OldFinalLength -and
                    $finalSnapshot.Sha256 -ceq $parsedEnvelope.OldFinalSha256) {
                    $finalBinding = 'old'
                }
                elseif ($finalSnapshot.FileId -ceq $parsedEnvelope.NewScratchFileId -and
                    $finalSnapshot.Length -eq $parsedEnvelope.NewManifestLength -and
                    $finalSnapshot.Sha256 -ceq $parsedEnvelope.NewManifestSha256) {
                    $finalBinding = 'new'
                }
                else {
                    throw "refresh final FILE_ID/length/hash matches neither envelope-bound object (observed_file_id=$($finalSnapshot.FileId), old_file_id=$($parsedEnvelope.OldFinalFileId), new_file_id=$($parsedEnvelope.NewScratchFileId)); byte-identical replacement is preserving"
                }
            }

            $hasOld = $null -ne $oldSnapshot
            $state = if ($parsedEnvelope.Phase -ceq 'prepared') {
                if ($finalBinding -ceq 'old' -and -not $hasOld) {
                    'prepared-envelope-old-final'
                }
                elseif ($finalBinding -ceq 'absent' -and $hasOld) {
                    'prepared-envelope-old-tombstone-no-final'
                }
                elseif ($finalBinding -ceq 'new' -and $hasOld) {
                    'prepared-envelope-old-tombstone-new-final'
                }
                else {
                    throw "unsupported prepared refresh crash cut (final_binding=$finalBinding, old_tombstone=$hasOld)"
                }
            }
            else {
                if ($finalBinding -ceq 'new' -and $hasOld) {
                    'proof-envelope-old-tombstone-new-final'
                }
                elseif ($finalBinding -ceq 'new' -and -not $hasOld) {
                    'proof-envelope-new-final'
                }
                else {
                    throw "unsupported disposition-proof refresh crash cut (final_binding=$finalBinding, old_tombstone=$hasOld)"
                }
            }

            $envelopeFinal = Get-AstroExactRetainedFileSnapshot `
                -Handle $envelopeHandle `
                -ExpectedPath $entry.Path `
                -MaximumBytes $script:AstroAttributionManifestMaxBytes
            Assert-AstroAttributionRetainedProtocolPath `
                $envelopeFinal ([IO.Path]::GetFileName($entry.Path)) `
                'attribution refresh envelope probe readback'
            if ($envelopeFinal.FileId -cne $envelopeInitial.FileId -or
                $envelopeFinal.Length -ne $envelopeInitial.Length -or
                $envelopeFinal.Sha256 -cne $envelopeInitial.Sha256 -or
                [Convert]::ToBase64String($envelopeFinal.Bytes) -cne
                    [Convert]::ToBase64String($envelopeInitial.Bytes)) {
                throw 'refresh envelope changed across transaction classification'
            }
            $logicalSnapshot = if ($state -ceq
                'prepared-envelope-old-tombstone-no-final') {
                $oldSnapshot
            } else { $finalSnapshot }
            $logicalParsed = if ($state -ceq
                'prepared-envelope-old-tombstone-no-final') {
                $oldParsed
            } else { $finalParsed }
            $transactions.Add([pscustomobject]@{
                Kind = 'refresh-transaction'
                Valid = $true
                Error = $null
                Key = $key
                State = $state
                Phase = $parsedEnvelope.Phase
                EnvelopePath = $entry.Path
                CanonicalEnvelopePath = $entry.CanonicalPath
                RecoverableRenameSuffix =
                    [bool]$entry.RecoverableRenameSuffix
                EnvelopeName = $entry.Name
                EnvelopeSnapshot = $envelopeFinal
                Parsed = $parsedEnvelope
                OldTombstonePath = $parsedEnvelope.OldTombstonePath
                OldSnapshot = $oldSnapshot
                OldParsed = $oldParsed
                FinalPath = $parsedEnvelope.FinalPath
                FinalSnapshot = $finalSnapshot
                FinalParsed = $finalParsed
                FinalBinding = $finalBinding
                LogicalFinalSnapshot = $logicalSnapshot
                LogicalFinalParsed = $logicalParsed
                OwnerProbe = $ownerProbe
                JobObjectProbe = $jobProbe
                RootIdentity = $RootIdentity
                ExpectedTempPath = Join-Path $context.Directory (
                    Get-AstroLauncherTempLeaf `
                        $parsedEnvelope.LauncherPid `
                        $parsedEnvelope.LauncherProcessStartUtcTicks `
                        $parsedEnvelope.LauncherLockSha256
                )
            })
        }
        catch {
            $message = $_.Exception.Message
            $errors.Add("refresh transaction '$key': $message")
            $transactions.Add([pscustomobject]@{
                Kind = 'refresh-transaction'
                Valid = $false
                Error = $message
                Key = $key
                State = 'unevaluable'
                EnvelopePath = $entry.Path
                EnvelopeName = $entry.Name
            })
        }
        finally {
            if ($null -ne $finalHandle) { $finalHandle.Dispose() }
            if ($null -ne $oldHandle) { $oldHandle.Dispose() }
            if ($null -ne $envelopeHandle) { $envelopeHandle.Dispose() }
        }
    }
    return [pscustomobject]@{
        Transactions = @($transactions)
        Errors = [string[]]@($errors)
    }
}

function Get-AstroAttributionInventory {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [switch]$AllowMalformedRenameSuffixQuarantine
    )

    try {
        $before = Get-AstroReservedAttributionEntries $Directory
    }
    catch {
        return [pscustomobject]@{
            State = 'unevaluable'
            Stable = $false
            Directory = [IO.Path]::GetFullPath($Directory)
            RootIdentity = $null
            Paths = @()
            Records = @()
            RefreshTransactions = @()
            Errors = @($_.Exception.Message)
        }
    }
    $records = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $refreshPaths = [Collections.Generic.List[string]]::new()
    foreach ($path in $before.Paths) {
        $leaf = [IO.Path]::GetFileName($path)
        if ($leaf.StartsWith(
                $script:AstroAttributionRefreshReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $leaf.StartsWith(
                $script:AstroAttributionRefreshOldReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $refreshPaths.Add($path)
            continue
        }
        $record = if ($leaf.StartsWith(
                $script:AstroAttributionManifestReservedPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            $manifest = Get-AstroAttributionManifestProbe `
                -ManifestPath $path `
                -RootIdentity $before.Context.RootIdentity
            $manifest | Add-Member -NotePropertyName Kind `
                -NotePropertyValue 'manifest' -Force
            $manifest
        }
        else {
            Get-AstroAttributionStageProbe `
                -StagePath $path `
                -RootIdentity $before.Context.RootIdentity
        }
        $records.Add($record)
        if (-not $record.Valid) {
            $errors.Add("$($record.Kind) '$path': $($record.Error)")
        }
        elseif ($record.OwnerProbe.State -eq 'unevaluable') {
            $errors.Add(
                "$($record.Kind) '$path' owner generation is unevaluable: $($record.OwnerProbe.Error)"
            )
        }
        elseif ($record.JobObjectProbe.State -eq 'unevaluable') {
            $errors.Add(
                "$($record.Kind) '$path' Job Object is unevaluable: $($record.JobObjectProbe.Error)"
            )
        }
    }
    $refresh = try {
        Get-AstroAttributionRefreshTransactions `
            -Directory $before.Context.Directory `
            -Paths ([string[]]@($refreshPaths)) `
            -RootIdentity $before.Context.RootIdentity `
            -AllowMalformedRenameSuffixQuarantine:$AllowMalformedRenameSuffixQuarantine
    }
    catch {
        [pscustomobject]@{
            Transactions = @()
            Errors = @($_.Exception.Message)
        }
    }
    foreach ($refreshError in [string[]]@($refresh.Errors)) {
        $errors.Add($refreshError)
    }
    foreach ($transaction in @($refresh.Transactions)) {
        if ($transaction.Valid -and
            $transaction.OwnerProbe.State -eq 'unevaluable') {
            $errors.Add(
                "refresh transaction '$($transaction.Key)' owner generation is unevaluable: $($transaction.OwnerProbe.Error)"
            )
        }
        elseif ($transaction.Valid -and
            $transaction.JobObjectProbe.State -eq 'unevaluable') {
            $errors.Add(
                "refresh transaction '$($transaction.Key)' Job Object is unevaluable: $($transaction.JobObjectProbe.Error)"
            )
        }
    }
    try {
        $after = Get-AstroReservedAttributionEntries $Directory
        $stable = $after.Paths.Count -eq $before.Paths.Count
        if ($stable) {
            for ($index = 0; $index -lt $before.Paths.Count; $index++) {
                if ($before.Paths[$index] -cne $after.Paths[$index]) {
                    $stable = $false
                    break
                }
            }
        }
        if (-not $stable) {
            $errors.Add('reserved attribution/stage/refresh inventory changed during classification')
        }
    }
    catch {
        $stable = $false
        $errors.Add("second reserved attribution inventory failed: $($_.Exception.Message)")
    }
    return [pscustomobject]@{
        State = if (-not $stable -or $errors.Count -gt 0) {
            'unevaluable'
        } elseif ($before.Paths.Count -eq 0) {
            'absent'
        } else {
            'observed'
        }
        Stable = $stable
        Directory = $before.Context.Directory
        RootIdentity = $before.Context.RootIdentity
        Paths = [string[]]@($before.Paths)
        Records = @($records)
        RefreshTransactions = @($refresh.Transactions)
        Errors = [string[]]@($errors)
    }
}

function Assert-AstroAttributionRefreshSnapshotBinding {
    param(
        [Parameter(Mandatory)]$Actual,
        [Parameter(Mandatory)]$Expected,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Actual.FileId -cne $Expected.FileId -or
        $Actual.Length -ne $Expected.Length -or
        $Actual.Sha256 -cne $Expected.Sha256 -or
        [Convert]::ToBase64String($Actual.Bytes) -cne
            [Convert]::ToBase64String($Expected.Bytes)) {
        throw "$Description changed FILE_ID/length/hash/bytes since stable classification"
    }
}

function Complete-AstroAttributionRefreshTransaction {
    param([Parameter(Mandatory)]$Transaction)

    if ($null -eq $Transaction -or -not $Transaction.Valid -or
        $Transaction.Kind -cne 'refresh-transaction') {
        throw 'refresh completion requires one valid strictly classified transaction'
    }
    if ($Transaction.OwnerProbe.State -notin @('absent', 'pid-reused') -or
        $Transaction.JobObjectProbe.State -cne 'absent') {
        throw "refresh completion is not mutation-authorizing (owner=$($Transaction.OwnerProbe.State), job=$($Transaction.JobObjectProbe.State))"
    }

    $directoryLease = $null
    $envelopeHandle = $null
    $oldHandle = $null
    $finalHandle = $null
    $envelopePath = [IO.Path]::GetFullPath($Transaction.EnvelopePath)
    $oldPath = [IO.Path]::GetFullPath($Transaction.OldTombstonePath)
    $finalPath = [IO.Path]::GetFullPath($Transaction.FinalPath)
    $proofPath = [IO.Path]::GetFullPath(
        $Transaction.Parsed.DispositionProofPath
    )
    $expectedFinalLeaf = Get-AstroAttributionManifestLeaf `
        $Transaction.Parsed.LauncherPid `
        $Transaction.Parsed.LauncherProcessStartUtcTicks `
        $Transaction.Parsed.LauncherLockSha256 `
        -SchemaVersion $Transaction.Parsed.ManifestSchemaVersion
    $expectedOldLeaf = Get-AstroAttributionRefreshOldLeaf `
        $Transaction.Parsed.LauncherPid `
        $Transaction.Parsed.LauncherProcessStartUtcTicks `
        $Transaction.Parsed.LauncherLockSha256 `
        $Transaction.Parsed.Nonce
    $expectedProofLeaf = Get-AstroAttributionRefreshEnvelopeLeaf `
        -Phase 'old-disposition-set' `
        -LauncherPid $Transaction.Parsed.LauncherPid `
        -LauncherProcessStartUtcTicks `
            $Transaction.Parsed.LauncherProcessStartUtcTicks `
        -LauncherLockSha256 $Transaction.Parsed.LauncherLockSha256 `
        -Nonce $Transaction.Parsed.Nonce
    $expectedEnvelopeLeaf = if ($Transaction.RecoverableRenameSuffix) {
        [IO.Path]::GetFileName($Transaction.EnvelopePath)
    } else {
        $Transaction.EnvelopeName.Leaf
    }
    $terminalBinding = if ($Transaction.State -ceq
        'prepared-envelope-old-tombstone-no-final' -or
        $Transaction.State -ceq 'prepared-envelope-old-final') {
        'old'
    } else { 'new' }
    $envelopeDispositionSet = $false
    $oldDispositionSet = $false
    try {
        $context = Get-AstroAttributionProtocolContext (
            [IO.Path]::GetDirectoryName($envelopePath)
        )
        if ($context.RootIdentity -cne $Transaction.RootIdentity) {
            throw 'refresh protocol root FILE_ID changed since strict classification'
        }
        $directoryLease = Open-AstroLauncherPinnedDirectoryLease (
            [IO.Path]::GetDirectoryName($envelopePath)
        )
        $envelopeHandle = [AstroLauncherLockNative]::OpenExactRenameSource(
            $envelopePath
        )
        $envelopeSnapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $envelopeHandle `
            -ExpectedPath $envelopePath `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $envelopeSnapshot $expectedEnvelopeLeaf `
            'refresh envelope mutation lease'
        Assert-AstroAttributionRefreshSnapshotBinding `
            $envelopeSnapshot $Transaction.EnvelopeSnapshot `
            'refresh envelope'

        if ($null -ne $Transaction.OldSnapshot) {
            $oldHandle = [AstroLauncherLockNative]::OpenExactRenameSource($oldPath)
            $oldSnapshot = Get-AstroExactRetainedFileSnapshot `
                -Handle $oldHandle `
                -ExpectedPath $oldPath `
                -MaximumBytes $script:AstroAttributionManifestMaxBytes
            Assert-AstroAttributionRetainedProtocolPath `
                $oldSnapshot $expectedOldLeaf `
                'refresh-old tombstone mutation lease'
            Assert-AstroAttributionRefreshSnapshotBinding `
                $oldSnapshot $Transaction.OldSnapshot `
                'refresh-old tombstone'
        }
        if ($null -ne $Transaction.FinalSnapshot) {
            $finalHandle = [AstroLauncherLockNative]::OpenExactRenameSource(
                $finalPath
            )
            $finalSnapshot = Get-AstroExactRetainedFileSnapshot `
                -Handle $finalHandle `
                -ExpectedPath $finalPath `
                -MaximumBytes $script:AstroAttributionManifestMaxBytes
            Assert-AstroAttributionRetainedProtocolPath `
                $finalSnapshot $expectedFinalLeaf `
                'refresh final-manifest mutation lease'
            Assert-AstroAttributionRefreshSnapshotBinding `
                $finalSnapshot $Transaction.FinalSnapshot `
                'refresh final'
        }

        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $Transaction.Parsed.LauncherPid `
            $Transaction.Parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe `
            $Transaction.Parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "refresh owner/Job state changed before namespace mutation (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
        }
        $scratchState = Get-AstroPathEntryState `
            $Transaction.Parsed.NewScratchPath
        if ($scratchState.State -ne 'absent') {
            throw "dead-owner refresh scratch is not exactly absent (state=$($scratchState.State), attributes=$($scratchState.Attributes), error=$($scratchState.Error)); never infer or consume scratch bytes"
        }

        switch ($Transaction.State) {
            'prepared-envelope-old-tombstone-no-final' {
                if ($null -eq $oldHandle -or $null -ne $finalHandle -or
                    (Get-AstroPathEntryState $finalPath).State -ne 'absent') {
                    throw 'rollback crash cut no longer has exactly old tombstone + absent final'
                }
                [AstroLauncherLockNative]::RenameFileHandleNoReplace(
                    $oldHandle,
                    $directoryLease.SafeFileHandle,
                    [IO.Path]::GetFileName($finalPath)
                )
                [AstroLauncherLockNative]::FlushExactFile($oldHandle)
                $restored = Get-AstroExactRetainedFileSnapshot `
                    -Handle $oldHandle `
                    -ExpectedPath $finalPath `
                    -MaximumBytes $script:AstroAttributionManifestMaxBytes
                Assert-AstroAttributionRetainedProtocolPath `
                    $restored $expectedFinalLeaf `
                    'restored refresh final manifest'
                Assert-AstroAttributionRefreshSnapshotBinding `
                    $restored $Transaction.OldSnapshot `
                    'restored old final'
                if ((Get-AstroPathEntryState $oldPath).State -ne 'absent') {
                    throw 'refresh rollback rename did not make old tombstone absent'
                }
                $finalHandle = $oldHandle
                $oldHandle = $null
                break
            }
            'prepared-envelope-old-tombstone-new-final' {
                [AstroLauncherLockNative]::RenameFileHandleNoReplace(
                    $envelopeHandle,
                    $directoryLease.SafeFileHandle,
                    [IO.Path]::GetFileName($proofPath)
                )
                [AstroLauncherLockNative]::FlushExactFile($envelopeHandle)
                $envelopePath = $proofPath
                $expectedEnvelopeLeaf = $expectedProofLeaf
                $proofSnapshot = Get-AstroExactRetainedFileSnapshot `
                    -Handle $envelopeHandle `
                    -ExpectedPath $proofPath `
                    -MaximumBytes $script:AstroAttributionManifestMaxBytes
                Assert-AstroAttributionRetainedProtocolPath `
                    $proofSnapshot $expectedEnvelopeLeaf `
                    'refresh disposition-proof envelope'
                Assert-AstroAttributionRefreshSnapshotBinding `
                    $proofSnapshot $Transaction.EnvelopeSnapshot `
                    'refresh disposition-proof envelope'
                if ((Get-AstroPathEntryState `
                        $Transaction.Parsed.PreparedEnvelopePath).State -ne
                    'absent') {
                    throw 'prepared envelope remains after exact proof transition'
                }
                break
            }
            'prepared-envelope-old-final' { break }
            'proof-envelope-old-tombstone-new-final' { break }
            'proof-envelope-new-final' { break }
            default { throw "unsupported refresh completion state '$($Transaction.State)'" }
        }

        if ($null -ne $oldHandle) {
            [AstroLauncherLockNative]::FlushExactFile($oldHandle)
            $oldBeforeDisposition = Get-AstroExactRetainedFileSnapshot `
                -Handle $oldHandle `
                -ExpectedPath $oldPath `
                -MaximumBytes $script:AstroAttributionManifestMaxBytes
            Assert-AstroAttributionRetainedProtocolPath `
                $oldBeforeDisposition $expectedOldLeaf `
                'refresh-old tombstone immediately before disposition'
            Assert-AstroAttributionRefreshSnapshotBinding `
                $oldBeforeDisposition $Transaction.OldSnapshot `
                'refresh-old tombstone before disposition'
            [AstroLauncherLockNative]::DeleteExactFileHandle($oldHandle)
            $oldHandle.Dispose()
            $oldHandle = $null
            $oldDispositionSet = $true
            if ((Get-AstroPathEntryState $oldPath).State -ne 'absent') {
                throw 'refresh-old tombstone is not absent after exact disposition'
            }
        }

        $terminalSnapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $finalHandle `
            -ExpectedPath $finalPath `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $terminalSnapshot $expectedFinalLeaf `
            'terminal refresh final manifest'
        $expectedTerminal = if ($terminalBinding -ceq 'old') {
            $Transaction.LogicalFinalSnapshot
        } else { $Transaction.FinalSnapshot }
        Assert-AstroAttributionRefreshSnapshotBinding `
            $terminalSnapshot $expectedTerminal `
            'terminal refresh final'

        [AstroLauncherLockNative]::FlushExactFile($envelopeHandle)
        $envelopeBeforeDisposition = Get-AstroExactRetainedFileSnapshot `
            -Handle $envelopeHandle `
            -ExpectedPath $envelopePath `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $envelopeBeforeDisposition $expectedEnvelopeLeaf `
            'refresh envelope immediately before disposition'
        Assert-AstroAttributionRefreshSnapshotBinding `
            $envelopeBeforeDisposition $Transaction.EnvelopeSnapshot `
            'refresh envelope before disposition'
        [AstroLauncherLockNative]::DeleteExactFileHandle($envelopeHandle)
        $envelopeHandle.Dispose()
        $envelopeHandle = $null
        $envelopeDispositionSet = $true
        if ((Get-AstroPathEntryState $envelopePath).State -ne 'absent') {
            throw 'refresh envelope is not absent after exact terminal disposition'
        }
        if ((Get-AstroPathEntryState `
                $Transaction.Parsed.NewScratchPath).State -ne 'absent') {
            throw 'refresh recovery refuses to infer new bytes while the envelope-bound scratch path is present'
        }
        return [pscustomobject]@{
            Key = $Transaction.Key
            InitialState = $Transaction.State
            State = 'final-only'
            FinalPath = $finalPath
            FinalBinding = $terminalBinding
            FinalFileId = $terminalSnapshot.FileId
            FinalLength = $terminalSnapshot.Length
            FinalSha256 = $terminalSnapshot.Sha256
            OldDispositionSet = $oldDispositionSet
            EnvelopeDispositionSet = $envelopeDispositionSet
            OwnerProbe = $ownerFinal
            JobObjectProbe = $jobFinal
        }
    }
    catch {
        throw "refresh transaction completion failed (key=$($Transaction.Key), state=$($Transaction.State), old_disposition_set=$oldDispositionSet, envelope_disposition_set=$envelopeDispositionSet): $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $finalHandle -and -not $finalHandle.IsClosed) {
            $finalHandle.Dispose()
        }
        if ($null -ne $oldHandle -and -not $oldHandle.IsClosed) {
            $oldHandle.Dispose()
        }
        if ($null -ne $envelopeHandle -and -not $envelopeHandle.IsClosed) {
            $envelopeHandle.Dispose()
        }
        if ($null -ne $directoryLease -and
            -not $directoryLease.SafeFileHandle.IsClosed) {
            $directoryLease.SafeFileHandle.Dispose()
        }
    }
}

function Resolve-AstroDeadAttributionRefreshTransactions {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Nullable[int]]$ExpectedLauncherPid = $null,
        [Nullable[long]]$ExpectedLauncherProcessStartUtcTicks = $null,
        [string]$ExpectedLauncherLockSha256 = $null,
        [object[]]$ExpectedTransactions = $null,
        [switch]$AllowMalformedRenameSuffixQuarantine
    )

    $initial = Get-AstroAttributionInventory `
        $Directory `
        -AllowMalformedRenameSuffixQuarantine:$AllowMalformedRenameSuffixQuarantine
    if (-not $initial.Stable -or @($initial.Errors).Count -gt 0) {
        throw "refresh recovery requires one stable valid attribution inventory: $(@($initial.Errors) -join '; ')"
    }
    if ($null -ne $ExpectedTransactions) {
        $expectedByKey = [Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($expected in @($ExpectedTransactions)) {
            $expectedKey = [string]$expected.key
            if ([string]::IsNullOrWhiteSpace($expectedKey) -or
                $expectedByKey.ContainsKey($expectedKey)) {
                throw 'durable refresh authorization contains a blank or duplicate transaction key'
            }
            $expectedByKey.Add($expectedKey, $expected)
        }
        if ($expectedByKey.Count -ne @($initial.RefreshTransactions).Count) {
            throw 'current refresh transaction cardinality differs from durable authorization'
        }
        foreach ($current in @($initial.RefreshTransactions)) {
            if (-not $expectedByKey.ContainsKey($current.Key)) {
                throw "current refresh transaction was not present in durable authorization: $($current.Key)"
            }
            $expected = $expectedByKey[$current.Key]
            $oldPresent = $null -ne $current.OldSnapshot
            $finalPresent = $null -ne $current.FinalSnapshot
            if ([string]$expected.state -cne $current.State -or
                [string]$expected.phase -cne $current.Phase -or
                [bool]$expected.rename_suffix_quarantine -ne
                    [bool]$current.RecoverableRenameSuffix -or
                [string]$expected.nonce -cne $current.Parsed.Nonce -or
                -not [string]::Equals(
                    [string]$expected.envelope_path,
                    $current.EnvelopePath,
                    [StringComparison]::Ordinal
                ) -or
                [string]$expected.envelope_file_identity -cne
                    $current.EnvelopeSnapshot.FileId -or
                [uint64]$expected.envelope_bytes -ne
                    $current.EnvelopeSnapshot.Length -or
                [string]$expected.envelope_sha256 -cne
                    $current.EnvelopeSnapshot.Sha256 -or
                -not [string]::Equals(
                    [string]$expected.old_tombstone_path,
                    $current.OldTombstonePath,
                    [StringComparison]::Ordinal
                ) -or
                [bool]$expected.old_tombstone_present -ne $oldPresent -or
                ($oldPresent -and
                    ([string]$expected.old_file_identity -cne
                        $current.OldSnapshot.FileId -or
                     [uint64]$expected.old_bytes -ne
                        $current.OldSnapshot.Length -or
                     [string]$expected.old_sha256 -cne
                        $current.OldSnapshot.Sha256)) -or
                -not [string]::Equals(
                    [string]$expected.final_path,
                    $current.FinalPath,
                    [StringComparison]::Ordinal
                ) -or
                [bool]$expected.final_present -ne $finalPresent -or
                [string]$expected.final_binding -cne $current.FinalBinding -or
                ($finalPresent -and
                    ([string]$expected.final_file_identity -cne
                        $current.FinalSnapshot.FileId -or
                     [uint64]$expected.final_bytes -ne
                        $current.FinalSnapshot.Length -or
                     [string]$expected.final_sha256 -cne
                        $current.FinalSnapshot.Sha256)) -or
                [string]$expected.logical_final_file_identity -cne
                    $current.LogicalFinalSnapshot.FileId -or
                [uint64]$expected.logical_final_bytes -ne
                    $current.LogicalFinalSnapshot.Length -or
                [string]$expected.logical_final_sha256 -cne
                    $current.LogicalFinalSnapshot.Sha256 -or
                [int]$expected.launcher_pid -ne
                    $current.Parsed.LauncherPid -or
                [long]$expected.launcher_process_start_utc_ticks -ne
                    $current.Parsed.LauncherProcessStartUtcTicks -or
                [string]$expected.launcher_lock_sha256 -cne
                    $current.Parsed.LauncherLockSha256 -or
                [long]$expected.launcher_lease_start_utc_ticks -ne
                    $current.Parsed.LauncherLeaseStartUtcTicks -or
                [string]$expected.job_object_name -cne
                    $current.Parsed.JobObjectName) {
                throw "current refresh transaction differs from its durable exact authorization: $($current.Key)"
            }
        }
    }
    $decisions = [Collections.Generic.List[object]]::new()
    $resolvedKeys = [Collections.Generic.List[string]]::new()
    foreach ($transaction in @($initial.RefreshTransactions)) {
        if (-not $transaction.Valid) {
            throw "invalid refresh transaction '$($transaction.Key)' is preserving: $($transaction.Error)"
        }
        if ($null -ne $ExpectedLauncherPid -and
            ($transaction.Parsed.LauncherPid -ne [int]$ExpectedLauncherPid -or
             $transaction.Parsed.LauncherProcessStartUtcTicks -ne
                [long]$ExpectedLauncherProcessStartUtcTicks -or
             $transaction.Parsed.LauncherLockSha256 -cne
                $ExpectedLauncherLockSha256)) {
            throw "refresh transaction '$($transaction.Key)' does not bind the exact requested launcher generation"
        }
        if ($transaction.OwnerProbe.State -eq 'exact-live') {
            $decisions.Add([pscustomobject]@{
                Key = $transaction.Key
                InitialState = $transaction.State
                Action = 'preserved-exact-live-owner'
                OwnerState = $transaction.OwnerProbe.State
                JobState = $transaction.JobObjectProbe.State
            })
            continue
        }
        if ($transaction.OwnerProbe.State -notin @('absent', 'pid-reused') -or
            $transaction.JobObjectProbe.State -cne 'absent') {
            throw "refresh transaction '$($transaction.Key)' is preserving because owner/Job state is not exact dead-or-reused/absent (owner=$($transaction.OwnerProbe.State), job=$($transaction.JobObjectProbe.State), pids=$(@($transaction.JobObjectProbe.ProcessIds) -join ','), error=$($transaction.JobObjectProbe.Error))"
        }
        if ($transaction.Parsed.ManifestSchemaVersion -ne 3 -or
            ($null -ne $transaction.LogicalFinalParsed -and
                -not $transaction.LogicalFinalParsed.KillOnJobCloseBound)) {
            throw "refresh transaction '$($transaction.Key)' uses diagnostic-only v$($transaction.Parsed.ManifestSchemaVersion) attribution; dead-owner Job-name absence is not recovery authority without v3 KILL_ON_JOB_CLOSE"
        }
        $result = Complete-AstroAttributionRefreshTransaction $transaction
        $resolvedKeys.Add($transaction.Key)
        $decisions.Add([pscustomobject]@{
            Key = $transaction.Key
            InitialState = $transaction.State
            Action = 'resolved-to-final-only'
            OwnerState = $result.OwnerProbe.State
            JobState = $result.JobObjectProbe.State
            Result = $result
        })
    }
    $terminal = Get-AstroAttributionInventory $Directory
    if (-not $terminal.Stable -or @($terminal.Errors).Count -gt 0) {
        throw "terminal refresh recovery inventory is unevaluable: $(@($terminal.Errors) -join '; ')"
    }
    foreach ($key in $resolvedKeys) {
        if (@($terminal.RefreshTransactions | Where-Object {
                    $_.Key -ceq $key
                }).Count -ne 0) {
            throw "resolved refresh transaction remains classifier-visible: $key"
        }
    }
    return [pscustomobject]@{
        State = if ($resolvedKeys.Count -gt 0) { 'resolved' } elseif (
            @($initial.RefreshTransactions).Count -eq 0
        ) { 'absent' } else { 'preserved-live' }
        ResolvedKeys = [string[]]@($resolvedKeys)
        Decisions = @($decisions)
        InitialInventory = $initial
        TerminalInventory = $terminal
    }
}

function Clear-DeadAttributionManifests {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [int]$SelfPid = $PID
    )

    $full = [IO.Path]::GetFullPath($Directory)
    $directoryState = Get-AstroPathEntryState $full
    if ($directoryState.State -eq 'absent') {
        return [pscustomobject]@{
            Removed = @()
            Kept = @()
            Skipped = @()
            EligiblePairs = @()
            EligibleStages = @()
            RefreshTransactions = @()
            Decisions = @()
            Errors = @()
            State = 'absent'
        }
    }
    $inventory = Get-AstroAttributionInventory $full
    $kept = [Collections.Generic.List[string]]::new()
    $skipped = [Collections.Generic.List[string]]::new()
    $eligiblePairs = [Collections.Generic.List[object]]::new()
    $eligibleStages = [Collections.Generic.List[object]]::new()
    $decisions = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    foreach ($errorText in [string[]]@($inventory.Errors)) {
        $errors.Add($errorText)
    }
    $refreshDecisions = [Collections.Generic.List[object]]::new()
    foreach ($transaction in @($inventory.RefreshTransactions)) {
        if ($transaction.Valid) {
            $kept.Add($transaction.EnvelopePath)
            if ($null -ne $transaction.OldSnapshot) {
                $kept.Add($transaction.OldTombstonePath)
            }
            $refreshDecisions.Add([pscustomobject]@{
                Key = $transaction.Key
                InitialState = $transaction.State
                Action = 'preserved-explicit-reclaim-required'
                OwnerState = $transaction.OwnerProbe.State
                JobState = $transaction.JobObjectProbe.State
            })
            $errors.Add(
                "typed attribution refresh transaction '$($transaction.Key)' is preserving; only tracker-evidenced explicit launcher reclaim may resolve it"
            )
        }
    }
    foreach ($record in $inventory.Records) {
        $reason = $null
        $eligible = $false
        if (-not $record.Valid) {
            $reason = 'malformed-or-unbound'
            $kept.Add($record.Path)
        }
        elseif ($record.OwnerProbe.State -eq 'exact-live') {
            $reason = if ($record.Parsed.LauncherPid -eq $SelfPid) {
                'exact-current-owner'
            } else {
                'exact-live-owner'
            }
            if ($record.Parsed.LauncherPid -eq $SelfPid) {
                $skipped.Add($record.Path)
            }
            else {
                $kept.Add($record.Path)
            }
        }
        elseif ($record.OwnerProbe.State -notin @('absent', 'pid-reused')) {
            $reason = 'owner-unevaluable'
            $kept.Add($record.Path)
        }
        elseif ($record.JobObjectProbe.State -cne 'absent') {
            $reason = "job-$($record.JobObjectProbe.State)"
            $kept.Add($record.Path)
        }
        elseif ($record.Parsed.SchemaVersion -ne 3 -or
            -not $record.Parsed.KillOnJobCloseBound) {
            $reason = 'diagnostic-v2-job-contract-untrustworthy'
            $kept.Add($record.Path)
            $errors.Add(
                "strict v2 attribution '$($record.Path)' is diagnostic only; named Job absence after owner death does not prove descendant absence"
            )
        }
        elseif ($record.Kind -ceq 'stage') {
            $reason = 'exact-stage-dead-owner-job-absent'
            $eligible = $true
            $kept.Add($record.Path)
            $eligibleStages.Add($record)
        }
        else {
            $tempState = Get-AstroPathEntryState $record.ExpectedTempPath
            if ($tempState.State -ne 'present' -or
                ($tempState.Attributes -band [IO.FileAttributes]::Directory) -eq 0 -or
                ($tempState.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $reason = "bound-temp-$($tempState.State)-or-invalid"
                $kept.Add($record.Path)
                $errors.Add(
                    "exact manifest '$($record.Path)' has no evaluable ordinary bound TEMP directory '$($record.ExpectedTempPath)'"
                )
            }
            else {
                $reason = 'exact-pair-dead-owner-job-absent'
                $eligible = $true
                $kept.Add($record.Path)
                $eligiblePairs.Add([pscustomobject]@{
                    ManifestPath = $record.Path
                    TempPath = $record.ExpectedTempPath
                    Record = $record
                })
            }
        }
        [int[]]$jobProcessIds = @()
        if ($record.Valid) {
            $jobProcessIds = [int[]]@(
                $record.JobObjectProbe.ProcessIds
            )
        }
        $decisions.Add([pscustomobject]@{
            Path = $record.Path
            Kind = $record.Kind
            Eligible = $eligible
            Reason = $reason
            OwnerState = if ($record.Valid) {
                $record.OwnerProbe.State
            } else { $null }
            JobState = if ($record.Valid) {
                $record.JobObjectProbe.State
            } else { $null }
            JobProcessIds = $jobProcessIds
        })
    }
    return [pscustomobject]@{
        # Pair deletion belongs to Clear-DeadLauncherTempDirs so the current launcher call
        # order cannot erase its only manifest before the TEMP classifier reads it.
        Removed = @()
        Kept = [string[]]@($kept)
        Skipped = [string[]]@($skipped)
        EligiblePairs = @($eligiblePairs)
        EligibleStages = @($eligibleStages)
        RefreshTransactions = @($refreshDecisions)
        Decisions = @($decisions)
        Errors = [string[]]@($errors)
        State = if (-not $inventory.Stable -or $errors.Count -gt 0) {
            'unevaluable'
        } elseif ($inventory.State -eq 'absent') {
            'absent'
        } else {
            'observed'
        }
        Inventory = $inventory
    }
}

function Open-AstroDeadAttributionEvidenceMutationLease {
    param([Parameter(Mandatory)]$Record)

    if ($null -eq $Record -or -not $Record.Valid -or
        $Record.Kind -cnotin @('manifest', 'stage', 'cleanup-tombstone')) {
        throw 'dead attribution evidence cleanup requires one prior valid manifest/stage/cleanup-tombstone record'
    }
    if ($Record.OwnerProbe.State -notin @('absent', 'pid-reused') -or
        $Record.JobObjectProbe.State -cne 'absent') {
        throw "dead attribution evidence preflight is not deletion-authorizing (owner=$($Record.OwnerProbe.State), job=$($Record.JobObjectProbe.State))"
    }
    if ($Record.Parsed.SchemaVersion -ne 3 -or
        -not $Record.Parsed.KillOnJobCloseBound) {
        throw "dead attribution evidence is diagnostic-only v$($Record.Parsed.SchemaVersion); exact mutation requires v3 KILL_ON_JOB_CLOSE"
    }

    $full = [IO.Path]::GetFullPath($Record.Path)
    $handle = $null
    try {
        $handle = [AstroLauncherLockNative]::OpenExactRenameSource($full)
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $handle `
            -ExpectedPath $full `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $snapshot $Record.Name.Leaf `
            'dead attribution evidence mutation lease'
        if ($snapshot.FileId -cne $Record.Snapshot.FileId -or
            $snapshot.Length -ne $Record.Snapshot.Length -or
            $snapshot.Sha256 -cne $Record.Snapshot.Sha256 -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($Record.Snapshot.Bytes)) {
            throw 'evidence file changed between classification and exact mutation lease'
        }
        $parsed = Convert-AstroAttributionBytesToState `
            $snapshot.Bytes `
            $Record.Name.LauncherPid `
            $Record.Name.LauncherProcessStartUtcTicks `
            $Record.Name.LauncherLockSha256 `
            $full
        if (-not $parsed.Valid) {
            throw $parsed.Error
        }
        $expectedJobName = Get-AstroLauncherTreeJobObjectName `
            -RootIdentity $Record.RootIdentity `
            -LauncherPid $parsed.LauncherPid `
            -LauncherProcessStartUtcTicks `
                $parsed.LauncherProcessStartUtcTicks `
            -LauncherLeaseStartUtcTicks $parsed.LauncherLeaseStartUtcTicks `
            -LauncherLockSha256 $parsed.LauncherLockSha256
        if ($parsed.JobObjectName -cne $expectedJobName) {
            throw 'retained evidence Job Object binding differs before deletion'
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $parsed.LauncherPid `
            $parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe $parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "owner/Job Object state changed before exact evidence lease acquisition (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
        }
        return [pscustomobject]@{
            OriginalPath = $full
            Path = $full
            Kind = $Record.Kind
            Record = $Record
            Handle = $handle
            SafeFileHandle = $handle
            Snapshot = $snapshot
            Parsed = $parsed
            OwnerProbe = $ownerFinal
            JobObjectProbe = $jobFinal
            ExpectedLeaf = $Record.Name.Leaf
            Disposed = $false
        }
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $handle) {
            $handle.Dispose()
        }
        throw "dead attribution evidence lease acquisition failed (path=$full): $message"
    }
}

function New-AstroAttributionCleanupNonce {
    $bytes = New-Object byte[] 16
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Move-AstroAttributionEvidenceLeaseToCleanupTombstone {
    param(
        [Parameter(Mandatory)]$Lease,
        [Parameter(Mandatory)]$DestinationDirectoryLease
    )

    if ($null -eq $Lease -or $null -eq $Lease.Handle -or
        $Lease.Handle.IsInvalid -or $Lease.Handle.IsClosed) {
        throw 'attribution cleanup rename requires one live retained evidence mutation lease'
    }
    if ($Lease.Kind -ceq 'cleanup-tombstone') {
        return [pscustomobject]@{
            State = 'already-cleanup-tombstone'
            SourcePath = $Lease.Path
            DestinationPath = $Lease.Path
            FileId = $Lease.Snapshot.FileId
            Length = $Lease.Snapshot.Length
            Sha256 = $Lease.Snapshot.Sha256
            SourcePathState = 'same-path'
        }
    }
    if ($Lease.Kind -cne 'manifest') {
        throw "only a final manifest can enter the attribution cleanup-tombstone state; observed kind '$($Lease.Kind)'"
    }

    $source = [IO.Path]::GetFullPath($Lease.Path)
    $directory = [IO.Path]::GetDirectoryName($source)
    $nonce = New-AstroAttributionCleanupNonce
    $leaf = '.astro-attribution-cleanup.v2.pid-{0}.ticks-{1}.lock-sha256-{2}.nonce-{3}.bin' -f
        $Lease.Parsed.LauncherPid,
        $Lease.Parsed.LauncherProcessStartUtcTicks,
        $Lease.Parsed.LauncherLockSha256,
        $nonce
    $destination = [IO.Path]::GetFullPath((Join-Path $directory $leaf))
    $name = ConvertFrom-AstroAttributionCleanupName $destination
    if (-not $name.Valid) {
        throw "generated attribution cleanup tombstone is not canonical: $($name.Error)"
    }
    $destinationState = Get-AstroPathEntryState $destination
    if ($destinationState.State -ne 'absent') {
        throw "attribution cleanup tombstone destination is not exactly absent (state=$($destinationState.State), error=$($destinationState.Error)): $destination"
    }

    $parent = Assert-AstroLauncherPinnedDirectoryLease (
        $DestinationDirectoryLease
    )
    if (-not [string]::Equals(
            $parent.Path,
            [IO.Path]::GetFullPath($directory).TrimEnd('\', '/'),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "retained attribution evidence is not inside the exact pinned cleanup parent ('$directory' != '$($parent.Path)')"
    }
    try {
        $before = Get-AstroExactRetainedFileSnapshot `
            -Handle $Lease.Handle `
            -ExpectedPath $source `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $before $Lease.ExpectedLeaf `
            'attribution manifest immediately before cleanup-tombstone rename'
        if ($before.FileId -cne $Lease.Snapshot.FileId -or
            $before.Length -ne $Lease.Snapshot.Length -or
            $before.Sha256 -cne $Lease.Snapshot.Sha256 -or
            [Convert]::ToBase64String($before.Bytes) -cne
                [Convert]::ToBase64String($Lease.Snapshot.Bytes)) {
            throw 'retained manifest changed before cleanup-tombstone rename'
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $Lease.Parsed.LauncherPid `
            $Lease.Parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe $Lease.Parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "owner/Job Object state changed before attribution cleanup rename (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
        }
        [AstroLauncherLockNative]::RenameFileHandleNoReplace(
            $Lease.Handle,
            $DestinationDirectoryLease.SafeFileHandle,
            $leaf
        )
        # Update the live path immediately after the only namespace mutation. If a
        # later readback fails, the caller closes the handle and leaves a reserved,
        # generation-bound tombstone for the next recovery pass.
        $Lease.Path = $destination
        $Lease.Kind = 'cleanup-tombstone'
        $Lease.ExpectedLeaf = $leaf
        [AstroLauncherLockNative]::FlushExactFile($Lease.Handle)
        $after = Get-AstroExactRetainedFileSnapshot `
            -Handle $Lease.Handle `
            -ExpectedPath $destination `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $after $Lease.ExpectedLeaf `
            'attribution cleanup-tombstone rename readback'
        if ($after.FileId -cne $before.FileId -or
            $after.Length -ne $before.Length -or
            $after.Sha256 -cne $before.Sha256 -or
            [Convert]::ToBase64String($after.Bytes) -cne
                [Convert]::ToBase64String($before.Bytes)) {
            throw 'attribution cleanup rename changed retained evidence identity or bytes'
        }
        $sourceState = Get-AstroPathEntryState $source
        if ($sourceState.State -ne 'absent') {
            throw "attribution cleanup rename did not make the original path absent (state=$($sourceState.State), error=$($sourceState.Error)): $source"
        }
        $Lease.Snapshot = $after
        return [pscustomobject]@{
            State = 'renamed'
            SourcePath = $source
            DestinationPath = $destination
            FileId = $after.FileId
            Length = $after.Length
            Sha256 = $after.Sha256
            SourcePathState = $sourceState.State
        }
    }
    finally {
        # The caller owns and continuously retains the pinned protocol directory.
        [void](Assert-AstroLauncherPinnedDirectoryLease (
            $DestinationDirectoryLease
        ))
    }
}

function Close-AstroAttributionEvidenceMutationLease {
    param([Parameter(Mandatory)]$Lease)

    if ($null -ne $Lease -and $null -ne $Lease.Handle -and
        -not $Lease.Handle.IsClosed) {
        $Lease.Handle.Dispose()
        $Lease.Disposed = $true
    }
}

function Complete-AstroDeadAttributionEvidenceDeletion {
    param([Parameter(Mandatory)]$Lease)

    if ($null -eq $Lease -or $null -eq $Lease.Handle -or
        $Lease.Handle.IsInvalid -or $Lease.Handle.IsClosed) {
        throw 'dead attribution evidence completion requires one live retained mutation lease'
    }
    $dispositionSet = $false
    try {
        $snapshot = Get-AstroExactRetainedFileSnapshot `
            -Handle $Lease.Handle `
            -ExpectedPath $Lease.Path `
            -MaximumBytes $script:AstroAttributionManifestMaxBytes
        Assert-AstroAttributionRetainedProtocolPath `
            $snapshot $Lease.ExpectedLeaf `
            'dead attribution evidence immediately before disposition'
        if ($snapshot.FileId -cne $Lease.Snapshot.FileId -or
            $snapshot.Length -ne $Lease.Snapshot.Length -or
            $snapshot.Sha256 -cne $Lease.Snapshot.Sha256 -or
            [Convert]::ToBase64String($snapshot.Bytes) -cne
                [Convert]::ToBase64String($Lease.Snapshot.Bytes)) {
            throw 'retained evidence changed before disposition completion'
        }
        $ownerFinal = Get-AstroAttributionOwnerGenerationProbe `
            $Lease.Parsed.LauncherPid `
            $Lease.Parsed.LauncherProcessStartUtcTicks
        $jobFinal = Get-AstroLauncherJobObjectProbe `
            $Lease.Parsed.JobObjectName
        if ($ownerFinal.State -notin @('absent', 'pid-reused') -or
            $jobFinal.State -cne 'absent') {
            throw "owner/Job Object state changed before exact evidence disposition (owner=$($ownerFinal.State), job=$($jobFinal.State), pids=$(@($jobFinal.ProcessIds) -join ','), error=$($jobFinal.Error))"
        }
        [AstroLauncherLockNative]::FlushExactFile($Lease.Handle)
        [AstroLauncherLockNative]::DeleteExactFileHandle($Lease.Handle)
        Close-AstroAttributionEvidenceMutationLease $Lease
        $dispositionSet = $true
    }
    catch {
        $message = $_.Exception.Message
        Close-AstroAttributionEvidenceMutationLease $Lease
        throw "dead attribution evidence deletion failed (path=$($Lease.Path), disposition_set=$dispositionSet): $message"
    }
    finally {
        Close-AstroAttributionEvidenceMutationLease $Lease
    }
    $terminal = Get-AstroPathEntryState $Lease.Path
    if ($terminal.State -ne 'absent') {
        throw "dead attribution evidence path is not absent after exact disposition (state=$($terminal.State), error=$($terminal.Error)): $($Lease.Path)"
    }
    return [pscustomobject]@{
        OriginalPath = $Lease.OriginalPath
        Path = $Lease.Path
        State = 'absent'
        FileId = $Lease.Snapshot.FileId
        Length = $Lease.Snapshot.Length
        Sha256 = $Lease.Snapshot.Sha256
        OwnerProbe = $ownerFinal
        JobObjectProbe = $jobFinal
        DispositionSet = $dispositionSet
        TerminalPathState = $terminal.State
    }
}

function Remove-AstroDeadAttributionEvidenceFile {
    param([Parameter(Mandatory)]$Record)

    $lease = $null
    try {
        $lease = Open-AstroDeadAttributionEvidenceMutationLease $Record
        return Complete-AstroDeadAttributionEvidenceDeletion $lease
    }
    finally {
        if ($null -ne $lease) {
            Close-AstroAttributionEvidenceMutationLease $lease
        }
    }
}
