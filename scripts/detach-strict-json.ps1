<#
.SYNOPSIS
    Compiler-free strict flat-JSON decoder used during detached bootstrap.

.DESCRIPTION
    Rejects duplicate decoded names, non-scalar values, malformed numbers,
    invalid escapes, and trailing data before any Add-Type compiler is loaded.
    This is a bootstrap dependency of detach-protocol.ps1. Refs #717.
#>

Set-StrictMode -Version Latest

function Get-AstroJsonNextTokenIndex {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex
    )

    $index = $StartIndex
    while ($index -lt $Json.Length -and
        ($Json[$index] -eq ' ' -or $Json[$index] -eq "`t" -or
            $Json[$index] -eq "`r" -or $Json[$index] -eq "`n")) {
        $index++
    }
    return $index
}

function Read-AstroJsonStringToken {
    param(
        [Parameter(Mandatory)][string]$Json,
        [Parameter(Mandatory)][int]$StartIndex
    )

    if ($StartIndex -ge $Json.Length -or $Json[$StartIndex] -ne '"') {
        throw "expected a JSON string token at character $StartIndex"
    }
    $builder = [Text.StringBuilder]::new()
    $index = $StartIndex + 1
    while ($index -lt $Json.Length) {
        $character = $Json[$index]
        if ($character -eq '"') {
            return [pscustomobject]@{
                Value = $builder.ToString()
                Raw = $Json.Substring($StartIndex, $index - $StartIndex + 1)
                NextIndex = $index + 1
            }
        }
        if ([int]$character -lt 0x20) {
            throw "unescaped control character in JSON string at character $index"
        }
        if ($character -ne '\') {
            [void]$builder.Append($character)
            $index++
            continue
        }

        $index++
        if ($index -ge $Json.Length) {
            throw 'unterminated JSON escape sequence'
        }
        $escape = $Json[$index]
        switch ($escape) {
            '"' { [void]$builder.Append('"') }
            '\' { [void]$builder.Append('\') }
            '/' { [void]$builder.Append('/') }
            'b' { [void]$builder.Append([char]0x08) }
            'f' { [void]$builder.Append([char]0x0c) }
            'n' { [void]$builder.Append([char]0x0a) }
            'r' { [void]$builder.Append([char]0x0d) }
            't' { [void]$builder.Append([char]0x09) }
            'u' {
                if ($index + 4 -ge $Json.Length) {
                    throw "truncated JSON Unicode escape at character $($index - 1)"
                }
                $hex = $Json.Substring($index + 1, 4)
                if ($hex -cnotmatch '^[0-9a-fA-F]{4}$') {
                    throw "invalid JSON Unicode escape '\u$hex'"
                }
                $codeUnit = [Convert]::ToInt32($hex, 16)
                $index += 4
                if ($codeUnit -ge 0xd800 -and $codeUnit -le 0xdbff) {
                    if ($index + 6 -ge $Json.Length -or
                        $Json[$index + 1] -ne '\' -or
                        $Json[$index + 2] -ne 'u') {
                        throw 'high surrogate JSON escape is not followed by a low surrogate'
                    }
                    $lowHex = $Json.Substring($index + 3, 4)
                    if ($lowHex -cnotmatch '^[0-9a-fA-F]{4}$') {
                        throw "invalid low-surrogate JSON escape '\u$lowHex'"
                    }
                    $lowCodeUnit = [Convert]::ToInt32($lowHex, 16)
                    if ($lowCodeUnit -lt 0xdc00 -or
                        $lowCodeUnit -gt 0xdfff) {
                        throw 'high surrogate JSON escape is not followed by a low surrogate'
                    }
                    [void]$builder.Append([char]$codeUnit)
                    [void]$builder.Append([char]$lowCodeUnit)
                    $index += 6
                }
                elseif ($codeUnit -ge 0xdc00 -and $codeUnit -le 0xdfff) {
                    throw 'unpaired low-surrogate JSON escape'
                }
                else {
                    [void]$builder.Append([char]$codeUnit)
                }
            }
            default { throw "invalid JSON escape sequence '\$escape'" }
        }
        $index++
    }
    throw "unterminated JSON string token at character $StartIndex"
}

function ConvertFrom-AstroStrictFlatJsonObject {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Json)

    $properties = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    $names = [Collections.Generic.List[string]]::new()
    $index = Get-AstroJsonNextTokenIndex $Json 0
    if ($index -ge $Json.Length -or $Json[$index] -ne '{') {
        throw 'JSON root must be one object'
    }
    $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
    if ($index -lt $Json.Length -and $Json[$index] -eq '}') {
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -ne $Json.Length) {
            throw "unexpected data after JSON object at character $index"
        }
        return [pscustomobject]@{
            Properties = $properties
            Names = @()
            Raw = $Json
        }
    }

    while ($true) {
        $nameToken = Read-AstroJsonStringToken $Json $index
        $name = [string]$nameToken.Value
        if ($properties.ContainsKey($name)) {
            throw "duplicate decoded JSON property '$name'"
        }
        $index = Get-AstroJsonNextTokenIndex $Json $nameToken.NextIndex
        if ($index -ge $Json.Length -or $Json[$index] -ne ':') {
            throw "expected ':' after JSON property '$name'"
        }
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
        if ($index -ge $Json.Length) {
            throw "missing value for JSON property '$name'"
        }

        $entry = $null
        if ($Json[$index] -eq '"') {
            $valueToken = Read-AstroJsonStringToken $Json $index
            $entry = [pscustomobject]@{
                Kind = 'string'
                Value = [string]$valueToken.Value
                Raw = [string]$valueToken.Raw
            }
            $index = $valueToken.NextIndex
        }
        elseif ($Json[$index] -eq '-' -or
            ($Json[$index] -ge '0' -and $Json[$index] -le '9')) {
            $numberMatch = [Regex]::Match(
                $Json.Substring($index),
                '^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
                [Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            if (-not $numberMatch.Success) {
                throw "invalid JSON number for property '$name'"
            }
            $rawNumber = $numberMatch.Value
            $entry = [pscustomobject]@{
                Kind = if ($rawNumber -cmatch '^-?(?:0|[1-9][0-9]*)$') {
                    'integer'
                }
                else {
                    'number'
                }
                Value = $rawNumber
                Raw = $rawNumber
            }
            $index += $rawNumber.Length
        }
        elseif ($Json.Substring($index).StartsWith(
                'true', [StringComparison]::Ordinal
            )) {
            $entry = [pscustomobject]@{
                Kind = 'boolean'; Value = $true; Raw = 'true'
            }
            $index += 4
        }
        elseif ($Json.Substring($index).StartsWith(
                'false', [StringComparison]::Ordinal
            )) {
            $entry = [pscustomobject]@{
                Kind = 'boolean'; Value = $false; Raw = 'false'
            }
            $index += 5
        }
        elseif ($Json.Substring($index).StartsWith(
                'null', [StringComparison]::Ordinal
            )) {
            $entry = [pscustomobject]@{
                Kind = 'null'; Value = $null; Raw = 'null'
            }
            $index += 4
        }
        else {
            throw "JSON property '$name' must have a scalar string/number/boolean/null value"
        }

        $properties.Add($name, $entry)
        $names.Add($name)
        $index = Get-AstroJsonNextTokenIndex $Json $index
        if ($index -ge $Json.Length) {
            throw 'unterminated JSON object'
        }
        if ($Json[$index] -eq '}') {
            $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
            if ($index -ne $Json.Length) {
                throw "unexpected data after JSON object at character $index"
            }
            break
        }
        if ($Json[$index] -ne ',') {
            throw "expected ',' or '}' at character $index"
        }
        $index = Get-AstroJsonNextTokenIndex $Json ($index + 1)
    }

    return [pscustomobject]@{
        Properties = $properties
        Names = @($names)
        Raw = $Json
    }
}
