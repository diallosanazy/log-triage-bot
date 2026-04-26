<#
.SYNOPSIS
    Collect recent IIS access events from W3C-formatted log files and emit
    them as NDJSON that the Python analyzer can ingest directly.

.PARAMETER LogDir
    Directory containing IIS W3C log files. Defaults to the standard
    C:\inetpub\logs\LogFiles\W3SVC1 path.

.PARAMETER Hours
    Look back this many hours. Defaults to 24.

.PARAMETER OutFile
    Path to the resulting NDJSON file. Defaults to .\iis_events.json.

.EXAMPLE
    .\collect_iis_logs.ps1 -Hours 24 -OutFile iis_events.json
#>
[CmdletBinding()]
param(
    [string] $LogDir = 'C:\inetpub\logs\LogFiles\W3SVC1',
    [int]    $Hours  = 24,
    [string] $OutFile = '.\iis_events.json'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $LogDir)) {
    Write-Error "IIS log directory not found: $LogDir"
    exit 1
}

$cutoff = (Get-Date).ToUniversalTime().AddHours(-$Hours)
$files  = Get-ChildItem -Path $LogDir -Filter 'u_ex*.log' |
          Where-Object { $_.LastWriteTimeUtc -ge $cutoff.AddDays(-1) }

if (-not $files) {
    Write-Warning "No IIS log files found under $LogDir"
    '' | Set-Content -Path $OutFile -Encoding utf8
    exit 0
}

# Build the writer once; we'll append one JSON object per line.
$writer = [System.IO.StreamWriter]::new($OutFile, $false, [System.Text.UTF8Encoding]::new($false))
try {
    $fields = @()
    foreach ($file in $files) {
        foreach ($line in Get-Content $file) {
            if ($line.StartsWith('#Fields:')) {
                $fields = $line.Substring(8).Trim() -split '\s+'
                continue
            }
            if ($line.StartsWith('#')) { continue }
            if (-not $fields) { continue }

            $parts = $line -split '\s+'
            if ($parts.Count -lt $fields.Count) { continue }

            $row = @{}
            for ($i = 0; $i -lt $fields.Count; $i++) {
                $row[$fields[$i]] = $parts[$i]
            }

            $dateStr = "$($row['date']) $($row['time'])"
            try {
                $ts = [datetime]::ParseExact($dateStr, 'yyyy-MM-dd HH:mm:ss',
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
            } catch { continue }

            if ($ts -lt $cutoff) { continue }

            $status = 0
            [int]::TryParse($row['sc-status'], [ref]$status) | Out-Null
            $level = if ($status -ge 500) { 'ERROR' }
                     elseif ($status -ge 400) { 'WARNING' }
                     else { 'INFO' }

            $rt = $null
            if ($row.ContainsKey('time-taken')) {
                [int]::TryParse($row['time-taken'], [ref]([int]0)) | Out-Null
                $rt = [int]$row['time-taken']
            }

            $obj = [ordered]@{
                ts          = $ts.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                source      = 'iis'
                level       = $level
                endpoint    = $row['cs-uri-stem']
                user_id     = if ($row['cs-username'] -and $row['cs-username'] -ne '-') { $row['cs-username'] } else { '' }
                exception   = ''
                response_ms = $rt
                message     = "$($row['cs-method']) $($row['cs-uri-stem']) -> $status"
            }
            $writer.WriteLine(($obj | ConvertTo-Json -Compress))
        }
    }
} finally {
    $writer.Dispose()
}

Write-Host "Wrote $OutFile"
