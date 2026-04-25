<#
.SYNOPSIS
  Collect recent Windows Security and PowerShell events into a normalized JSON
  file for log-triage-bot.

.DESCRIPTION
  Pulls Security log (logon successes/failures) and Microsoft-Windows-PowerShell
  Operational events from the last N hours and emits a JSON array shaped like:

    [{
       "TimeCreated": "2026-04-24T03:15:00Z",
       "MachineName": "DC01",
       "Id": 4625,
       "User": "Administrator",
       "IpAddress": "1.2.3.4",
       "Process": "powershell.exe",
       "Parent": "winword.exe",
       "Message": "..."
    }, ...]

.EXAMPLE
  .\collect_windows_logs.ps1 -Hours 24 -OutFile windows_events.json
#>
param(
    [int]$Hours = 24,
    [string]$OutFile = "windows_events.json"
)

$start = (Get-Date).AddHours(-$Hours)

function Get-EventField {
    param($Event, [string]$Name)
    $node = $Event.Properties | Where-Object { $_ -ne $null } | Select-Object -First 1
    # Use XML for reliable field access
    $xml = [xml]$Event.ToXml()
    ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name }).'#text'
}

$results = @()

# Security log: 4624 (success) / 4625 (failure) / 4688 (process create)
$secEvents = Get-WinEvent -FilterHashtable @{
    LogName  = 'Security'
    Id       = 4624, 4625, 4688
    StartTime = $start
} -ErrorAction SilentlyContinue

foreach ($e in $secEvents) {
    $obj = [pscustomobject]@{
        TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
        MachineName = $e.MachineName
        Id          = $e.Id
        User        = (Get-EventField $e 'TargetUserName')
        IpAddress   = (Get-EventField $e 'IpAddress')
        Process     = (Get-EventField $e 'NewProcessName')
        Parent      = (Get-EventField $e 'ParentProcessName')
        Message     = $e.Message -replace "`r`n", " " -replace "\s+", " "
    }
    $results += $obj
}

# PowerShell Operational: 4104 (script block logging)
$psEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-PowerShell/Operational'
    Id        = 4104
    StartTime = $start
} -ErrorAction SilentlyContinue

foreach ($e in $psEvents) {
    $obj = [pscustomobject]@{
        TimeCreated = $e.TimeCreated.ToUniversalTime().ToString("o")
        MachineName = $e.MachineName
        Id          = $e.Id
        User        = $e.UserId
        IpAddress   = $null
        Process     = "powershell.exe"
        Parent      = $null
        Message     = $e.Message -replace "`r`n", " " -replace "\s+", " "
    }
    $results += $obj
}

$results | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "Wrote $($results.Count) events to $OutFile"
