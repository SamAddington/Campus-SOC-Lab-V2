param(
  [string]$CollectorUrl = $env:COLLECTOR_URL,
  [string]$ApiKey = $env:SOC_API_KEY,
  [string]$LogName = "Security",
  [int]$PollSeconds = 5
)

if (-not $CollectorUrl) { $CollectorUrl = "http://localhost:8001" }
if (-not $ApiKey) {
  Write-Error "Missing SOC_API_KEY (or pass -ApiKey)."
  exit 2
}

$CollectorUrl = $CollectorUrl.TrimEnd("/")
$uri = "$CollectorUrl/ingest"

Write-Host "Shipping Windows Event Log '$LogName' to $uri (poll ${PollSeconds}s)"

$lastRecordId = 0

while ($true) {
  try {
    # Pull a small batch of the newest events since last record id.
    $filter = @{ LogName = $LogName }
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction Stop |
      Sort-Object RecordId

    foreach ($ev in $events) {
      if ($ev.RecordId -le $lastRecordId) { continue }
      $lastRecordId = [int]$ev.RecordId

      $msg = $ev.Message
      if (-not $msg) { continue }
      if ($msg.Length -gt 5000) { $msg = $msg.Substring(0, 4997) + "..." }

      $payload = @{
        user_id = "host"
        email = "host@example.invalid"
        source = "windows_eventlog"
        message = $msg
        event_type = "windows_eventlog:$LogName"
        language = "en"
        consent_use_for_distillation = $false
      } | ConvertTo-Json -Depth 4

      Invoke-RestMethod -Method Post -Uri $uri -Headers @{ "X-API-Key" = $ApiKey } -ContentType "application/json" -Body $payload | Out-Null
    }
  } catch {
    Write-Warning $_.Exception.Message
  }

  Start-Sleep -Seconds $PollSeconds
}

