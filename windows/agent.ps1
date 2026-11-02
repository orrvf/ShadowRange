# Visible Windows PowerShell 5.1 agent for the localhost ShadowRange laboratory.
# No arbitrary shell commands, stealth, persistence, or remote network binding.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$AllowedPid,

    [ValidateRange(2, 60)]
    [int]$IntervalSeconds = 5,

    [ValidatePattern('^[a-zA-Z0-9_-]{1,48}$')]
    [string]$AgentId = 'windows-lab'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tokenPath = Join-Path $root '.shadowrange-lab-tokens'
$collector = Join-Path $PSScriptRoot 'collect.ps1'
$server = 'http://127.0.0.1:8000'
$maxTelemetryBytes = 1000000

if (-not (Test-Path -LiteralPath $collector -PathType Leaf)) {
    throw "Collector not found: $collector"
}
if (-not (Test-Path -LiteralPath $tokenPath -PathType Leaf)) {
    throw 'Token file missing. Generate tokens in WSL as in the Linux MVP.'
}
# Parse only the dedicated agent token, without executing the shell token file.
$tokenLine = Get-Content -LiteralPath $tokenPath | Where-Object { $_ -match '^export SHADOWRANGE_AGENT_TOKEN=[0-9a-fA-F]{16,}$' } | Select-Object -First 1
if (-not $tokenLine) { throw 'SHADOWRANGE_AGENT_TOKEN missing or malformed in token file.' }
$token = ($tokenLine -split '=', 2)[1].Trim()
$headers = @{ Authorization = "Bearer $token" }

function Post-LabJson([string]$Route, [hashtable]$Payload) {
    $json = ConvertTo-Json -InputObject $Payload -Depth 6 -Compress
    return Invoke-RestMethod -Uri ($server + $Route) -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 12
}

function Collect-ApprovedProcess([int]$TargetPid) {
    $output = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + '.jsonl')
    try {
        # Invoke the known collector script with fixed parameters, not a remote command string.
        $global:LASTEXITCODE = 0
        & $collector -TargetPid $TargetPid -Output $output | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Windows collector reported failure' }
        if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw 'Collector did not produce telemetry' }
        $bytes = [System.IO.File]::ReadAllBytes($output)
        if ($bytes.Length -eq 0 -or $bytes.Length -gt $maxTelemetryBytes) {
            throw 'Collector output empty or exceeds 1 MB limit'
        }
        return [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    finally {
        if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Force }
    }
}

Write-Host "ShadowRange Windows lab agent active: id=$AgentId, allowed_pid=$AllowedPid. Ctrl+C to stop."
while ($true) {
    try {
        $reply = Post-LabJson '/agent/poll' @{ agent_id = $AgentId }
        $task = $reply.task
        if ($null -ne $task) {
            $result = @{ agent_id = $AgentId; task_id = [string]$task.id; status = 'ok' }
            try {
                if ($task.action -eq 'health') {
                    # No other action required.
                }
                elseif ($task.action -eq 'collect_process' -and $null -ne $task.pid -and [int]$task.pid -eq $AllowedPid) {
                    $result.telemetry = Collect-ApprovedProcess -TargetPid $AllowedPid
                }
                else {
                    throw 'Task was not approved by this agent'
                }
            }
            catch {
                $result = @{ agent_id = $AgentId; task_id = [string]$task.id; status = 'error'; error = $_.Exception.Message.Substring(0, [Math]::Min(200, $_.Exception.Message.Length)) }
            }
            [void](Post-LabJson '/agent/result' $result)
            Write-Host "Task $($task.id) ($($task.action)): $($result.status)"
        }
    }
    catch {
        Write-Warning "Controller unavailable or response rejected: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $IntervalSeconds
}
