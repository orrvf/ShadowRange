# PowerShell 5.1-compatible launcher for the shared Python agent.
# All remote task and HMAC validation logic lives in agent/agent.py.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateRange(1,2147483647)][int]$AllowedPid,
    [Parameter(Mandatory=$true)][string]$Config,
    [string]$Server
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script = Join-Path $root 'agent\agent.py'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw 'Missing shared Python agent' }
$argsList = @('-3', $script, '--allowed-pid', [string]$AllowedPid, '--config', $Config)
if ($Server) { $argsList += @('--server', $Server) }
& py @argsList
if ($LASTEXITCODE -ne 0) { throw "Agent exited with code $LASTEXITCODE" }
