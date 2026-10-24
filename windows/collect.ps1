# ShadowRange Windows process and module snapshot collector.
# Run from PowerShell: .\windows\collect.ps1 -TargetPid 1234
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$TargetPid,

    [string]$Output = 'windows.telemetry'
)

$ErrorActionPreference = 'Stop'

try {
    $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $TargetPid" -ErrorAction Stop
    if ($null -eq $process) {
        throw "Process $TargetPid was not found."
    }

    $runtime = Get-Process -Id $TargetPid -ErrorAction Stop
    $collectedAt = (Get-Date).ToUniversalTime().ToString('o')

    $records = [System.Collections.Generic.List[object]]::new()
    $records.Add([ordered]@{
        type = 'process'
        platform = 'windows'
        pid = [int]$process.ProcessId
        ppid = [int]$process.ParentProcessId
        name = [string]$process.Name
        exe = $process.ExecutablePath
        cmdline = $process.CommandLine
        start_time_utc = $runtime.StartTime.ToUniversalTime().ToString('o')
        collected_at_utc = $collectedAt
    })

    $moduleCount = 0
    $modulesAvailable = $true
    try {
        foreach ($module in $runtime.Modules) {
            $records.Add([ordered]@{
                type = 'module'
                platform = 'windows'
                pid = [int]$process.ProcessId
                name = [string]$module.ModuleName
                path = [string]$module.FileName
            })
            $moduleCount++
        }
    }
    catch {
        $modulesAvailable = $false
        Write-Warning "Module enumeration unavailable: $($_.Exception.Message)"
        # Avoid presenting an incomplete module list as complete.
        while ($records.Count -gt 1) { $records.RemoveAt($records.Count - 1) }
    }

    # Serialize completely before touching the destination.
    $lines = foreach ($record in $records) {
        ConvertTo-Json -InputObject $record -Compress -Depth 5
    }
    $outputPath = [System.IO.Path]::GetFullPath($Output)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($outputPath)
    if (-not [System.IO.Directory]::Exists($outputDirectory)) {
        throw "Output directory does not exist: $outputDirectory"
    }
    $temporaryPath = [System.IO.Path]::Combine($outputDirectory, ([System.IO.Path]::GetRandomFileName() + '.tmp'))
    try {
        [System.IO.File]::WriteAllLines($temporaryPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
        if ([System.IO.File]::Exists($outputPath)) {
            # .NET Framework / Windows PowerShell 5.1 has no File.Move(source, destination, overwrite).
            [System.IO.File]::Replace($temporaryPath, $outputPath, $null)
        }
        else {
            [System.IO.File]::Move($temporaryPath, $outputPath)
        }
    }
    finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }

    Write-Host 'ShadowRange Windows Collector'
    Write-Host "PID: $TargetPid"
    Write-Host "Modules: $moduleCount"
    Write-Host "Module enumeration complete: $modulesAvailable"
    Write-Host "Output: $outputPath"
}
catch {
    Write-Error "Collection failed: $($_.Exception.Message)"
    exit 1
}
