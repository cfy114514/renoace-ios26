param([switch]$Restore)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$recordPath = Join-Path $workspace 'out\bootchain\adb-guid-backup.json'
$resultPath = Join-Path $workspace 'out\bootchain\adb-guid-result.json'
$adbGuid = '{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}'
$result = @{ Success = $false; Restore = [bool]$Restore }
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required for this device registry key.' }
    if ($Restore) {
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
        $instance = [string]$record.InstanceId
    } else {
        $devices = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_05C6&PID_90DB&MI_05\*' -and $_.FriendlyName -eq 'ADB Interface' })
        if ($devices.Count -ne 1) { throw 'Expected exactly one current Qualcomm 90DB ADB interface.' }
        $instance = $devices[0].InstanceId
        $driver = (Get-PnpDeviceProperty -InstanceId $instance -KeyName DEVPKEY_Device_DriverInfPath).Data
        if ($driver -ne 'winusb.inf') { throw 'Driver changed; this repair only applies to Microsoft WinUSB.' }
    }
    if ($instance -notlike 'USB\VID_05C6&PID_90DB&MI_05\*') { throw 'Refusing an unrelated device.' }
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $instance + '\Device Parameters'
    if (-not (Test-Path -LiteralPath $key)) { throw 'Device parameters key missing.' }
    if ($Restore) {
        if ($record.Existed) {
            New-ItemProperty -LiteralPath $key -Name DeviceInterfaceGUIDs -PropertyType MultiString -Value ([string[]]$record.OldValues) -Force | Out-Null
        } else {
            Remove-ItemProperty -LiteralPath $key -Name DeviceInterfaceGUIDs -ErrorAction SilentlyContinue
        }
    } else {
        $properties = Get-ItemProperty -LiteralPath $key
        $existed = $properties.PSObject.Properties.Name -contains 'DeviceInterfaceGUIDs'
        $oldValues = if ($existed) { @($properties.DeviceInterfaceGUIDs) } else { @() }
        if (Test-Path -LiteralPath $recordPath) { throw 'Backup already exists; inspect it before applying a second repair.' }
        @{ InstanceId = $instance; Existed = $existed; OldValues = $oldValues; Key = $key } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $recordPath -Encoding UTF8
        $values = @($oldValues) + $adbGuid | Select-Object -Unique
        New-ItemProperty -LiteralPath $key -Name DeviceInterfaceGUIDs -PropertyType MultiString -Value ([string[]]$values) -Force | Out-Null
    }
    $restartOutput = & "$env:SystemRoot\System32\pnputil.exe" /restart-device $instance 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Device restart failed: ' + ($restartOutput -join ' ')) }
    $result.Success = $true
    $result.Message = $restartOutput -join "`n"
} catch {
    $result.Message = $_.Exception.Message
} finally {
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
