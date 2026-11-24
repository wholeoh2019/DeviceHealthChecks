#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Interactive Windows 10/11 health & hardening script. Detects the hardware at runtime;
  nothing in this file is specific to any one PC.

.DESCRIPTION
  Every step asks Y/N before changing anything (use -Yes to skip prompts).
  A transcript log is written to the current user's Desktop (or -LogPath).

    0. Create a System Restore point
    1. Read-only checks: OS support status, TPM, Secure Boot, BitLocker, VBS
    2. Turn on Microsoft Defender Network Protection + PUA blocking
    3. Remove the legacy PowerShell 2.0 engine
    4. Install pending driver updates offered by Windows Update
    5. Update apps/runtimes via winget
    6. Chipset drivers: lists devices with errors and offers the CPU vendor's updater
    7. Report: old third-party drivers, firmware/BIOS info, enabled local accounts

.PARAMETER Yes
  Answer "yes" to every prompt (non-interactive).

.PARAMETER OldDriverYears
  Third-party drivers older than this many years are flagged in step 7. Default: 3.

.PARAMETER WingetIds
  winget package IDs to upgrade in step 5. Default: Visual C++ 2015+ runtimes.
  Pass @() to upgrade nothing, or '*' to run "winget upgrade --all".

.PARAMETER LogPath
  Folder for the transcript log. Default: Desktop.

.EXAMPLE
  # From an elevated PowerShell:
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\Fix-SystemHealth.ps1

.EXAMPLE
  .\Fix-SystemHealth.ps1 -Yes -OldDriverYears 2 -WingetIds '*'
#>
[CmdletBinding()]
param(
    [switch]$Yes,
    [int]$OldDriverYears = 3,
    [string[]]$WingetIds = @('Microsoft.VCRedist.2015+.x64', 'Microsoft.VCRedist.2015+.x86'),
    [string]$LogPath = [Environment]::GetFolderPath('Desktop')
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $LogPath ("SystemFix_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $log | Out-Null

function Confirm-Step([string]$Question) {
    if ($Yes) { return $true }
    do { $a = Read-Host "$Question [Y/N]" } while ($a -notmatch '^[YyNn]$')
    return $a -match '^[Yy]$'
}
function Write-Section([string]$Title) { Write-Host "`n=== $Title ===" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Fail([string]$m) { Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Info([string]$m) { Write-Host "         $m" }

# ---------------------------------------------------------------- inventory
$os    = Get-CimInstance Win32_OperatingSystem
$cv    = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cpu   = Get-CimInstance Win32_Processor | Select-Object -First 1
$board = Get-CimInstance Win32_BaseBoard
$bios  = Get-CimInstance Win32_BIOS
$isWin10 = [int]$cv.CurrentBuild -lt 22000

Write-Section 'System'
Write-Info "OS:    $($os.Caption) $($cv.DisplayVersion) (build $($cv.CurrentBuild).$($cv.UBR))"
Write-Info "CPU:   $($cpu.Name.Trim())"
Write-Info "Board: $($board.Manufacturer) $($board.Product)"
Write-Info "BIOS:  $($bios.SMBIOSBIOSVersion) ($('{0:yyyy-MM-dd}' -f $bios.ReleaseDate))"

# ---------------------------------------------------------------- 0
Write-Section '0. System Restore point'
if (Confirm-Step 'Create a restore point before changing anything? (recommended)') {
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction Stop
        Checkpoint-Computer -Description 'Before SystemHealth fixes' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Ok 'Restore point created.'
    } catch { Write-Warn "Could not create restore point: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- 1
Write-Section '1. OS support & security hardware (read-only)'
if ($isWin10) {
    Write-Warn 'Windows 10 is past end of support (consumer ESU ended Oct 2026). Plan an upgrade to Windows 11.'
} else { Write-Ok 'Windows 11.' }

$win11Ready = $true
try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent -and $tpm.TpmReady) { Write-Ok 'TPM present and ready.' }
    else { $win11Ready = $false; Write-Warn 'TPM not present/ready -> enable firmware TPM in the BIOS (Intel "PTT" / AMD "fTPM").' }
    $spec = (Get-CimInstance -Namespace root\cimv2\security\microsofttpm Win32_Tpm -ErrorAction SilentlyContinue).SpecVersion
    if ($spec) { Write-Info "TPM spec: $spec" }
} catch { $win11Ready = $false; Write-Warn "TPM query failed: $($_.Exception.Message)" }

try {
    if (Confirm-SecureBootUEFI) { Write-Ok 'Secure Boot ON.' }
    else { $win11Ready = $false; Write-Warn 'Secure Boot OFF -> enable it in the BIOS.' }
} catch { $win11Ready = $false; Write-Warn 'Secure Boot unsupported or Legacy/CSM boot mode -> switch the BIOS to UEFI-only.' }

try {
    Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
        $state = if ($_.ProtectionStatus -eq 'On') { 'ON' } else { 'OFF' }
        Write-Info "BitLocker $($_.MountPoint) : $state ($($_.VolumeStatus))"
    }
    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -ne 'On') {
        Write-Warn 'System drive is not encrypted. Optional: enable BitLocker and back up the recovery key.'
    }
} catch { Write-Warn "BitLocker status unavailable (Home edition?): $($_.Exception.Message)" }

$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2) { Write-Ok 'Virtualization-based security running.' }
else { Write-Warn 'VBS / Memory Integrity off. Optional: Windows Security > Device security > Core isolation.' }

# ---------------------------------------------------------------- 2
Write-Section '2. Microsoft Defender hardening'
try {
    $p = Get-MpPreference -ErrorAction Stop
    Write-Info "Network Protection: $($p.EnableNetworkProtection)  PUA: $($p.PUAProtection)  (0 = off, 1 = on)"
    if ($p.EnableNetworkProtection -eq 1 -and $p.PUAProtection -eq 1) { Write-Ok 'Already enabled.' }
    elseif (Confirm-Step 'Turn on Network Protection and PUA (potentially unwanted app) blocking?') {
        Set-MpPreference -EnableNetworkProtection Enabled -PUAProtection Enabled -ErrorAction Stop
        Update-MpSignature -ErrorAction SilentlyContinue
        Write-Ok 'Defender settings applied and signatures refreshed.'
    }
} catch { Write-Warn "Defender not available (third-party AV active?): $($_.Exception.Message)" }

# ---------------------------------------------------------------- 3
Write-Section '3. Legacy PowerShell 2.0 engine'
try {
    $ps2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
    if ($ps2.State -eq 'Enabled') {
        if (Confirm-Step 'PowerShell 2.0 is enabled (can be used to bypass logging). Remove it?') {
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
            Write-Ok 'PowerShell 2.0 removed (takes effect after restart).'
        }
    } else { Write-Ok 'PowerShell 2.0 not enabled.' }
} catch { Write-Ok 'PowerShell 2.0 feature not present.' }

# ---------------------------------------------------------------- 4
Write-Section '4. Driver updates from Windows Update'
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    Write-Info 'Searching (this can take a minute)...'
    $res = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")
    if ($res.Updates.Count -eq 0) { Write-Ok 'No pending driver updates.' }
    else {
        $res.Updates | ForEach-Object { Write-Info "- $($_.Title)" }
        if (Confirm-Step "Install these $($res.Updates.Count) driver update(s)?") {
            $coll = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($u in $res.Updates) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$coll.Add($u) }
            $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
            $in = $session.CreateUpdateInstaller();  $in.Updates = $coll; $r = $in.Install()
            # ResultCode: 2 = succeeded, 3 = succeeded with errors, 4 = failed
            if ($r.ResultCode -eq 2) { Write-Ok 'Driver updates installed.' } else { Write-Warn "Install result code $($r.ResultCode)." }
            if ($r.RebootRequired) { Write-Warn 'A restart is required.' }
        }
    }
} catch { Write-Fail "Windows Update driver step failed: $($_.Exception.Message)" }

# ---------------------------------------------------------------- 5
$winget = Get-Command winget -ErrorAction SilentlyContinue
$wingetArgs = @('--silent', '--accept-package-agreements', '--accept-source-agreements')
Write-Section '5. App/runtime updates (winget)'
if (-not $winget) { Write-Warn 'winget not found - install "App Installer" from the Microsoft Store.' }
elseif (-not $WingetIds -or $WingetIds.Count -eq 0) { Write-Info 'Skipped (no -WingetIds given).' }
elseif ($WingetIds -contains '*') {
    winget upgrade --accept-source-agreements
    if (Confirm-Step 'Upgrade ALL packages listed above?') { winget upgrade --all @wingetArgs }
}
elseif (Confirm-Step "Upgrade: $($WingetIds -join ', ')?") {
    foreach ($id in $WingetIds) { winget upgrade --id $id -e @wingetArgs }
    Write-Host "`n         Other packages with updates available:"; winget upgrade --accept-source-agreements
}

# ---------------------------------------------------------------- 6
Write-Section '6. Devices with errors / chipset drivers'
$bad = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
if ($bad.Count -eq 0) { Write-Ok 'No devices report errors.' }
else {
    $bad | ForEach-Object { Write-Info "- $($_.Name)  (error code $($_.ConfigManagerErrorCode))" }
    Write-Info 'Code 28 = no driver installed. Usually fixed by the chipset driver package.'
}

if ($cpu.Manufacturer -match 'Intel') {
    if ($winget -and (Confirm-Step 'Install Intel Driver & Support Assistant (official Intel updater)?')) {
        winget install --id Intel.IntelDriverAndSupportAssistant -e @wingetArgs
        if ($LASTEXITCODE -eq 0) {
            Write-Ok 'Installed. Opening the Intel DSA page - install the suggested Chipset, ME, and network drivers there.'
            Start-Process 'https://www.intel.com/content/www/us/en/support/intel-driver-support-assistant.html'
        } else { Write-Warn 'winget install failed - use your motherboard/PC vendor support page instead.' }
    }
} elseif ($cpu.Manufacturer -match 'AMD') {
    Write-Info 'AMD platform: install "AMD Chipset Drivers" from https://www.amd.com/en/support'
    if (Confirm-Step 'Open the AMD drivers page now?') { Start-Process 'https://www.amd.com/en/support/download/drivers.html' }
}
Write-Info "Alternative: $($board.Manufacturer) support page for '$($board.Product)' > Drivers."

# ---------------------------------------------------------------- 7
Write-Section '7. Report (manual follow-ups)'

# Firmware
$biosAgeYears = ((Get-Date) - $bios.ReleaseDate).TotalDays / 365
if ($biosAgeYears -gt 1) {
    Write-Warn ("BIOS is {0:N1} years old. Check {1} for an update to '{2}' (do this before a major OS upgrade)." -f $biosAgeYears, $board.Manufacturer, $board.Product)
} else { Write-Ok 'BIOS is less than a year old.' }

# Old third-party drivers
$cutoff = (Get-Date).AddYears(-$OldDriverYears)
$old = Get-CimInstance Win32_PnPSignedDriver |
    Where-Object { $_.DriverDate -and $_.DriverDate -lt $cutoff -and $_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft' } |
    Sort-Object DeviceName -Unique
if ($old) {
    Write-Warn "Third-party drivers older than $OldDriverYears years (update from the vendor, or uninstall if the device is unused):"
    $old | ForEach-Object { Write-Info ("- {0}  [{1} {2}, {3:yyyy-MM-dd}]" -f $_.DeviceName, $_.DriverProviderName, $_.DriverVersion, $_.DriverDate) }
} else { Write-Ok "No third-party drivers older than $OldDriverYears years." }

# Local accounts (built-in SID suffixes 500/501/503/504 excluded)
$users = Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' }
Write-Info "Enabled local accounts: $(@($users).Count). Review that each is still needed and has a strong password (lusrmgr.msc)."
$admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
Write-Info "Members of Administrators: $(@($admins).Count)"
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
if ($builtinAdmin.Enabled) { Write-Warn 'The built-in Administrator account is enabled - consider disabling it.' }

if ($isWin10) {
    if ($win11Ready) { Write-Ok 'TPM and Secure Boot look ready for Windows 11 (confirm with PC Health Check).' }
    else { Write-Warn 'Fix the TPM / Secure Boot items above before upgrading to Windows 11.' }
}

$still = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
if ($still.Count) { Write-Warn "$($still.Count) device(s) still report problems (re-check after a restart)." }

Write-Host "`nLog saved to: $log" -ForegroundColor Cyan
Write-Host 'Restart the PC to finish any driver/feature changes.' -ForegroundColor Cyan
Stop-Transcript | Out-Null
