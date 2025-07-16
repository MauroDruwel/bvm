# Define log file path
$LogFile = "C:\Windows\Temp\firstlogin_log.txt"

# Start logging
Start-Transcript -Path $LogFile -Append

# Function to log and execute commands
function Execute-Command {
    param (
        [string]$Command
    )
    Write-Output "`n========== Executing: $Command =========="
    $Output = Invoke-Expression $Command 2>&1
    $Output
    if ($LASTEXITCODE -ne 0) {
        Write-Output "ERROR: Command failed with exit code $LASTEXITCODE"
    }
    Write-Output "========== End of Output ==========`n"
}

Write-Output "BVM setting up this Virtual Machine... please do not close this window! This VM will shutdown once done."

Start-Sleep -Seconds 5

# Disable Hibernation
Execute-Command "powercfg -H OFF"

# Disable recovery environment partition
Execute-Command "reagentc /disable"

# qemu guest agent
Execute-Command 'msiexec /i E:\guest-agent\qemu-ga-x86_64.msi /quiet /passive /qn'

# Enable rounded corners
Execute-Command 'reg add HKLM\SOFTWARE\Microsoft\Windows\Dwm /v ForceEffectMode /t REG_DWORD /d 2 /f'

# Enable RDP
Execute-Command 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
Execute-Command 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f'

# Allow incoming RDP connections through the firewall
Execute-Command 'netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389'

# Configure and start Remote Desktop Service
Execute-Command 'sc config TermService start=auto'
Execute-Command 'net start TermService'

# Logout account after RDP connection is inactive for 1 minute
# This is now skipped due to https://github.com/Botspot/bvm/issues/48
#Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MaxDisconnectionTime /t REG_DWORD /d 60000 /f'

# Block Windows feature updates (prevents 22H2 -> 23H2 upgrade)
Write-Output "`n========== Blocking Windows Feature Updates =========="
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v TargetReleaseVersion /t REG_DWORD /d 1 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v TargetReleaseVersionInfo /t REG_SZ /d "22H2" /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ProductVersion /t REG_SZ /d "Windows 11" /f'

# Additional Windows Update controls
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v IncludeRecommendedUpdates /t REG_DWORD /d 1 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f'

# Block feature updates via additional registry keys
Execute-Command 'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v DeferFeatureUpdatesPeriodInDays /t REG_DWORD /d 365 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f'

# Set Windows Update to download security updates only
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DeferFeatureUpdates /t REG_DWORD /d 1 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DeferFeatureUpdatesPeriodInDays /t REG_DWORD /d 365 /f'
Execute-Command 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v BranchReadinessLevel /t REG_DWORD /d 32 /f'

Write-Output "Windows Update configured to stay on 22H2 and only install security updates."

# Prevent "your password has expired and must be changed" after 42 days from using BVM
Execute-Command 'net accounts /maxpwage:unlimited'

# Allow Windows upgrades with unsupported TPM or CPU
Execute-Command 'reg add HKLM\SYSTEM\Setup\MoSetup /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 0x00000001 /f'

# Enable Dark Mode for System UI, Apps, and wallpaper
Execute-Command 'reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize /v SystemUsesLightTheme /t REG_DWORD /d 0 /f'
Execute-Command 'reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize /v AppsUseLightTheme /t REG_DWORD /d 0 /f'
Execute-Command 'reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\WINDOWS\web\wallpaper\Windows\img19.jpg" /f'

# Activate Windows using a generic license key from microsoft
Execute-Command 'slmgr /ipk VK7JG-NPHTM-C97JM-9MPGT-3V66T'

# Run debloat script and log output
$DebloatScript = "E:\Win11Debloat\Win11Debloat.ps1"
if (Test-Path $DebloatScript) {
    Write-Output "Executing Debloat Script..."
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File $DebloatScript -RunDefaults -Silent
    if ($LASTEXITCODE -ne 0) {
        Write-Output "ERROR: Debloat script failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Output "WARNING: Debloat script not found at $DebloatScript"
}

# Shutdown after completion
Execute-Command 'shutdown.exe -s -t 60 -c "First-run setup complete. This VM will SHUTDOWN in 60 seconds"'

# Stop logging
Stop-Transcript
