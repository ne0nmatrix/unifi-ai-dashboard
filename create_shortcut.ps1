# ============================================================
#  Run ONCE to create a taskbar-pinnable Desktop shortcut for
#  the UniFi AI Dashboard launcher.
#
#  Usage: right-click this file -> "Run with PowerShell"
#         (or in a terminal:  powershell -ExecutionPolicy Bypass -File .\create_shortcut.ps1)
# ============================================================

$proj    = 'M:\repos\unifi-ai-dashboard'
$bat     = Join-Path $proj 'Launch UniFi Dashboard.bat'
$desktop = [Environment]::GetFolderPath('Desktop')
$lnkPath = Join-Path $desktop 'UniFi AI Dashboard.lnk'

$ws  = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($lnkPath)

# Target cmd.exe (NOT the .bat directly) so Windows offers "Pin to taskbar".
# Shortcuts whose target is a .bat/.cmd can't be pinned; an .exe target can.
$lnk.TargetPath       = "$env:WINDIR\System32\cmd.exe"
$lnk.Arguments        = "/c `"$bat`""
$lnk.WorkingDirectory = $proj
$lnk.IconLocation     = "$env:WINDIR\System32\shell32.dll,13"   # network/globe icon; change if you like
$lnk.WindowStyle      = 7                                       # 7 = launch minimized
$lnk.Description       = 'Kill + relaunch the UniFi AI Dashboard Flask app'
$lnk.Save()

Write-Host "Created shortcut: $lnkPath"
Write-Host ""
Write-Host "To pin it: right-click the shortcut -> Show more options -> Pin to taskbar."
