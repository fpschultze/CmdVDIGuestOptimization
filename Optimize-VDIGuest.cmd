:: 
:: Optimize-VDIGuest.cmd
::
:: Optimizes the Default User settings and Local Machine settings for usage
:: within a Virtual Desktop Infrastructure
::
:: Frank Peter Schultze
::

:: ============================================================================
:: Default User Settings
:: ============================================================================

:: Setting Default HKCU values by loading and modifying the default user registry hive
reg.exe LOAD "HKU\TEMP" "%USERPROFILE%\..\Default User\NTUSER.DAT"

:: Disable Logon Screensaver
reg.exe ADD "HKU\TEMP\Control Panel\Desktop" /v "ScreenSaveActive" /d "0" /f

:: Force Offscreen Composition for Internet Explorer
reg.exe ADD "HKU\TEMP\Software\Microsoft\Internet Explorer\Main" /v "Force Offscreen Composition" /t REG_DWORD /d 0x1 /f

:: Reduce Menu Show Delay
reg.exe ADD "HKU\TEMP\Control Panel\Desktop" /v "MenuShowDelay" /d "1" /f

:: Disable all Visual Effects except "Use common tasks in folders" and "Use visual styles on windows and buttons"
reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 0x3 /f
reg.exe ADD "HKU\TEMP\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /d "0" /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewWatermark" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKU\TEMP\Control Panel\Desktop" /v "DragFullWindows" /d "0" /f
reg.exe ADD "HKU\TEMP\Control Panel\Desktop" /v "FontSmoothing" /d "0" /f
reg.exe ADD "HKU\TEMP\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "90 12 01 80 10 00 00 00" /f

reg.exe ADD "HKU\TEMP\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v SCRNSAVE.
reg.exe ADD "HKU\TEMP\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveTimeOut /d "600" /f
reg.exe ADD "HKU\TEMP\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /d "1" /f

reg.exe ADD "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /d " " /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\Feeds" /v SyncStatus /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKU\TEMP\Software\Microsoft\WIndows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 0x1 /f

reg.exe UNLOAD "HKU\TEMP"


:: ============================================================================
:: Machine Settings
:: ============================================================================

:: Disable NTFS Last Access Timestamp
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 0x1 /f

:: Disable Large Send Offload
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Services\BNNS\Parameters" /v "EnableOffload" /t REG_DWORD /d 0x0 /f

:: Disable TCP/IP Offload
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d 0x1 /f

:: Increase Service Startup Timeout
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d 0x2bf20 /f

:: Hide Hard Error Messages
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\Windows" /v "ErrorMode" /t REG_DWORD /d 0x2 /f

:: Disable CIFS Change Notifications
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRemoteRecursiveEvents" /t REG_DWORD /d 0x1 /f

:: Disable Offline Files
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache" /v "Enabled" /t REG_DWORD /d 0x0 /f

:: Disable Background Defragmentation
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /d "N" /f

:: Disable Background Layout Service
reg.exe ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d 0x0 /f

:: Disable Hibernation
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "Heuristics" /t REG_BINARY /d "05 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 3f 42 0f 00" /f

:: Disable Memory Dumps, Log + Alert
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "SendAlert" /t REG_DWORD /d 0x0 /f

reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v DisableFirstRunCustomize /t REG_DWORD /d 0x1 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0x1 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 0x1 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Disk" /v TimeOutValue /t REG_DWORD /d 200 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Image" /v Revision /t REG_SZ /d 1.0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Image" /v Virtual /t REG_SZ /d Yes /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application" /v MaxSize /t REG_DWORD /d 0x100000 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Application" /v Retention /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System" /v MaxSize /t REG_DWORD /d 0x100000 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\System" /v Retention /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security" /v MaxSize /t REG_DWORD /d 0x100000 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\eventlog\Security" /v Retention /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoRecycleFiles /t REG_DWORD /d 0x1 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\ WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0x0 /f
reg.exe ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\policies\system" /v EnableLUA /t REG_DWORD /d 0x0 /f
reg.exe Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Sideshow" /v Disabled /t REG_DWORD /d 0x1 /f

:: Using powershell to perform Windows Services modifications
powershell.exe Set-Service 'BDESVC' -StartupType "Disabled"
powershell.exe Set-Service 'wbengine' -StartupType "Disabled" 
powershell.exe Set-Service 'DPS' -StartupType "Disabled"
powershell.exe Set-Service 'UxSms' -StartupType "Disabled"
powershell.exe Set-Service 'Defragsvc' -StartupType "Disabled"
powershell.exe Set-Service 'HomeGroupListener' -StartupType "Disabled"
powershell.exe Set-Service 'HomeGroupProvider' -StartupType "Disabled"
powershell.exe Set-Service 'iphlpsvc' -StartupType "Disabled"
powershell.exe Set-Service 'MSiSCSI' -StartupType "Disabled"
powershell.exe Set-Service 'swprv' -StartupType "Disabled"
powershell.exe Set-Service 'CscService' -StartupType "Disabled"
powershell.exe Set-Service 'SstpSvc' -StartupType "Disabled"
powershell.exe Set-Service 'wscsvc' -StartupType "Disabled"
powershell.exe Set-Service 'SSDPSRV' -StartupType "Disabled"
powershell.exe Set-Service 'SysMain' -StartupType "Disabled"
powershell.exe Set-Service 'TabletInputService' -StartupType "Disabled"
powershell.exe Set-Service 'Themes' -StartupType "Disabled"
powershell.exe Set-Service 'upnphost' -StartupType "Disabled"
powershell.exe Set-Service 'VSS' -StartupType "Disabled"
powershell.exe Set-Service 'SDRSVC' -StartupType "Disabled"
powershell.exe Set-Service 'WinDefend' -StartupType "Disabled"
powershell.exe Set-Service 'WerSvc' -StartupType "Disabled"
powershell.exe Set-Service 'MpsSvc' -StartupType "Disabled"
powershell.exe Set-Service 'ehRecvr' -StartupType "Disabled"
powershell.exe Set-Service 'ehSched' -StartupType "Disabled"
powershell.exe Set-Service 'WSearch' -StartupType "Disabled"
powershell.exe Set-Service 'Wlansvc' -StartupType "Disabled"
powershell.exe Set-Service 'WwanSvc' -StartupType "Disabled"

:: Making miscellaneous modifications
bcdedit.exe /set BOOTUX disabled
vssadmin.exe Delete Shadows /All /Quiet
powershell.exe Disable-ComputerRestore -Drive %SystemDrive%\
netsh.exe advfirewall set allprofiles state off
powercfg.exe -H OFF
net.exe STOP "sysmain"
fsutil.exe behavior set DisableLastAccess 1

:: Making modifications to Scheduled Tasks
schtasks.exe /change /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks.exe /change /TN "\Microsoft\Windows\SystemRestore\SR" /Disable
schtasks.exe /change /TN "\Microsoft\Windows\Registry\RegIdleBackup" /Disable
schtasks.exe /change /TN "\Microsoft\Windows Defender\MPIdleTask" /Disable
schtasks.exe /change /TN "\Microsoft\Windows Defender\MP Scheduled Scan" /Disable
schtasks.exe /change /TN "\Microsoft\Windows\Maintenance\WinSAT" /Disable

winrm quickconfig
winrm set winrm/config/Service @{EnableCompatibilityHttpListener="true"}
