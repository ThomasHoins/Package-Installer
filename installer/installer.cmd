@echo off
IF %Username% EQU %COMPUTERNAME%$ goto SYSTEM
IF "%Username%" NEQ "%COMPUTERNAME%" goto User
goto EXIT

:SYSTEM
START "Installer" /I /MIN "%~dp0\Resources\ServiceUI.exe" -process:explorer.exe "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" "%~dp0Resources\Installer.ps1" %1 %2
goto EXIT

:User
START "Installer" /I /MIN "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" "%~dp0Resources\Installer.ps1" %1 %2
goto EXIT

:EXIT	