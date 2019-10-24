@ECHO OFF
IF %Username% EQU %COMPUTERNAME%$ goto SYSTEM
IF "%Username%" NEQ "%COMPUTERNAME$%" goto USER
GOTO EXIT

:SYSTEM
START "Installer" /I /MIN "%~dp0\Resources\ServiceUI.exe" -process:explorer.exe "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1 %2
GOTO EXIT

:USER
START "Installer" /I /MIN "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1 %2
GOTO EXIT

:EXIT	

