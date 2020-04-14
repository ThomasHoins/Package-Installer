@ECHO OFF
"%~dp0Resources\CONSOLESTATE.exe" /Hide
Set logpath=%temp%
Set logfile="%logpath%\installer.log"
For /F "Tokens=*" %%I in ('tasklist /FI "IMAGENAME eq OSDSETUPHOOK.exe" ^| find /I "OSDSETUPHOOK.exe"') Do Set OSDSETUPHOOK=%%I

ECHO -------------------------------------------------- >> %logfile%
ECHO Starting Installation %date% %time% >> %logfile%

IF DEFINED OSDSETUPHOOK GOTO TASKSEQUENCE
IF %Username% EQU %COMPUTERNAME%$ GOTO SYSTEM
IF "%Username%" NEQ "%COMPUTERNAME%$" GOTO USER
GOTO EXIT

:SYSTEM
ECHO "SYSTEM" >> %logfile%
ECHO Launching: START "Installer" /I /MIN /WAIT "%~dp0Resources\ServiceUI.exe" -process:explorer.exe "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1  "%~dp0%2" >> %logfile%
START "Installer" /I /MIN /WAIT "%~dp0Resources\ServiceUI.exe" -process:explorer.exe "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1  "%~dp0%2" >> %logfile%
GOTO EXIT

:TASKSEQUENCE
ECHO "TASKSEQUENCE" >> %logfile%
ECHO Launching: START "Installer" /I /MIN /WAIT "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1  "%~dp0%2" >> %logfile%
START "Installer" /I /MIN /WAIT "%~dp0Resources\ServiceUI.exe" -process:TSProgressUI.exe "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1  "%~dp0%2" >> %logfile%
GOTO EXIT

:USER
ECHO "USER" >> %logfile%
ECHO Launching: START "Installer" /I /MIN /WAIT "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1 "%~dp0%2" >> %logfile%
START "Installer" /I /MIN /WAIT "%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle "hidden" -ExecutionPolicy "ByPass" -File "%~dp0Resources\Installer.ps1" %1 "%~dp0%2" >> %logfile%
GOTO EXIT


:EXIT	
ECHO Ending Installation  %date% %time% >> %logfile%
ECHO -------------------------------------------------- >> %logfile%
ECHO. >> %logfile%
"%~dp0Resources\CONSOLESTATE.exe" /Show
