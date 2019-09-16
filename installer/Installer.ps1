
#requires -version 3
<#
.SYNOPSIS
  This Script is made to simplify installations with SCCM 
  This Script can be used to wrap multiple installation files into a single XML file, instead using a batch.
  It has a function to check for running processes and shows a message to end the process.
  At the end it can restart the PC if required and requested. 
.DESCRIPTION
  This script uses a installer*.xml file to execute installations
  See installer XML template for more information
.PARAMETER 
  installer.ps1 [Option] [XMLPath]

  Option:
    /i for installation
    /u for uninstallation
    /r for repair

  XMLPath:
    path to the intaller XML  
  
  Example:

.INPUTS
  Option 
  XMLPath

.OUTPUTS
  Log file stored under %LOGFILENAME%.log, can be defined in the installer XML
  
.NOTES
  Version:        1.0
  Author:         Thomas Hoins, DATAGROUP Hamburg GmbH
  Creation Date:  16.09.2019
  Purpose/Change: Initial script development
  
.EXAMPLE
  <installer.ps1 /i %temp%\installer.xml>
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
Param(
  [Parameter(Mandatory=$false,
  HelpMessage="Enter /i for install, /u for uninstall, /r for repair")]
   [string]$Option,
	
   [Parameter(Mandatory=$false,
   HelpMessage="Enter the full path of the installer XML file")]
   [String]$XMLPath
)
$ExecutionString = Switch ($Option){
"/i" {"SETUP" }
"/u" {"UNINSTALL"}
"/r" {"REPAIR" }
default {"SETUP" }
}

#Load required libraries
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing 
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

#Get Main Window content
[xml]$xaml = Get-Content "$PSScriptRoot\Resources\Main.xaml"
#Read the form
$Reader = (New-Object System.Xml.XmlNodeReader $xaml) 
$Form = [Windows.Markup.XamlReader]::Load($reader) 
#AutoFind all controls
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")  | ForEach-Object { 
  try{
    New-Variable  -Name $_.Name -Value $Form.FindName($_.Name) -Force 
  }
  catch{
  }
}


#Check for multiple installer XML files
If ($XMLPath -eq ""){
  $installerFiles = Get-ChildItem "$PSScriptRoot\*Installer*.xml"
  }
Else {
  $installerFiles = $XMLPath
  }  
# End of XAML import

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$MainWindow.Icon = "$PSScriptRoot\Resources\LogoSmall.png"      #load Icon
$Logo.Source = "$PSScriptRoot\Resources\Logo.png"          #load Logo

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Function to write to the Log file
function Write-Log {
 Param (
    [Parameter(Mandatory=$true)] 
    [Alias("LogFile")] 
    [string]$LogFilePath, 

    [Parameter(Mandatory=$true, 
                ValueFromPipelineByPropertyName=$true)] 
    [ValidateNotNullOrEmpty()] 
    [Alias("LogContent")] 
    [string]$LogMessage
    )
If ($global:LoggingEnabled){
  # Format Date for our Log File 
  $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 

  # Write log entry to $Path 
  "$FormattedDate : $LogMessage" | Out-File -FilePath $LogFilePath -Append 
  } 
}

# Function to create a Mif file
Function Write-Mif{
    param (
    [string]$MifFilePath,
    [string]$MifResultcodes
  )
  If ($global:MifEnabled){
    Out-File -FilePath $MifFilePath -InputObject "Start Component" 
    Out-File -FilePath $MifFilePath -InputObject "NAME = ""Workstation""" -Append
    Out-File -FilePath $MifFilePath -InputObject "" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Group NAME = ""Installed Package"" ID = 1 CLASS = ""PACKAGE""" -Append
    Out-File -FilePath $MifFilePath -InputObject "" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Description"" ID = 1 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.DESCRIPTION)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Version"" ID = 2 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.VERSION)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Manufacturer"" ID = 3 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.MANUFACTURER)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Language"" ID = 4 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Package Version"" ID = 5 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.PACKAGEVERSION)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Package Number"" ID = 6 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Install Account"" ID = 7 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($myWindowsPrincipal.Identity.Name)"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Installation Time"" ID = 8 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$(Get-Date -Format "yyyy-MM-dd HH-mm-ss")"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "Start Attribute NAME = ""Result Codes"" ID = 9 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$MifResultcodes"" End Attribute" -Append
    Out-File -FilePath $MifFilePath -InputObject "" -Append
    Out-File -FilePath $MifFilePath -InputObject "End Group" -Append
    Out-File -FilePath $MifFilePath -InputObject "" -Append
    Out-File -FilePath $MifFilePath -InputObject "End Component" -Append
  }
}

# Show a Dialogue
Function Show-Message{
  param (
    [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]  
    [string]$MessageString,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)] 
    [int]$TimeoutTime,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)] 
    [string]$Countdown,

    [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)] 
    [string]$Unit
    )
  $MainGrid.Visibility = "Hidden"
  $ListGrid.Visibility = "Hidden"
  $MessageGrid.Visibility = "Visible"
  $MessageBox.Text = $MessageString
  $TimeLeft = $TimeoutTime
  $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
  $global:MsgOK = $false
  While (($TimeLeft -ne 0) -xor ($global:MsgOK -eq $true)){
    For ($w=1;$w -le 10; $w ++){
      Start-Sleep -Milliseconds 80 
      $CountdownText.Content = "$Countdown $TimeLeft $Unit"
      $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
      }
      $TimeLeft --
    }
  $MessageGrid.Visibility = "Hidden"
  $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
#OK Message Button Action
$MsgOKButton.Add_Click({
  $MainGrid.Visibility = "Visible"
  $MessageGrid.Visibility = "Hidden"
  $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
  $global:MsgOK=$true
}) 

#List Cancel Button Action
$CancelButton.Add_Click({
  $Form.Close()
  Exit
})

#List OK Button Action
$OKButton.Add_Click({
    $MainGrid.Visibility = "Visible"
    $ListGrid.Visibility = "Hidden"
    $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
    $global:Wait=$false
})

#Make sure to stop PS when closing
$Form.Add_Closing({
  $Form.Close()|Out-Null
  #Exit
})

#When the Form is loaded, this will be executed
$Form.Add_ContentRendered({

#Check for multiple installer XML files
If ($installerFiles.Count -gt 1){
    $global:Wait=$true
    ForEach ($InstallerFile in $installerFiles){
        [xml]$installertemp = Get-Content $InstallerFile
        $PackageList.AddChild("$($InstallerFile.Name) - $($installertemp.'PKG-INSTALLER'.PRODUCT.MANUFACTURER) $($installertemp.'PKG-INSTALLER'.PRODUCT.DESCRIPTION) $($installertemp.'PKG-INSTALLER'.PRODUCT.VERSION)")
        }
    $ListGrid.Visibility = "Visible"
    $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
    
    #wait for installer.xml selection
    While ($global:Wait){
        $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
        }
    $SelInstallerfile = $installerFiles[$PackageList.SelectedIndex].FullName
    #load installer.xml
    [xml]$installer = Get-Content $SelInstallerfile
    }
Else {
    #load installer.xml
    [xml]$installer = Get-Content "$PSScriptRoot\Installer.xml"
    }

$MainWindow.Title = $installer.'PKG-INSTALLER'.STARTUP.TITLE
$Description.Content = $installer.'PKG-INSTALLER'.PRODUCT.DESCRIPTION
$Manufacterer.Content = $installer.'PKG-INSTALLER'.PRODUCT.MANUFACTURER
$Version.Content = $installer.'PKG-INSTALLER'.PRODUCT.VERSION
$Language.Content = $installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE
$Assetnumber.Content = $installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER
$global:LoggingEnabled = Switch ($installer.'PKG-INSTALLER'.STARTUP.LOGFILE){
  "true" {$true}
  "false"{$false}
  default {$true}
  }
$MifName = "$($installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER)-$(($installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE).SubString(0,3)).mif"
$MifFileName="$($installer.'PKG-INSTALLER'.STARTUP.MIFPATH)$MifName"
If ($MifFileName -eq "$MifName"){
  $MifFileName= "$((Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\SMS\Client\Configuration\Client Properties")."NOIDMIF Directory")$MifName"
}
$global:MifEnabled = Switch ($installer.'PKG-INSTALLER'.STARTUP.MIFFILE){
  "true" {$true}
  "false" {$false}
  default {$false}
  }
$RequireAdmin = Switch ($installer.'PKG-INSTALLER'.STARTUP.REQUIREADMINRIGHTS){
  "true" {$true}
  "false" {$false}
  default {$false}
  }
$LogPath=$installer.'PKG-INSTALLER'.STARTUP.LOGPATH
$LogFileName=$installer.'PKG-INSTALLER'.STARTUP.LOGFILENAME
$SCCMInstallerVersion="2.0.0"
$XMLVersion=$installer.'PKG-INSTALLER'.STARTUP.XMLVERSION
$LoggedOnUserName=(Get-WmiObject -Class win32_computersystem -ComputerName $env:COMPUTERNAME).UserName
$OSArchitecture=(Get-WmiObject Win32_OperatingSystem).OSArchitecture
$OSVersion=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
$RequiredOS=$installer.'PKG-INSTALLER'.STARTUP.REQUIREOS.Split(";")
$CommandlinesX64 = $installer.'PKG-INSTALLER'.SETUP_X64.EXE 
If ($CommandlinesX64 -ne "") {$X64SetupExists = $true}
$Onlyx64 = Switch($installer.'PKG-INSTALLER'.STARTUP.ONLYX64){
  "true" {$true}
  "false" {$false}
  default {$false}
  }
# check if OS matches
$OSMatch=$false
ForEach($OS in $RequiredOS){
    If ($OSVersion -like "$OS*"){
        $OSMatch=$true
    }
  }

#----------------------------------------------[Installation Processes starts here]----------------------------------

# create empty log file
If ($global:LoggingEnabled){
  $NewLogFile = New-Item "$LogPath$LogFileName" -Force -ItemType File 
  }

#Start Logging
Write-Log "$LogPath$LogFileName" -LogContent "Installer started (ScriptVersion: $SCCMInstallerVersion - XML File Version $XMLVersion)" 
Write-Log "$LogPath$LogFileName" -LogContent "Logged On UserName: $LoggedOnUserName"
Write-Log "$LogPath$LogFileName" -LogContent "Executing UserName: $($myWindowsPrincipal.Identity.Name)"
Write-Log "$LogPath$LogFileName" -LogContent "Executing User Is Admin: $($myWindowsPrincipal.IsInRole($adminRole))"
Write-Log "$LogPath$LogFileName" -LogContent "OS Version: $OSVersion"
Write-Log "$LogPath$LogFileName" -LogContent "OS Architecture: $OSArchitecture"
Write-Log "$LogPath$LogFileName" -LogContent "OS Architecture matches Required OS: $OSMatch"
Write-Log "$LogPath$LogFileName" -LogContent "x64 Setup block found: $X64SetupExists"
If ($RequireAdmin -ne $myWindowsPrincipal.IsInRole($adminRole)){
  Write-Log "$LogPath$LogFileName" -LogContent "Required Admin rigths not available, stopping!"
  $Form.Close()
  Exit
}
If ($Onlyx64 -eq $true -and !($X64SetupExists)){
  Write-Log "$LogPath$LogFileName" -LogContent "Required X64 setup entries are missing, stopping!"
  $Form.Close()
  Exit
}
If ($Onlyx64 -eq $true -and !($OSArchitecture = "64-Bit") ){
  Write-Log "$LogPath$LogFileName" -LogContent "Required X64 does not match OS, stopping!"
  $Form.Close()
  Exit
}

#Reset variables
$v=1
$i=0
$j=0
$x=0
$ExitCodes=""

#Close running Tasks Message Handling
$ProcessToCheck = $installer.'PKG-INSTALLER'.CHECK.EXE

$MessageBoxText = Out-String -InputObject $installer.'PKG-INSTALLER'.CHECK.MESSAGEBOXTEXT 
$Autokill = Switch ($installer.'PKG-INSTALLER'.CHECK.AUTOKILL){
  "true" {$true}
  "false" {$false}
  default {$false}
}

If ($Autokill){
  $CountdownText.Visibility = "Visible"
  $Timer = 60
  $CountText = $installer.'PKG-INSTALLER'.CHECK.COUNTDOWNTEXT
  $CountUnit = $installer.'PKG-INSTALLER'.CHECK.COUNTDOWNUNIT
  If ($CountText -eq "") {$CountText = "Waiting for"}
  If ($CountUnit -eq "") {$CountUnit = "sec."}
  }
Else{
  $CountdownText.Visibility = "Hidden"
  $Timer = -1
}
ForEach($Process in $ProcessToCheck){
  #show the message 5x if the user just presses OK kill the process
  If ($Process -ne ""){
    For ($Try=1; $Try -le 4;$Try ++){
      $RunningProcess = Get-Process -Name $Process
      If ($RunningProcess -ne $null){
        Show-Message $MessageBoxText -TimeoutTime $Timer -Countdown $CountText -Unit $CountUnit
        $MainGrid.Visibility = "Visible"
        $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
        If ($Autokill){
          Stop-Process $RunningProcess
          Write-Log "$LogPath$LogFileName" -LogContent "Process $($RunningProcess.Name) has been closed with by Autokill with Exit Code: $($StopResult.ExitCode)"
          Break 
          }
        }
      }
    Stop-Process $RunningProcess
    Write-Log "$LogPath$LogFileName" -LogContent "Process $($RunningProcess.Name) has been closed with Exit Code: $($StopResult.ExitCode)"
    }
  }  


#Start Installation
$MainGrid.Visibility = "Visible"
If ($OSArchitecture = "64-Bit" -and $X64SetupExists){
    $ExecutionString = "$($ExecutionString)_X64"
    }
$CommandLines = $($installer.'PKG-INSTALLER'.$ExecutionString.EXE)
$PackageCount = $CommandLines.Count
ForEach($Line In $CommandLines){
  $CommandLine = [System.Environment]::ExpandEnvironmentVariables($Line) -Split ' +(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
  Write-Log "$LogPath$LogFileName" -LogContent "Executable to run: $CommandLine"
  $Progress.Value = ($x/$PackageCount)*100
  $Form.Dispatcher.Invoke([Action]{},[Windows.Threading.DispatcherPriority]::ContextIdle)
  $ExitCode = (Start-Process $CommandLine[0] -ArgumentList $CommandLine[1..9] -PassThru -Wait).ExitCode
  Write-Log "$LogPath$LogFileName" -LogContent "Application finished with exitcode:  $ExitCode"
  $ExitCodes = $ExitCodes+$ExitCode+";"
  $i=0
  $v=-$v
  $x++
}
Write-Log "$LogPath$LogFileName" -LogContent "Installer Result Codes: $ExitCodes"
Write-Mif $MifFileName $ExitCodes

#Exit Message Handling
$ExitMessageActive = Switch ($installer.'PKG-INSTALLER'.EXIT.MESSAGEBOX_ACTIVE){
  "true" {$true}
  "false" {$false}
  default {$false} 
}
$AutoRebootActive = Switch ($installer.'PKG-INSTALLER'.EXIT.AUTOREBOOT){
  "true" {$true}
  "false" {$false}
  default {$false} 
}
If ($ExitMessageActive){
  $ExitMessageTimeout = $installer.'PKG-INSTALLER'.EXIT.TIMEOUT
  If ($ExitMessageTimeout -ne ""){
    $RestartTimerMsg = $installer.'PKG-INSTALLER'.EXIT.COUNTDOWNTEXT
    $RestartTimerUnit = $installer.'PKG-INSTALLER'.EXIT.COUNTDOWNUNIT
    If ($RestartTimerMsg -eq "") {$RestartTimerMsg = "Restarting in"}
    If ($RestartTimerUnit -eq "") {$RestartTimerUnit = "sec."}
    $CountdownText.Visibility = "Visible"
    }
  Else {
    $CountdownText.Visibility = "Hidden"
    $ExitMessageTimeout = -1
    }
  $ExitMessageText = Out-String -InputObject $installer.'PKG-INSTALLER'.EXIT.MESSAGEBOXTEXT
  $OSD = $false
  $ExitMessageOSDFlag = $installer.'PKG-INSTALLER'.EXIT.OSDFLAG
  Switch ($installer.'PKG-INSTALLER'.EXIT.OSDFLAG_MODE){
    "registry" {
      $RegValues= $ExitMessageOSDFlag.Split(";")
      $Value = (Get-ItemProperty "Registry::$($RegValues[0])").$($RegValues[1])
      If ($Value -eq $RegValues[2]){ $OSD = $true}
    }
    "file" {
      $OSD = Test-Path ($ExitMessageOSDFlag).Replace("""","")
      }
    "process" {
      $ExitProcess = (Get-Process $ExitMessageOSDFlag).Id
      If ($ExitProcess -is [int]){$OSD = $true}
      }
    }
  Write-Log "$LogPath$LogFileName" -LogContent "Showing Exit Message. AutoReboot: $AutoRebootActive Timeout: $ExitMessageTimeout"
  If (!$OSD){
    Show-Message $ExitMessageText -TimeoutTime $ExitMessageTimeout -Countdown $RestartTimerMsg -Unit $RestartTimerUnit
    $MainGrid.Visibility = "Visible"
    }
  If ($AutoRebootActive){
    Write-Log "$LogPath$LogFileName" -LogContent "Auto Reboot will restart the computer now!"
    Restart-Computer -Force
  }
}  


# End of the Main Program  
$Form.Close()
Exit
})


#Show the Main Window
$Form.ShowDialog()| out-null
Exit