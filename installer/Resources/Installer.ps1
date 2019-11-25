#Requires -Version 3.0
<#
.SYNOPSIS
  This Script is made to simplify installations with SCCM 
  This Script can be used to wrap multiple installation files into a single XML file, instead using a batch.
  It has a function to check for running processes and shows a message to end the process.
  At the end it can restart the PC if required and requested. 

.DESCRIPTION
  This script uses a installer*.xml file to execute installations
  See installer XML template for more information

.LINK
https://github.com/ThomasHoins/Package-Installer

.PARAMETER Option
    /i for installation
    /u for uninstallation
    /r for repair

.PARAMETER XMLPath:
    path to the intaller XML 
   
.EXAMPLE
  <installer.ps1 /i %temp%\installer.xml>    

.INPUTS
  Option 
  XMLPath

.OUTPUTS
  Log file stored under %LOGFILENAME%.log, can be defined in the installer XML
  
.NOTES
    Version:        2.1.5
    Author:         Thomas Hoins, Markus Belle 
    Company:        DATAGROUP Hamburg GmbH
    Creation Date:  16.09.2019
    Purpose/Change: Initial script development

History:
    2.0.0     16.09.2019    Initial Version
    2.0.8     18.09.2019    Added Functionality
    2.0.9     20.09.2019    Added RC functionality, added RegEntry Function
    2.0.10    20.09.2019    fixed some bugs 
    2.0.11    20.09.2019    added NOGUI   
    2.0.12    20.09.2019    added Inventory functionality  
    2.0.13    30.09.2019    fixed Reg Key Name and MIF path
    2.0.14    30.09.2019    added dynamic resizing of the window to support long messages
    2.1.0     24.10.2019    Minor GUI fixes, Fix at Installer.cmd, New Logo handling, Error Handling for MIF and Reg creation
    2.1.1     24.10.2019    fixed %sourcedir% and %logdir% issue (MB)
    2.1.2     20.11.2019    fixed Version Number, <REQUIREADMINRIGHS> working as expected now (TH)
    2.1.3     20.11.2019    Minor enhancements to the main installation routine (TH)
    2.1.4     21.11.2019    Changed installation routine (TH)
    2.1.5     25.11.2019    Removed a Bug with the MIF file name from Write-Mif (TH)

Known Bugs:
  






#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------
$SCCMInstallerVersion = "2.1.5"

Param(
    [ValidateSet("/i", "/u", "/r")]
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter /i for install, /u for uninstall, /r for repair")]
    [string]$Option,
	
    [Parameter(Mandatory = $false,
        HelpMessage = "Enter the full path of the installer XML file")]
    [String]$XMLPath
)
$ExecutionString = Switch ($Option) {
    "/i" { "SETUP" }
    "/u" { "UNINSTALL" }
    "/r" { "REPAIR" }
    default { "SETUP" }
}

#Load required libraries
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing 
# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Get SourceDir
$SourceDir = (Get-Item "$PSScriptRoot\..\").FullName
$SourceDir = $SourceDir.Substring(0, $Sourcedir.Length - 1)

#Get Main Window content
[xml]$xaml = Get-Content "$PSScriptRoot\Main.xaml"

#Read the form
$Reader = (New-Object System.Xml.XmlNodeReader $xaml) 
$Form = [Windows.Markup.XamlReader]::Load($reader) 
#AutoFind all controls
$xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | ForEach-Object { 
    try {
        New-Variable  -Name $_.Name -Value $Form.FindName($_.Name) -Force 
    }
    catch {
    }
}


#Check for multiple installer XML files
If ($XMLPath -eq "") {
    $installerFiles = Get-ChildItem "$PSScriptRoot\..\*Installer*.xml"
}
Else {
    $installerFiles = $XMLPath
}  
# End of XAML import

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$MainWindow.Icon = "$PSScriptRoot\LogoSmall.png"      #load Icon

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Function to write to the Log file
function Write-Log {
    Param (
        [Parameter(Mandatory = $true)] 
        [Alias("LogFile")] 
        [string]$LogFilePath, 

        [Parameter(Mandatory = $true, 
            ValueFromPipelineByPropertyName = $true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$LogMessage
    )
    If ($global:LoggingEnabled) {
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
        # Write log entry to $Path 
        "$FormattedDate : $LogMessage" | Out-File -FilePath $LogFilePath -Append 
    } 
}

# Function to create a Mif file
Function Write-Mif {
    param (
        [string]$MifResultcodes
    )
    If ($globaL:MifEnabled) {
        $MifFilePath = $installer.'PKG-INSTALLER'.STARTUP.MIFPATH
        If ($MifFilePath -eq "") {
            $MifFilePath = "$((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties")."NOIDMIF Directory")"
        }
        $MifFileName = "$($installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER)-$($installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE).mif"
        If (($installer.'PKG-INSTALLER'.STARTUP.MIFFILE -eq "true") -and ($ExecutionString -like "SETUP*")) {
            $Error.Clear()
            Try {
                New-Item -ItemType "directory" -Path $MifFilePath -Force -ErrorAction Stop
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Component" 
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "NAME = ""Workstation""" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Group NAME = ""Installed Package"" ID = 1 CLASS = ""PACKAGE""" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Description"" ID = 1 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.DESCRIPTION)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Version"" ID = 2 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.VERSION)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Manufacturer"" ID = 3 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.MANUFACTURER)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Language"" ID = 4 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Package Version"" ID = 5 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.PACKAGEVERSION)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Package Number"" ID = 6 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$($installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Install Account"" ID = 7 STORAGE = SPECIFIC TYPE = STRING(100) VALUE = ""$($myWindowsPrincipal.Identity.Name)"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Installation Time"" ID = 8 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$(Get-Date -Format "yyyy-MM-dd HH-mm-ss")"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "Start Attribute NAME = ""Result Codes"" ID = 9 STORAGE = SPECIFIC TYPE = STRING(25) VALUE = ""$MifResultcodes"" End Attribute" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "End Group" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "" -Append
                Out-File -FilePath "$MifFilePath\$MifFileName" -InputObject "End Component" -Append
                Write-Log "$LogPath$LogFileName" -LogContent "MIF file ""$MifFilePath\$MifFileName"" has been created"
            }
            Catch { Write-Log "$LogPath$LogFileName" -LogContent "Error: MIF file ""$MifFilePath\$MifFileName"" could not be created: $Error" }
        }
        If ($ExecutionString -like "UNINSTALL*") {
            #Delete the MIF file
            Try {
                Remove-Item "$MifFilePath\$MifFileName" -Force -ErrorAction SilentlyContinue
                Write-Log "$LogPath$LogFileName" -LogContent "MIF file ""$MifFilePath\$MifFileName"" has been removed"
            }
            Catch { Write-Log "$LogPath$LogFileName" -LogContent "ERROR: MIF file ""$MifFilePath\$MifFileName"" could bot be removed" }
        }
    }
}

Function Write-RegEntry {
    param (
        [string]$MifResultcodes
    )
    $RegPath = "HKLM:\$($installer.'PKG-INSTALLER'.STARTUP.REGISTRYPATH)"
    $Lang = ($installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE).Substring(0, 3)
    $KeyName = "$($installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER)-$Lang"

    #Write/remove the Registry entry
    If (($installer.'PKG-INSTALLER'.STARTUP.REGISTRY -eq "true") -and ($ExecutionString -like "SETUP*")) {
        $Error.Clear()
        Try {
            New-Item -Path $RegPath -Name $KeyName -Force -ErrorAction Stop
            New-ItemProperty -Path $RegPath$KeyName -Name "Description" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.DESCRIPTION
            New-ItemProperty -Path $RegPath$KeyName -Name "Version" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.VERSION
            New-ItemProperty -Path $RegPath$KeyName -Name "Manufacturer" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.MANUFACTURER
            New-ItemProperty -Path $RegPath$KeyName -Name "Language" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE
            New-ItemProperty -Path $RegPath$KeyName -Name "Package Version" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.PACKAGEVERSION
            New-ItemProperty -Path $RegPath$KeyName -Name "Package Number" -PropertyType String -Value $installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER
            New-ItemProperty -Path $RegPath$KeyName -Name "Installation Time" -PropertyType String -Value  $(Get-Date -Format "yyyy-MM-dd HH-mm-ss")
            New-ItemProperty -Path $RegPath$KeyName -Name "Install Account" -PropertyType String -Value $myWindowsPrincipal.Identity.Name
            New-ItemProperty -Path $RegPath$KeyName -Name "Result Codes" -PropertyType String -Value $MifResultcodes
            Write-Log "$LogPath$LogFileName" -LogContent "Registry Entry ""$RegPath$KeyName"" has been created"
        }
        Catch { Write-Log "$LogPath$LogFileName" -LogContent "Error: Registry Entry ""$RegPath$KeyName"" could not be created: $Error" }
    }
    If ($ExecutionString -like "UNINSTALL*") {
        #Remove the Registry entry
        Try {
            Remove-Item "$RegPath$KeyName" -Recurse -Force -ErrorAction Stop
            Write-Log "$LogPath$LogFileName" -LogContent "Registry Entry ""$RegPath$KeyName"" has been removed"
        }
        Catch { Write-Log "$LogPath$LogFileName" -LogContent "Error: Registry Entry ""$RegPath$KeyName"" could not be removed" }
    }
}

# Show a Dialogue
Function Show-Message {
    param (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]  
        [string]$MessageString,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)] 
        [int]$TimeoutTime,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)] 
        [string]$Countdown,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)] 
        [string]$Unit
    )
    Show-Grid "MessageGrid"
    $MessageBox.Text = $MessageString
    $TimeLeft = $TimeoutTime
    Update-GUI
    $global:MsgOK = $false
    While (($TimeLeft -ne 0) -xor ($global:MsgOK -eq $true)) {
        For ($w = 1; $w -le 10; $w ++) {
            Start-Sleep -Milliseconds 80 
            $CountdownText.Content = "$Countdown $TimeLeft $Unit"
            Update-GUI
        }
        $TimeLeft --
    }
    $MessageBox.Text = $null
    Show-Grid "MainGrid"
}

#Switch between the differnt Grids
Function Show-Grid {
    param (
        [Parameter(Mandatory = $true)]  
        [string]$GridName
    )
    $MainGrid.Visibility = "Hidden"
    $ListGrid.Visibility = "Hidden"
    $MessageGrid.Visibility = "Hidden" 
    Switch ($GridName) {
        "MainGrid" { $MainGrid.Visibility = "Visible" }
        "ListGrid" { $ListGrid.Visibility = "Visible" }
        "MessageGrid" { $MessageGrid.Visibility = "Visible" }
        default {
            $MainGrid.Visibility = "Hidden"
            $ListGrid.Visibility = "Hidden"
            $MessageGrid.Visibility = "Hidden" 
        }
    }
    Update-GUI
} 

Function Update-GUI {
    $Form.Dispatcher.Invoke([Action] { }, [Windows.Threading.DispatcherPriority]::ContextIdle)
}

Function Invoke-Inventory {
    $InventoryCommandLine = [System.Environment]::ExpandEnvironmentVariables($installer.'PKG-INSTALLER'.STARTUP.INVENTORY)
    $error.clear()
    Try {
        $ExitCode = (Start-Process $InventoryCommandLine -PassThru -Wait -ErrorAction SilentlyContinue).ExitCode
        Write-Log "$LogPath$LogFileName" -LogContent "Inventory finished with exitcode:  $ExitCode"
    }
    Catch {
        Write-Log "$LogPath$LogFileName" -LogContent "Error: Inventory could not be started! $error[0].Exception.Message"
    } 
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------
#OK Message Button Action
$MsgOKButton.Add_Click( {
        Show-Grid "MainGrid"
        $global:MsgOK = $true
    }) 

#List Cancel Button Action
$CancelButton.Add_Click( {
        $Form.Close()
        Exit
    })

#List OK Button Action
$OKButton.Add_Click( {
        Show-Grid "MainGrid"
        $global:Wait = $false
    })
    
# List double click
$PackageList.Add_MouseDoubleClick( {
        Show-Grid "MainGrid"
        $global:Wait = $false
    }) 

#Make sure to stop PS when closing
$Form.Add_Closing( {
        #Exit
    })
    
    
#When the Form is loaded, this will be executed
$Form.Add_ContentRendered( {
        #Check for multiple installer XML files
        If ($installerFiles.Count -gt 1) {
            $global:Wait = $true
            ForEach ($InstallerFile in $installerFiles) {
                [xml]$installertemp = Get-Content $InstallerFile
                $PackageList.AddChild("$($InstallerFile.Name) - $($installertemp.'PKG-INSTALLER'.PRODUCT.MANUFACTURER) $($installertemp.'PKG-INSTALLER'.PRODUCT.DESCRIPTION) $($installertemp.'PKG-INSTALLER'.PRODUCT.VERSION)")
            }
            Show-Grid "ListGrid"
    
            #wait for installer.xml selection
            While ($global:Wait) {
                Update-GUI
            }
            $SelInstallerfile = $installerFiles[$PackageList.SelectedIndex].FullName
            #load installer.xml
            [xml]$installer = Get-Content $SelInstallerfile
            $PackageList.Items.Clear()
        }
        ElseIf ($installerFiles.Count -eq 1) {
            #load installer.xml
            [xml]$installer = Get-Content $installerFiles
        }
        Else {
            #load installer.xml
            [xml]$installer = Get-Content "$PSScriptRoot\..\Installer.xml"
            Write-Host
        }
        #load Logo
        If ($installer.'PKG-INSTALLER'.STARTUP.USEAPPICON -eq "true") {
            If (Test-Path "$PSScriptRoot\AppIcon.png") {
                $Logo.Source = "$PSScriptRoot\AppIcon.png"
            }
            Else {
                $Logo.Source = "$PSScriptRoot\Logo.png"
            }
        }
        Else {
            $Logo.Source = "$PSScriptRoot\Logo.png"          
        }

        If ($installer.'PKG-INSTALLER'.STARTUP.NOGUI -eq "true") {
            $MainWindow.Visibility = "Hidden"
            Update-GUI
        }
        $MainWindow.Title = $installer.'PKG-INSTALLER'.STARTUP.TITLE
        $Description.Content = $installer.'PKG-INSTALLER'.PRODUCT.DESCRIPTION
        $Manufacterer.Content = $installer.'PKG-INSTALLER'.PRODUCT.MANUFACTURER
        $Version.Content = $installer.'PKG-INSTALLER'.PRODUCT.VERSION
        $Language.Content = $installer.'PKG-INSTALLER'.PRODUCT.LANGUAGE
        $Assetnumber.Content = $installer.'PKG-INSTALLER'.PRODUCT.ASSETNUMBER
        $global:LoggingEnabled = Switch ($installer.'PKG-INSTALLER'.STARTUP.LOGFILE) {
            "true" { $true }
            "false" { $false }
            default { $true }
        }
        $global:MifEnabled = Switch ($installer.'PKG-INSTALLER'.STARTUP.MIFFILE) {
            "true" { $true }
            "false" { $false }
            default { $false }
        }
        $RequireAdmin = Switch ($installer.'PKG-INSTALLER'.STARTUP.REQUIREADMINRIGHTS) {
            "true" { $true }
            "false" { $false }
            default { $false }
        }
        $LogPath = $installer.'PKG-INSTALLER'.STARTUP.LOGPATH
        $LogFileName = $installer.'PKG-INSTALLER'.STARTUP.LOGFILENAME
        $XMLVersion = $installer.'PKG-INSTALLER'.STARTUP.XMLVERSION
        $LoggedOnUserName = (Get-WmiObject -Class win32_computersystem -ComputerName $env:COMPUTERNAME).UserName
        $OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
        $OSVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        $RequiredOS = $installer.'PKG-INSTALLER'.STARTUP.REQUIREOS.Split(";")
        $CommandlinesX64 = $installer.'PKG-INSTALLER'.SETUP_X64.EXE 
        If ($CommandlinesX64 -ne "") { $X64SetupExists = $true }
        $Onlyx64 = Switch ($installer.'PKG-INSTALLER'.STARTUP.ONLYX64) {
            "true" { $true }
            "false" { $false }
            default { $false }
        }
        $UninstallEnabled = Switch ($installer.'PKG-INSTALLER'.STARTUP.UNINSTALLENABLED) {
            "true" { $true }
            "false" { $false }
            default { $true }
        }
        # check if OS matches
        $OSMatch = $false
        ForEach ($OS in $RequiredOS) {
            If ($OSVersion -like "$OS*") {
                $OSMatch = $true
            }
        }

        #----------------------------------------------[Installation Processes starts here]----------------------------------

        # create empty log file
        If ($global:LoggingEnabled -and ($ExecutionString -like "SETUP*")) {
            $NewLogFile = New-Item "$LogPath$LogFileName" -Force -ItemType File 
        }

        #Start Logging
        Switch ($ExecutionString) {
            "SETUP" {
                Write-Log "$LogPath$LogFileName" -LogContent "Installer started (ScriptVersion: $SCCMInstallerVersion - XML File Version $XMLVersion)" 
            }
            "UNINSTALL" {
                Write-Log "$LogPath$LogFileName" -LogContent "--------------------------------------------------------------------------" 
                Write-Log "$LogPath$LogFileName" -LogContent "Uninstall started (ScriptVersion: $SCCMInstallerVersion - XML File Version $XMLVersion)" 
            }
            "REPAIR" {
                Write-Log "$LogPath$LogFileName" -LogContent "--------------------------------------------------------------------------"
                Write-Log "$LogPath$LogFileName" -LogContent "Repair started (ScriptVersion: $SCCMInstallerVersion - XML File Version $XMLVersion)" 
            }
        }
        Write-Log "$LogPath$LogFileName" -LogContent "Logged On UserName: $LoggedOnUserName"
        Write-Log "$LogPath$LogFileName" -LogContent "Executing UserName: $($myWindowsPrincipal.Identity.Name)"
        Write-Log "$LogPath$LogFileName" -LogContent "Executing User Is Admin: $($myWindowsPrincipal.IsInRole($adminRole))"
        Write-Log "$LogPath$LogFileName" -LogContent "Admin Permission required: $RequireAdmin"
        Write-Log "$LogPath$LogFileName" -LogContent "OS Version: $OSVersion"
        Write-Log "$LogPath$LogFileName" -LogContent "OS Architecture: $OSArchitecture"
        Write-Log "$LogPath$LogFileName" -LogContent "OS Architecture matches Required OS: $OSMatch"
        Write-Log "$LogPath$LogFileName" -LogContent "x64 Setup block found: $X64SetupExists"
        Write-Log "$LogPath$LogFileName" -LogContent "Calling command line: $PSCommandPath $Option $XMLPath"
        If ($RequireAdmin -and ($RequireAdmin -ne $myWindowsPrincipal.IsInRole($adminRole))) {
            Write-Log "$LogPath$LogFileName" -LogContent "Required Admin rigths not available, stopping!"
            $Form.Close()
            Exit
        }
        If ($Onlyx64 -eq $true -and !($X64SetupExists)) {
            Write-Log "$LogPath$LogFileName" -LogContent "Error: Required X64 setup entries are missing, stopping!"
            $Form.Close()
            Exit
        }
        If ($Onlyx64 -eq $true -and !($OSArchitecture = "64-Bit") ) {
            Write-Log "$LogPath$LogFileName" -LogContent "Error: Required X64 does not match OS, stopping!"
            $Form.Close()
            Exit
        }
        If ($ExecutionString -like "UNINSTALL*" -and ($UninstallEnabled -eq $false) ) {
            Write-Log "$LogPath$LogFileName" -LogContent "Error: Uninstallation was selected, but is disabled in XML, stopping!"
            $Form.Close()
            Exit
        }

        #Reset variables
        $x = 0
        $ExitCodes = ""

        #Close running Tasks Message Handling
        $ProcessToCheck = $installer.'PKG-INSTALLER'.CHECK.EXE

        $MessageBoxText = Out-String -InputObject $installer.'PKG-INSTALLER'.CHECK.MESSAGEBOXTEXT 
        $Autokill = Switch ($installer.'PKG-INSTALLER'.CHECK.AUTOKILL) {
            "true" { $true }
            "false" { $false }
            default { $false }
        }

        If ($Autokill) {
            $CountdownText.Visibility = "Visible"
            $Timer = 60
            $CountText = $installer.'PKG-INSTALLER'.CHECK.COUNTDOWNTEXT
            $CountUnit = $installer.'PKG-INSTALLER'.CHECK.COUNTDOWNUNIT
            If ($CountText -eq "") { $CountText = "Waiting for" }
            If ($CountUnit -eq "") { $CountUnit = "sec." }
        }
        Else {
            $CountdownText.Visibility = "Hidden"
            $Timer = -1
        }
        ForEach ($Process in $ProcessToCheck) {
            #show the message 5x if the user just presses OK kill the process
            If ($Process -ne "") {
                For ($t = 1; $t -le 4; $t ++) {
                    try {
                        $RunningProcess = Get-Process -Name $Process -ErrorAction SilentlyContinue      
                    }
                    catch {
                        Write-Log "$LogPath$LogFileName" -LogContent "Process $Process is not running"
                    }
                    If ($RunningProcess -ne $null) {
                        Show-Message $MessageBoxText -TimeoutTime $Timer -Countdown $CountText -Unit $CountUnit
                        Show-Grid "MainGrid"
                        If ($Autokill) {
                            $StopResult = Stop-Process $RunningProcess -Force
                            Write-Log "$LogPath$LogFileName" -LogContent "Process $($RunningProcess.Name) has been closed with by Autokill with Exit Code: $($StopResult.ExitCode)"
                            Break   
                        }
                    }
                }
                If ($RunningProcess -ne $null) {
                    $StopResult = Stop-Process $RunningProcess -Force
                    Write-Log "$LogPath$LogFileName" -LogContent "Process $($RunningProcess.Name) has been closed with Exit Code: $($StopResult.ExitCode)"
                }
            }
        }

        #Start Installation
        Show-Grid "MainGrid"
        $Finalresultcode = 0
        If ($OSArchitecture = "64-Bit" -and $X64SetupExists) {
            $ExecutionString = "$($ExecutionString)_X64"
        }
        $CommandLines = $($installer.'PKG-INSTALLER'.$ExecutionString.EXE)
        $PackageCount = $CommandLines.Count
        ForEach ($Line In $CommandLines) {
            $Line = $Line -ireplace ('%SourceDir%', $SourceDir)
            $Line = $Line -ireplace ('%LogPath%', $LogPath)
            $CommandLine = $null
            If ($Line.InnerXML) {
                $CommandLine = [System.Environment]::ExpandEnvironmentVariables($Line.InnerXML) -Split ' +(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
                $WriteRC = Switch ($Line.RC) {
                    "true" { $true }
                    "false" { $false }
                    default { $true }
                }
            }
            ElseIf($Line) {
                $CommandLine = [System.Environment]::ExpandEnvironmentVariables($Line) -Split ' +(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
                $WriteRC = $true
            }
            If($CommandLine) {Write-Log "$LogPath$LogFileName" -LogContent "Executable to run: $CommandLine"}
            $Progress.Value = ($x / $PackageCount) * 100
            Update-GUI
            $ExitCode = 1
            Try {
                If ($CommandLine[1..9] -ne "") {
                    $error.clear()
                    $ExitCode = (Start-Process $CommandLine[0] -ArgumentList $CommandLine[1..9] -PassThru -Wait -ErrorAction SilentlyContinue).ExitCode
                }
                ElseIf($CommandLine) {
                    $error.clear()
                    $ExitCode = (Start-Process $CommandLine[0] -PassThru -Wait -ErrorAction SilentlyContinue).ExitCode
                }
                Write-Log "$LogPath$LogFileName" -LogContent "Application finished with exitcode:  $ExitCode"
                If ($WriteRC) { $ExitCodes = $ExitCodes + $ExitCode + ";" }
                If ($ExitCode -gt $Finalresultcode) { $Finalresultcode = $ExitCode }
            }
            Catch {
                Write-Log "$LogPath$LogFileName" -LogContent "Error: Application could not be started! $error[0].Exception.Message"
            }
            $x++
        }
        Write-Log "$LogPath$LogFileName" -LogContent "Installer Result Codes: $ExitCodes"
        If($Finalresultcode -in {0,1707,3010,1641,1618}){
            Write-Mif $ExitCodes
            Write-RegEntry $ExitCodes
            }
        Invoke-Inventory


        #Exit Message Handling
        $ExitMessageActive = Switch ($installer.'PKG-INSTALLER'.EXIT.MESSAGEBOX_ACTIVE) {
            "true" { $true }
            "false" { $false }
            default { $false } 
        }
        $AutoRebootActive = Switch ($installer.'PKG-INSTALLER'.EXIT.AUTOREBOOT) {
            "true" { $true }
            "false" { $false }
            default { $false } 
        }
        If ($ExitMessageActive) {
            $ExitMessageTimeout = $installer.'PKG-INSTALLER'.EXIT.TIMEOUT
            If ($ExitMessageTimeout -ne "") {
                $RestartTimerMsg = $installer.'PKG-INSTALLER'.EXIT.COUNTDOWNTEXT
                $RestartTimerUnit = $installer.'PKG-INSTALLER'.EXIT.COUNTDOWNUNIT
                If ($RestartTimerMsg -eq "") { $RestartTimerMsg = "Restarting in" }
                If ($RestartTimerUnit -eq "") { $RestartTimerUnit = "sec." }
                $CountdownText.Visibility = "Visible"
            }
            Else {
                $CountdownText.Visibility = "Hidden"
                $ExitMessageTimeout = -1
            }
            $ExitMessageText = Out-String -InputObject $installer.'PKG-INSTALLER'.EXIT.MESSAGEBOXTEXT
            $OSD = $false
            $ExitMessageOSDFlag = $installer.'PKG-INSTALLER'.EXIT.OSDFLAG
            Switch ($installer.'PKG-INSTALLER'.EXIT.OSDFLAG_MODE) {
                "registry" {
                    $RegValues = $ExitMessageOSDFlag.Split(";")
                    $Value = (Get-ItemProperty "HKLM:\$($RegValues[0])").$($RegValues[1])
                    If ($Value -eq $RegValues[2]) { $OSD = $true }
                }
                "file" {
                    $OSD = Test-Path ($ExitMessageOSDFlag).Replace("""", "")
                }
                "process" {
                    $ExitProcess = (Get-Process $ExitMessageOSDFlag).Id
                    If ($ExitProcess -is [int]) { $OSD = $true }
                }
            }
            Write-Log "$LogPath$LogFileName" -LogContent "Showing Exit Message. AutoReboot: $AutoRebootActive Timeout: $ExitMessageTimeout"
            If (!$OSD) {
                Show-Message $ExitMessageText -TimeoutTime $ExitMessageTimeout -Countdown $RestartTimerMsg -Unit $RestartTimerUnit
                Show-Grid "MainGrid"
            }
            If ($AutoRebootActive) {
                Write-Log "$LogPath$LogFileName" -LogContent "Auto Reboot will restart the computer now!"
                Restart-Computer -Force
            }
        }  

        # End of the Main Program  
        $Form.Close()
        Exit $Finalresultcode
    })


#Show the Main Window
$Form.ShowDialog() | out-null
$Form.Close()
Exit