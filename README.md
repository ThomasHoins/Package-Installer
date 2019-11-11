# Package-Installer

  This Script is made to simplify installations with SCCM or any other Windows bases Software distribution Tool.
  The focus of this tool is to have a simple Tool that is simple to understand, maintain and support.
  This Script can be used to wrap multiple installation files into a single XML file, instead using a batch.
  It has a function to check for running processes and shows a message to end the process.
  At the end it can restart the PC if required and requested. 

  This script uses a installer*.xml file to execute installations
  See installer XML template for more information

  installer.ps1 [Option] [XMLPath]
  Option:
    /i for installation
    /u for uninstallation
    /r for repair
  XMLPath:
    path to the intaller XML  


The ServiceUI.exe is needed to run the powershell script in System Context and still be able to show a UI in User context. It has to be fetched from the SCCM Server ...\OSD\Packages\Microsoft_Deployment_Toolkit_Files_2013\Tools\x64.
And it has to be placed inside the Resources folder.

The ServiceUI.exe is not open source and is not part of this Project. So we will had to leave it out of here.
