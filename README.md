# Package-Installer

  This Script is made to simplify installations with SCCM 
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
