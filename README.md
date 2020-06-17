# Package-Installer

  This Script is made to simplify installations with SCCM or any other Windows bases Software distribution Tool.
  The focus of this tool is to have a Tool that is simple to understand, maintain and support.
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

Instead of using a batch, as you probably normaly would do, you can use a XML file to build your installation. 
This tool also provides a litle Status dialogue, the possibility to create MIF files for monitoring in SCCM 
It has a built in timer and user dialogue if you need to restart or want the user to aknowledge some text. 
The tool is also aware if it is running in a user or system context. 
The XML file can be used (together with the SCCM-Application-Deployment-Wizard) easily create a SCCM Application 
including a collection and deployment. This is nice, espcially if you want to use your Package in several 
different SCCM infrastructures.

Usually you would use this tool in the following structure (asuming we are packaging 7zip)

Igor Pavlov_7-Zip\Resources

Igor Pavlov_7-Zip\Installer.xml

Igor Pavlov_7-Zip\Installer.cmd

Igor Pavlov_7-Zip\Resources\Installer.ps1

Igor Pavlov_7-Zip\Resources\Logo.png

Igor Pavlov_7-Zip\Resources\LogoSmall.png

Igor Pavlov_7-Zip\Resources\Main.xaml

Igor Pavlov_7-Zip\Setup\7z.msi

In this case you would only need to modify the installer.xml (see Documentation inside the Template) to point to the 7z.msi and
add the 7z.msi installer to the Setup folder.
You do not need to touch any other file or folder. 
The PNG files can be replaced with any other PNG of the same size and name.
Logo.PNG is the big logo in the installation dialogue, LogoSmall.png the logo for the title bar.
