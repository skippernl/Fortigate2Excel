# Fortigate2Excel
Parse a fortigate configurationfile and export it to Excel
Works with Excel Office365

.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.conf"
    Parses a FortiGate config file and places the Excel file in the same folder where the config was found.
	
.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.cred"
    Parses a saved credential file and places the Excel file in the same folder where the file was found.
    If the credential file does not exist you will be prompted for the information and the file is created
	
Optional flags
-SkipFilter:$true		Skipping the filter function in Excel for tables with more than one row.   
-SkipFortiISDB:$true	Skipping the Fortigate InternetServiceDatabase conversion to Text.
-SkipTimeZone:$true		Skipping the TimeZone conversion to Text.

Files with extention .conf are saved config files
Files with extention .cred are saved credential files (IP/Username/Encryptedpassword)
For each section that is found a new Tab will be created.
It is VDOM aware.

Powershell version 7.1.0-preview.6 or newer recommended for performance reasons