# Fortigate2Excel
Parse a fortigate configurationfile and export it to Excel
Works with Excel Office365
Usage
.\Fortigate2Excel.ps1 -fortiGateConfig "c:\temp\config.conf"
OR
.\Fortigate2Excel.ps1 -fortiGateConfig "c:\temp\config.cred"

Files with extention .conf are saved configfiles
Files with extention .cred are saved credential files (IP/Username/Encryptedpassword)
For each section that is found a new Tab will be created.
It is VDOM aware.

Powershell version 7.1.0-preview.6 or newer reconmended for performance reasons