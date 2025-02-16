<#
.SYNOPSIS
Fortigate2Excel parses the configuration from a FortiGate device into a Excel file.
.DESCRIPTION
The Fortigate2Excel reads a FortiGate config file and pulls out the configuration for each VDOM in the file into excel.
.PARAMETER FortigateConfig
[REQUIRED] This is the path to the FortiGate config/credential file
.PARAMETER SkipFilter 
[OPTIONAL] Set this value to $TRUE for not using Excel Filters.
.PARAMETER SkipFortiISDB 
[OPTIONAL] Set this value to $TRUE for keeping the number instead of the Fortigate ISDB name
.PARAMETER SkipTimeZone
[OPTIONAL] Set this value to $TRUE for keeping the number instead of the Timezone name
.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.conf"
    Parses a FortiGate config file and places the Excel file in the same folder where the config was found.
.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.cred"
    Parses a saved credential file and places the Excel file in the same folder where the file was found.
    If the credential file does not exist you will be prompted for the information and the file is created.
    .\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.conf" -SkipFilter:$true
    Parses a FortiGate config file and places the Excel file in the same folder where the config was found.
    No filters will be auto applied.
.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.conf" -SkipFortiISDB:$true
    Parses a FortiGate config file and places the Excel file in the same folder where the config was found.
    Skipping the Fortigate InternetServiceDatabase conversion to Text.
.\Fortigate2Excel.ps1 -FortiGateConfig "c:\temp\config.conf" -SkipTimeZone:$true
    Parses a FortiGate config file and places the Excel file in the same folder where the config was found.
    Skipping the TimeZone conversion to Text.   
.NOTES
Author: Xander Angenent (@XaAng70)
Idea: Drew Hjelm (@drewhjelm) (creates csv of ruleset only)
Last Modified: 2020/10/26
#Uses Estimated completion time from http://mylifeismymessage.net/1672/
#Uses Posh-SSH https://github.com/darkoperator/Posh-SSH if reading directly from the firewall
#Uses Function that converts any Excel column number to A1 format https://gallery.technet.microsoft.com/office/Powershell-function-that-88f9f690
#>
Param
(
    [Parameter(Mandatory = $true)]
    $fortigateConfig,
    [switch]$SkipFilter = $false,
    [switch]$SkipFortiISDB = $false,
    [switch]$SkipTimeZone = $false
)
Function InitAuthenticationRule {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name Groups -Value "" 
    $InitRule | Add-Member -type NoteProperty -name Portal -Value ""
    return $InitRule   
}
Function InitAcme {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Interface -Value "" 
    return $InitRule    
}
Function InitAcmeAccounts {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name url -Value ""
    $InitRule | Add-Member -type NoteProperty -name ca_url -Value ""
    $InitRule | Add-Member -type NoteProperty -name email -Value ""
    $InitRule | Add-Member -type NoteProperty -name privatekey -Value "" 
    return $InitRule
}
Function InitBookmark {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Group -Value "" 
    $InitRule | Add-Member -type NoteProperty -name Name -Value "" 
    $InitRule | Add-Member -type NoteProperty -name Apptype -Value ""
    $InitRule | Add-Member -type NoteProperty -name Host -Value ""  
    $InitRule | Add-Member -type NoteProperty -name Port -Value "" 
    $initRule | Add-Member -type NoteProperty -Name PortalName -Value ""
    $InitRule | Add-Member -type NoteProperty -name Security  -Value "" 
    return $InitRule
}
Function InitDHCPOptions {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name code -Value "" 
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name value -Value ""  
    return $InitRule
}
Function InitDHCPRange {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name "end-ip" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "end-prefix" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "prefix-length" -Value ""   
    $InitRule | Add-Member -type NoteProperty -name "start-ip" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "start-prefix" -Value ""    
    return $InitRule
}
Function InitDHCPReservedAddress {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name ip -Value "" 
    $InitRule | Add-Member -type NoteProperty -name mac -Value ""
    $InitRule | Add-Member -type NoteProperty -name description -Value ""     
    return $InitRule
}
Function InitFirewallAddress {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name associated-interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name country -Value ""
    $InitRule | Add-Member -type NoteProperty -name End-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name FQDN -Value ""
    $InitRule | Add-Member -type NoteProperty -name name -Value ""
    $InitRule | Add-Member -type NoteProperty -name network -Value ""
    $InitRule | Add-Member -type NoteProperty -name Start-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name tag -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name visibility -Value ""
    $InitRule | Add-Member -type NoteProperty -name wildcard-fqdn -Value ""
    return $InitRule
}
Function InitFirewallAddress6 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Associated-interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name country -Value ""
    $InitRule | Add-Member -type NoteProperty -name End-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name FQDN -Value ""
    #default ::/0
    $InitRule | Add-Member -type NoteProperty -name ip6 -Value "::/0"
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Network -Value ""
    $InitRule | Add-Member -type NoteProperty -name Start-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name tag -Value ""
    $InitRule | Add-Member -type NoteProperty -name Type -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name Visibility -Value ""
    $InitRule | Add-Member -type NoteProperty -name Wildcard-fqdn -Value ""
    return $InitRule
}
Function InitFirewallAddressGroup {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Member -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    return $InitRule
}
Function InitFirewallAddressGroup6 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Member -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    return $InitRule
}
Function InitFirewallIPpool {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name startip -Value ""
    $InitRule | Add-Member -type NoteProperty -name endip -Value ""
    $InitRule | Add-Member -type NoteProperty -name arp-reply -Value ""
    $InitRule | Add-Member -type NoteProperty -name associated-interface -Value ""
    return $InitRule
}
Function InitFirewallLdbMonitor {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name prt -Value ""
    return $InitRule
}
Function InitFirewallRule {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name action -Value ""
    $InitRule | Add-Member -type NoteProperty -name application-list -Value ""
    $InitRule | Add-Member -type NoteProperty -name av-profile -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name groups -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-id -Value ""
    #Default is disable
    $InitRule | Add-Member -type NoteProperty -name ippool -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name ips-sensor -Value ""
    $InitRule | Add-Member -type NoteProperty -name logtraffic -Value ""
    #Default is disable
    $InitRule | Add-Member -type NoteProperty -name nat -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name poolname -Value ""
    $InitRule | Add-Member -type NoteProperty -name profile-protocol-options -Value ""
    $InitRule | Add-Member -type NoteProperty -name schedule -Value ""
    $InitRule | Add-Member -type NoteProperty -name service -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name ssl-ssh-profile -Value ""
    #Default is enable
    $InitRule | Add-Member -type NoteProperty -name status -Value "enable"
    $InitRule | Add-Member -type NoteProperty -name traffic-shaper -Value ""
    $InitRule | Add-Member -type NoteProperty -name traffic-shaper-reverse -Value ""
    $InitRule | Add-Member -type NoteProperty -name Type -Value ""
    $InitRule | Add-Member -type NoteProperty -name utm-status -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name webfilter-profile -Value ""
    return $InitRule
}
Function InitFirewallServiceCategory {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""
    return $InitRule
}
Function InitFirewallServiceCustom {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name category -Value ""
    $initRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol -Value ""
    $InitRule | Add-Member -type NoteProperty -name tcp-portrange -Value ""
    $InitRule | Add-Member -type NoteProperty -name udp-portrange -Value ""
    $InitRule | Add-Member -type NoteProperty -name unset -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol-number -Value ""
    $InitRule | Add-Member -type NoteProperty -name visibility -Value ""
    return $InitRule
}
Function InitFirewallServiceGroup {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name Member -Value ""
    return $InitRule
}
Function InitFirewallShaperPerIpShaper {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name maximum-bandwith -Value ""
    $InitRule | Add-Member -type NoteProperty -name max-concurrent-session -Value ""
    $InitRule | Add-Member -type NoteProperty -name forward-DSCP -Value ""
    $InitRule | Add-Member -type NoteProperty -name reverse-DSCP -Value ""
    return $InitRule    
}  
Function InitFirewallShaperTrafficshaper {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name per-policy -Value ""
    $InitRule | Add-Member -type NoteProperty -name maximum-bandwith -Value ""
    $InitRule | Add-Member -type NoteProperty -name quaranteed-bandwidth -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name DSCP -Value ""
    return $InitRule    
}    
Function InitFirewallShapingPolicy {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name dsraddr  -Value ""
    $InitRule | Add-Member -type NoteProperty -name service -Value ""
    $InitRule | Add-Member -type NoteProperty -name app-category -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-id -Value ""
    $InitRule | Add-Member -type NoteProperty -name url-category -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name traffic-shaper -Value ""
    $InitRule | Add-Member -type NoteProperty -name traffic-shaper-reverse -Value ""
    $InitRule | Add-Member -type NoteProperty -name per-ip-shaper -Value ""
    return $InitRule    
}
Function InitFirewallVIP {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name ExtIP -Value ""
    $InitRule | Add-Member -type NoteProperty -name ExtIntf -Value ""
    $InitRule | Add-Member -type NoteProperty -name PortForward -Value ""
    $InitRule | Add-Member -type NoteProperty -name MappedIp -Value ""
    $InitRule | Add-Member -type NoteProperty -name ExtPort -Value ""
    $InitRule | Add-Member -type NoteProperty -name MappedPort -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""
    $InitRule | Add-Member -type NoteProperty -name color -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    #When using loadbalance these values are used
    #Setting ldb-method to none to indicate no loadbalance is done
    #this gets overwritten when loadbalance is used
    $InitRule | Add-Member -type NoteProperty -name ldb-method -Value "none"
    $InitRule | Add-Member -type NoteProperty -name http-host -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name port -Value ""
    $InitRule | Add-Member -type NoteProperty -name monitor -Value ""
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    return $InitRule
}
Function InitFirewallVIPGRP {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name Interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name Color -Value ""
    $InitRule | Add-Member -type NoteProperty -name Member -Value ""
    return $InitRule
}
Function InitRouterAccessList {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name prefix -Value ""
    $InitRule | Add-Member -type NoteProperty -name exact-match -Value ""
    #default action is allow it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name action -Value "allow"
    return $InitRule    
}
Function InitRouterBGP {
    $InitRule = New-Object System.Object;
    #BGP is always present in config set AS to none for checking
    $InitRule | Add-Member -type NoteProperty -name as -Value "none"   
    $InitRule | Add-Member -type NoteProperty -name router-id -Value ""
    $InitRule | Add-Member -type NoteProperty -name bestpath-med-missing-as-worst -Value ""
    $InitRule | Add-Member -type NoteProperty -name fast-external-failover -Value ""
    $InitRule | Add-Member -type NoteProperty -name graceful-restart -Value ""
    $InitRule | Add-Member -type NoteProperty -name graceful-restart-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name graceful-stalepath-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name graceful-update-delay -Value ""
    $InitRule | Add-Member -type NoteProperty -name holdtime-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name keepalive-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name log-neighbor-changes -Value ""
    return $InitRule
}
Function InitRouterISIS {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name is-type -Value "none" 
    $InitRule | Add-Member -type NoteProperty -name adv-passive-only -Value "" 
    $InitRule | Add-Member -type NoteProperty -name adv-passive-only6 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-mode-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-mode-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-password-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-password-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-sendonly-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auth-sendonly-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name ignore-lsp-errors -Value "" 
    $InitRule | Add-Member -type NoteProperty -name lsp-gen-interval-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name lsp-gen-interval-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name lsp-refresh-interval -Value "" 
    $InitRule | Add-Member -type NoteProperty -name max-lsp-lifetime -Value "" 
    $InitRule | Add-Member -type NoteProperty -name spf-interval-exp-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name spf-interval-exp-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name dynamic-hostname -Value "" 
    $InitRule | Add-Member -type NoteProperty -name adjacency-check -Value "" 
    $InitRule | Add-Member -type NoteProperty -name adjacency-check6 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name overload-bit -Value "" 
    $InitRule | Add-Member -type NoteProperty -name overload-bit-on-startup -Value "" 
    $InitRule | Add-Member -type NoteProperty -name default-originate -Value "" 
    $InitRule | Add-Member -type NoteProperty -name default-originate6 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name metric-style -Value "" 
    $InitRule | Add-Member -type NoteProperty -name redistribute-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name redistribute-l2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name redistribute6-l1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name redistribute6-l2 -Value "" 
    return $InitRule
}
Function InitRouterDistributeList {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name "access-list" -Value ""   
    return $InitRule       
}
Function InitRouterNeighbor {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name remote-as -Value ""  
    $InitRule | Add-Member -type NoteProperty -name connect-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name holdtime-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name keepalive-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name weight -Value ""       
    return $InitRule     
}
Function InitRouterNetwork {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name prefix -Value "" 
    return $InitRule       
}
Function InitRouterOSPFInterface {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name cost -Value ""
    $InitRule | Add-Member -type NoteProperty -name dead-interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name hello-interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name network-type -Value ""
    return $InitRule
}
Function InitRouterPolicy {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name action -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    #default route has no data in config setting dst route to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    $InitRule | Add-Member -type NoteProperty -name output-device -Value ""
    $InitRule | Add-Member -type NoteProperty -name src -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value "enable"
    return $InitRule
}
Function InitRouterRedistribute {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Redistribute -Value ""
    #Default is disabled
    $InitRule | Add-Member -type NoteProperty -name status -Value "Disabled"   
    return $InitRule       
}
Function InitRouterStatic {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name blackhole -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""
    $InitRule | Add-Member -type NoteProperty -name Device -Value ""
    $InitRule | Add-Member -type NoteProperty -name distance -Value ""
    #default route has no data in config setting dst route to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""    
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value "enable"
    $InitRule | Add-Member -type NoteProperty -name virtual-wan-link -Value ""
    return $InitRule
}
Function InitSplitDNS {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name PortalName -Value "" 
    $InitRule | Add-Member -type NoteProperty -name domain -Value "" 
    $InitRule | Add-Member -type NoteProperty -name dns-server1 -Value ""
    $InitRule | Add-Member -type NoteProperty -name dns-server2 -Value ""  
    return $InitRule
}
Function InitSystemAccprofile {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name mntgrp -Value ""
    $InitRule | Add-Member -type NoteProperty -name admingrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name updategrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name authgrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name sysgrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name netgrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name loggrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name routegrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name fwgrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name vpngrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name utmgrp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name endpoint-control-grp -Value "" 
    $InitRule | Add-Member -type NoteProperty -name wifi -Value "" 
    return $InitRule 
}
Function InitSystemAdmin {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name accprofile -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name email-to -Value ""
    $InitRule | Add-Member -type NoteProperty -name force-password-change -Value ""
    $InitRule | Add-Member -type NoteProperty -name fortitoken -Value ""
    $InitRule | Add-Member -type NoteProperty -name guest-auth -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip6trustedhosts -Value ""
    $InitRule | Add-Member -type NoteProperty -name peer-auth -Value ""
    $InitRule | Add-Member -type NoteProperty -name remote-auth -Value ""
    $InitRule | Add-Member -type NoteProperty -name schedule -Value ""
    $InitRule | Add-Member -type NoteProperty -name sms-phone -Value ""
    $InitRule | Add-Member -type NoteProperty -name sms-server -Value ""
    $InitRule | Add-Member -type NoteProperty -name two-factor -Value ""
    $InitRule | Add-Member -type NoteProperty -name vdom -Value ""
    $InitRule | Add-Member -type NoteProperty -name trustedhosts -Value ""
    return $InitRule 
}
Function InitSystemDDNS {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name ddns-domain -Value ""
    $InitRule | Add-Member -type NoteProperty -name ddns-server -Value ""
    $InitRule | Add-Member -type NoteProperty -name use-public-ip -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name monitor-interface -Value ""
    return $InitRule 
}
Function InitSystemDHCP {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name "lease-time" -Value ""
    $InitRule | Add-Member -type NoteProperty -name domain -Value ""
    $InitRule | Add-Member -type NoteProperty -name "default-gateway" -Value "    "
    $InitRule | Add-Member -type NoteProperty -name "timezone-option" -Value ""
    $InitRule | Add-Member -type NoteProperty -name timezone -Value ""
    $InitRule | Add-Member -type NoteProperty -name netmask -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name "dns-server1" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "dns-server2" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "dns-server3" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "dns-server4" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "ntp-server1" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "ntp-server2" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "ntp-server3" -Value ""
    $InitRule | Add-Member -type NoteProperty -Name "filename" -Value ""
    $InitRule | Add-Member -type NoteProperty -Name status -Value "Enable"
    return $InitRule
}
Function InitSystemDNSDatabase {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name allow-transfer -Value ""
    $InitRule | Add-Member -type NoteProperty -name authoritative -Value ""
    $InitRule | Add-Member -type NoteProperty -name contact -Value ""
    $InitRule | Add-Member -type NoteProperty -name DNSName -Value ""
    $InitRule | Add-Member -type NoteProperty -name domain -Value ""
    $InitRule | Add-Member -type NoteProperty -name forwarder -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip-master -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip-primary -Value ""
    $InitRule | Add-Member -type NoteProperty -name primary-name -Value ""
    $InitRule | Add-Member -type NoteProperty -name rr-max -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name source-ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name ttl -Value "86400"
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name view -Value ""
    return $InitRule 
}
Function InitSystemDNSEntry {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name canonical -Value ""
    $InitRule | Add-Member -type NoteProperty -name hostname -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name ipv6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name preference -Value "10"
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name ttl -Value "0"
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    return $InitRule     
}
Function InitSystemDNSServer {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name name -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name dnsfilter-profile -Value ""
    $InitRule | Add-Member -type NoteProperty -name doh -Value ""
    return $InitRule 
}
Function InitSystemGlobal {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name admin-concurrent -Value ""
    $InitRule | Add-Member -type NoteProperty -name admin-console-timeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name admin-https-ssl-versions -Value ""
    $InitRule | Add-Member -type NoteProperty -name admin-server-cert -Value "Selfsigned"
    $InitRule | Add-Member -type NoteProperty -name admin-telnet -Value "enable"
    $InitRule | Add-Member -type NoteProperty -name admintimeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name admin-sport -Value "443"
    $InitRule | Add-Member -type NoteProperty -name alias -Value "    "
    $initRule | Add-Member -type NoteProperty -name compliance-check -Value ""
    $InitRule | Add-Member -type NoteProperty -name disk-usage -Value ""
    $InitRule | Add-Member -type NoteProperty -name fortigate-cloud-sandbbox -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-allow-default-hostname -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-certificates -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-custom-languages -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-date-format -Value "yyyy/MM/dd"
    $initRule | Add-Member -type NoteProperty -name gui-device-latitude -Value ""
    $initRule | Add-Member -type NoteProperty -name gui-device-longitude -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-displayhostname -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-firmware-upgrade-warning -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-ipv6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-local-out -Value ""
    $initRule | Add-Member -type NoteProperty -name gui-theme -Value "green"
    $InitRule | Add-Member -type NoteProperty -name gui-replacement-message-groups -Value ""
    $InitRule | Add-Member -type NoteProperty -name gui-wireless-opensecurity -Value ""
    $InitRule | Add-Member -type NoteProperty -name hostname -Value ""
    $InitRule | Add-Member -type NoteProperty -name language -Value ""
    $InitRule | Add-Member -type NoteProperty -name proxy-auth-timeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name remoteauthtimeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name revision-backup-on-logout -Value ""
    $InitRule | Add-Member -type NoteProperty -name revision-image-auto-backup -Value ""
    $InitRule | Add-Member -type NoteProperty -name ssl-min-proto-version -Value "TLSv1-2"
    $InitRule | Add-Member -type NoteProperty -name switch-controller -Value ""
    $InitRule | Add-Member -type NoteProperty -name tcp-halfclose-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name tcp-halfopen-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name timezone -Value ""
    $InitRule | Add-Member -type NoteProperty -name udp-idle-timer -Value ""
    return $InitRule
}
Function InitSystemHA {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name group-id -Value ""
    $InitRule | Add-Member -type NoteProperty -name group-Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name ha-mgmt-status -Value ""
    $InitRule | Add-Member -type NoteProperty -name hbdev -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name monitor -Value ""
    #Next line gets filterd out when creating the ExcelSheet
    $InitRule | Add-Member -type NoteProperty -name password -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name override -Value ""
    $InitRule | Add-Member -type NoteProperty -name session-pickup -Value ""
    $InitRule | Add-Member -type NoteProperty -name session-sync-dev -Value ""
    $InitRule | Add-Member -type NoteProperty -name sync-config -Value "enable"
    return $InitRule
}
Function InitSystemHAMGMTInterfaces {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""    
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    return $InitRule
}
Function InitSystemInterface {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name alias -Value ""
    $InitRule | Add-Member -type NoteProperty -name allowaccess -Value ""
    $InitRule | Add-Member -type NoteProperty -name description -Value ""
    $InitRule | Add-Member -type NoteProperty -name dedicated-to -Value ""
    $InitRule | Add-Member -type NoteProperty -name estimated-downstream-bandwidth -Value ""
    $InitRule | Add-Member -type NoteProperty -name estimated-upstream-bandwidth -Value ""
    $InitRule | Add-Member -type NoteProperty -name explicit-web-proxy -Value ""
    $InitRule | Add-Member -type NoteProperty -name fortiheartbeat -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name mtu -Value ""
    $InitRule | Add-Member -type NoteProperty -name mtu-override -Value ""
    $InitRule | Add-Member -type NoteProperty -name name -Value ""
    $InitRule | Add-Member -type NoteProperty -name remote-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name role -Value ""
    $InitRule | Add-Member -type NoteProperty -name scan-botnet-connections -Value ""
    $InitRule | Add-Member -type NoteProperty -name secondary-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name stp -Value ""
    $InitRule | Add-Member -type NoteProperty -name snmp-index -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name User -Value ""
    $InitRule | Add-Member -type NoteProperty -name vdom -Value ""
    $InitRule | Add-Member -type NoteProperty -name vlanid -Value ""
    return $InitRule
}
Function InitSystemLinkMonitor {
    $InitRule = New-Object System.Object;
    #Default values are set here they get overwritten if changed
    $InitRule | Add-Member -type NoteProperty -name failtime -Value "5"
    $InitRule | Add-Member -type NoteProperty -name gateway-ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name interval -Value "5"
    $InitRule | Add-Member -type NoteProperty -name name -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol -Value ""
    $InitRule | Add-Member -type NoteProperty -name recoverytime -Value "5"
    $InitRule | Add-Member -type NoteProperty -name srcintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name server -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name timeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name update-cascade-interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name update-static-route -Value ""    
    return $InitRule
}
Function InitSystemSessionHelper {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol -Value ""
    $InitRule | Add-Member -type NoteProperty -name port -Value ""
    return $InitRule
}
Function InitSystemSettings {
    $InitRule = New-Object System.Object;
    #There is only ONE set of this settting. Therefore is is not needed to define the NoteProperties.
    return $InitRule
}
Function InitSystemSNMPSysInfo {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name status -Value "" 
    $InitRule | Add-Member -type NoteProperty -name description -Value ""
    $InitRule | Add-Member -type NoteProperty -name contact-info -Value ""
    $InitRule | Add-Member -type NoteProperty -name location -Value ""
    return $InitRule
}
Function InitSystemSNMPCommunity {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name name -Value ""
    $InitRule | Add-Member -type NoteProperty -name events -Value "None"    
    return $InitRule
}
Function InitSystemSNMPCommunityHost {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name ha-direct -Value ""
    $InitRule | Add-Member -type NoteProperty -name host-type -Value "Any" 
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name source-ip -Value ""
    return $InitRule
}
Function InitSystemSNMPUser {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name notify-hosts -Value ""
    $InitRule | Add-Member -type NoteProperty -name security-level -Value ""
    $InitRule | Add-Member -type NoteProperty -name auth-pwd -Value ""
    return $InitRule
}
Function InitSystemVirtualWanLink {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name load-balance-mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name speedtest-bypass-routing -Value ""
    $InitRule | Add-Member -type NoteProperty -name duplication-max-num -Value ""
    $InitRule | Add-Member -type NoteProperty -name neighbor-hold-down -Value ""
    $InitRule | Add-Member -type NoteProperty -name neighbor-hold-down-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name neighbor-hold-boot-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name fail-detect -Value ""
    $InitRule | Add-Member -type NoteProperty -name fail-alert-interfaces -Value ""
    return $InitRule
}
Function InitSystemZone {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    return $InitRule    
}
Function InitTag {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Category -Value ""
    $InitRule | Add-Member -type NoteProperty -name Tags -Value ""
    return $InitRule    
}
Function InitUserGroup {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name member -Value ""
    $InitRule | Add-Member -type NoteProperty -name match -Value ""
    $InitRule | Add-Member -type NoteProperty -name server-name -Value ""
    $InitRule | Add-Member -type NoteProperty -name group-name -Value ""
    return $InitRule      
}
Function InitUserLdap {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name server -Value ""    
    $InitRule | Add-Member -type NoteProperty -name cnid -Value ""
    $InitRule | Add-Member -type NoteProperty -name dn -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name username -Value ""
    $InitRule | Add-Member -type NoteProperty -name secure -Value "disabled"
    $InitRule | Add-Member -type NoteProperty -name ca-cert -Value "none"
    $InitRule | Add-Member -type NoteProperty -name port -Value "389"
    return $InitRule      
}
Function InitUserLocal {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name two-factor -Value "None" 
    $InitRule | Add-Member -type NoteProperty -name Fortitoken -Value "" 
    $InitRule | Add-Member -type NoteProperty -name email-to -Value ""
    $InitRule | Add-Member -type NoteProperty -name ldap-server -Value ""
    return $InitRule      
}
Function InitUserRadius {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name auth-type -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name secret -Value ""
    $InitRule | Add-Member -type NoteProperty -name server -Value ""
    $InitRule | Add-Member -type NoteProperty -name timeout -Value "5" 
    return $InitRule      
}
Function InitUserSAML {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name entity-id -Value ""
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name single-sign-on-url -Value ""
    $InitRule | Add-Member -type NoteProperty -name single-logout-url -Value ""
    $InitRule | Add-Member -type NoteProperty -name idp-entity-id -Value "" 
    $InitRule | Add-Member -type NoteProperty -name idp-single-sign-on-url -Value "" 
    $InitRule | Add-Member -type NoteProperty -name idp-single-logout-url -Value "" 
    $InitRule | Add-Member -type NoteProperty -name idp-cert -Value "" 
    $InitRule | Add-Member -type NoteProperty -name group-name -Value "" 
    $InitRule | Add-Member -type NoteProperty -name digest-method -Value "" 
    return $InitRule      
}
Function InitVirtualWanLinkHealthCheck {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""    
    $InitRule | Add-Member -type NoteProperty -name server -Value ""
    $InitRule | Add-Member -type NoteProperty -name members -Value ""
    return $InitRule  
}
Function InitVirtualWanLinkMember {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name cost -Value ""    
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name weight -Value "1"
    $InitRule | Add-Member -type NoteProperty -name zone -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    $InitRule | Add-Member -type NoteProperty -name source -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name source6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name spillover-threshold -Value ""
    $InitRule | Add-Member -type NoteProperty -name ingress-spillover-threshold -Value ""
    $InitRule | Add-Member -type NoteProperty -name volume-ratio -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""  
    return $InitRule   
}
Function InitVirtualWanLinkService {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""    
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name member -Value ""
    $InitRule | Add-Member -type NoteProperty -name dst -Value ""
    $InitRule | Add-Member -type NoteProperty -name src -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority-members -Value ""
    $InitRule | Add-Member -type NoteProperty -name use-shortcut-sla -Value ""
    $InitRule | Add-Member -type NoteProperty -name addr-mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name input-device -Value ""
    $InitRule | Add-Member -type NoteProperty -name input-device-negate -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name minimum-sla-meet-members -Value ""
    $InitRule | Add-Member -type NoteProperty -name hash-mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name role -Value ""
    $InitRule | Add-Member -type NoteProperty -name standalone-action -Value ""
    $InitRule | Add-Member -type NoteProperty -name quality-link -Value ""
    $InitRule | Add-Member -type NoteProperty -name tos -Value ""
    $InitRule | Add-Member -type NoteProperty -name tos-mask -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol -Value ""
    $InitRule | Add-Member -type NoteProperty -name start-port -Value ""
    $InitRule | Add-Member -type NoteProperty -name end-port -Value ""
    $InitRule | Add-Member -type NoteProperty -name route-tag -Value ""
    $InitRule | Add-Member -type NoteProperty -name dst-negate -Value ""
    $InitRule | Add-Member -type NoteProperty -name dst6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name src6 -Value ""
    $InitRule | Add-Member -type NoteProperty -name src-negate -Value ""
    $InitRule | Add-Member -type NoteProperty -name users -Value ""
    $InitRule | Add-Member -type NoteProperty -name groups -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-custom -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-custom-group -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-name -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-group -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-app-ctrl -Value ""
    $InitRule | Add-Member -type NoteProperty -name internet-service-app-ctrl-group -Value ""
    $InitRule | Add-Member -type NoteProperty -name health-check -Value ""
    $InitRule | Add-Member -type NoteProperty -name link-cost-factor -Value ""
    $InitRule | Add-Member -type NoteProperty -name packet-loss-weight -Value ""
    $InitRule | Add-Member -type NoteProperty -name latency-weight -Value ""
    $InitRule | Add-Member -type NoteProperty -name jitter-weight -Value ""
    $InitRule | Add-Member -type NoteProperty -name bandwidth-weight -Value ""
    $InitRule | Add-Member -type NoteProperty -name link-cost-threshold -Value ""
    $InitRule | Add-Member -type NoteProperty -name hold-down-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name dscp-forward -Value ""
    $InitRule | Add-Member -type NoteProperty -name dscp-reverse -Value ""
    $InitRule | Add-Member -type NoteProperty -name dscp-forward-tag -Value ""
    $InitRule | Add-Member -type NoteProperty -name dscp-reverse-tag -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority-zone -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    $InitRule | Add-Member -type NoteProperty -name default -Value ""
    $InitRule | Add-Member -type NoteProperty -name sla-compare-method -Value ""
    $InitRule | Add-Member -type NoteProperty -name tie-break -Value ""
    return $InitRule  
}
Function InitVpnIpsecPhase1 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name keylife "86400"
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name peertype -Value ""
    $InitRule | Add-Member -type NoteProperty -name proposal -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name dhgrp -Value ""
    #default dpd = enable
    $InitRule | Add-Member -type NoteProperty -name dpd -Value "enable"
    #default ikeversion = 1
    $InitRule | Add-Member -type NoteProperty -name ike-version -Value "1"
    $InitRule | Add-Member -type NoteProperty -name nattraversal -Value "enabled"
    $InitRule | Add-Member -type NoteProperty -name remote-gw -Value ""
    $InitRule | Add-Member -type NoteProperty -name remotegw-ddns -Value ""
    $InitRule | Add-Member -type NoteProperty -name peerid -Value ""
    $InitRule | Add-Member -type NoteProperty -name authusrgrp -Value ""
    $InitRule | Add-Member -type NoteProperty -name ipv4-end-ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name ipv4-netmask -Value ""
    $InitRule | Add-Member -type NoteProperty -name ipv4-start-ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode-cfg -Value ""
    $InitRule | Add-Member -type NoteProperty -name net-device -Value ""
    $InitRule | Add-Member -type NoteProperty -name wizard-type -Value ""
    $InitRule | Add-Member -type NoteProperty -name xauthtype -Value ""
    #Next line gets filterd out when creating the ExcelSheet
    $InitRule | Add-Member -type NoteProperty -name psksecret -Value ""
    return $InitRule
}
Function InitVpnIpsecPhase2 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name phase1name -Value ""
    $InitRule | Add-Member -type NoteProperty -name proposal -Value ""
    $InitRule | Add-Member -type NoteProperty -name dhgrp -Value "14,5"
    $InitRule | Add-Member -type NoteProperty -name replay -Value "enable"
    $InitRule | Add-Member -type NoteProperty -name auto-negotiate -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name keylifeseconds -Value "43200"
    #default has no data in config setting src-subnet to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name src-subnet -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name src-name -Value ""
    #default has no data in config setting dst-subnet to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst-subnet -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name dst-name -Value ""
    #default keepalive = disable
    $InitRule | Add-Member -type NoteProperty -name keepalive -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name pfs -Value "enable"
    return $InitRule
}
#Function InitVPNSSLWebPortal
#Default values are present these will be overwritten when needed
Function InitVPNSSLWebPortal {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name PortalName -Value "" 
    $InitRule | Add-Member -type NoteProperty -name auto-connect "" 
    $InitRule | Add-Member -type NoteProperty -name display-connection-tools ""                   
    $InitRule | Add-Member -type NoteProperty -name display-history ""                            
    $InitRule | Add-Member -type NoteProperty -name display-status ""                             
    $InitRule | Add-Member -type NoteProperty -name heading ""
    $InitRule | Add-Member -type NoteProperty -name forticlient-download "" 
    $InitRule | Add-Member -type NoteProperty -name ipv6-tunnel-mode -Value "disable" 
    $InitRule | Add-Member -type NoteProperty -name ip-pools -Value "" 
    $InitRule | Add-Member -type NoteProperty -name ipv6-pools -Value ""
    $InitRule | Add-Member -type NoteProperty -name keep-alive "" 
    $InitRule | Add-Member -type NoteProperty -name limit-user-logins ""
    $InitRule | Add-Member -type NoteProperty -name save-password ""                                               
    $InitRule | Add-Member -type NoteProperty -name split-tunneling "enabled" 
    $InitRule | Add-Member -type NoteProperty -name tunnel-mode -Value "disable" 
    $InitRule | Add-Member -type NoteProperty -name user-bookmark "" 
    $InitRule | Add-Member -type NoteProperty -name web-mode -Value "disable"                             
    
    return $InitRule   
}
#Function for SSLWebPortal OS CheckList
Function InitVPNSSLWebPortalOSCheckList {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name PortalName -Value ""
    $InitRule | Add-Member -type NoteProperty -name OS -Value "" 
    $InitRule | Add-Member -type NoteProperty -name Action "Allow"

    return $InitRule
}
Function InitVPNSSLSettings {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name default-portal -Value ""   
    $InitRule | Add-Member -type NoteProperty -name dns-server1 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name dns-server2 -Value "" 
    $InitRule | Add-Member -type NoteProperty -name dns-suffix -Value "" 
    $InitRule | Add-Member -type NoteProperty -name idle-timeout -Value "600"
    $InitRule | Add-Member -type NoteProperty -name port -Value "" 
    $InitRule | Add-Member -type NoteProperty -name tunnel-ip-pools -Value "" 
    $InitRule | Add-Member -type NoteProperty -name tunnel-ipv6-pools -Value "" 
    $InitRule | Add-Member -type NoteProperty -name servercert  -Value ""
    $InitRule | Add-Member -type NoteProperty -name source-address  -Value ""
    $InitRule | Add-Member -type NoteProperty -name source-address6  -Value ""  
    $InitRule | Add-Member -type NoteProperty -name source-interface  -Value ""
    $InitRule | Add-Member -type NoteProperty -name ssl-min-proto-ver tls1-1
    return $InitRule   
}

Function CleanupLine ($LineToCleanUp) {
    $LineToCleanUp = $LineToCleanUp.TrimStart()
    $LineToCleanUpArray = $LineToCleanUp.Split('"')
    $i=1
    $ReturnValue = $null
    if ($LineToCleanUpArray.Count -gt 1) {
        #Line has "" in it 
        DO {
            $LineToCleanUpArrayMember = $LineToCleanUpArray[$i]
            if ($LineToCleanUpArrayMember -ne "") {
                if ($ReturnValue) { $ReturnValue = $ReturnValue + "," + $LineToCleanUpArrayMember }
                else { $ReturnValue = $LineToCleanUpArrayMember}
            }
            $i++
            #The next value is a space and can always be skipped
            $i++
        } While ($i -le $LineToCleanUpArray.Count-1)
    }
    else {
        #Line has only Space as seperators
        $LineToCleanUpArray = $LineToCleanUp.Split(' ')
        if ($LineToCleanUpArray.Count -ge 3) {
            $i=2
            $ReturnValue = $null
            DO {
                if ($LineToCleanUpArray[$i] -ne " ") {
                    if ($ReturnValue) { $ReturnValue = $ReturnValue + "," + $LineToCleanUpArray[$i] }
                    else { $ReturnValue = $LineToCleanUpArray[$i]}
                }
                $i++
            } While ($i -le $LineToCleanUpArray.Count-1)
        }
        else { $ReturnValue = $LineToCleanUpArray[$LineToCleanUpArray.Count-1] }
    }
    return $ReturnValue
}

Function CleanSheetName ($CSName) {
    $CSName = $CSName.Replace("-","_")
    $CSName = $CSName.Replace(" ","_")
    $CSName = $CSName.Replace("\","_")
    $CSName = $CSName.Replace("/","_")
    $CSName = $CSName.Replace("[]","_")
    $CSName = $CSName.Replace("]","_")
    $CSName = $CSName.Replace("*","_")
    $CSName = $CSName.Replace("?","_")
    if ($CSName.Length -gt 32) {
        Write-output "Sheetname ($CSName) cannot be longer that 32 character shorting name to fit."
        $CSName = $CSName.Substring(0,31)
    }    

    return $CSName
}
Function ChangeFontExcelCell ($ChangeFontExcelCellSheet, $ChangeFontExcelCellRow, $ChangeFontExcelCellColumn) {
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).HorizontalAlignment = -4108
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.Size = 18
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.Bold=$True
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.Name = "Cambria"
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.ThemeFont = 1
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.ThemeColor = 4
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.ColorIndex = 55
    $ChangeFontExcelCellSheet.Cells.Item($ChangeFontExcelCellRow, $ChangeFontExcelCellColumn).Font.Color = 8210719
}
Function ConvertHaInterfaces ($HAline) {
#This function formats the online hbdev to a nicer format
    $TempLine = "("
    $HAArray = $HAline.Split(",")
    for ($Counter=0;$Counter -le $HAArray.Count-1;$Counter++) {
        $TempLine = $Templine + $HAArray[$Counter]
        if ($Counter % 2 -eq 0) {
            $TempLine = $TempLine + ","
        }
        else {
            $TempLine = $TempLine + "),("
        }
    }
    $TempLine = $TempLine.Substring(0,$TempLine.Length-3)
    $TempLine = $TempLine + ")"
    Return $TempLine
}
Function ConvertTagArrayToLine ($ConvertTagArray) {
#This function formats the SecurityTag (config tagging) subsection to a nice oneliner
    $TempLine = ""
    If ($ConvertTagArray) {
        foreach ($ConvertTag in $ConvertTagArray) {
            $TempLine = $TempLine + "("
            #$NoteProperties = $ConvertTagArray | get-member -Type NoteProperty
            $NoteProperties = SkipEmptyNoteProperties $ConvertTagArray
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $TempLine = $TempLine + $ConvertTag.$PropertyString + ","
            }
            #Drop the last char (,)
            $TempLine = $TempLine.Substring(0,$TempLine.Length-1)
            $TempLine = $TempLine + "),"
        }
        #Drop the last char (,)
        $TempLine = $TempLine.Substring(0,$TempLine.Length-1)
    }
    Return $TempLine
}
#CopyArrayMember ($ActiveArray)
#This Function copies the $ActiveArray value by value thus creating a new object
Function CopyArrayMember ($ActiveArray) {
    $NewMember = New-Object System.Object;
    $NoteProperties = $ActiveArray | get-member -Type NoteProperty
    foreach ($ActiveMember in $ActiveArray) {
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            $Value = $ActiveMember.$PropertyString         
            $NewMember | Add-Member -MemberType NoteProperty -Name $PropertyString -Value $Value
        }                      
    }    
    Return $NewMember
}
#Function SkipEmptyNoteProperties ($SkipEmptyNotePropertiesArray)
#This function Loopt through all available noteproperties and checks if it is used.
#If it is not used the property will not be returned as it is not needed in the export.
Function SkipEmptyNoteProperties ($SkipEmptyNotePropertiesArray) {
    $ReturnNoteProperties = [System.Collections.ArrayList]@()
    $SkipNotePropertiesOrg = $SkipEmptyNotePropertiesArray | get-member -Type NoteProperty
    foreach ($SkipNotePropertieOrg in $SkipNotePropertiesOrg) {
        foreach ($SkipEmptyNotePropertiesMember in $SkipEmptyNotePropertiesArray) {
            $NotePropertyFound = $False
            $SkipNotePropertiePropertyString = [string]$SkipNotePropertieOrg.Name
            if ($SkipEmptyNotePropertiesMember.$SkipNotePropertiePropertyString) { 
                $NotePropertyFound = $True
                break;
            }
        }
        If ($NotePropertyFound) { $ReturnNoteProperties.Add($SkipNotePropertieOrg) | Out-Null  }
    }
    return $ReturnNoteProperties
}
Function Convert-NumberToA1 { 
    <# 
    .SYNOPSIS 
    This converts any integer into A1 format. 
    .DESCRIPTION 
    See synopsis. 
    .PARAMETER number 
    Any number between 1 and 2147483647 
    #>
    Param([parameter(Mandatory=$true)] 
        [int]$number) 

    $a1Value = $null 
    While ($number -gt 0) { 
    $multiplier = [int][system.math]::Floor(($number / 26)) 
    $charNumber = $number - ($multiplier * 26) 
    If ($charNumber -eq 0) { $multiplier-- ; $charNumber = 26 } 
        $a1Value = [char]($charNumber + 64) + $a1Value 
        $number = $multiplier 
    } 
    Return $a1Value 
}
#Function CreateExcelTabel ($ActiveSheet, $ActiveArray)
#This Function Creates the Excel tabel 
#$ActiveSheet is the used Excelsheet
#$ActiveArray is the array that needs to be exported
Function CreateExcelTabel ($ActiveSheet, $ActiveArray, $StartColomn=1) {
    $NoteProperties = SkipEmptyNoteProperties $ActiveArray
    $Column=$StartColomn
    foreach ($Noteproperty in $NoteProperties) {
        $PropertyString = [string]$NoteProperty.Name
        #Keep passwords/psksecrets out of the documentation
        if (!$SkipExportProperties.Contains($PropertyString)) { 
            $excel.cells.item($row,$Column) = $PropertyString
            $Column++
        }
    }
    $StartRow = $Row
    $Row++
    foreach ($ActiveMember in $ActiveArray) {
        #$Column=1
        $Column=$StartColomn
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            if (!$SkipExportProperties.Contains($PropertyString)) { 
                $Value = $ActiveMember.$PropertyString         
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }
        }                      
        $row++
    }    
    #No need to filter if there is only one row.
    if (!($Global:SkipFilter) -and ($ActiveArray.Count -gt 1)) {
        $ColumExcel = Convert-NumberToA1 $NoteProperties.count
        $Sheet.Range("A$($StartRow):$($ColumExcel)$($Row-1)").AutoFilter()  | Out-Null
    }
    Return $row
}
Function CreateExcelSheet ($SheetName, $SheetArray) {
    #If the sheet is empty no need to create the Excelpage
    if ($SheetArray) {
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $Column = 1
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column  
        $row=$row+2
        $row = CreateExcelTabel $Sheet $SheetArray
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null
    }
}
Function CreateExcelSheetDHCP {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    #Remember Skipfilter when making a sheet with multiple arrays and create a filter on only one.
    if (!$SkipFilter) {
        $RemberSkipFilter = $true
        $SkipFilter = $true
    }
    if ($DHCPIP4) { $SheetName = "DHCP_IPV4_" }
    else { $SheetName = "DHCP_IPV6_" }
    $SheetName = $SheetName + $rule.Interface + "_" + $rule.ID
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column = 1   
    $excel.cells.item($row,$Column) = $SheetName 
    ChangeFontExcelCell $Sheet $row $Column 
    $row=$row+2
    $excel.cells.item($row,$Column) = "Normal DHCP options"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $row = CreateExcelTabel $Sheet $rule
    $row++
    if ($DHCPOptionsArray) {                
        $Column=1
        $excel.cells.item($row,$Column) = "Extra DHCP options"
        ChangeFontExcelCell $Sheet $row $Column
        $row++   
        $row = CreateExcelTabel $Sheet $DHCPOptionsArray   
    }
    $row++
    if ($DHCPRangeArray) {
        #Add IP ranges
        $Column=1
        $excel.cells.item($row,$Column) = "DHCP Range"
        ChangeFontExcelCell $Sheet $row $Column
        $row++
        if ($RemberSkipFilter -and $DHCPReservedAddressArray) {
            $SkipFilter = $false
        }
        $DHCPRangeArray = $DHCPRangeArray | Sort-Object ID 
        $row = CreateExcelTabel $Sheet $DHCPRangeArray
        $row++ 
        $SkipFilter = $true
    }
    $Column=1
    if ($DHCPReservedAddressArray) {
        $excel.cells.item($row,$Column) = "Reserved Addresses"
        ChangeFontExcelCell $Sheet $row $Column
        $row++  
        if ($RemberSkipFilter) {
            $SkipFilter = $false
        }  
        $DHCPReservedAddressArray = $DHCPReservedAddressArray | Sort-Object ID  
        if ($RemberSkipFilter) {
            $SkipFilter = $false
        }
        $row = CreateExcelTabel $Sheet $DHCPReservedAddressArray     
    }     
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null    
    if ($RemberSkipFilter) {
        $SkipFilter = $false
    }
}
Function CreateExcelSheetDNSDatabase {
    if ($ruleList) {
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = "DNSDatabase$VdomName"
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $SheetName = $SheetName.Replace("-","_")
        $Column = 1   
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column 
        $row=$row+2
        $excel.cells.item($row,$Column) = "DNSServers"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $Row = CreateExcelTabel $Sheet $ruleList  
        if ($DNSEntryArray) {
            $excel.cells.item($row,$Column) = "DNS Entries"
            ChangeFontExcelCell $Sheet $row $Column
            $row++    
            $DNSEntryArray = $DNSEntryArray | Sort-Object ID  
            $row = CreateExcelTabel $Sheet $DNSEntryArray             
        }
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null 
    }    
}

Function CreateExcelSheetHA {
    #If group-name is empty HA is not active and this excel tab would be useless
    if ($rule."group-name" -ne "") {
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = "HA$VdomName"
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $Column = 1   
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column 
        $row=$row+2
        $row = CreateExcelTabel $Sheet $rule
        if ($HAMGMTInterfaceArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "HA management interface(s)" 
            ChangeFontExcelCell $Sheet $row $Column
            $Row++      
            $row = CreateExcelTabel $Sheet $HAMGMTInterfaceArray 
        }      
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null      
    }
}
Function CreateExcelSheetVPNSSLSettings {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    $SheetName = "VPN_SSLSettings$VdomName"  
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column=1
    $excel.cells.item($row,$Column) = $SheetName 
    ChangeFontExcelCell $Sheet $row $Column  
    $row=$row+2
    $row = CreateExcelTabel $Sheet $rulelist
    $Row++
    if ($AuthenticationRuleArray) {
        $AuthenticationRuleArray = $AuthenticationRuleArray | Sort-Object ID 
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Authentication Rule(s)"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $AuthenticationRuleArray
    }
    $UsedRange = $Sheet.usedRange               
    $UsedRange.EntireColumn.AutoFit() | Out-Null 
}
Function CreateExcelSheetSSLwebportal {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    $SheetName = "VPN_SSLWebportal$VdomName"  
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column=1
    $excel.cells.item($row,$Column) = $SheetName 
    ChangeFontExcelCell $Sheet $row $Column  
    $row=$row+2
    $row = CreateExcelTabel $Sheet $rulelist
    $row++
    if ($SplitDNSArray) {
        $SplitDNSArray = $SplitDNSArray | Sort-Object PortalName,ID
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Split DNS Configuration"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $SplitDNSArray 
    }  
    $row++ 
    if ($BookmarkArray) {
        $BookmarkArray = $BookmarkArray | Sort-Object PortalName,Group,Name
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Configured bookmarks"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $BookmarkArray
    }  
    $row++ 
    if ($OSCheckListArray) {
        $OSCheckListArray = $OSCheckListArray | Sort-Object PortalName,OS
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Configured OS check"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $OSCheckListArray
    }     
    $UsedRange = $Sheet.usedRange               
    $UsedRange.EntireColumn.AutoFit() | Out-Null      
}
Function CreateExcelSheetVirtualWanLink {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    if ($SDWAN) {
        $SheetName = "SDWAN$VdomName"
        $ExcelSDWANText = "SDWAN"
    }
    else {
        $SheetName = "Virtual_Wan_Link$VdomName"
        $ExcelSDWANText = "Virtual Wan"
    }
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column = 1   
    $excel.cells.item($row,$Column) = $SheetName 
    ChangeFontExcelCell $Sheet $row $Column 
    $row=$row+2
    $excel.cells.item($row,$Column) = "Global $ExcelSDWANText Link settings"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $row = CreateExcelTabel $Sheet $rule 
    if ($VirtualWanLinkMemberArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link $ExcelSDWANText members"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $VirtualWanLinkMemberArray  
    }  
    if ($VirtualWanLinkHealthCheckArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link $ExcelSDWANText healthcheck"
        ChangeFontExcelCell $Sheet $row $Column
        $row++
        $row = CreateExcelTabel $Sheet $VirtualWanLinkHealthCheckArray        
    }   
    if ($VirtualWanLinkServiceArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link $ExcelSDWANText service"
        ChangeFontExcelCell $Sheet $row $Column
        $row++
        $row = CreateExcelTabel $Sheet $VirtualWanLinkServiceArray        
    }      
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null                  
}
Function CreateExcelSheetAcme {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    $SheetName = "Acme$VdomName"
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column = 1   
    $excel.cells.item($row,$Column) = $SheetName 
    ChangeFontExcelCell $Sheet $row $Column  
    $row=$row+2 
    $row = CreateExcelTabel $Sheet $AcmeAccountArray  
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null    
}
Function CreateExcelSheetBGP {
    #If BGP is not used AS = none then this sheet does not need to be created
    if ($Rule."as" -ne "none") {
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = "Router_$RouterSection$VdomName"
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $Column = 1   
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column  
        $row=$row+2
        $row = CreateExcelTabel $Sheet $rule
        if ($RouterNeighborArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "BGP Neighbors" 
            ChangeFontExcelCell $Sheet $row $Column
            $Row++      
            $row = CreateExcelTabel $Sheet $RouterNeighborArray 
        }
        if ($RouterNetworkArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "Networks"
            ChangeFontExcelCell $Sheet $row $Column
            $Row++  
            $row = CreateExcelTabel $Sheet $RouterNetworkArray
        }
        if ($RouterRedistibuteArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "Redistribute routes"
            ChangeFontExcelCell $Sheet $row $Column
            #Make the default that no routes are redistibuted. If there are redistubuted routes this field wil get overwritten.
            $excel.cells.item($row,$Column+1) = "none"   
            Foreach ($ArrayMember in $RouterRedistibuteArray) {
                if ($ArrayMember.status -eq "enable") {
                    $Column++
                    $excel.cells.item($row,$Column) = $ArrayMember.Redistribute
                }                        
            }
            $Row++ 
        }       
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null  
    }    
}
Function CreateExcelSheetISIS {
    if ($Rule."is-type" -ne "none") {
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = "Router_$RouterSection$VdomName"
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $Column = 1   
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column  
        $row=$row+2
        $row = CreateExcelTabel $Sheet $rule
        if ($RouterRedistibuteArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "Redistribute routes"
            ChangeFontExcelCell $Sheet $row $Column
            #Make the default that no routes are redistibuted. If there are redistubuted routes this field wil get overwritten.
            $excel.cells.item($row,$Column+1) = "none"   
            Foreach ($ArrayMember in $RouterRedistibuteArray) {
                if ($ArrayMember.status -eq "enable") {
                    $Column++
                    $excel.cells.item($row,$Column) = $ArrayMember.Redistribute
                }                        
            }
            $Row++ 
        }       
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null   
}  
}
Function CreateExcelSheetOSPF {
    #if $OSPFRouterID is "no-ospf" it has not been overwritten and OSPF is not used -> Do not create the sheet.
    if ($OSPFRouterID -ne "no-ospf") {
        #Remember Skipfilter when making a sheet with multiple arrays and create a filter on only one.
        if (!$SkipFilter) {
            $RemberSkipFilter = $true
            $SkipFilter = $true
        }
        $row = 2
        $Sheet = $workbook.Worksheets.Add()
        PlaceLinkToToC $Sheet
        $SheetName = "Router_$RouterSection$VdomName"
        $SheetName = CleanSheetName $SheetName
        $Sheet.Name = $SheetName
        $Column=1
        $excel.cells.item($row,$Column) = $SheetName 
        ChangeFontExcelCell $Sheet $row $Column  
        $row=$row+2 
        $excel.cells.item($row,$Column) = "Router ID"
        ChangeFontExcelCell $Sheet $row $Column
        $Column++
        $excel.cells.item($row,$Column) = $OSPFRouterID
        $row++
        $Column = 1 
        $excel.cells.item($row,$Column) = "OSPF Area"
        ChangeFontExcelCell $Sheet $row $Column
        $Column++
        $excel.cells.item($row,$Column) = $OSPFRouterArea
        $row++   
        if ($RouterNetworkArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "OSPF Networks"
            ChangeFontExcelCell $Sheet $row $Column 
            $Row++     
            $row = CreateExcelTabel $Sheet $RouterNetworkArray 
        }  
        if ($RouterInterfaceArray) {
            if ($RemberSkipFilter) {
                $SkipFilter = $false
            }
            $Column=1
            $excel.cells.item($row,$Column) = "OSPF Interfaces"
            ChangeFontExcelCell $Sheet $row $Column 
            $Row++      
            $row = CreateExcelTabel $Sheet $RouterInterfaceArray
            if ($RemberSkipFilter) {
                $SkipFilter = $true
            }
        } 
        $row++
        $Column=1
        $excel.cells.item($row,$Column) = "OSPF Passive Interfaces"
        ChangeFontExcelCell $Sheet $row $Column 
        $row++ 
        $Column++
        if ($OSPFPassiveInterface) {
            $OSPFPassiveInterfaceArray = $OSPFPassiveInterface.Split(",")
            if ($OSPFPassiveInterfaceArray) {
                foreach ($Member in $OSPFPassiveInterfaceArray) {
                    $excel.cells.item($row,$Column) = $Member
                    $Column++
                }
            }
        } 
        else { $excel.cells.item($row,$Column) = "none"  } 
        $Row++  
        if ($RouterRedistibuteArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "Redistribute routes"
            ChangeFontExcelCell $Sheet $row $Column
            $row++  
            #Make the default that no routes are redistibuted. If there are redistibuted routes this field wil get overwritten.
            $excel.cells.item($row,$Column+1) = "none"   
            Foreach ($ArrayMember in $RouterRedistibuteArray) {
                if ($ArrayMember.status -eq "enable") {
                    $Column++
                    $excel.cells.item($row,$Column) = $ArrayMember.Redistribute
                }                        
            }
            $Row++ 
        }       
        if ($RouterDistibuteListArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "OSPF Distributelist"
            ChangeFontExcelCell $Sheet $row $Column   
            $Row++     
            $row = CreateExcelTabel $Sheet $RouterDistibuteListArray
        }     
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null  
        if ($RemberSkipFilter) {
            $SkipFilter = $false
        }
    }    
}
Function CreateExcelSheetSNMP {
    $row = 2
    $Sheet = $workbook.Worksheets.Add()
    PlaceLinkToToC $Sheet
    $SheetName = "SNMP$VdomName"
    $SheetName = CleanSheetName $SheetName
    $Sheet.Name = $SheetName
    $Column=1
    $excel.cells.item($row,$Column) = $SheetName
    ChangeFontExcelCell $Sheet $row $Column  
    $row=$row+2 
    #Enter SNMP Sysinfo to the sheet
    $excel.cells.item($row,$Column) = "System Info"
    $Row++
    $excel.cells.item($row,$Column) = "Status"
    $excel.cells.item($row,$Column+1) = $SNMPSysinfo.Status
    $Row++
    $excel.cells.item($row,$Column) = "Description"
    $excel.cells.item($row,$Column+1) = $SNMPSysinfo.Description
    $Row++
    $excel.cells.item($row,$Column) = "Contact"
    $excel.cells.item($row,$Column+1) = $SNMPSysinfo."Contact-info"
    $Row++
    $excel.cells.item($row,$Column) = "Location"
    $excel.cells.item($row,$Column+1) = $SNMPSysinfo.Location
    $row=$row+2 
    if ($SNMPCommunities) {
        $excel.cells.item($row,$Column) = "SNMP v1/v2 Community settings"
        $Row++
        $row = CreateExcelTabel $Sheet $SNMPCommunities 3
    }
    $row=$row+2 
    if ($SNMPCommunityHosts) {
        $excel.cells.item($row,$Column) = "SNMP v1/v2 Hosts"
        $Row++
        $row = CreateExcelTabel $Sheet $SNMPCommunityHosts 3
    }
    $Column=1
    if ($SNMPUsers) {
        $excel.cells.item($row,$Column) = "SNMP v3"
        $Row++
        $row = CreateExcelTabel $Sheet $SNMPUsers
    }
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null 
}
Function GetNumber ($NumberString) {
    [int]$IntNum = [convert]::ToInt32($NumberString, 10)
    return $IntNum
}
Function Get-ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}
Function GetSubnetCIDR ([string]$Subnet,[IPAddress]$SubnetMask) {
    $binaryOctets = $SubnetMask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2) }
    $SubnetCIDR = $Subnet + "/" + ($binaryOctets -join '').Trim('0').Length
    return $SubnetCIDR
}
Function GetSubnetCIDRPolicy ($SubnetCIDRPolicy) {
    $SubnetCIDRPolicyArray =  $SubnetCIDRPolicy.Split("/")
    #Drop the first " from the policy line subnet    
    $SubnetCIDRPolicyArray[0] = $SubnetCIDRPolicyArray[0].Substring(1)
    #Drop the last " from the policy line subnet
    $SubnetCIDRPolicyArray[1] = $SubnetCIDRPolicyArray[1].Substring(0,$SubnetCIDRPolicyArray[1].Length-1)
    $ReturnGetSubnetCIDRPolicy = GetSubnetCIDR $SubnetCIDRPolicyArray[0] $SubnetCIDRPolicyArray[1]
    return $ReturnGetSubnetCIDRPolicy
}
# Utility function that turns unquoted, space-separated strings into an array.
# It means you can write "MakeArray foo bar baz" rather than "@('foo', 'bar', 'baz')".
Function MakeArray { $args }
Function ParseConfigFile {
    Param([array]$requiredValues, [string]$PconfigFile) 

    $config = @{}
    if (-not (Test-Path -PathType Leaf $PconfigFile)) {
        Write-Output "Fatal error: File $PconfigFile not found. Processing aborted."
        exit 1       
    }
    Get-Content $PconfigFile | Where-Object { $_ -match '\S' } | # Skip blank (whitespace only) lines.
        Foreach-Object { $key, $value = $_ -split '\s*;\s*'; $config.$key = $value 
    }
    # Initialize this to false and exit after the loop if a required value is missing.
    [bool] $missingRequiredValue = $false
    foreach ($requiredValue in $requiredValues) {
        if (-not $config.ContainsKey($requiredValue)) {
            Write-Output "Error: Missing '$requiredValue'. Processing will be aborted."
            $missingRequiredValue = $true
        }
    } 
    # Exit the program if a required value is missing in the configuration file.
    if ($missingRequiredValue) { exit 2 }
    $config
}
#This function Parses the ISDB and changes the ID for the name if found.
Function ParseISDB ($ParseISDBlist) {
    Foreach  ($rule in $ParseISDBlist) {
        if ($Rule."internet-service-id" -ne "") {
            foreach ($FortiISDB in  $FortiISDBArray) {
                if ($Rule."internet-service-id" -eq $FortiISDB.ID) {
                    #we found the ID change the name and break out of the foreach loop.
                    $Rule."internet-service-id" = $FortiISDB.Name + "(" + $FortiISDB.ID + ")"
                    break
                }
            }
        }
    }
    return $ParseISDBlist
}
Function  PlaceLinkToToC ($CurrentSheet) {
    $CurrentSheet.Cells.Item(1,1) = "Table of Contents"
    $CurrentSheet.Hyperlinks.Add(
        $CurrentSheet.Cells.Item(1,1),
        "",
        "ToC!A1",
        "Return to table of contents",
        $CurrentSheet.Cells.Item(1,1).Text
    ) | Out-Null
}
Function UpdateMainSheet ( $ActiveArray ) {
    $MainSheet.Cells.Item(3,1) = 'Excel Creation Date'
    $MainSheet.Cells.Item(3,2) = $Date
    $MainSheet.Cells.Item(3,2).numberformat = "00"
    $MainSheet.Cells.Item(4,1) = 'Config Creation Date'
    if ($SSHConfig) {
        $configdate = $date
    }
    else {
        $configdateArray=$Filename.Split("_")
        $FWMainVersion = $FWVersion.Split(".")
        if ($FWMainVersion[0] -eq "6") {
            $configdate = $configdateArray[$configdateArray.Count-2] + $configdateArray[$configdateArray.Count-1]
        }
        else {
            $configdate = $configdateArray[$configdateArray.Count-1]
        }     
    }
    $MainSheet.Cells.Item(4,2) = $ConfigDate 

    $MainSheet.Cells.Item(4,2).numberformat = "00"                       
    $MainSheet.Cells.Item(5,1) = 'Type'
    $MainSheet.Cells.Item(5,2) = $FWType
    $MainSheet.Cells.Item(6,1) = 'Version'
    $MainSheet.Cells.Item(6,2) = $FWVersion  
    #$NoteProperties = $ActiveArray | get-member -Type NoteProperty
    $NoteProperties = SkipEmptyNoteProperties $ActiveArray
    $Row = 7
    $Column = 1
    foreach ($Noteproperty in $NoteProperties) {
        $excel.cells.item($row,$Column) = $Noteproperty.Name
        $Row++
    }
    $Row = 7
    $Column = 2
    foreach ($ActiveMember in $ActiveArray) {
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            [Int32]$OutNumber = $null
            #Test if Timezone is a number, if it is find the timezone name
            if (($PropertyString -eq "timezone") -and ([Int32]::TryParse($PropertyString,[ref]$OutNumber))) {
                $TimeZoneNumber = GetNumber $ActiveMember.$PropertyString
                $Value = $TimeZoneArray[$TimeZoneNumber].TimeName
            }
            else {
                $Value = $ActiveMember.$PropertyString
            }
            $excel.cells.item($row,$Column) = $Value
            $Row++
        }                        
    }                         
}
Function UpdateToC ($CurrentSheetName) {
    $TocSheet.Cells.Item($TocRow,1) = $CurrentSheetName
    $TocSheet.Hyperlinks.Add(
        $TocSheet.Cells.Item($TocRow,1),
        "",
        "$CurrentSheetName!A1",
        "Link to $CurrentSheetName",
        $TocSheet.Cells.Item($TocRow,1).Text
    ) | Out-Null
    $TocRow++
    return $TocRow
}

#Start MAIN Script
$StartTime = get-date 
Clear-Host
Write-Output "Started script"
#Clear 5 additional lines for the progress bar
$I=0
DO {
    Write-output ""
    $I++
} While ($i -le 5)
If ($Global:SkipFilter) {
    Write-Output "SkipFilter parmeter is set to True. Skipping filter function in Excel."
}
#Command to disable the more prompt when reading the fortigate configuration
$SetOutputStandard = 'config system console
set output standard
end
'
#Command to restore the more prompt when reading the fortigate configuration
$SetOutputMore = 'config system console
set output more
end
'
$FortigateConfigArray = $FortigateConfig.Split(".")
Switch ($FortigateConfigArray[$FortigateConfigArray.Count-1]) {
    "cred" {
        if (Get-Module -ListAvailable -Name Posh-SSH) {
            $LoadedModules = Get-Module | Select-Object Name
            if (!$LoadedModules -like "*Posh-SSH*") { Import-Module Posh-SSH }
        } 
        else {
            Write-Output "Module Posh-SSH does not exist!"
            Write-Output "Download it from https://github.com/darkoperator/Posh-SSH"
            exit 1
        }
        Write-Output "Reading credentialfile"
        if (!(Test-Path($FortigateConfig))) {
            Write-Output "Credential file does not exist -> Creating One."
            $FirewallIP = Read-Host "Enter FirewallIP or DNS name."
            $FirewallPort = Read-Host "Enter portnumber SSH is listening on. (Default 22)"
            if (!($FirewallPort)) { $FirewallPort = 22 }
            $Credential = Get-Credential -Message "Enter Firewall credentials."
            $FWUser = $Credential.UserName
            $FWPassword = $Credential.password | ConvertFrom-SecureString
            $ConfigString = @"
#Fortigate Firewall Credential File
FirewallIP;$FirewallIP
FirewallPort;$FirewallPort
FWUser;$FWUser
FWPassword;$FWPassword
"@
            $ConfigString | Set-Content $FortigateConfig
        }
        $RequiredConfigValues = MakeArray FirewallIP FWUser FWPassword
        $config = ParseConfigFile $RequiredConfigValues $FortigateConfig
        $FirewallIP = $config.FirewallIP
        $FWPassword = $config.FWPassword | ConvertTo-SecureString 
        if ($Config.FirewallPort) { $FirewallPort = $Config.FirewallPort }
        else { $FirewallPort = 22 }
        $Credential = New-Object System.Management.Automation.PsCredential($config.FWUser,$FWPassword)
        $SSHSession = New-SSHSession -ComputerName $FirewallIP -Credential $Credential -Port $FirewallPort
        If ($SSHSession.Connected -eq $True) {
            Write-Output "Reading configuration from Firewall."
            #First test if we are in the standard or more configuration
            #We need it in standard to not get prompts
            $AnswerCommand = Invoke-SSHCommand -Index 0 -Command "show system console"
            $ConfigStandard = $AnswerCommand.Output.Contains("standard")
            if (!$ConfigStandard) {
                Write-Output "Fortigate is in default (more) configuration setting this to standard."
                $AnswerCommand = Invoke-SSHCommand -Index 0 -Command $SetOutputStandard
            }
            $Answer = Invoke-SSHCommand -Index 0 -Command "show"
            $loadedConfig = $Answer.Output
            If (!$ConfigStandard) {
                Write-Output "Restore the more setting."
                $AnswerCommand = Invoke-SSHCommand -Index 0 -Command $SetOutputMore
            }
            $Answer = Remove-SSHSession -Index 0 
            $SSHConfig = $true
        }
        else { 
            Write-Output "Error connecting to $FirewallIP!"
            exit 1
        }
    }
    "conf" {
        if (!( Test-Path "$fortigateConfig" )) {
            Write-Output "[!] ERROR: Could not find FortiGate config file at $fortigateConfig."
            exit 1
        }
        $loadedConfig = Get-Content $FortigateConfig
    }
    default {
        Write-Output "Extention needs to be .conf for a config file OR .cred for a credential file!"
        exit 1
    }
} 
$ScriptDirectoryPath = Get-ScriptDirectory
if ($SkipTimeZone) {
    Write-Output "Timezone file not imported due to SkipTimeZone flag set to true."
}
else {
    if (Test-Path "$ScriptDirectoryPath\TimeZones.csv") {
        $TimeZoneArray = Import-CSV "$ScriptDirectoryPath\TimeZones.csv" -delimiter ";"
        Write-Output "Timezone file imported. Time-zone names will be used instead of ID."
    }
    else { 
        $TimeZoneArray = $null
        Write-Output "Could not find Timezones.csv in $ScriptDirectoryPath."
        Write-Output "Script will continue, ID will be used instead of time-zone name."
    }    
}
if ($SkipFortiISDB) {
    Write-Output "FortiNet ISDB file not imported due to SkipFortiISDB flag set to true."   
}
else {
    if (Test-Path "$ScriptDirectoryPath\ISDB-Fortigate.csv") {
        $FortiISDBArray = Import-CSV "$ScriptDirectoryPath\ISDB-Fortigate.csv" -delimiter ";"
        Write-Output "FortiNet ISDB file imported. Database names will be used instead of ID."
    }
    else { 
        $FortiISDBArray = $null
        Write-Output "Could not find ISDB-Fortigate.csv in $ScriptDirectoryPath."
        Write-Output "Script will continue, ID will be used instead of FortiNet ISDB name."
    }
}

$Counter=0
$MaxCounter=$loadedConfig.count
$date = Get-Date -Format yyyyMMddHHmm
$WorkingFolder = (Get-Item $fortigateConfig).DirectoryName
$FileName = (Get-Item $fortigateConfig).Basename
if ($SSHConfig) {
    #$configdate = $date
    $ExcelFullFilePad = "$workingFolder\$fileName-$ConfigDate"
}
else {
    #$configdateArray=$Filename.Split("_")
    #$configdate = $configdateArray[$configdateArray.Count-2] + $configdateArray[$configdateArray.Count-1]
    #$configdate = $configdateArray[$configdateArray.Count-1]
    $ExcelFullFilePad = "$workingFolder\$fileName"
}

$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false
$excel.ScreenUpdating = $false
$excel.DisplayStatusBar = $false
$excel.EnableEvents = $false
$workbook = $excel.Workbooks.Add()
$TocSheet = $workbook.Worksheets.Item(1) 
$MainSheet = $workbook.Worksheets.Add()
$TocSheet.Name = "ToC"
$TocRow=2
$TocSheet.Cells.Item(1,1)= 'Table of Contents'
$MergeCells = $TocSheet.Range("A1:C1")
$MergeCells.MergeCells = $true
ChangeFontExcelCell $TocSheet 1 1
if ($Filename.Length -gt 31) {
    Write-output "Sheetname ($Filename) cannot be longer that 32 characters shorting name to fit."
    $SheetName = $FileName.Substring(0,31)
}
else {
    $Sheetname = $FileName
}
$SheetName = $SheetName.Replace("-","_")
$MainSheet.Name = $SheetName
PlaceLinkToToC $MainSheet
$MainSheet.Cells.Item(2,1)= 'Fortigate Configuration'
$MergeCells = $MainSheet.Range("A2:B2")
$MergeCells.Select() | out-null
$MergeCells.MergeCells = $true
ChangeFontExcelCell $MainSheet 2 1
#Getting fortigate information from the firstline of the configuration file
$FirstLine = $loadedConfig[0]
$FirstLineArray = $FirstLine.Split(":")
$FirewallInfoArray = $FirstLineArray[0].Split("-")
$FWTypeVersion = $FirewallInfoArray[1]
$FirewallTypeArray = $FWTypeVersion.Split("=")
$FWVersion = $FirewallInfoArray[2]
$FWType = $FirewallTypeArray[1]
$SUBSection = $False
$SNMPFound = $False
$SDWAN=$false
#Creating empty Arrays
$ruleList = [System.Collections.ArrayList]@()
$AcmeAccountArray = [System.Collections.ArrayList]@()
$AuthenticationRuleArray = [System.Collections.ArrayList]@()
$BookMarkArray = [System.Collections.ArrayList]@()
$DHCPRangeArray = [System.Collections.ArrayList]@()
$DHCPOptionsArray = [System.Collections.ArrayList]@()
$DHCPReservedAddressArray = [System.Collections.ArrayList]@()
$DNSEntryArray = [System.Collections.ArrayList]@()
$HAMGMTInterfaceArray = [System.Collections.ArrayList]@()
$ObjectTagArray = [System.Collections.ArrayList]@()
$OSCheckListArray = [System.Collections.ArrayList]@()
$RouterAccessListArray = [System.Collections.ArrayList]@()
$RouterRedistibuteArray = [System.Collections.ArrayList]@()
$RouterInterfaceArray = [System.Collections.ArrayList]@()
$RouterNetworkArray = [System.Collections.ArrayList]@()
$RouterDistibuteListArray = [System.Collections.ArrayList]@()
$RouterNeighborArray = [System.Collections.ArrayList]@()
$SNMPCommunities = [System.Collections.ArrayList]@()
$SNMPCommunityHosts = [System.Collections.ArrayList]@()
$SNMPUsers = [System.Collections.ArrayList]@()
$SplitDNSArray = [System.Collections.ArrayList]@()
$VirtualWanLinkMemberArray = [System.Collections.ArrayList]@()
$VirtualWanLinkHealthCheckArray = [System.Collections.ArrayList]@()
$VirtualWanLinkServiceArray = [System.Collections.ArrayList]@()
#Make sure $OSPFRouterID has a known value
$OSPFRouterID = "no-ospf"
#Set all properties that contain password to be excluded from the excel file.
$SkipExportProperties = MakeArray "passwd" "password" "psksecret" "secret" "ppk-secret" "auth-password-l1" "auth-password-l2" "auth-pwd" "privatekey"
foreach ($Line in $loadedConfig) {
    $Proc = $Counter/$MaxCounter*100
    $ProcString = $Proc.ToString("0.00")
    $elapsedTime = $(get-date) - $startTime 
    if ($Counter -eq 0) { $estimatedTotalSeconds = $MaxCounter / 1 * $elapsedTime.TotalSecond }
    else { $estimatedTotalSeconds = $MaxCounter/ $counter * $elapsedTime.TotalSeconds }
    $estimatedTotalSecondsTS = New-TimeSpan -seconds $estimatedTotalSeconds
    $estimatedCompletionTime = $startTime + $estimatedTotalSecondsTS    
    Write-Progress -Activity "Parsing config file ($ProcString%). ETC $estimatedCompletionTime" -PercentComplete ($Proc)
    $Counter++
    $Configline=$Line.Trim() -replace '\s+',' '
    $ConfigLineArray = $Configline.Split(" ")    
    switch($ConfigLineArray[0]) {
        "config" {
            switch($ConfigLineArray[1]) {
                "accounts" {
                    $SUBSection = $True
                    $SUBSectionConfig = "acmeacc" 
                }
                "area" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ospfarea"                      
                }    
                "authentication-rule" {
                    $SUBSection = $True
                    $SUBSectionConfig = "authenticationrule"   
                }
                "bookmarks" {
                    $SUBSection2 = $True  
                }      
                "bookmark-group" {
                    $SUBSection = $True
                    $SUBSectionConfig = "bookmarkgroup"   
                }
                "distribute-list" {
                    $SUBSection = $True
                    $SUBSectionConfig = "Routerdistributelist"                 
                }  
                "dns-entry" {
                    $SUBSection = $True
                    $SUBSectionConfig = "DNSEntry"                     
                }  
                "firewall" {
                    switch($ConfigLineArray[2]) {
                        "policy" { 
                            $ConfigSection = "ConfigFirewallPolicy"
                            Write-Output "Config firewall policy line found."
                        }
                        "address" { 
                            $ConfigSection = "ConfigFirewallAddress" 
                            Write-Output "Config firewall address (IPV4) line found."
                        }
                        "address6" { 
                            $ConfigSection = "ConfigFirewallAddress6" 
                            Write-Output "Config firewall address (IPV6) line found."
                        }                        
                        "addrgrp" { 
                            $ConfigSection = "ConfigFirewallAddrgrp" 
                            Write-Output "Config firewall addgrp (IPV4) line found."
                        } 
                        "addrgrp6" { 
                            $ConfigSection = "ConfigFirewallAddrgrp6" 
                            Write-Output "Config firewall addgrp (IPV6) line found."
                        }                           
                        "ldb-monitor" {
                            $ConfigSection = "ConfigFirewallLdbMonitor"
                            Write-Output "Config firewall ldb-monitor line found."
                        }
                        "ippool" {
                            $ConfigSection = "ConfigFirewallIPpool" 
                            Write-Output "Config firewall ippool line found."                            
                        }
                        "service"  {
                            switch($ConfigLineArray[3]) {
                                    "category" {
                                        $ConfigSection = "ConfigFirewallServicecategory" 
                                        Write-Output "Config firewall service category line found."
                                    }
                                    "custom" {
                                        $ConfigSection = "ConfigFirewallServiceCustom" 
                                        Write-Output "Config firewall service custom line found."
                                    }
                                    "group" {
                                        $ConfigSection = "ConfigFirewallServiceGroup" 
                                        Write-Output "Config firewall service group line found."
                                    }
                            }
                        }  
                        "shaper" {
                            switch($ConfigLineArray[3]) {
                                "per-ip-shaper" {
                                    $ConfigSection = "ConfigFirewallShaperPerIPShaper" 
                                    Write-Output "Config firewall shaper per-ip-shaper line found."  
                                }
                                "traffic-shaper" {
                                    $ConfigSection = "ConfigFirewallShaperTrafficShaper" 
                                    Write-Output "Config firewall shaper traffic-shaper line found."                                    
                                }
                            }
                        }
                        "shaping-policy" {
                            $ConfigSection = "ConfigFirewallShapingPolicy"
                            Write-Output "Config firewall shaping-policy line found."
                        }
                        "vip" {
                            $ConfigSection = "ConfigFirewallVIP"
                            Write-Output "Config firewall vip line found."
                        }  
                        "vipgrp" {
                            $ConfigSection = "ConfigFirewallVIPGRP"
                            Write-Output "Config firewall vipgrp line found."
                        }           
                    }
                }  
                "Gui-dashboard" {
                    $SUBSection = $true
                    $SUBSectionConfig = "Gui-Dashboard"
                }               
                "ha-mgmt-interfaces" {
                    $SUBSection = $true
                    $SUBSectionConfig = "HA-MGMTInterfaces"
                }             
                "health-check" {
                    $SUBSection = $True
                    $SUBSectionConfig = "virtualwanlinkhealthcheck"                 
                }
                "hosts" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ConfigSystemSNMPCommunityHost"                    
                }     
                "ipv6" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ipv6"                    
                }           
                "ip-range" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpiprange"
                }
                "match" {
                    $SUBSection = $True
                    $SUBSectionConfig = "groupmatch"                     
                }
                "members" {
                    $SUBSection = $True
                    $SUBSectionConfig = "virtualwanlinkmember"                     
                }  
                "neighbor" {
                    $SUBSection = $True
                    $SUBSectionConfig = "RouterNeighbor"                     
                }
                "network" {
                    $SUBSection = $True
                    $SUBSectionConfig = "RouterNetwork"                       
                }             
                "options" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpoptions"
                }
                "os-check-list" {
                    $SUBSection = $True 
                    $SUBSectionConfig = "oschecklist" 
                    $OSCheckListRule = InitVPNSSLWebPortalOSCheckList
                    $OSCheckListRule.OS = CleanupLine $ConfigLineArray[2]
                    $OSCheckListRule.PortalName = $Rule.PortalName
                }
                "ospf-interface" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ospfinterface"                    
                }
                "ospf6-interface" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ospf6interface"                    
                }
                "prefix-range" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpiprange"
                }                
                "realservers" {
                    $SUBSection = $True
                    $SUBSectionConfig = "VIPrealservers"
                    $ConfigRealservers = $true
                    $RuleRealServer = $rule
                }
                "redistribute" {
                    $SUBSection = $True
                    $SUBSectionConfig = "routerredistribute"
                    $Value = CleanupLine $ConfigLine
                    $RouterRedistribute = InitRouterRedistribute
                    $RouterRedistribute | Add-Member -MemberType NoteProperty -Name "Redistribute" -Value $Value -force
                }
                "redistribute6" {
                    $SUBSection = $True
                    $SUBSectionConfig = "routerredistribute"
                    $Value = CleanupLine $ConfigLine
                    $RouterRedistribute = InitRouterRedistribute
                    $RouterRedistribute | Add-Member -MemberType NoteProperty -Name "Redistribute" -Value $Value -force
                }                
                "reserved-address" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpreservedaddress"                 
                }
                "router" {
                    $RouterSection = $ConfigLineArray[2]
                    switch($ConfigLineArray[2]) {
                        "Access-list" {
                            $ConfigSection = "ConfigRouterAccessList"
                            Write-Output "Config router access-list line found."                            
                        }
                        "bgp" {
                            $ConfigSection = "ConfigRouterBGP"
                            Write-Output "Config router bgp line found." 
                            $rule = InitRouterBGP   
                            #Init RouterNeighborOLD value (config has two concecutive next statements)
                            $RouterNeighborOLD = InitRouterNeighbor                     
                        }
                        "isis" {
                            $ConfigSection = "ConfigRouterISIS"
                            Write-Output "Config router isis line found." 
                            $rule = InitRouterISIS                              
                        }
                        "static" {
                            $ConfigSection = "ConfigRouterStatic"
                            Write-Output "Config router static line found."
                        }
                        "policy" {
                            $ConfigSection = "ConfigRouterPolicy"
                            Write-Output "Config router policy line found."
                        }
                        default {
                            #Router section default
                            $RouterSection = $ConfigLineArray[2]
                            $ConfigSection = "ConfigRouter$RouterSection"
                            Write-Output "Config router $RouterSection found."
                        }
                    }
                }
                "rule" {
                    $SUBSection = $True
                    $SUBSectionConfig = "RouterAccessListRule"                     
                }
                "service" {
                    $SUBSection = $True
                    $SUBSectionConfig = "virtualwanlinkservice"  
                    #if () {
                    #    $SUBSection2 = $True    
                    #}                   
                }
                "split-dns" {
                    $SUBSection = $True
                    $SUBSectionConfig = "splitdns"  
                }
                "tagging" {
                    $SUBSection = $true
                    $SUBSectionConfig = "tagging"
                }    
                "secondaryip" {
                    $SUBSection = $true
                    $SUBSectionConfig = "secondaryip"                   
                }                           
                "system" {
                    switch($ConfigLineArray[2]) {
                        "Acme" {
                            $ConfigSection = "ConfigSystemAcme"
                            Write-Output "Config system acme line found."
                        }
                        "admin" {
                            $ConfigSection = "ConfigSystemAdmin"
                            Write-Output "Config system admin line found."                            
                        }
                        "accprofile" {
                            $ConfigSection = "ConfigSystemAccprofile"
                            Write-Output "Config sytem accprofile line found."
                        }
                        "dhcp" {
                            $ConfigSection = "ConfigSystemDHCP"
                            Write-Output "Config system dhcp (IPV4) line found."
                        }
                        "dhcp6" {
                            $ConfigSection = "ConfigSystemDHCP6"
                            Write-Output "Config system dhcp (IPV6) line found."
                        }                        
                        "ddns" {
                            $ConfigSection = "ConfigSystemDDNS"
                            Write-Output "Config system ddns line found."
                        }
                        "dns-database" {
                            $ConfigSection = "ConfigSystemDNSDatabase"
                            Write-Output "Config system dns-database line found."
                        }
                        "dns-server" {
                            $ConfigSection = "ConfigSystemDNSServer"
                            Write-Output "Config system dns-server line found."
                        }
                        "global" {
                            $ConfigSection = "ConfigSystemGlobal"
                            $rule = InitSystemGlobal
                            Write-Output "Config system global line found."
                        }
                        "ha" {
                            $ConfigSection = "ConfigSystemHA"
                            Write-Output "Config system ha line found."
                            $rule = InitSystemHA 
                        }
                        "interface" {
                            $ConfigSection = "ConfigSystemInterface"
                            Write-Output "Config system interface line found."
                        }
                        "link-monitor" {
                            $ConfigSection = "ConfigSystemLinkmonitor"
                            Write-Output "Config system link-monitor line found."
                        }
                        "sdwan" {
                            $ConfigSection = "ConfigSystemVirtualWanLink" 
                            $rule = InitSystemVirtualWanLink
                            $SDWAN=$true
                            Write-Output "Config system SDWAN line found."                            
                        }
                        "Settings" {
                            $ConfigSection = "ConfigSystemSettings" 
                            $rule = InitSystemSettings
                            Write-Output "Config system Settings line found."
                        }
                        "session-helper" {
                            $ConfigSection = "ConfigSystemSessionHelper"
                            Write-Output "Config system session-helper line found."
                        }
                        "snmp" {
                            switch($ConfigLineArray[3]) {
                                "sysinfo" {
                                    $ConfigSection = "ConfigSystemSNMPSysinfo"
                                    $rule = InitSystemSNMPSysInfo
                                    $SNMPFound=$true
                                    Write-Output "Config system snmp sysinfo line found."
                                }
                                "community" {
                                    $ConfigSection = "ConfigSystemSNMPCommunity"
                                    $SNMPFound=$true
                                    Write-Output "Config system snmp community line found."
                                }
                                "user" {
                                    $ConfigSection = "ConfigSystemSNMPUser"
                                    $SNMPFound=$true
                                    Write-Output "Config system snmp user line found."
                                }
                            }
                        }
                        "virtual-wan-link" {
                            $ConfigSection = "ConfigSystemVirtualWanLink"
                            Write-Output "Config system virtual-wan-link line found."                            
                            $rule = InitSystemVirtualWanLink
                        }
                        "zone" {
                            $ConfigSection = "ConfigSystemZone"
                            Write-Output "Config system zone line found." 
                        }
                    } 
                }  
                "user" { 
                    switch ($ConfigLineArray[2]) {
                        "group" {
                            $ConfigSection = "ConfigUsergroup"
                            Write-Output "Config user group line found."
                        }
                        "ldap" {
                            $ConfigSection = "ConfigUserLdap"
                            Write-Output "Config user ldap line found."
                        }
                        "local" {
                            $ConfigSection = "ConfigUserLocal"
                            Write-Output "Config user local line found."                           
                        }
                        "radius" {
                            $ConfigSection = "ConfigUserRadius"
                            Write-Output "Config user radius line found."                           
                        }
                        "saml" {
                            $ConfigSection = "ConfigUserSAML"
                            Write-Output "Config user saml line found."                           
                        }                        
                    }   # switch ($ConfigLineArray[2])
                }        
                "vdom" { $ConfigSection = "ConfigVDOM" }
                "vpn" {
                    switch ($ConfigLineArray[2]) {
                        "ipsec" {
                            switch ($ConfigLineArray[3]) {
                                "phase1-interface" {
                                    $ConfigSection = "Configvpnipsecphase1"
                                    Write-Output "Config vpn ipsec phase1-interface line found."
                                }
                                "phase2-interface" {
                                    $ConfigSection = "Configvpnipsecphase2"
                                    Write-Output "Config vpn ipsec phase2-interface line found."
                                }
                            }
                        }
                        "ssl" {
                            switch($ConfigLineArray[3]) {
                                "settings" {
                                    $ConfigSection = "ConfigvpnsslSettings"
                                    Write-Output "Config vpn ssl settings line found."
                                    $rule = InitVPNSSLSettings
                                }
                                "web" {
                                    switch($ConfigLineArray[4]) {
                                        "portal" {
                                            $ConfigSection = "Configvpnsslwebportal"
                                            Write-Output "Config vpn ssl web portal line found."
                                        }
                                    }
                                }
                            }   # switch($ConfigLineArray[3])
                        }   # ssl
                    }   # switch ($ConfigLineArray[2])
                }
                "widget" {
                    $SUBSection2 = $True
                }
                "zone" {
                    #Zone is defined on multiple levels 
                    if ($SDWAN) {
                        $SUBSection = $True
                        $SUBSectionConfig = "SDWANZone"
                    }
                    else {
                        $SUBSection2 = $True
                    }
                }
            }   # switch($ConfigLineArray[1])
        }   # "config"
        "edit" {
            if ($ConfigSection) { 
                $Value = CleanupLine $ConfigLine
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
                        "acmeacc" {
                            $AcmeAccount = InitAcmeAccounts
                            $AcmeAccount | Add-Member -MemberType NoteProperty -Name ID -Value $value -force
                        }
                        "authenticationrule" {
                            $AuthenticationRule = InitAuthenticationRule
                            $AuthenticationRule | Add-Member -MemberType NoteProperty -Name ID -Value $value -force
                        }
                        "bookmarkgroup" {
                            if ($SUBSection2) {
                                $BookMark = InitBookmark
                                $BookMark | Add-member -MemberType NoteProperty -Name bookmark-Group -Value $BookMarkGroup -force
                                $BookMark | Add-member -MemberType NoteProperty -Name Name -Value $Value -force
                                $BookMark | Add-member -MemberType NoteProperty -Name PortalName -Value $rule.PortalName -force
                            }
                            else { $BookMarkGroup = $Value }
                        }
                        "ConfigSystemSNMPCommunityHost" {
                            $SNMPCommunityHost = InitSystemSNMPCommunityHost
                            $IDNumber = GetNumber($Value)
                            $SNMPCommunityHost | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                           
                        }
                        "dhcpiprange" {
                            $DHCPRange = InitDHCPRange
                            $IDNumber = GetNumber($Value)
                            $DHCPRange | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "dhcpoptions" {
                            $DHCPOptions = InitDHCPOptions
                            $IDNumber = GetNumber($Value)
                            $DHCPOptions | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddress = InitDHCPReservedAddress
                            $IDNumber = GetNumber($Value)
                            $DHCPReservedAddress | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "DNSEntry"  {
                            $DNSEntry = InitSystemDNSEntry
                            $IDNumber = GetNumber($Value)
                            $DNSEntry | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                            
                        }
                        "Gui-Dashboard" {
                            if ($SubSection2) {
                                #Do nothing not implemented
                            }
                            #Do nothing not implemented
                        }
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterface = InitSystemHAMGMTInterfaces
                            $IDNumber = GetNumber($Value)
                            $HAMGMTInterface | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "groupmatch" {
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "Match" -Value $IDNumber -force
                        }
                        "ospfarea"  {
                            $OSPFRouterArea = $Value
                        }
                        "RouterDistributeList" {
                            $RouterDistibuteList = InitRouterDistributeList
                            $IDNumber = GetNumber($Value)
                            $RouterDistibuteList  | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "RouterNeighbor" {
                            $RouterNeighbor = InitRouterNeighbor
                            $RouterNeighbor | Add-Member -MemberType NoteProperty -Name IP -Value $Value -force
                        }
                        "RouterNetwork" {
                            $RouterNetwork = InitRouterNetwork
                            $IDNumber = GetNumber($Value)
                            $RouterNetwork | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "splitdns" {
                            $SplitDNS = InitSplitDNS
                            $IDNumber = GetNumber($Value)
                            $SplitDNS | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                            $SplitDNS | Add-Member -MemberType NoteProperty -Name PortalName -Value $rule.PortalName -force
                        }
                        "ospfinterface" {
                            $OSPFInterface = InitRouterOSPFInterface
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -forc
                        }
                        "ospf6interface" {
                            $OSPFInterface = InitRouterOSPFInterface
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -forc
                        }                        
                        "RouterAccessListRule" {
                            $RouterAccessList = InitRouterAccessList
                            $RouterAccessList | Add-Member -MemberType NoteProperty -Name "Name" -Value $RouterAccessListName -force
                            $IDNumber = GetNumber($Value)
                            $RouterAccessList | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "tagging" {
                            $ObjectTag = InitTag
                            $ObjectTag | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }
                        "VIPrealservers" {
                            #If the rule is copied then there will be 2 lines with the same data in the array
                            #Using the Function CopyArrayMember to create a new $rule with data that is in the old rule
                            $Rule = CopyArrayMember $RuleRealServer 
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -Force
                        }
                        "virtualwanlinkhealthcheck" {
                            $VirtualWanLinkHealthCheck = InitVirtualWanLinkHealthCheck
                            $VirtualWanLinkHealthCheck | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }                        
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMember = InitVirtualWanLinkMember
                            $IDNumber = GetNumber($Value)
                            $VirtualWanLinkMember | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "virtualwanlinkservice" {
                            $VirtualWanLinkService = InitVirtualWanLinkService
                            $IDNumber = GetNumber($Value)
                            $VirtualWanLinkService | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                            
                        }                     
                    }   # Switch ($SUBSectionConfig)
                }   # if ($SUBSection)
                else {
                    switch ($ConfigSection) { 
                        "ConfigSystemAccprofile" {
                            $rule = InitSystemAccprofile
                            $rule | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }  
                        "ConfigSystemAcme" {
                            $rule = InitAcme
                            $rule | Add-Member -MemberType NoteProperty -Name Interface -Value $Value -force
                        }    
                        "ConfigSystemAdmin" {
                            $rule = InitSystemAdmin
                            $TrustedHosts = ""
                            $IP6TrustedHosts = ""
                            $rule | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }      
                        "ConfigSystemDHCP" {
                            $rule = InitSystemDHCP
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }  
                        "ConfigSystemDHCP6" {
                            $rule = InitSystemDHCP
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }                                                  
                        "ConfigVDOM" {
                            #look for vdom name 
                            $vdom = $ConfigLineArray[1]
                            $ConfigSection = $null
                        }
                        "ConfigFirewallIPpool" {
                            $rule = InitFirewallIPpool
                            $rule | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }
                        "ConfigFirewallLdbMonitor" {
                            $rule = InitFirewallLdbMonitor
                            $rule | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }
                        "ConfigFirewallPolicy" {
                            $rule = InitFirewallRule
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigFirewallAddress" {
                            $rule = InitFirewallAddress
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigFirewallAddress6" {
                            $rule = InitFirewallAddress6
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }                        
                        "ConfigFirewallAddrgrp" {
                            $rule = InitFirewallAddressGroup
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        } 
                        "ConfigFirewallAddrgrp6" {
                            $rule = InitFirewallAddressGroup6
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }                         
                        "ConfigFirewallShaperPerIPShaper" {
                            $rule = InitFirewallshaperperipshaper
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigFirewallShaperTrafficShaper" {
                            $rule = InitFirewallshapertrafficshaper
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigFirewallShapingPolicy" {
                            $rule = InitFirewallShapingPolicy
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                            
                        }
                        "ConfigRouterAccessList" {
                            $RouterAccessListName = $Value
                        }
                        "ConfigRouterStatic" {
                            $rule = InitRouterStatic
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigRouterStatic6" {
                            $rule = InitRouterStatic
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }                        
                        "ConfigRouterPolicy" {
                            $rule = InitRouterPolicy
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigSystemDDNS" {
                            $rule = InitSystemDDNS
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                            
                        }
                        "ConfigSystemDNSDatabase" {
                            $rule = InitSystemDNSDatabase
                            $rule | Add-Member -MemberType NoteProperty -Name "DNSname" -Value $Value -force 
                        }
                        "ConfigSystemDNSServer" {
                            $rule = InitSystemDNSServer
                            $rule | Add-Member -MemberType NoteProperty -Name "Interface" -Value $Value -force 
                        }
                        "ConfigSystemLinkmonitor" {
                            $rule = InitSystemLinkMonitor
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigSystemInterface" {
                            $rule = InitSystemInterface
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigSystemSessionHelper" {
                            $rule = InitSystemSessionHelper
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigSystemSNMPCommunity" {
                            $rule = InitSystemSNMPCommunity
                            #$SNMPCommunityHosts = [System.Collections.ArrayList]@()
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigSystemSNMPUser" {
                            $rule = InitSystemSNMPUser
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }                        
                        "ConfigSystemZone" {
                            $rule = InitSystemInterface
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force                            
                        }
                        "ConfigUsergroup" {
                            $rule = InitUserGroup
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigUserLdap" {
                            $rule = InitUserLdap
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -Force
                        }
                        "ConfigUserLocal" {
                            $rule = InitUserLocal
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -Force                            
                        }
                        "ConfigUserRadius" {
                            $rule = InitUserRadius
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -Force                            
                        }      
                        "ConfigUserSAML" {
                            $rule = InitUserSAML
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -Force  
                        }                  
                        "ConfigFirewallServiceCategory" {
                            $rule = InitFirewallServiceCategory
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force                      
                        }
                        "ConfigFirewallServiceCustom" {
                            $rule = InitFirewallServiceCustom
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force                      
                        }
                        "ConfigFirewallServiceGroup" {
                            $rule = InitFirewallServiceGroup
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }                          
                        "ConfigFirewallVIP" {
                            $rule = InitFirewallVip
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force                 
                        }
                        "ConfigFirewallVIPGRP" {
                            $rule = InitFirewallVipgrp
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force                 
                        }
                        "Configvpnipsecphase1" {
                            $rule = Initvpnipsecphase1
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "Configvpnipsecphase2" {
                            $rule = Initvpnipsecphase2
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        } 
                        "Configvpnsslwebportal" {
                            $rule = InitVPNSSLWebPortal
                            $rule | Add-Member -MemberType NoteProperty -Name "PortalName" -Value $Value -force
                        }                        
                    }   # switch ($ConfigSection)
                }   # else if ($SUBSection)
            }   # if ($ConfigSection)
        }   # "next"
        "set" {
            if ($ConfigSection) {
                $Value = CleanupLine $ConfigLine
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
                        "acmeacc" {
                            $AcmeAccount | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "authenticationrule" {
                            $AuthenticationRule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "bookmarkgroup" {
                            $BookMark | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "ConfigSystemSNMPCommunityHost" {
                            If ($ConfigLineArray[1] -eq "ip") {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                                $SNMPCommunityHost | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            else {
                                #$Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                                $SNMPCommunityHost | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $ConfigLineArray[2] -force
                            }
                        }                          
                        "dhcpiprange" {
                            $DHCPRange | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "dhcpoptions" {
                            $DHCPOptions | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force 
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddress | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }  
                        "DNSEntry" {
                            $DNSEntry | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "Gui-Dashboard" {
                            if ($SubSection2) {
                                #Do nothing not implemented
                            }
                            #Do nothing not implemented
                        }
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterface | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "groupmatch" {
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterDistributeList" {
                            $RouterDistibuteList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterNeighbor" {
                            $RouterNeighbor | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterNetwork" {
                            if ($ConfigLineArray[1] -eq "prefix") {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                            }
                            else {
                                $Value = $ConfigLineArray[2]
                            }
                            $RouterNetwork |  Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterRedistribute" {
                            $RouterRedistribute | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force                            
                        }
                        "oschecklist" {
                            $OSCheckListRule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force  
                        }
                        "ospfinterface" {
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "ospf6interface" {
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterAccessListRule" {
                            if ($ConfigLineArray[1] -eq "prefix") {
                                if ($ConfigLineArray[2] -eq "any") { $Value = "0.0.0.0/0" } 
                                else { $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] }
                                $RouterAccessList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            else { $RouterAccessList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force }
                        }                      
                        "splitdns" {
                            $SplitDNS | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "tagging" {
                            $ObjectTag | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "virtualwanlinkhealthcheck" {
                            if ($ConfigLineArray[1] -eq "members") {
                                if ($ConfigLineArray.Count -gt 3) {
                                    $Value = $ConfigLineArray[2]
                                    for ($i=3;$i -le $ConfigLineArray.Count-1;$i++) { $Value = $Value + "," + $ConfigLineArray[$i] }
                                    $VirtualWanLinkHealthcheck | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                                }
                                else {
                                    #Only ONE member
                                    $Value = $ConfigLineArray[2]
                                    if ($Value -eq 0) { $Value = "All" }
                                    $VirtualWanLinkHealthcheck | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                                }
                            }
                            else {
                                $VirtualWanLinkHealthcheck | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                        }  
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMember | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }  
                        "virtualwanlinkservice" {
                            $VirtualWanLinkService | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force                           
                        }  
                        default {
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }               
                    }
                }   # if ($SUBSection)
                else {
                    switch ($ConfigSection) {   
                        "ConfigFirewallAddress" {
                            if ($ConfigLineArray[1] -eq "subnet") {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name "Type" -Value $ConfigLineArray[1] -force
                                $rule | Add-Member -MemberType NoteProperty -Name "Network" -Value $Value -force
                            }
                            else {
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            } 
                        }
                        "ConfigFirewallAddress6" {
                            if ($ConfigLineArray[1] -eq "start-ip") {
                                #$Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name "start-ip" -Value $ConfigLineArray[2] -force
                                $rule | Add-Member -MemberType NoteProperty -Name "ipv6" -Value "" -force
                            }
                            else {
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            } 
                        }
                        "ConfigSystemAdmin" {
                            if ($ConfigLineArray[1].StartsWith("trusthost")) {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                                if ($TrustedHosts) {
                                    $TrustedHosts = $TrustedHosts + "," + $Value
                                }
                                else { $TrustedHosts = $Value }
                            }
                            elseif ($ConfigLineArray[1].StartsWith("ip6-trusthost")) {
                                #$Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                                if ($IP6TrustedHosts) {
                                    $IP6TrustedHosts = $IP6TrustedHosts + "," + $ConfigLineArray[2]
                                }
                                else { $IP6TrustedHosts = $Value }
                            }                            
                            else { 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                        }
                        "ConfigSystemHA" {
                            if ($ConfigLineArray[1] -eq "hbdev") { $Value = ConvertHaInterfaces $Value }
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force                             
                        }
                        "Configvpnipsecphase2" {                           
                            if (($ConfigLineArray[1] -eq "src-subnet") -or ($ConfigLineArray[1] -eq "dst-subnet")) {
                                $Value= GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            elseif ($ConfigLineArray[1] -eq "src-name") {
                                $rule | Add-Member -MemberType NoteProperty -Name "src-name" -Value $Value -force
                                $rule | Add-Member -MemberType NoteProperty -Name "src-subnet" -Value "" -force
                            }
                            elseif ($ConfigLineArray[1] -eq "dst-name") {
                                $rule | Add-Member -MemberType NoteProperty -Name "dst-name" -Value $Value -force
                                $rule | Add-Member -MemberType NoteProperty -Name "dst-subnet" -Value "" -force
                            }                        
                            else { $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force }
                        }
                        "ConfigSystemInterface" {
                            if ($ConfigLineArray[1] -eq "ip" ) {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }  
                            else { $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force }
                        }
                        "ConfigRouterStatic" {
                            if ($ConfigLineArray[1] -eq "dst" ) {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            elseif ($ConfigLineArray[1] -eq "dstaddr" ) {
                                $rule | Add-Member -MemberType NoteProperty -Name dst -Value "" -force
                                $rule | Add-Member -MemberType NoteProperty -Name dstaddr -Value $Value -force
                            }
                            else {
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }                        
                        }
                        "ConfigRouterStatic6" {
                            if ($ConfigLineArray[1] -eq "dst" ) {
                                $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            elseif ($ConfigLineArray[1] -eq "dstaddr" ) {
                                $rule | Add-Member -MemberType NoteProperty -Name dst -Value "" -force
                                $rule | Add-Member -MemberType NoteProperty -Name dstaddr -Value $Value -force
                            }
                            else {
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }                        
                        }       
                        "ConfigRouterISIS" {
                            if (($ConfigLineArray[1] -eq 'spf-interval-exp-l1') -or ($ConfigLineArray[1] -eq 'spf-interval-exp-l2')) {
                                $Value = $ConfigLineArray[2] + " - " + $ConfigLineArray[3]
                            }
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }                 
                        "ConfigRouterOSPF" {
                            if ($ConfigLineArray[1] -eq 'router-id') { $OSPFRouterID = $ConfigLineArray[2] }
                            elseif ($ConfigLineArray[1] -eq 'passive-Interface') { $OSPFPassiveInterface = $Value }
                        }
                        "ConfigRouterOSPF6" {
                            if ($ConfigLineArray[1] -eq 'router-id') { $OSPFRouterID = $ConfigLineArray[2] }
                            elseif ($ConfigLineArray[1] -eq 'passive-Interface') { $OSPFPassiveInterface = $Value }
                        }                        
                        "ConfigRouterPolicy" {
                            if (($ConfigLineArray[1] -eq "src" ) -or ($ConfigLineArray[1] -eq "dst" )) {
                                $Value = GetSubnetCIDRPolicy $ConfigLineArray[2]
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
                            else { $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force }                        
                        } 
                        default {
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                    }   # switch ($ConfigSection)
                }   # else if ($SUBSection)    
            }   # if ($ConfigSection)
        }   # "set"
        "next" {
            if ($ConfigSection) {   
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
                        "acmeacc" {
                            $AcmeAccountArray.Add($AcmeAccount) | Out-Null
                        }
                        "AuthenticationRule" {
                            $AuthenticationRuleArray.Add($AuthenticationRule) | Out-Null
                        }
                        "bookmarkgroup" {
                            if ($SUBSection2) {
                                $BookMarkArray.Add($BookMark) | Out-Null
                            }  
                        }
                        "ConfigSystemSNMPCommunityHost" {
                            $SNMPCommunityHost | Add-Member -MemberType NoteProperty -Name SNMP-Community -Value $rule.Name -force
                            $SNMPCommunityHosts.Add($SNMPCommunityHost) | Out-Null
                        }
                        "dhcpiprange" {
                            $DHCPRangeArray.Add($DHCPRange) | Out-Null 
                        }
                        "dhcpoptions" {
                            $DHCPOptionsArray.Add($DHCPOptions) | Out-Null 
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddressArray.Add($DHCPReservedAddress) | Out-Null 
                        } 
                        "DNSEntry" {
                            $DNSEntryArray.Add($DNSEntry) | Out-Null 
                        }
                        "Gui-Dashboard" {
                            if ($SubSection2) {
                                #Do nothing not implemented
                            }
                            #Do nothing not implemented
                        }
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterfaceArray.Add($HAMGMTInterface) | Out-Null 
                        }
                        "ospfinterface" {
                            $RouterInterfaceArray.Add($OSPFInterface) | Out-Null 
                        }
                        "ospf6interface" {
                            $RouterInterfaceArray.Add($OSPFInterface) | Out-Null 
                        }
                        "RouterDistibuteList" {
                            $RouterDistibuteListArray.Add($RouterDistibuteList) | Out-Null 
                        }
                        "RouterNeighbor" {
                            #Check if the new value is not the same as the OLD (config has two concecutive next statements)
                            if ($RouterNeighbor.IP -ne $RouterNeighborOLD.IP) {
                                $RouterNeighborOLD = $RouterNeighbor
                                $RouterNeighborArray.Add($RouterNeighbor) | Out-Null 
                            }   
                        }
                        "RouterNetwork" {
                            $RouterNetworkArray.Add($RouterNetwork) | Out-Null 
                        }
                        "RouterAccessListRule" {
                            $RouterAccessListArray.Add($RouterAccessList) | Out-Null 
                        }
                        "splitdns" {
                            $SplitDNSArray.Add($SplitDNS) | Out-Null
                        }
                        "tagging" {
                            $ObjectTagArray.Add($ObjectTag) | Out-Null 
                        }
                        "virtualwanlinkhealthcheck" {
                            $VirtualWanLinkHealthCheckArray.Add($VirtualWanLinkHealthCheck) | Out-Null 
                        }
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMemberArray.Add($VirtualWanLinkMember) | Out-Null 
                        }
                        "virtualwanlinkservice" {
                            $VirtualWanLinkServiceArray.Add($VirtualWanLinkService) | Out-Null 
                        }     
                        default {
                            $rulelist.Add($rule) | Out-Null 
                        }                   
                    }   # Switch ($SUBSectionConfig)
                }   #if ($SUBSection)
                else {   
                    switch ($ConfigSection) {
                        "ConfigSystemAdmin" {
                            $Rule.TrustedHosts = $TrustedHosts
                            $Rule.IP6TrustedHosts = $IP6TrustedHosts
                            $rulelist.Add($rule) | Out-Null 
                            $TrustedHosts = "" 
                            $IP6TrustedHosts = ""
                        }
                        "ConfigSystemDHCP" {
                            $DHCPIP4=$true
                            CreateExcelSheetDHCP
                            $DHCPRangeArray = [System.Collections.ArrayList]@()
                            $DHCPOptionsArray = [System.Collections.ArrayList]@()
                            $DHCPReservedAddressArray = [System.Collections.ArrayList]@()
                        }
                        "ConfigSystemDHCP6" {
                            $DHCPIP4=$false
                            CreateExcelSheetDHCP
                            $DHCPRangeArray = [System.Collections.ArrayList]@()
                            $DHCPOptionsArray = [System.Collections.ArrayList]@()
                            $DHCPReservedAddressArray = [System.Collections.ArrayList]@()
                        }                        
                        "ConfigFirewallVIP"  {
                            #if ($SUBSectionConfig -ne "VIPRealservers") {
                            if (!($ConfigRealservers)) {
                                $ruleList.Add($rule)  | Out-Null 
                            }
                            $ConfigRealservers = $False
                        }
                        "ConfigSystemSNMPCommunity" {
                            #$rule | Add-Member -MemberType NoteProperty -Name hosts -Value $SNMPHosts -force
                            $SNMPCommunities.Add($rule)  | Out-Null 
                        }
                        "ConfigSystemSNMPUser" {
                            $SNMPUsers.Add($rule)  | Out-Null 
                        }
                        "ConfigUserGroup" {
                            if ($SUBSectionConfig -eq "groupmatch") {
                                $SUBSectionConfig = ""
                            }
                            else { $ruleList.Add($rule) | Out-Null }
                        }
                        Default { 
                            $ruleList.Add($rule) | Out-Null
                        }
                    }   # switch ($ConfigSection)  
                }   # else if ($SUBSection)
            }   # if ($ConfigSection)
        }    # "next"             
        "end" {
            if ($SUBSection) {
                if ($SubSection2) {
                    $SubSection2 = $False
                }
                else {
                    Switch ($SUBSectionConfig) {
                        "oschecklist" {
                            $OSCheckListArray.Add($OSCheckListRule)  | Out-Null
                        }
                        "routerredistribute" { 
                            $RouterRedistibuteArray.Add($RouterRedistribute)  | Out-Null 
                        }
                        "tagging" {
                            $Value = ConvertTagArrayToLine $ObjectTagArray
                            $rule | Add-Member -MemberType NoteProperty -Name tag -Value $Value -force
                            $ObjectTagArray = [System.Collections.ArrayList]@()
                        }                    
                    }
                    $SUBSection = $False
                    #Segment END in configfile this should be the last SubSectionConfig line
                    $SUBSectionConfig = ""
                    #switch ($ConfigSection) {
                    #    "VIPRealservers" {
                    #        $ruleList.Add($rule) | Out-Null 
                    #    } 
                    #}
                } 
            } # if ($SUBSection)
            else {            
                if ($ConfigSection) {
                    if ($vdom) { 
                        $VdomName = "_" + $vdom
                    }
                    else { $VdomName = "" }
                    switch ($ConfigSection) {  
                        "ConfigFirewallPolicy" { 
                            $rulelist = $rulelist | Sort-Object ID
                            if ($FortigateConfigArray) {
                                $rulelist = ParseISDB $rulelist
                            }
                            CreateExcelSheet "IPV4_Rules$VdomName" $rulelist  
                        }
                        "ConfigFirewallAddress" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV4_Addresses$VdomName" $rulelist  
                        }
                        "ConfigFirewallAddress6" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV6_Addresses$VdomName" $rulelist  
                        }                        
                        "ConfigFirewallAddrgrp" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV4_AddressGRP$VdomName" $rulelist  
                        }
                        "ConfigFirewallAddrgrp6" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV6_AddressGRP$VdomName" $rulelist  
                        }                        
                        "ConfigFirewallIPpool" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPpool$VdomName" $ruleList
                        }
                        "ConfigFirewallLdbMonitor" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Ldb_Monitor$VdomName" $ruleList                            
                        }
                        "ConfigFirewallServiceCategory" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services_Category$VdomName" $rulelist  
                        }
                        "ConfigFirewallServiceCustom" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services$VdomName" $rulelist  
                        }
                        "ConfigFirewallServiceGroup" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services_Group$VdomName" $rulelist  
                        }
                        "ConfigFirewallShaperPerIPShaper" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "ShaperPerIP$VdomName" $rulelist                               
                        }
                        "ConfigFirewallShaperTrafficShaper" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "ShaperTrafficShaper$VdomName" $rulelist                              
                        }
                        "ConfigFirewallShapingPolicy" {
                            $rulelist = $rulelist | Sort-Object ID
                            CreateExcelSheet "ShapingPolicy$VdomName" $rulelist                              
                        }
                        "ConfigFirewallVIP" {
                            $rulelist = $rulelist | Sort-Object Name,ID
                            CreateExcelSheet "VIP$VdomName" $rulelist
                        }         
                        "ConfigFirewallVIPGRP" {
                            $rulelist = $rulelist | Sort-Object Name,ID
                            CreateExcelSheet "VIPGroup$VdomName" $rulelist
                        }                   
                        "ConfigRouterAccessList" {
                            $RouterAccessListArray = $RouterAccessListArray | Sort-Object Name,ID
                            CreateExcelSheet "Router_AccesList$vdomName" $RouterAccessListArray
                        }
                        "ConfigRouter$RouterSection" {
                            switch ($ConfigSection) {
                                "ConfigRouterStatic" { 
                                    $rulelist = $rulelist | Sort-Object ID
                                    CreateExcelSheet "IPV4_Router_Static$VdomName" $rulelist 
                                }
                                "ConfigRouterStatic6" { 
                                    $rulelist = $rulelist | Sort-Object ID
                                    CreateExcelSheet "IPV6_Router_Static$VdomName" $rulelist 
                                }                                
                                "ConfigRouterBGP" {
                                    CreateExcelSheetBGP                                    
                                }
                                "ConfigRouterBGP6" {
                                    CreateExcelSheetBGP                                    
                                }
                                "ConfigRouterISIS" {
                                    CreateExcelSheetISIS                                    
                                }                                
                                "ConfigRouterOSPF" {
                                    CreateExcelSheetOSPF
                                    #reset router-ID just in case OSPF6 is not used
                                    $OSPFRouterID = "no-ospf"   
                                    $RouterNetworkArray = [System.Collections.ArrayList]@()
                                    $RouterInterfaceArray = [System.Collections.ArrayList]@()
                                    $OSPFPassiveInterface = [System.Collections.ArrayList]@()
                                    $OSPFInterface = [System.Collections.ArrayList]@()              
                                }
                                "ConfigRouterOSPF6" {
                                    CreateExcelSheetOSPF                               
                                }                                
                                "ConfigRouterPolicy" { 
                                    $rulelist = $rulelist | Sort-Object ID
                                    CreateExcelSheet "Router_Policy$VdomName" $rulelist 
                                }
                            } 
                            $RouterAccessListArray = [System.Collections.ArrayList]@()
                            $RouterRedistibuteArray = [System.Collections.ArrayList]@()  
                        }
                        "ConfigSystemAccprofile" {
                            CreateExcelSheet "AccProfile$VdomName" $rulelist 
                        }
                        "ConfigSystemAcme" {
                            if ($AcmeAccountArray) { CreateExcelSheetAcme }
                        }
                        "ConfigSystemAdmin"  {
                            CreateExcelSheet "AdminUsers$VdomName" $rulelist 
                        } 
                        "ConfigSystemDDNS" {
                            $rulelist = $rulelist | Sort-Object ID
                            CreateExcelSheet "DDNS$VdomName" $rulelist                             
                        }
                        "ConfigSystemDNSDatabase" {
                            $ruleList = $rulelist | Sort-Object DNSName
                            CreateExcelSheetDNSDatabase
                        }
                        "ConfigSystemDNSServer" {
                            $ruleList = $rulelist | Sort-Object interface
                            CreateExcelSheet "DNSServer$VdomName" $rulelist 
                        }
                        "ConfigSystemGlobal" {
                            UpdateMainSheet $rule
                            $UsedRange = $MainSheet.usedRange                  
                            $UsedRange.EntireColumn.AutoFit() | Out-Null
                        }
                        "ConfigSystemHA" {
                            $HAMGMTInterfaceArray = $HAMGMTInterfaceArray | Sort-Object ID
                            CreateExcelSheetHA   
                        }
                        "ConfigSystemInterface" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Interfaces$VdomName" $rulelist                 
                        }
                        "ConfigSystemLinkmonitor" {
                            CreateExcelSheet "LinkMonitor$VdomName" $rulelist                         
                        }
                        "ConfigSystemSDWAN"  {
                            CreateExcelSheetVirtualWanLink
                        }
                        "ConfigSystemSettings" {
                            $rulelist.Add($rule) | Out-Null 
                            CreateExcelSheet "SystemSettings$VdomName" $ruleList
                        }
                        "ConfigSystemSessionHelper" {
                            $ruleList = $ruleList | Sort-Object ID
                            CreateExcelSheet "Session_Helper$VdomName" $ruleList
                        }
                        "ConfigSystemSNMPSysinfo" {
                            $SNMPSysinfo = $rule
                        }
                        "ConfigSystemSNMPCommunity" {
                            #$ruleList = $ruleList  | Sort-Object Name
                            #$SNMPCommunities = $ruleList
                            $SNMPCommunities =  $SNMPCommunities | Sort-Object Name
                        }
                        "ConfigSystemSNMPUser" {
                            $SNMPUsers = $SNMPUsers  | Sort-Object Name
                        }
                        "ConfigSystemVirtualWanLink" {
                            CreateExcelSheetVirtualWanLink
                        }
                        "ConfigSystemZone" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Zone$VdomName" $rulelist 
                        }
                        "ConfigUsergroup" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "UserGroup$VdomName" $ruleList
                        }
                        "ConfigUserLdap" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "UserLdap$VdomName" $rulelist                             
                        }
                        "ConfigUserLocal" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "UserLocal$VdomName" $rulelist                         
                        }
                        "ConfigUserRadius" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "UserRadius$VdomName" $rulelist                         
                        }
                        "ConfigUserSAML" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "UserSaml$VdomName" $rulelist                              
                        }
                        "Configvpnipsecphase1" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN_Phase1$VdomName" $rulelist 
                        }
                        "Configvpnipsecphase2" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN_Phase2$VdomName" $rulelist 
                        }
                        "Configvpnsslsettings" {
                            $ruleList.Add($rule) | Out-Null  
                            CreateExcelSheetVPNSSLSettings
                        }
                        "Configvpnsslwebportal" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheetSSLwebportal                    
                        }
                    }   # switch ($ConfigSection)     
                    $ConfigSection = $null
                    $ruleList = [System.Collections.ArrayList]@()
                    Write-Output "Section done."
                } # if ($ConfigSection)
            } # else if ($SUBSection)
        }    # "end"
    } # switch($ConfigLineArray[0])
}    # foreach ($Line in $loadedConfig)
#Check if we have SNMP info (This is in three separate section so now is the time to create the sheet if we have info)
if ($SNMPFound) {
    CreateExcelSheetSNMP
}
#make sure that the first sheet that is opened by Excel is the Table of Content sheet.
$TocSheet.Activate()
Write-Output "Creating Table of Contents"
for ($ExcelSheetNumber=1; $ExcelSheetNumber -le $workbook.Sheets.Count; $ExcelSheetNumber++) {
    $TocRow = UpdateToc  $workbook.Worksheets.Item($ExcelSheetNumber).Name
}
$UsedRange = $TocSheet.usedRange 
$SortRange = $TocSheet.Range("A2")  
[void] $UsedRange.Sort($SortRange,1,$null,$null,1,$null,1,1)              
$UsedRange.EntireColumn.AutoFit() | Out-Null     
Write-Output "Writing Excelfile $ExcelFullFilePad.xls"
$excel.ScreenUpdating = $true
$excel.DisplayStatusBar = $true
$excel.EnableEvents = $true
$workbook.SaveAs($ExcelFullFilePad)
$excel.Quit()
$elapsedTime = $(get-date) - $startTime
$Minutes = $elapsedTime.Minutes
$Seconds = $elapsedTime.Seconds
Write-Output "Script done in $Minutes Minute(s) and $Seconds Second(s)."