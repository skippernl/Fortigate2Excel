<#
.SYNOPSIS
Fortigate2Excel parses rules from a FortiGate device into a CSV file.
.DESCRIPTION
The Fortigate2Excel reads a FortiGate config file and pulls out the configuration for each VDOM in the file into excell.
.PARAMETER fortigateConfig
[REQUIRED] This is the path to the FortiGate config file
.EXAMPLE
.\Fortigate2Excel.ps1 -fortiGateConfig "c:\temp\config.conf"
Parses a FortiGate config file and places the CSV file in the same folder where the config was found.
.NOTES
Author: Xander Angenent
Idea: Drew Hjelm (@drewhjelm) (creates csv of ruleset only)
Last Modified: 18/12/19
#Estimated completion time from http://mylifeismymessage.net/1672/
#>
Param
(
    [Parameter(Mandatory = $true)]
    $fortigateConfig
)

Function InitDHCPRange {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value "" 
    $InitRule | Add-Member -type NoteProperty -name "start-ip" -Value ""
    $InitRule | Add-Member -type NoteProperty -name "end-ip" -Value ""  
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
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Type -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name Visibility -Value ""
    $InitRule | Add-Member -type NoteProperty -name Associated-interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name Start-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name End-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name Network -Value ""
    $InitRule | Add-Member -type NoteProperty -name Wildcard-fqdn -Value ""
    $InitRule | Add-Member -type NoteProperty -name FQDN -Value ""
    return $InitRule
}
Function InitFirewallAddressGroup {
    $InitRule = New-Object System.Object;
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
    $InitRule | Add-Member -type NoteProperty -name Type -Value ""
    $InitRule | Add-Member -type NoteProperty -name UUID -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name action -Value ""
    $InitRule | Add-Member -type NoteProperty -name schedule -Value ""
    $InitRule | Add-Member -type NoteProperty -name utm-status -Value ""
    $InitRule | Add-Member -type NoteProperty -name logtraffic -Value ""
    $InitRule | Add-Member -type NoteProperty -name av-profile -Value ""
    $InitRule | Add-Member -type NoteProperty -name ips-sensor -Value ""
    $InitRule | Add-Member -type NoteProperty -name profile-protocol-options -Value ""
    $InitRule | Add-Member -type NoteProperty -name ssl-ssh-profile -Value ""
    $InitRule | Add-Member -type NoteProperty -name application-list -Value ""
    #Default is disable
    $InitRule | Add-Member -type NoteProperty -name nat -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name status -Value "enable"
    $InitRule | Add-Member -type NoteProperty -name webfilter-profile -Value ""
    $InitRule | Add-Member -type NoteProperty -name poolname -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
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
Function InitFirewallShaperPeripshaper {
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
    #When using loadbalance this values are used
    #Setting ldb-method to none to indicate no loadbalance is done
    #this gets overwritten is loadbalance is used
    $InitRule | Add-Member -type NoteProperty -name ldb-method -Value "none"
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name port -Value ""
    $InitRule | Add-Member -type NoteProperty -name monitor -Value ""
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
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
Function InitRouterPolicy {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name src -Value ""
    #default route has no data in config setting dst route to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name action -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    $InitRule | Add-Member -type NoteProperty -name output-device -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    return $InitRule
}
Function InitRouterOSPFInterface {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name cost -Value ""
    $InitRule | Add-Member -type NoteProperty -name dead-interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name hello-interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name network-type -Value ""
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
    #default route has no data in config setting dst route to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name dstaddr -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""    
    $InitRule | Add-Member -type NoteProperty -name Device -Value ""
    $InitRule | Add-Member -type NoteProperty -name comment -Value ""
    $InitRule | Add-Member -type NoteProperty -name blackhole -Value ""
    $InitRule | Add-Member -type NoteProperty -name distance -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name virtual-wan-link -Value ""
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
    $InitRule | Add-Member -type NoteProperty -name "ntp-server1" -Value ""
    return $InitRule
}
Function InitSystemGlobal {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name admin-sport -Value "443"
    $InitRule | Add-Member -type NoteProperty -name admin-Cert -Value "Selfsigned"
    $InitRule | Add-Member -type NoteProperty -name admintimeout -Value ""
    $initRule | Add-Member -type NoteProperty -name compliance-check -Value ""
    $initRule | Add-Member -type NoteProperty -name gui-device-latitude -Value ""
    $initRule | Add-Member -type NoteProperty -name gui-device-longitude -Value ""
    $initRule | Add-Member -type NoteProperty -name gui-theme -Value ""
    $InitRule | Add-Member -type NoteProperty -name alias -Value "    "
    $InitRule | Add-Member -type NoteProperty -name disk-usage -Value ""
    $InitRule | Add-Member -type NoteProperty -name hostname -Value ""
    $InitRule | Add-Member -type NoteProperty -name proxy-auth-timeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name switch-controller -Value ""
    $InitRule | Add-Member -type NoteProperty -name remoteauthtimeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name revision-backup-on-logout -Value ""
    $InitRule | Add-Member -type NoteProperty -name revision-image-auto-backup -Value ""
    $InitRule | Add-Member -type NoteProperty -name tcp-halfclose-timer -Value ""
    $InitRule | Add-Member -type NoteProperty -name tcp-halfopen-time -Value ""
    $InitRule | Add-Member -type NoteProperty -name timezone -Value ""
    $InitRule | Add-Member -type NoteProperty -name udp-idle-timer -Value ""
    return $InitRule
}
Function InitSystemHA {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Group-id -Value ""
    $InitRule | Add-Member -type NoteProperty -name Group-Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    #Next line gets filterd out when creating the ExcelSheet
    $InitRule | Add-Member -type NoteProperty -name Password -Value ""
    $InitRule | Add-Member -type NoteProperty -name hbdev -Value ""
    $InitRule | Add-Member -type NoteProperty -name session-sync-dev -Value ""
    $InitRule | Add-Member -type NoteProperty -name ha-mgmt-status -Value ""
    $InitRule | Add-Member -type NoteProperty -name override -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name session-pickup -Value ""
    $InitRule | Add-Member -type NoteProperty -name monitor -Value ""
    return $InitRule
}
Function InitSystemHAMGMTInterfaces {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""    
    $InitRule | Add-Member -type NoteProperty -name gateway -Value ""
    return $InitRule
}
Function InitSytemInterface {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name vdom -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name snmp-index -Value ""
    $InitRule | Add-Member -type NoteProperty -name ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name allowaccess -Value ""
    $InitRule | Add-Member -type NoteProperty -name explicit-web-proxy -Value ""
    $InitRule | Add-Member -type NoteProperty -name alias -Value ""
    $InitRule | Add-Member -type NoteProperty -name fortiheartbeat -Value ""
    $InitRule | Add-Member -type NoteProperty -name role -Value ""
    $InitRule | Add-Member -type NoteProperty -name secondary-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name scan-botnet-connections -Value ""
    $InitRule | Add-Member -type NoteProperty -name estimated-upstream-bandwidth -Value ""
    $InitRule | Add-Member -type NoteProperty -name estimated-downstream-bandwidth -Value ""
    $InitRule | Add-Member -type NoteProperty -name description -Value ""
    $InitRule | Add-Member -type NoteProperty -name dedicated-to -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name remote-IP -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name vlanid -Value ""
    return $InitRule
}
Function InitSystemLinkMonitor {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name protocol -Value ""
    $InitRule | Add-Member -type NoteProperty -name gateway-ip -Value ""
    $InitRule | Add-Member -type NoteProperty -name interval -Value ""
    $InitRule | Add-Member -type NoteProperty -name timeout -Value ""
    $InitRule | Add-Member -type NoteProperty -name failtime -Value ""
    $InitRule | Add-Member -type NoteProperty -name recoverytime -Value ""
    $InitRule | Add-Member -type NoteProperty -name update-cascade-interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name update-static-route -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name srcintf -Value ""
    $InitRule | Add-Member -type NoteProperty -name server -Value ""
    return $InitRule
}
Function InitSystemVirtualWanLink {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name load-balance-mode -Value ""
    return $InitRule
}
Function InitSystemZone {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    return $InitRule    
}
Function InitUserGroup {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name member -Value ""
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
    $InitRule | Add-Member -type NoteProperty -name secure -Value ""
    $InitRule | Add-Member -type NoteProperty -name ca-cert -Value ""
    $InitRule | Add-Member -type NoteProperty -name port -Value ""
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
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name weight -Value ""
    return $InitRule   
}
Function InitVirtualWanLinkService {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""    
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name member -Value ""
    $InitRule | Add-Member -type NoteProperty -name dst -Value ""
    $InitRule | Add-Member -type NoteProperty -name src -Value ""
    return $InitRule  
}
Function InitVpnipsecphase1 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
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
Function InitVpnipsecphase2 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name phase1name -Value ""
    $InitRule | Add-Member -type NoteProperty -name proposal -Value ""
    $InitRule | Add-Member -type NoteProperty -name dhgrp -Value ""
    $InitRule | Add-Member -type NoteProperty -name replay -Value ""
    $InitRule | Add-Member -type NoteProperty -name auto-negotiate -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name keylifeseconds -Value ""
    #default has no data in config setting src-subnet to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name src-subnet -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name src-name -Value ""
    #default has no data in config setting dst-subnet to 0.0.0.0/0 it gets overwritten if needed
    $InitRule | Add-Member -type NoteProperty -name dst-subnet -Value "0.0.0.0/0"
    $InitRule | Add-Member -type NoteProperty -name dst-name -Value ""
    #default keepalive = disable
    $InitRule | Add-Member -type NoteProperty -name keepalive -Value "disable"
    $InitRule | Add-Member -type NoteProperty -name pfs -Value ""
    return $InitRule
}
Function CleanupLine ($LineToCleanUp) {
    $LineToCleanUp = $LineToCleanUp.TrimStart()
    $LineToCleanUpArray = $LineToCleanUp.Split('`"')
    $i=1
    $ReturnValue = $null
    if ($LineToCleanUpArray.Count -gt 1) {
        DO {
            $LineToCleanUpArrayMember = $LineToCleanUpArray[$i].Trim()
            if ($LineToCleanUpArrayMember -ne "") {
                if ($ReturnValue) { $ReturnValue = $ReturnValue + "," + $LineToCleanUpArrayMember }
                else { $ReturnValue = $LineToCleanUpArrayMember}
            }
            $i++
        } While ($i -le $LineToCleanUpArray.Count-1)
    }
    else {
        $LineToCleanUpArray = $LineToCleanUp.Split(' ')
        if ($LineToCleanUpArray.Count -ge 8) {
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
Function CreateExcelTabel ($ActiveSheet, $ActiveArray) {
    $NoteProperties = $ActiveArray | get-member -Type NoteProperty
    foreach ($Noteproperty in $NoteProperties) {
        $PropertyString = [string]$NoteProperty.Name
        #Keep passwords/psksecrets out of the documentation
        if (($PropertyString -ne "password") -and ($PropertyString -ne "psksecret")) {
            $excel.cells.item($row,$Column) = $PropertyString
            $Column++
        }
    }
    $Row++
    foreach ($ActiveMember in $ActiveArray) {
        $Column=1
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            if (($PropertyString -ne "password") -and ($PropertyString -ne "psksecret")) {
                $Value = $ActiveMember.$PropertyString         
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }
        }                      
        $row++
    }    
    Return $row
}
Function CreateExcelSheet ($SheetName, $SheetArray) {
    if ($SheetArray) {
        $row = 1
        $Sheet = $workbook.Worksheets.Add()
        $Sheet.Name = $SheetName
        $Column = 1
        #Keeping Visual Studio happy
        $excel.cells.item($row,$Column) = ""
        $row = CreateExcelTabel $Sheet $SheetArray
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null
    }
}
Function CreateExcelSheetDHCP {
    $row = 1
    $Sheet = $workbook.Worksheets.Add()
    $SheetName = "DHCP-" + $rule.Interface + "-" + $rule.ID
    $Sheet.Name = $SheetName
    $Column=1
    $excel.cells.item($row,$Column) = "Normal DHCP options"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $row = CreateExcelTabel $Sheet $rule
    if ($DHCPOptionsArray) {                
        $Column=1
        $excel.cells.item($row,$Column) = "Extra DHCP options"
        ChangeFontExcelCell $Sheet $row $Column
        $row++     
        $row = CreateExcelTabel $Sheet $DHCPOptionsArray   
    }
    #Add IP ranges
    $Column=1
    $excel.cells.item($row,$Column) = "DHCP Range"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $DHCPRangeArray = $DHCPRangeArray | Sort-Object ID 
    $row = CreateExcelTabel $Sheet $DHCPRangeArray
    $row++ 
    $Column=1
    if ($DHCPReservedAddressArray) {
        $excel.cells.item($row,$Column) = "Reserved Addresses"
        ChangeFontExcelCell $Sheet $row $Column
        $row++      
        $DHCPReservedAddressArray = $DHCPReservedAddressArray | Sort-Object ID  
        $row = CreateExcelTabel $Sheet $DHCPReservedAddressArray     
    }     
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null    
}
Function CreateExcelSheetHA {
    #If group-name is empty HA is not active and this excel tab would be useless
    if ($rule."group-name" -ne "") {
        $row = 1
        $Sheet = $workbook.Worksheets.Add()
        $SheetName = "HA$VdomName"
        $Sheet.Name = $SheetName
        $Column = 1   
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
Function CreateExcelSheetVirtualWanLink {
    $row = 1
    $Sheet = $workbook.Worksheets.Add()
    $SheetName = "Virtual-Wan-Link"
    $Sheet.Name = $SheetName
    $Column=1
    $excel.cells.item($row,$Column) = "Global Virtual Wan Link settings"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $row = CreateExcelTabel $Sheet $rule 
    if ($VirtualWanLinkMemberArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN members"
        ChangeFontExcelCell $Sheet $row $Column
        $row++    
        $row = CreateExcelTabel $Sheet $VirtualWanLinkMemberArray  
    }  
    if ($VirtualWanLinkHealthCheckArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN healtcheck"
        ChangeFontExcelCell $Sheet $row $Column
        $row++
        $row = CreateExcelTabel $Sheet $VirtualWanLinkHealthCheckArray        
    }   
    if ($VirtualWanLinkServiceArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN service"
        ChangeFontExcelCell $Sheet $row $Column
        $row++
        $row = CreateExcelTabel $Sheet $VirtualWanLinkServiceArray        
    }      
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null                  
}
Function CreateExcelSheetBGP {
    #If BGP is not used AS = none then this sheet does not need to be created
    if ($Rule."as" -ne "none") {
        $row = 1
        $Sheet = $workbook.Worksheets.Add()
        $SheetName = "Router-$RouterSection$VdomName"
        $Sheet.Name = $SheetName
        $Column = 1   
        $row = CreateExcelTabel $Sheet $rule
        if ($RouterNeighborArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "BGP Neighbors" 
            ChangeFontExcelCell $Sheet $row $Column
            $Row++      
            $row = CreateExcelTabel $Sheet $RouterNeighborArray 
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
Function CreateExcelSheetOSPF {
    #id $OSPFRouterID is "no-ospf" it has not been overwritten and OSPF is not used -> Do not create the sheet.
    if ($OSPFRouterID -ne "no-ospf") {
        $row = 1
        $Sheet = $workbook.Worksheets.Add()
        $SheetName = "Router-$RouterSection$VdomName"
        $Sheet.Name = $SheetName
        $Column=1    
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
            $Column=1
            $excel.cells.item($row,$Column) = "OSPF Interfaces"
            ChangeFontExcelCell $Sheet $row $Column 
            $Row++      
            $row = CreateExcelTabel $Sheet $RouterInterfaceArray
        } 
        $Column=1
        $excel.cells.item($row,$Column) = "OSPF Passive Interfaces"
        ChangeFontExcelCell $Sheet $row $Column 
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
        if ($RouterDistibuteListArray) {
            $Column=1
            $excel.cells.item($row,$Column) = "OSPF Distributelist"
            ChangeFontExcelCell $Sheet $row $Column   
            $Row++     
            $row = CreateExcelTabel $Sheet $RouterDistibuteListArray
        }     
        $UsedRange = $Sheet.usedRange                  
        $UsedRange.EntireColumn.AutoFit() | Out-Null  
    }    
}
Function GetNumber ($NumberString) {
    [int]$IntNum = [convert]::ToInt32($NumberString, 10)
    return $IntNum
}
Function GetNumber ($NumberString) {
    [int]$IntNum = [convert]::ToInt32($NumberString, 10)
    return $IntNum
}
Function Get-ScriptDirectory
{
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
Function UpdateFirstSheet ( $ActiveArray ) {
    $FirstSheet.Cells.Item(2,1) = 'Excel Creation Date'
    $FirstSheet.Cells.Item(2,2) = $Date
    $FirstSheet.Cells.Item(2,2).numberformat = "00"
    $FirstSheet.Cells.Item(3,1) = 'Config Creation Date'
    $FirstSheet.Cells.Item(3,2) = $ConfigDate 
    $FirstSheet.Cells.Item(3,2).numberformat = "00"                       
    $FirstSheet.Cells.Item(4,1) = 'Type'
    $FirstSheet.Cells.Item(4,2) = $FWType
    $FirstSheet.Cells.Item(5,1) = 'Version'
    $FirstSheet.Cells.Item(5,2) = $FWVersion  
    $NoteProperties = $ActiveArray | get-member -Type NoteProperty
    $Row = 6
    $Column = 1
    foreach ($Noteproperty in $NoteProperties) {
        $excel.cells.item($row,$Column) = $Noteproperty.Name
        $Row++
    }
    $Row = 6
    $Column = 2
    foreach ($ActiveMember in $ActiveArray) {
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            if (($PropertyString -eq "timezone") -and $TimeZoneArray) {
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

#Start MAIN Script
if (!( Test-Path "$fortigateConfig" )) {
    Write-Output "[!] ERROR: Could not find FortiGate config file at $fortigateConfig."
    exit 1
}
$TimeZoneFilePath = Get-ScriptDirectory
if (Test-Path "$TimeZoneFilePath\TimeZones.csv") {
    $TimeZoneArray = Import-CSV "$TimeZoneFilePath\TimeZones.csv" -delimiter ";"
}
else { $TimeZoneArray = $null}
$startTime = get-date 
Clear-Host
Write-Output "Started script"
#Clear 5 additional lines for the progress bar
$I=0
DO {
    Write-output ""
    $I++
} While ($i -le 5)
$loadedConfig = Get-Content $fortigateConfig
$Counter=0
#default values these are getting over written when they are changed
#
#End default values
$MaxCounter=$loadedConfig.count
$date = Get-Date -Format yyyyMMddHHmm
$WorkingFolder = (Get-Item $fortigateConfig).DirectoryName
$FileName = (Get-Item $fortigateConfig).Basename
$configdateArray=$Filename.Split("_")
$configdate = $configdateArray[$configdateArray.Count-2] + $configdateArray[$configdateArray.Count-1]
$ExcelFullFilePad = "$workingFolder\$fileName"
$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false
$workbook = $excel.Workbooks.Add()
$FirstSheet = $workbook.Worksheets.Item(1) 
if ($Filename.Length -gt 31) {
    Write-output "Sheetname cannot be longer that 31 caracters shorting name to fit."
    $SheetName = $FileName.Substring(0,31)
}
else {
    $Sheetname = $FileName
}
$FirstSheet.Name = $SheetName
$FirstSheet.Cells.Item(1,1)= 'Fortigate Configuration'
$MergeCells = $FirstSheet.Range("A1:G1")
$MergeCells.Select() | out-null
$MergeCells.MergeCells = $true
ChangeFontExcelCell $FirstSheet 1 1
$FirstLine = $loadedConfig[0]
$FirstLineArray = $FirstLine.Split(":")
$FirewallInfoArray = $FirstLineArray[0].Split("-")
$FWTypeVersion = $FirewallInfoArray[1]
$FirewallTypeArray = $FWTypeVersion.Split("=")
$FWVersion = $FirewallInfoArray[2]
$FWType = $FirewallTypeArray[1]
$SUBSection = $False
#Creating empty Arrays
$ruleList = @()
$DHCPRangeArray = @()
$DHCPOptionsArray = @()
$DHCPReservedAddressArray = @()
$VirtualWanLinkMemberArray = @()
$VirtualWanLinkHealthCheckArray = @()
$VirtualWanLinkServiceArray = @()
$RouterAccessListArray = @()
$RouterRedistibuteArray = @()
$RouterInterfaceArray = @()
$RouterNetworkArray = @()
$RouterDistibuteListArray = @()
$RouterNeighborArray = @()
$HAMGMTInterfaceArray = @()
$OSPFRouterID = "no-ospf"
foreach ($Line in $loadedConfig) {
    $Proc = $Counter/$MaxCounter*100
    $ProcString = $Proc.ToString("0.00")
    $elapsedTime = $(get-date) - $startTime 
    if ($Counter -eq 0) { $estimatedTotalSeconds = $MaxCounter / 1 * $elapsedTime.TotalSecond }
    else { $estimatedTotalSeconds = $MaxCounter/ $counter * $elapsedTime.TotalSeconds }
    $estimatedTotalSecondsTS = New-TimeSpan -seconds $estimatedTotalSeconds
    $estimatedCompletionTime = $startTime + $estimatedTotalSecondsTS    
    Write-Progress -Activity "Parsing config file ($ProcString%). Estimate completion time $estimatedCompletionTime" -PercentComplete ($Proc)
    $Counter++
    $Configline=$Line.Trim() -replace '\s+',' '
    $ConfigLineArray = $Configline.Split(" ")    
    switch($ConfigLineArray[0]) {
        "config" {
              switch($ConfigLineArray[1]) {
                "area" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ospfarea"                      
                } 
                "distribute-list" {
                    $SUBSection = $True
                    $SUBSectionConfig = "Routerdistributelist"                 
                }    
                "ha-mgmt-interfaces" {
                    $SUBSection = $true
                    $SUBSectionConfig = "HA-MGMTInterfaces"
                }             
                "health-check" {
                    $SUBSection = $True
                    $SUBSectionConfig = "virtualwanlinkhealthcheck"                 
                }                
                "ip-range" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpiprange"
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
                "ospf-interface" {
                    $SUBSection = $True
                    $SUBSectionConfig = "ospfinterface"                    
                }
                "realservers" {
                    $SUBSection = $True
                    $SUBSectionConfig = "VIPrealservers"
                    $RuleRealServer = $rule
                }
                "redistribute" {
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
                "rule" {
                    $SUBSection = $True
                    $SUBSectionConfig = "RouterAccessListRule"                     
                }
                "service" {
                    $SUBSection = $True
                    $SUBSectionConfig = "virtualwanlinkservice"                     
                }
                "firewall" {
                    switch($ConfigLineArray[2]) {
                        "policy" { 
                            $ConfigSection = "ConfigFirewallPolicy"
                            Write-Output "Config firewall policy line found."
                        }
                        "address" { 
                            $ConfigSection = "ConfigFirewallAddress" 
                            Write-Output "Config firewall address line found."
                        }
                        "addrgrp" { 
                            $ConfigSection = "ConfigFirewallAddrgrp" 
                            Write-Output "Config firewall addgrp line found."
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
                    }
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
                        "static" {
                            $ConfigSection = "ConfigRouterStatic"
                            Write-Output "Config router static line found."
                        }
                        "policy" {
                            $ConfigSection = "ConfigRouterPolicy"
                            Write-Output "Config router policy line found."
                        }
                        default {
                            #Router section default (redistribute section)
                            $RouterSection = $ConfigLineArray[2]
                            $ConfigSection = "ConfigRouter$RouterSection"
                            Write-Output "Config router $RouterSection found."
                        }
                    }
                }
                "system" {
                    switch($ConfigLineArray[2]) {
                        "dhcp" {
                            $ConfigSection = "ConfigSystemDHCP"
                            Write-Output "Config system dhcp line found."
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
                    switch($ConfigLineArray[2]) {
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
                    }
                }        
                "vdom" { $ConfigSection = "ConfigVDOM" }
                "vpn" {
                    switch($ConfigLineArray[3]) {
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
            }
        }
        "edit" {
            if ($ConfigSection) { 
                $Value = CleanupLine $ConfigLine
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
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
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterface = InitSystemHAMGMTInterfaces
                            $IDNumber = GetNumber($Value)
                            $HAMGMTInterface | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
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
                        "ospfinterface" {
                            $OSPFInterface = InitRouterOSPFInterface
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name "Interface" -Value $Value -forc
                        }
                        "RouterAccessListRule" {
                            $RouterAccessList = InitRouterAccessList
                            $RouterAccessList | Add-Member -MemberType NoteProperty -Name "Name" -Value $RouterAccessListName -force
                            $IDNumber = GetNumber($Value)
                            $RouterAccessList | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "VIPrealservers" {
                            #If the rule is copied then there will be 2 lines with the same data in the array
                            #Using the function CopyArrayMember to create a new $rule with data that is in the old rule
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
                        "virtualwanlinkservice"{
                            $VirtualWanLinkService = InitVirtualWanLinkService
                            $IDNumber = GetNumber($Value)
                            $VirtualWanLinkService | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force                            
                        }
                    }
                }
                else {
                    switch ($ConfigSection) {             
                        "ConfigSystemDHCP" {
                            $rule = InitSystemDHCP
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber  -force
                        }                          
                        "ConfigVDOM" {
                            #look for vdom name 
                            $vdom = $ConfigLineArray[1]
                            #Write-Output "vdom $vdom found."
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
                        "ConfigFirewallAddrgrp" {
                            $rule = InitFirewallAddressGroup
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        } 
                        "ConfigFirwallShaperPerIPShaper" {
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
                        "ConfigRouterPolicy" {
                            $rule = InitRouterPolicy
                            $IDNumber = GetNumber($Value)
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $IDNumber -force
                        }
                        "ConfigSystemLinkmonitor" {
                            $rule = InitSystemLinkMonitor
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigSystemInterface" {
                            $rule = InitSytemInterface
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigSystemZone" {
                            $rule = InitSytemInterface
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
                        "Configvpnipsecphase1" {
                            $rule = Initvpnipsecphase1
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "Configvpnipsecphase2" {
                            $rule = Initvpnipsecphase2
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        } 
                    }
                }
            }
        }
        "set" {
            if ($ConfigSection) {
                $Value = CleanupLine $ConfigLine
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
                        "dhcpiprange" {
                            $DHCPRange | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "dhcpoptions" {
                            $DHCPOptions | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force 
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddress | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }  
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterface | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterDistributeList" {
                            $RouterDistibuteList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterNeighbor" {
                            $RouterNeighbor | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterNetwork" {
                            $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3]
                            $RouterNetwork |  Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterRedistribute" {
                            $RouterRedistribute | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force                            
                        }
                        "ospfinterface" {
                            $OSPFInterface | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                        }
                        "RouterAccessListRule" {
                            if ($ConfigLineArray[1] -eq "prefix") {
                                if ($ConfigLineArray[2] -eq "any") { $Value = "0.0.0.0/0" } 
                                else { $Value = $Value = GetSubnetCIDR $ConfigLineArray[2] $ConfigLineArray[3] }
                                $RouterAccessList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -forc
                            }
                            else { $RouterAccessList | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force }
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
                }
                else {
                    switch ($ConfigSection) {   
                        "ConfigSystemDHCP" {  
                            $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force 
                        }  
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
                        "Configvpnipsecphase1" {
                            #if ($ConfigLineArray[1] -ne "psksecret") { 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            #}
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
                        "ConfigRouterOSPF" {
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
                    } 
                }       
            }
        }
        "next" {
            if ($ConfigSection) {   
                if ($SUBSection) {
                    Switch ($SUBSectionConfig) {
                        "dhcpiprange" {
                            $DHCPRangeArray += $DHCPRange
                        }
                        "dhcpoptions" {
                            $DHCPOptionsArray += $DHCPOptions
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddressArray += $DHCPReservedAddress
                        } 
                        "HA-MGMTInterfaces" {
                            $HAMGMTInterfaceArray += $HAMGMTInterface
                        }
                        "RouterDistibuteList" {
                            $RouterDistibuteListArray += $RouterDistibuteList
                        }
                        "RouterNeighbor" {
                            #Check if the new value is not the same as the OLD (config has two concecutive next statements)
                            if ($RouterNeighbor.IP -ne $RouterNeighborOLD.IP) {
                                $RouterNeighborOLD = $RouterNeighbor
                                $RouterNeighborArray += $RouterNeighbor
                            }   
                        }
                        "RouterNetwork" {
                            $RouterNetworkArray += $RouterNetwork
                        }
                        "ospfinterface" {
                            $RouterInterfaceArray += $OSPFInterface
                        }
                        "RouterAccessListRule" {
                            $RouterAccessListArray += $RouterAccessList
                        }
                        "virtualwanlinkhealthcheck" {
                            $VirtualWanLinkHealthCheckArray += $VirtualWanLinkHealthCheck
                        }
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMemberArray += $VirtualWanLinkMember
                        }
                        "virtualwanlinkservice" {
                            $VirtualWanLinkServiceArray += $VirtualWanLinkService
                        }     
                        default {
                            $rulelist += $rule
                        }                   
                    }
                }
                else {   
                    switch ($ConfigSection) {
                        "ConfigSystemDHCP" {
                            CreateExcelSheetDHCP
                            $DHCPRangeArray = @()
                            $DHCPOptionsArray = @()
                            $DHCPReservedAddressArray = @()
                        }
                        "ConfigFirewallVIP"  {
                            if ($SUBSectionConfig -ne "VIPRealservers") {
                                $ruleList += $rule 
                            }
                        }
                        Default { $ruleList += $rule }
                    }   
                }
            }
        }                 
        "end" {
            if ($SUBSection) {
                $SUBSection = $False
                switch ($ConfigSection) {
                    "routerredistribute" { 
                        $RouterRedistibuteArray += $RouterRedistribute 
                    }
                    "VIPRealservers" {
                        $ruleList += $rule
                    } 
                } 
            }
            else {            
                if ($ConfigSection) {
                    if ($vdom) { 
                        $VdomName = "-" + $vdom
                    }
                    else { $VdomName = "" }
                    switch ($ConfigSection) {
                        "ConfigFirewallPolicy" { 
                            $rulelist = $rulelist | Sort-Object ID
                            CreateExcelSheet "IPV4-Rules$VdomName" $rulelist  
                        }
                        "ConfigFirewallAddress" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV4-Addresses$VdomName" $rulelist  
                        }
                        "ConfigFirewallAddrgrp" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPV4-AddressGRP$VdomName" $rulelist  
                        }
                        "ConfigFirewallIPpool" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "IPpool$VdomName" $ruleList
                        }
                        "ConfigFirewallLdbMonitor" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Ldb-Monitor$VdomName" $ruleList                            
                        }
                        "ConfigFirewallServiceCategory" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services-Category$VdomName" $rulelist  
                        }
                        "ConfigFirewallServiceCustom" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services$VdomName" $rulelist  
                        }
                        "ConfigFirewallServiceGroup" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "Services-Group$VdomName" $rulelist  
                        }
                        "ConfigFirwallShaperPerIPShaper" {
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
                        "ConfigRouterAccessList" {
                            $RouterAccessListArray = $RouterAccessListArray | Sort-Object Name,ID
                            CreateExcelSheet "Router-AccesList$vdomName" $RouterAccessListArray
                        }
                        "ConfigRouter$RouterSection" {
                            switch ($ConfigSection) {
                                "ConfigRouterStatic" { 
                                    $rulelist = $rulelist | Sort-Object ID
                                    CreateExcelSheet "Router-Static$VdomName" $rulelist 
                                }
                                "ConfigRouterBGP" {
                                    CreateExcelSheetBGP                                    
                                }
                                "ConfigRouterOSPF" {
                                    CreateExcelSheetOSPF                               
                                }
                                "ConfigRouterPolicy" { 
                                    $rulelist = $rulelist | Sort-Object ID
                                    CreateExcelSheet "Router-Policy$VdomName" $rulelist 
                                }
                                #default {
                                #    CreateExcelSheet "Router-$RouterSection$VdomName" $RouterRedistibuteArray                                
                                #}
                            } 
                            $RouterAccessListArray = @()
                            $RouterRedistibuteArray = @()  
                        }
                        "ConfigSystemGlobal" {
                            UpdateFirstSheet $rule
                            $UsedRange = $FirstSheet.usedRange                  
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
                            CreateExcelSheet "Link-Monitor$VdomName" $rulelist                         
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
                            CreateExcelSheet "User-Group$VdomName" $ruleList
                        }
                        "ConfigUserLdap" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "User-Ldap$VdomName" $rulelist                             
                        }
                        "ConfigUserLocal" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "User-Local$VdomName" $rulelist                         
                        }
                        "Configvpnipsecphase1" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN-Phase1$VdomName" $rulelist 
                        }
                        "Configvpnipsecphase2" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN-Phase2$VdomName" $rulelist 
                        }
                    }        
                    $ConfigSection = $null
                    $ruleList = @()
                    Write-Output "Section done."
                }
            }
        }    
    }
}    
#make sure that the first sheet that is opened by Excel is the global sheet.
$FirstSheet.Activate()
Write-Output "Writing Excelfile $ExcelFullFilePad.xls"
$workbook.SaveAs($ExcelFullFilePad)
$excel.Quit()
#[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
$elapsedTime = $(get-date) - $startTime
$Minutes = $elapsedTime.Minutes
$Seconds = $elapsedTime.Seconds
Write-Output "Script done in $Minutes Minute(s) and $Seconds Second(s)."