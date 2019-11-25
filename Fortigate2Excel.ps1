<#
.SYNOPSIS
Parse-FortiGateRules parses rules from a FortiGate device into a CSV file.
.DESCRIPTION
The Parse-FortiGateRules reads a FortiGate config file and pulls out the rules for each VDOM in the file into a CSV.
.PARAMETER fortigateConfig
[REQUIRED] This is the path to the FortiGate config file
.PARAMETER utf8
[OPTIONAL] This is a switch to parse a config in UTF8 formatting. Optional.
.EXAMPLE
.\Parse-FortiGateRules.ps1 -fortiGateConfig "c:\temp\config.conf"
Parses a FortiGate config file and places the CSV file in the same folder where the config was found.
.NOTES
Author: Drew Hjelm (@drewhjelm)
Adapted by : Xander Angenent 
Last Modified: 10/29/19
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
    $InitRule | Add-Member -type NoteProperty -name Members -Value ""
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
    $InitRule | Add-Member -type NoteProperty -name nat -Value ""
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
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
Function InitFirewallServiceGroup {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name Member -Value ""
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
Function InitSystemHA {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Group-Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name mode -Value ""
    $InitRule | Add-Member -type NoteProperty -name hbdev -Value ""
    $InitRule | Add-Member -type NoteProperty -name override -Value ""
    $InitRule | Add-Member -type NoteProperty -name priority -Value ""
    $InitRule | Add-Member -type NoteProperty -name session-pickup -Value ""
    $InitRule | Add-Member -type NoteProperty -name monitor -Value ""
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
    return $InitRule
}
Function InitSystemVirtualWanLink {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name status -Value ""
    $InitRule | Add-Member -type NoteProperty -name load-balance-mode -Value ""
    return $InitRule
}
Function InitVirtualWanLinkMember {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name ID -Value ""    
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name weight -Value ""
    return $InitRule   
}
Function InitVirtualWanLinkHealthCheck {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""    
    $InitRule | Add-Member -type NoteProperty -name server -Value ""
    $InitRule | Add-Member -type NoteProperty -name members -Value ""
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
Function Initvpnipsecphase1 {
    $InitRule = New-Object System.Object;
    $InitRule | Add-Member -type NoteProperty -name Name -Value ""
    $InitRule | Add-Member -type NoteProperty -name type -Value ""
    $InitRule | Add-Member -type NoteProperty -name interface -Value ""
    $InitRule | Add-Member -type NoteProperty -name peertype -Value ""
    $InitRule | Add-Member -type NoteProperty -name proposal -Value ""
    $InitRule | Add-Member -type NoteProperty -name comments -Value ""
    $InitRule | Add-Member -type NoteProperty -name dhgrp -Value ""
    #default ikeversion = 1
    $InitRule | Add-Member -type NoteProperty -name ikeversion -Value "1"
    $InitRule | Add-Member -type NoteProperty -name nattraversal -Value ""
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
    #psksecret not in export
    return $InitRule
}
Function Initvpnipsecphase2 {
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
    $InitRule | Add-Member -type NoteProperty -name keepalive -Value ""
    $InitRule | Add-Member -type NoteProperty -name pfs -Value ""
    return $InitRule
}
Function CleanupLine ($LineToCleanUp) {
    $LineToCleanUp = $LineToCleanUp.TrimStart()
    $LineToCleanUpArray = $LineToCleanUp.Split('`"')
    if ($LineToCleanUpArray[1]) {
     $i=1
     $ReturnValue = $null
     DO {
      if ($LineToCleanUpArray[$i] -ne " ") {
       if ($ReturnValue) {
        $ReturnValue = $ReturnValue + "," + $LineToCleanUpArray[$i]
       }
       else { $ReturnValue = $LineToCleanUpArray[$i]}
      }
      $i++
      } While ($i -le $LineToCleanUpArray.Count-2)
    }
    else { 
     $LineToCleanUpArray = $LineToCleanUp.Split(' ')
     if ($LineToCleanUpArray.Count -ge 8) {
       $i=2
       $ReturnValue = $null
       DO {
        if ($LineToCleanUpArray[$i] -ne " ") {
         if ($ReturnValue) {
          $ReturnValue = $ReturnValue + "," + $LineToCleanUpArray[$i]
         }
         else { $ReturnValue = $LineToCleanUpArray[$i]}
        }
        $i++
       } While ($i -le $LineToCleanUpArray.Count-1)
     }
     else { $ReturnValue = $LineToCleanUpArray[$LineToCleanUpArray.Count-1] }
    }
    return $ReturnValue
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
Function CreateExcelSheet ($SheetName, $SheetArray) {
    if ($SheetArray) {
        $row = 1
        $Sheet = $workbook.Worksheets.Add()
        $Sheet.Name = $SheetName
        $Column=1
        $NoteProperties = $SheetArray | get-member -Type NoteProperty
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
        }
        $Row++
        foreach ($rule in $SheetArray) {
            $Column=1
            #$NoteProperties = $rulelist | get-member -Type NoteProperty
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $Rule.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }                      
            $row++
        }    
        #Use autoFit to expand the colums
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
    $NoteProperties = $rule | get-member -Type NoteProperty
    foreach ($Noteproperty in $NoteProperties) {
        $excel.cells.item($row,$Column) = $Noteproperty.Name
        $Column++
    }
    $Column=1
    $Row++
    foreach ($Noteproperty in $NoteProperties) {
        $PropertyString = [string]$NoteProperty.Name
        $Value = $Rule.$PropertyString
        $excel.cells.item($row,$Column) = $Value
        $Column++
    }    
    #Normal DHCP options done  
    if ($DHCPOptionsArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Extra DHCP options"
        ChangeFontExcelCell $Sheet $row $Column
        $row++        
        $NoteProperties = $DHCPOptionsArray | get-member -Type NoteProperty
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
         }
        $row++      
        Foreach ($DHCPOptions in $DHCPOptionsArray) {
            $Column=1 
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $DHCPOptions.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }                      
            $row++
        }
    }
    #Add IP ranges
    $row++ 
    $Column=1
    $excel.cells.item($row,$Column) = "DHCP Range"
    ChangeFontExcelCell $Sheet $row $Column
    $row++
    $NoteProperties = $DHCPRangeArray | get-member -Type NoteProperty  
    foreach ($Noteproperty in $NoteProperties) {
        $excel.cells.item($row,$Column) = $Noteproperty.Name
        $Column++
    }
    $row++  
    $DHCPRangeArray = $DHCPRangeArray | Sort-Object ID   
    Foreach ($DHCPRange in $DHCPRangeArray) {
        $Column=1 
        foreach ($Noteproperty in $NoteProperties) {
            $PropertyString = [string]$NoteProperty.Name
            $Value = $DHCPRange.$PropertyString
            $excel.cells.item($row,$Column) = $Value
            $Column++
        }                      
        $row++
    }    
    #Add reserved address
    $row++ 
    $Column=1
    if ($DHCPReservedAddressArray) {
        $excel.cells.item($row,$Column) = "Reserved Addresses"
        ChangeFontExcelCell $Sheet $row $Column
        $row++           
        $NoteProperties = $DHCPReservedAddressArray | get-member -Type NoteProperty  
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
        }
        $row++   
        $DHCPReservedAddressArray = $DHCPReservedAddressArray | Sort-Object ID    
        Foreach ($DHCPReservedAddress in $DHCPReservedAddressArray) {
            $Column=1
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $DHCPReservedAddress.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }                      
            $row++
        }
    }     
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null    
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
    $NoteProperties = $rule | get-member -Type NoteProperty
    foreach ($Noteproperty in $NoteProperties) {
        $excel.cells.item($row,$Column) = $Noteproperty.Name
        $Column++
    }
    $Column=1
    $Row++
    foreach ($Noteproperty in $NoteProperties) {
        $PropertyString = [string]$NoteProperty.Name
        $Value = $Rule.$PropertyString
        $excel.cells.item($row,$Column) = $Value
        $Column++
    }
    if ($VirtualWanLinkMemberArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN members"
        ChangeFontExcelCell $Sheet $row $Column
        $row++        
        $NoteProperties = $VirtualWanLinkMemberArray | get-member -Type NoteProperty
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
         }
        $row++      
        Foreach ($VirtualWanLinkMember in $VirtualWanLinkMemberArray) {
            $Column=1 
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $VirtualWanLinkMember.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $excel.cells.item($row,$Column).numberformat = "@"                 
                $Column++
            }                      
            $row++
        }
    }  
    if ($VirtualWanLinkHealthCheckArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN healtcheck"
        ChangeFontExcelCell $Sheet $row $Column
        $row++        
        $NoteProperties = $VirtualWanLinkHealthCheckArray | get-member -Type NoteProperty
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
         }
        $row++      
        Foreach ($VirtualWanLinkHealthCheck in $VirtualWanLinkHealthCheckArray) {
            $Column=1 
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $VirtualWanLinkHealthCheck.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $excel.cells.item($row,$Column).numberformat = "@"                
                $Column++
            }                      
            $row++
        }
    }   
    if ($VirtualWanLinkServiceArray) {                
        $row++   
        $Column=1
        $excel.cells.item($row,$Column) = "Link WAN service"
        ChangeFontExcelCell $Sheet $row $Column
        $row++        
        $NoteProperties = $VirtualWanLinkServiceArray | get-member -Type NoteProperty
        foreach ($Noteproperty in $NoteProperties) {
            $excel.cells.item($row,$Column) = $Noteproperty.Name
            $Column++
         }
        $row++      
        Foreach ($VirtualWanLinkService in $VirtualWanLinkServiceArray) {
            $Column=1 
            foreach ($Noteproperty in $NoteProperties) {
                $PropertyString = [string]$NoteProperty.Name
                $Value = $VirtualWanLinkService.$PropertyString
                $excel.cells.item($row,$Column) = $Value
                $Column++
            }                      
            $row++
        }
    }      
    $UsedRange = $Sheet.usedRange                  
    $UsedRange.EntireColumn.AutoFit() | Out-Null                  
}
if (!( Test-Path "$fortigateConfig" )) {
    Write-Output "[!] ERROR: Could not find FortiGate config file at $fortigateConfig."
    exit 1
   }

#$StopWatch = [system.diagnostics.stopwatch]::StartNew()
$startTime = get-date 
Clear-Host
Write-Output "Started script"
#Clear 5 additional lines for the progress bar
$I=0
DO {
    Write-output ""
    $I++
} While ($i -le 4)
$loadedConfig = Get-Content $fortigateConfig
$Counter=0
#default values these are getting over written when they are changed
$AdminSport = "443"
#End default values
$MaxCounter=$loadedConfig.count
$ruleList = @()
$date = Get-Date -Format yyyyMMddHHmm
$workingFolder = Split-Path $fortigateConfig;
$fileName = Split-Path $fortigateConfig -Leaf;
$fileName = (Get-Item $fortigateConfig).Basename
$configdateArray=$Filename.Split("_")
$configdate = $configdateArray[$configdateArray.Count-2] + $configdateArray[$configdateArray.Count-1]
$ExcelFullFilePad = "$workingFolder\$fileName"
$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false
$workbook = $excel.Workbooks.Add()
$FirstSheet = $workbook.Worksheets.Item(1) 
$FirstSheet.Name = $FileName
$FirstSheet.Cells.Item(1,1)= 'Fortigate Configuration'
$MergeCells = $FirstSheet.Range("A1:G1")
$MergeCells.Select()
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
$DHCPRangeArray = @()
$DHCPOptionsArray = @()
$DHCPReservedAddressArray = @()
$VirtualWanLinkMemberArray = @()
$VirtualWanLinkHealthCheckArray = @()
$VirtualWanLinkServiceArray = @()
foreach ($Line in $loadedConfig) {
    $Proc = $Counter/$MaxCounter*100
    $elapsedTime = $(get-date) - $startTime 
    if ($Counter -eq 0) { $estimatedTotalSeconds = $MaxCounter/ 1 * $elapsedTime.TotalSecond }
    else { $estimatedTotalSeconds = $MaxCounter/ $counter * $elapsedTime.TotalSeconds }
    $estimatedTotalSecondsTS = New-TimeSpan -seconds $estimatedTotalSeconds
    $estimatedCompletionTime = $startTime + $estimatedTotalSecondsTS    
    Write-Progress -Activity "Parsing config file. Estimate completion time $estimatedCompletionTime" -PercentComplete ($Proc)
    $Counter++
    $Configline=$Line.Trim() -replace '\s+',' '
    $ConfigLineArray = $Configline.Split(" ")    
    switch($ConfigLineArray[0]) {
        "config" {
            switch($ConfigLineArray[1]) {
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
                "options" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpoptions"
                }
                "reserved-address" {
                    $SUBSection = $True
                    $SUBSectionConfig = "dhcpreservedaddress"                 
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
                        "vip" {
                            $ConfigSection = "ConfigFirewallVIP"
                            Write-Output "Config firewall vip line found."
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
                            $rule = InitSystemLinkMonitor
                        }
                        "virtual-wan-link" {
                            $ConfigSection = "ConfigSystemVirtualWanLink"
                            Write-Output "Config system virtual-wan-link line found."                            
                            $rule = InitSystemVirtualWanLink
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
                "router" {
                    switch($ConfigLineArray[2]) {
                        "static" {
                            $ConfigSection = "ConfigRouterStatic"
                            Write-Output "Config router static line found."
                        }
                        "policy" {
                            $ConfigSection = "ConfigRouterPolicy"
                            Write-Output "Config router policy line found."
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
                            $DHCPRange | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "dhcpoptions" {
                            $DHCPOptions = InitDHCPOptions
                            $DHCPOptions | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "dhcpreservedaddress" {
                            $DHCPReservedAddress = InitDHCPReservedAddress
                            $DHCPReservedAddress | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "virtualwanlinkhealthcheck" {
                            $VirtualWanLinkHealthCheck = InitVirtualWanLinkHealthCheck
                            $VirtualWanLinkHealthCheck | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                            #$Value
                            #$VirtualWanLinkHealthCheck
                        }                        
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMember = InitVirtualWanLinkMember
                            $VirtualWanLinkMember | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "virtualwanlinkservice"{
                            $VirtualWanLinkService = InitVirtualWanLinkService
                            $VirtualWanLinkService | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force                            
                        }
                    }
                }
                else {
                    switch ($ConfigSection) {             
                        "ConfigSystemDHCP" {
                            $rule = InitSystemDHCP
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }                          
                        "ConfigVDOM" {
                            #look for vdom name 
                            $vdom = $ConfigLineArray[1]
                            #Write-Output "vdom $vdom found."
                            $ConfigSection = $null
                            break
                        }
                        "ConfigFirewallIPpool" {
                            $rule = InitFirewallIPpool
                            $rule | Add-Member -MemberType NoteProperty -Name Name -Value $Value -force
                        }
                        "ConfigFirewallPolicy" {
                            $rule = InitFirewallRule
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "ConfigFirewallAddress" {
                            $rule = InitFirewallAddress
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        }
                        "ConfigFirewallAddrgrp" {
                            $rule = InitFirewallAddressGroup
                            $rule | Add-Member -MemberType NoteProperty -Name "Name" -Value $Value -force
                        } 
                        "ConfigSystemInterface" {
                            $rule = InitSytemInterface
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
                        "ConfigRouterStatic" {
                            $rule = InitRouterStatic
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
                        }
                        "ConfigRouterPolicy" {
                            $rule = InitRouterPolicy
                            $rule | Add-Member -MemberType NoteProperty -Name "ID" -Value $Value -force
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
                            if ($ConfigLineArray[1] -ne "psksecret") { 
                                $rule | Add-Member -MemberType NoteProperty -Name $ConfigLineArray[1] -Value $Value -force
                            }
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
                        "ConfigSystemGlobal" {
                            Switch ($ConfigLineArray[1]) {
                                "admin-sport" {
                                    $AdminSport = $Value 
                                }
                                "admintimeout" {
                                    $AdminTimeout= $Value 
                                }
                                "hostname" {
                                    $Hostname = $Value 
                                }
                                "timezone" {
                                    $TimeZone = $Value 
                                }
                                "admin-server-cert" {
                                    $AdminCert = $Value
                                }
                            }
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
                        "virtualwanlinkhealthcheck" {
                            $VirtualWanLinkHealthCheckArray += $VirtualWanLinkHealthCheck
                        }
                        "virtualwanlinkmember" {
                            $VirtualWanLinkMemberArray += $VirtualWanLinkMember
                        }
                        "virtualwanlinkservice" {
                            $VirtualWanLinkServiceArray += $VirtualWanLinkService
                        }                        
                    }
                }
                else {                
                    if ($ConfigSection -eq "ConfigSystemDHCP") {
                        CreateExcelSheetDHCP
                        $DHCPRangeArray = @()
                        $DHCPOptionsArray = @()
                        $DHCPReservedAddressArray = @()
                    }
                    else { $ruleList += $rule }
                }
            }
        }                 
        "end" {
            if ($SUBSection) {
                $SUBSection = $False
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
                        "ConfigSystemGlobal" {
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
                            $FirstSheet.Cells.Item(6,1) = 'ManagementPort'
                            $FirstSheet.Cells.Item(6,2) = $AdminSport
                            $FirstSheet.Cells.Item(7,1) = 'Certificate'
                            $FirstSheet.Cells.Item(7,2) = $AdminCert
                            $FirstSheet.Cells.Item(8,1) = 'TimeOut'
                            $FirstSheet.Cells.Item(8,2) = $AdminTimeout
                            $FirstSheet.Cells.Item(9,1) = 'Hostname'
                            $FirstSheet.Cells.Item(9,2) = $Hostname
                            $FirstSheet.Cells.Item(10,1) = 'TimeZone'
                            $FirstSheet.Cells.Item(10,2) = $TimeZone
                            $UsedRange = $FirstSheet.usedRange                  
                            $UsedRange.EntireColumn.AutoFit() | Out-Null
                        }
                        "ConfigSystemHA" {
                            CreateExcelSheet "HA$VdomName" $rule   
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
                        "ConfigRouterStatic" { 
                            $rulelist = $rulelist | Sort-Object ID
                            CreateExcelSheet "Router-Static$VdomName" $rulelist 
                        }
                        "ConfigRouterPolicy" { 
                            $rulelist = $rulelist | Sort-Object ID
                            CreateExcelSheet "Router-Policy$VdomName" $rulelist 
                        }
                        "Configvpnipsecphase1" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN-Phase1$VdomName" $rulelist 
                        }
                        "Configvpnipsecphase2" { 
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VPN-Phase2$VdomName" $rulelist 
                        }
                        "ConfigFirewallVIP" {
                            $rulelist = $rulelist | Sort-Object Name
                            CreateExcelSheet "VIP$VdomName" $rulelist
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
$elapsedTime = $(get-date) - $startTime
$Minutes = $elapsedTime.Minutes
$Seconds = $elapsedTime.Seconds
Write-Output "Script done in $Minutes Minute(s) and $Seconds Second(s)."