# NITProcessTools

This is a hardware related PowerShell module to determine the percentage CPU usage for processes. WMI often causes a high load on servers and the Get-Process command provides this data.

```powershell
#Copy Module zu a module folder
import-module NITProcessTools -force
Get-Command -module NITProcessTools 

CommandType     Name                                               Version    Source                                                                                                          
-----------     ----                                               -------    ------                                                                                                          
Function        Export-NITProcessCPULoad                           1.0        NITProcessTools                                                                                                 
Cmdlet          Get-NITProcessCpuLoad                              1.0        NITProcessTools                                                                                                 

(Get-NITProcessCpuLoad).ProcessList | Sort-Object -Property PercentProcessorTime -Descending | ft

   ID UserName Domain BasePriority PercentProcessorTime UsedMemory ThreadCount  UpTime ExeName                         ParentPID
   -- -------- ------ ------------ -------------------- ---------- -----------  ------ -------                         ---------
 3948 Andreas  GOBI              8     5,88235294117647 3072200704          23   11617 vmware-vmx.exe                       5556
13500 SYSTEM                     4                    0  100352000          18 1563265 msedge.exe                           4496
23208 Andreas  GOBI              8                    0    8921088           2 1580221 RuntimeBroker.exe                    1448
22984 SYSTEM                     8                    0   12361728           4 1580415 dllhost.exe                          1448
23392 Andreas  GOBI              8                    0   18460672           4 1580484 RuntimeBroker.exe                    1448

````