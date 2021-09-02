<#
Realtime  11000   24 
hight       1101   13
AboveNomal  1010   10
Normal      1000   8
BlowNormal  0110   6
Low          100   4
#>

write-host "Import Module" -ForegroundColor Green

#Import-Module $PSScriptRoot\bin\Debug\NITPerfCmdLets.dll -Force
Import-Module $PSScriptRoot\bin\Release\NITPerfCmdLets.dll -Force

break

write-host "Test-Module" -ForegroundColor Green

Get-Command -module NITPerfCmdLets



#Get-Help Get-NITPerf 

$a = Measure-Command{
	$List = Get-NITPerf -UpdateTime 200
}

$a

$List | ft
$List | where-Object -Property PercentProcessorTime -GT 0 | ft

<#
$a = Measure-Command{
	$List = Get-Process
}

$a

#>


$List.proclist.Count

 

write-host "Press Enter" -ForegroundColor Green
[System.Console]::ReadKey()