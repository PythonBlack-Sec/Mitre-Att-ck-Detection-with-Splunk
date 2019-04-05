## Technique Description

Adversaries will likely look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbtstat, and route.


## Execution (test script used)

**Potential Attacks:** cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe

## Detection -- Visibility -- Filter/ Correlation Rule

**Filter:** (source="wineventlog:microsoft-windows-sysmon/operational" OR source="wineventlog:microsoft-windows-powershell/operational" OR "cmd.exe") AND cmd.exe /c copy AND NOT ("UserID='S-1-5-21domain'")


