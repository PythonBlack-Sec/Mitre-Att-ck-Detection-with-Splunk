## Technique Description - Jorin DELETE

Registry keys play a virtal role and as such are a main target to adversaries looking to obtian persistence within a system. As such the permissions to access and modify them should be controlled but there are tool that can modify them if the permissions are not set appropriately. Some of those tools are as follows: controller, sc.exe, PowerShell and Reg.


## Execution (test script used)

**Potential Attacks:** ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config

## Detection -- Visibility -- Filter/ Correlation Rule

**Filter:** ("Name='CommandLine'>ipconfig  /all" OR "Name='CommandLine'>ipconfig") OR ("netsh.exe" interface ip show"" OR "ARP.EXE" OR "nbtstat.exe" OR "net1 config")
