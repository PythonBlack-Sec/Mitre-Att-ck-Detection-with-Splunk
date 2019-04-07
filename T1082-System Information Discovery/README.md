## Technique Description

This technique serves to gain critical information about the a target's system. Such information includes type of operating system, hardware specifications, service packs, and details regarding architecture. 

## Execution (test script used)

**Potential Attacks:** ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config

## Detection -- Visibility -- Filter/ Correlation Rule

**Filter:** ("Name='CommandLine'>ipconfig  /all" OR "Name='CommandLine'>ipconfig") OR ("netsh.exe" interface ip show"" OR "ARP.EXE" OR "nbtstat.exe" OR "net1 config")
