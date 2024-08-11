
sc create mydumbedr type=kernel binpath=C:\Users\hacker\source\repos\mydumbedr\x64\Debug\MyDumbEDRDriver\MyDumbEDRDriver.sys
sc start mydumbedr

echo EDR's running, press any key to stop it
pause

sc stop mydumbedr
sc delete mydumbedr
