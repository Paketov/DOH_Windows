if "%1" == "" (
 call "%~dp0__sudo.bat" "%~f0" 1
 goto batExit
)

IF EXIST "%PROGRAMFILES(X86)%" (set target_dll_name="%~dp0DOH_Windows64.dll") ELSE (set target_dll_name="%~dp0DOH_Windows32.dll")

copy /Y %target_dll_name% "%systemroot%\system32\DOH_Windows.dll"

copy /Y "%~dp0doh.txt" "%systemroot%\system32\drivers\etc\doh.txt"

sc delete DOH_Windows

timeout 2

sc create DOH_Windows binPath= "C:\Windows\system32\svchost.exe -k NetworkService" type= share start= auto

reg add HKLM\SYSTEM\CurrentControlSet\services\DOH_Windows\Parameters /v ServiceDll /t REG_EXPAND_SZ /d %systemroot%\system32\DOH_Windows.dll /f

reg add HKLM\SYSTEM\CurrentControlSet\services\DOH_Windows /v ObjectName /t REG_SZ /d "NT AUTHORITY\NetworkService" /f

rundll32 "%systemroot%\system32\DOH_Windows.dll" InstallService

rem rundll32 "%systemroot%\system32\DOH_Windows.dll" SetFailureActions

sc failure DOH_Windows reset= 30 actions= restart/1000

rem  Enum adapters and set DNS ip 127.0.0.1 to this adapters

SETLOCAL EnableDelayedExpansion

for /F "skip=3 tokens=3*" %G in ('netsh interface show interface') do ( netsh interface ip set dns name="%H" static 127.0.0.1 )

for /F "skip=3 tokens=3*" %G in ('netsh interface show interface') do ( netsh interface ipv6 set dns name="%H" static ::ffff:127.0.0.1 )

:batExit