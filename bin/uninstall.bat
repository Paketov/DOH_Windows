if "%1" == "" (
 call "%~dp0__sudo.bat" "%~f0" 1
 goto batExit
)

sc delete DOH_Windows
timeout 2
del /Y "%systemroot%\system32\DOH_Windows.dll"
del /Y "%systemroot%\system32\drivers\etc\doh.txt"

reg delete HKLM\SYSTEM\CurrentControlSet\services\DOH_Windows /va /f

SETLOCAL EnableDelayedExpansion

for /F "skip=3 tokens=3*" %G in ('netsh interface show interface') do ( netsh interface ip set dns "%H" dhcp )

:batExit