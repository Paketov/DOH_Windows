cd /D "%~dp0"

copy "%~dp0x64\Release\DOH_Windows.dll" "%~dp0..\..\bin\DOH_Windows64.dll"
copy "%~dp0Release\DOH_Windows.dll" "%~dp0..\..\bin\DOH_Windows32.dll"
