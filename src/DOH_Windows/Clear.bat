cd /D "%~dp0"

rmdir /Q /S "%~dp0x64"
rmdir /Q /S "%~dp0Release"
rmdir /Q /S "%~dp0Debug"

rmdir /Q /S "%~dp0DOH_Windows\x64"
rmdir /Q /S "%~dp0DOH_Windows\Release"
rmdir /Q /S "%~dp0DOH_Windows\Debug"

del /Q "%~dp0DOH_Windows.sdf"
del /Q "%~dp0DOH_Windows.VC.db"
