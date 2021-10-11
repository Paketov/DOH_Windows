@echo off

set t=%1
set t2="%t:"=%"

set t4=
set t5=
:loop
 shift
 if "t5" == "" (
  set t4=%1 
 ) else (
  set t4=%t4% %1
 )
 set t5=1
if not "%~1"=="" goto loop

IF "%t5%"=="" (
 set t3=
) ELSE (
 set t3=%t4:"=" ^&chr(34)^& "%
)

echo Set objShell = CreateObject("Shell.Application") > %temp%\sudo.vbs
echo objShell.ShellExecute %t2%, "%t3%", "", "runas" >> %temp%\sudo.vbs
cscript %temp%\sudo.vbs
