~~~~~~~~~~~~~~~~~~~DOH (DNS Over HTTPS) Windows~~~~~~~~~~~~~~~~

This programm install as svchost service(some antiviruses can detect them, you must add DOH_Windows.dll to white list). This service recive UDP DNS pakets and send him to HTTPS servers.
This programm tested on windows 8.1

Installation and use:
	1. For install run bin\install.bat
	2. For config change C:\windows\system32\drivers\etc\doh.txt
	3. Reboot PC
	4. For uninstall run bin\uninstall.bat

Have fun!