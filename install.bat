@echo off
set R2_BASE=""
if exist radare2 (
	set R2_BASE=%CD%\radare2
) else (
	if exist C:\radare2 (
		set R2_BASE=C:\radare2
	) else (
		echo ERROR: Cannot find radare2 in CWD or C:\
		exit /b 1
	)
)
set PATH=%R2_BASE%\bin:%PATH%

for /f %%i in ('%R2_BASE%\bin\radare2 -H R2_USER_PLUGINS') do set R2_PLUGDIR=%%i

echo Installing Plugin into %R2_PLUGDIR%
md "%R2_PLUGDIR%"
echo Copying 'io_frida.dll' to %R2_PLUGDIR%
copy src\io_frida.dll "%R2_PLUGDIR%\io_frida.dll"
REM echo Installing 'io_frida.pdb' to %R2_PLUGDIR%
REM copy src\io_frida.pdb "%R2_PLUGDIR%\io_frida.pdb"
echo Installing 'r2frida-compile.exe' to %R2_BASE%\bin
copy src\r2frida-compile.exe "%R2_BASE%\bin\r2frida-compile.exe"
