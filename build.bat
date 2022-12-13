@echo off
setlocal EnableDelayedExpansion
set R2_BASE=""
set frida_version=16.0.8
if "%PLATFORM%" == "x64" (set frida_os_arch=x86_64) else (set frida_os_arch=x86)
for /f %%i in ('radare2 -H R2_USER_PLUGINS') do set R2_PLUGDIR=%%i
REM for /f %%i in ('where radare2') do set R2_BASE=%%i\..
set R2_BASE=%cd%\radare2
set DEBUG=/O2
set INSTALL=

for /f %%i in ('radare2 -qv') do set R2V=%%i

if not exist %R2_BASE% (
	echo radare2 not found
	set /p R2_BASE="Please enter full path of radare2 installation: "
	set /p R2_PLUGDIR="Please enter full path of radare2 plugin dir (radare2 -H): "
)

echo Using R2_BASE: %R2_BASE%
set R2_INC=/I"%R2_BASE%\include" /I"%R2_BASE%\include\libr" /I"%R2_BASE%\include\libr\sdb"

for %%i in (%*) do (
	if "%%i"=="debug" (set DEBUG=/Z7)
	if "%%i"=="install" (set INSTALL=1)
)

copy config.h.w64 config.h
REM call npm install

cd src

mkdir frida > nul 2>&1
cd frida

set FRIDA_SDK_URL="https://github.com/frida/frida/releases/download/!frida_version!/frida-core-devkit-!frida_version!-windows-!frida_os_arch!.exe"

if not exist ".\frida-core-sdk-!frida_version!-!frida_os_arch!.exe" (
	echo Downloading Frida Core Sdk

	powershell -command "(New-Object System.Net.WebClient).DownloadFile($env:FRIDA_SDK_URL, ""frida-core-sdk.exe-!frida_version!-!frida_os_arch!"")" ^
	|| wget -q --show-progress %FRIDA_SDK_URL% .\frida-core-sdk.exe -O .\frida-core-sdk-!frida_version!-!frida_os_arch!.exe || python -m wget %FRIDA_SDK_URL% -o frida-core-sdk-!frida_version!-!frida_os_arch!.exe

	echo Extracting...
	.\frida-core-sdk-!frida_version!-!frida_os_arch!.exe || (echo Failed to extract & exit /b 1)
)
cd ..
echo Compiling the Compiler...

cl %DEBUG% /MT /nologo /Gy /DFRIDA_VERSION_STRING="!frida_version!" %R2_INC% /I"%cd%" /I"%cd%\frida" "%cd%\frida\frida-core.lib" "%R2_BASE%\lib\*.lib" frida-compile.c
frida-compile.exe agent/index.js > _agent.js
REM type .\_agent.js | xxd -i > .\_agent.h || (echo "xxd not in path?" & exit /b 1)
echo DONE
radare2 -nfqc "pcq~0x" _agent.js > _agent.h
echo HEADER DONE

echo Compiling the Agent...
echo cl %DEBUG% /MT /nologo /LD /Gy /D_USRDLL /D_WINDLL /DFRIDA_VERSION_STRING="!frida_version!" io_frida.c %R2_INC% /I"%cd%" /I"%cd%\frida" "%cd%\frida\frida-core.lib" "%R2_BASE%\lib\*.lib"
cl %DEBUG% /MT /nologo /LD /Gy /D_USRDLL /D_WINDLL /DFRIDA_VERSION_STRING="""!frida_version!""" io_frida.c %R2_INC% /I"%cd%" /I"%cd%\frida" "%cd%\frida\frida-core.lib" "%R2_BASE%\lib\*.lib" || (echo Compilation Failed & exit /b 1)

del ..\r2frida-%R2V%-w64.zip
zip ..\r2frida-%R2V%-w64.zip io_frida.dll
if not "%INSTALL%"=="" (
	echo Installing...
	mkdir "%R2_PLUGDIR%" > nul 2>&1
	echo Copying 'io_frida.dll' to %R2_PLUGDIR%
	copy io_frida.dll "%R2_PLUGDIR%\io_frida.dll"
	if not "%DEBUG%"=="/O2" (
		echo Copying 'io_frida.pdb' to %R2_PLUGDIR%
		cp io_frida.pdb "%R2_PLUGDIR%\io_frida.pdb"
	)
)
