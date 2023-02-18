@echo off
setlocal EnableDelayedExpansion
set frida_version=16.0.9
if "%PLATFORM%" == "x64" (set frida_os_arch=x86_64) else (set frida_os_arch=x86)
set DEBUG=/O2

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

for /f %%i in ('radare2 -qv') do set R2V=%%i
for /f %%i in ('radare2 -H R2_USER_PLUGINS') do set R2_PLUGDIR=%%i

echo Using R2_BASE: %R2_BASE%
echo Radare2 Version: %R2V%
set R2_INC=/I"%R2_BASE%\include" /I"%R2_BASE%\include\libr" /I"%R2_BASE%\include\libr\sdb"
set R2=%R2_BASE%\bin\radare2.exe
for %%i in (%*) do (
	if "%%i"=="debug" (set DEBUG=/Z7)
	if "%%i"=="install" (set INSTALL=1)
)

echo Copying custom header for Windows
copy config.h.w64 config.h

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

echo Building r2frida-compile...
cl %DEBUG% /MT /nologo /Gy /DFRIDA_VERSION_STRING="!frida_version!" %R2_INC% /I"%cd%" /I"%cd%\frida" "%cd%\frida\frida-core.lib" "%R2_BASE%\lib\*.lib" r2frida-compile.c
cd ..

echo Building the Agent...
del src\_agent.js
src\r2frida-compile.exe -Sc src\agent\index.ts > src\_agent.js
echo Creating the header...
del src\_agent.js.hex
%R2_BASE%\bin\radare2 -nfqc "pcq~0x" src\_agent.js > src\_agent.js.hex
powershell -command "Get-Content .\src\_agent.js.hex | Select-String -Exclude Start 0x" > src\_agent.h
DEL src\_agent.js.hex

echo Compiling the Plugin...
cd src
cl %DEBUG% /MT /nologo /LD /Gy /D_USRDLL /D_WINDLL /DFRIDA_VERSION_STRING="""!frida_version!""" io_frida.c %R2_INC% /I"%cd%" /I"%cd%\frida" "%cd%\frida\frida-core.lib" "%R2_BASE%\lib\*.lib" || (echo Compilation Failed & exit /b 1)
cd ..

echo Distribution Zip...
del r2frida-%R2V%-w64.zip
rd /q /s r2frida-%R2V%-w64
md r2frida-%R2V%-w64
copy README.md r2frida-%R2V%-w64\
copy src\r2frida-compile.exe r2frida-%R2V%-w64\
copy src\io_frida.dll r2frida-%R2V%-w64\
REM copy src\io_frida.pdb r2frida-%R2V%-w64\
copy install.bat r2frida-%R2V%-w64\
powershell -command "Compress-Archive -Path r2frida-%R2V%-w64 -DestinationPath r2frida-%R2V%-w64.zip"

.\install.bat
