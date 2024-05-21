@echo OFF
setlocal
set "R2V=5.9.2"
echo Checking radare2 %R2V% in PATH...
for /f "delims=" %%i in ('radare2 -qv') do (
	set "CURRENT_R2V=%%i"
)
if "%CURRENT_R2V%"=="%R2V%" (
	echo OK
	endlocal
	exit /b
) else (
	echo radare2 version from path does not match
)
if exist radare2 (
	set "PATH=%CD%\radare2\bin;%PATH%"
	for /f "delims=" %%i in ('radare2 -qv') do (
		set "CURRENT_R2V=%%i"
	)
	if "%CURRENT_R2V%"=="%R2V%" (
		echo OK
		endlocal
		exit /b
	) else (
		echo radare2 version from current directory does not match ( %CURRENT_R2V% )
		del *.zip
		rd/s /q radare2 radare2*.zip
	)
)

REM Stuff
echo Downloading radare2 from release...
set "R2ZIP=https://github.com/radareorg/radare2/releases/download/%R2V%/radare2-%R2V%-w64.zip"
powershell -Command "Invoke-WebRequest -Uri '%R2ZIP%' -OutFile 'radare2-%R2V%.zip'"
echo Extracting ZIP...
powershell -Command "Expand-Archive -Path radare2-%R2V%.zip -DestinationPath '%CD%' -Force"
ren radare2-%R2V%-w64 radare2
for /f "delims=" %%i in ('radare2 -qv') do (
	set "CURRENT_R2V=%%i"
)
if "%CURRENT_R2V%"=="%R2V%" (
	echo OK
	endlocal
	exit /b
) else (
	echo Something went wrong
)
endlocal
exit /b
