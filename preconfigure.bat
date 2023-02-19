:: This is a comment
@echo off
:: Preconfigure script for Windows

echo === Finding Git...
git --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo OK
) else (
  echo You need to install GIT
  exit /b 1
)
git pull

REM vs uses HOST_TARGET syntax, so: x86_amd64 means 32bit compiler for 64bit target
REM: Hosts: x86 amd64 x64
REM: Targets: x86 amd64 x64 arm arm64
if "%*" == "x86" (
  set VSARCH=x86
) ELSE (
  set VSARCH=x86_amd64
)

echo === Finding Visual Studio...
cl --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else (
  if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" (
    echo "Found 2022 Enterprise edition"
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else (
    if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community" (
      echo "Found 2022 Community edition"
      call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
    ) else (
      if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
        echo "Found 2019 community edition"
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
      ) else (
        if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
          echo "Found 2019 Enterprise edition"
          call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
        ) else (
          if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
            echo "Found 2019 Professional edition"
            call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
          ) else (
            if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
              echo "Found 2019 BuildTools"
              call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
            ) else (
              echo "Not Found"
              exit /b 1
            )
          )
        )
      )
    )
  )
)

echo Now you can run 'configure'
cmd
