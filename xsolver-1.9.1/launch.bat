@echo off
setlocal
where wsl.exe >nul 2>nul
if errorlevel 1 (
  echo WSL2 with Ubuntu is required.
  pause
  exit /b 2
)
set "WSL_ROOT="
for /f "usebackq delims=" %%I in (`wsl.exe --exec wslpath -a "%~dp0."`) do set "WSL_ROOT=%%I"
if not defined WSL_ROOT (
  echo Could not locate the package in WSL.
  pause
  exit /b 2
)
if "%~1"=="" goto ui
set "WSL_TARGET="
for /f "usebackq delims=" %%I in (`wsl.exe --exec wslpath -a "%~f1"`) do set "WSL_TARGET=%%I"
if not defined WSL_TARGET (
  echo Could not convert the target path.
  pause
  exit /b 2
)
wsl.exe --cd "%WSL_ROOT%" --exec bash ./launch.sh solve "%WSL_TARGET%"
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
:ui
wsl.exe --cd "%WSL_ROOT%" --exec bash ./launch.sh tui "%WSL_ROOT%"
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
