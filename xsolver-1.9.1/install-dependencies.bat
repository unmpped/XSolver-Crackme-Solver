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
wsl.exe --cd "%WSL_ROOT%" --exec bash ./setup.sh
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
