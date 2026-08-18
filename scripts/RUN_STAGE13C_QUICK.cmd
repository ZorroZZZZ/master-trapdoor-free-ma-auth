@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_stage13c.ps1" -Mode Quick
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo [FAIL] Stage13C stopped with code %RC%.
if "%RC%"=="0" echo [PASS] Stage13C completed. Zip and upload the results folder.
pause
exit /b %RC%
