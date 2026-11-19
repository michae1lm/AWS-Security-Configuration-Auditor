@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 -m aws_security_auditor --fixture fixtures/demo.json --output reports/demo
set "auditExit=%errorlevel%"
goto done
:use_python
python -m aws_security_auditor --fixture fixtures/demo.json --output reports/demo
set "auditExit=%errorlevel%"
:done
echo.
echo Scanner exit code: %auditExit%
echo The mixed demo intentionally returns 2 because it contains UNKNOWN results.
echo Open reports\demo\report.md or reports\demo\report.json.
echo If Python was not found, install Python 3.11 or newer and try again.
echo.
pause
exit /b %auditExit%
