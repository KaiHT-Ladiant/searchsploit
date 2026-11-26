@echo off
REM PATH launcher — requires the package installed (pip install -e .)
python -m searchsploit %*
exit /b %ERRORLEVEL%
