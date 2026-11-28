@echo off
rem CLI `natxajo` desde CMD: reenvía todos los argumentos a main.py, en la carpeta de este archivo.
python "%~dp0main.py" %*
exit /b %ERRORLEVEL%
