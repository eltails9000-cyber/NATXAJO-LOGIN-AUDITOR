# CLI `natxajo` desde PowerShell 5.1 o 7: reenvía los argumentos a main.py, en la carpeta de este archivo.
& python (Join-Path $PSScriptRoot 'main.py') @args
exit $LASTEXITCODE
