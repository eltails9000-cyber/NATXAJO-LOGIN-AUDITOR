# Lanzador de NATXAJO-LOGIN-AUDITOR para Windows 10 y 11.
# Busca un intérprete Python 3.11 o posterior y ejecuta main.py con los mismos argumentos.
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

$Check = "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
$Candidates = @(
    @{ Exe = "py"; Prefix = @("-3.11") },
    @{ Exe = "py"; Prefix = @("-3") },
    @{ Exe = "python"; Prefix = @() }
)

$Selected = $null
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($candidate in $Candidates) {
    $command = Get-Command $candidate.Exe -ErrorAction SilentlyContinue
    if (-not $command) { continue }
    & $command.Source @($candidate.Prefix) -c $Check 2>$null
    if ($LASTEXITCODE -eq 0) {
        $Selected = @{ Exe = $command.Source; Prefix = $candidate.Prefix }
        break
    }
}
$ErrorActionPreference = $previousPreference

if (-not $Selected) {
    throw "Python 3.11 o posterior no está disponible. Instálelo desde python.org o con winget."
}

& $Selected.Exe @($Selected.Prefix) main.py @args
exit $LASTEXITCODE
