# Lanzador de NATXAJO-LOGIN-AUDITOR para Windows 10 y 11.
#
# Uso: .\launcher.ps1 [argumentos de main.py]
#
# - Busca un intérprete Python 3.11 o posterior real: py -3.11, py -3, python y python3.
# - Ignora los alias de la Microsoft Store (carpeta WindowsApps): no son instalaciones.
# - Comprueba cada candidato ejecutándolo; un alias roto o una instalación antigua no pasan.
# - Ejecuta main.py desde la carpeta del proyecto, acepta sus argumentos y devuelve su código de
#   salida. Si el lanzador no puede empezar, devuelve 1.
# - No cambia la política de ejecución de PowerShell.

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot

$Check = "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
$VersionQuery = "import sys; print('.'.join(str(part) for part in sys.version_info[:3]))"
$Candidates = @(
    @{ Exe = "py"; Prefix = @("-3.11") },
    @{ Exe = "py"; Prefix = @("-3") },
    @{ Exe = "python"; Prefix = @() },
    @{ Exe = "python3"; Prefix = @() }
)

function Find-Interpreter {
    # Los programas nativos escriben en stderr al fallar; con Stop, PowerShell lo trataría como error.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        foreach ($candidate in $Candidates) {
            $command = Get-Command $candidate.Exe -CommandType Application -ErrorAction SilentlyContinue
            if (-not $command) { continue }
            if ($command.Source -match '\\WindowsApps\\') { continue }
            & $command.Source @($candidate.Prefix) -c $Check *> $null
            if ($LASTEXITCODE -ne 0) { continue }
            $version = & $command.Source @($candidate.Prefix) -c $VersionQuery 2>$null |
                Select-Object -First 1
            return @{
                Exe = $command.Source
                Prefix = $candidate.Prefix
                Version = [string]$version
            }
        }
        return $null
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

$Interpreter = Find-Interpreter
if (-not $Interpreter) {
    [Console]::Error.WriteLine("Error: no se encontró Python 3.11 o posterior en este equipo.")
    [Console]::Error.WriteLine("Instálelo desde https://www.python.org/downloads/ y marque 'Add python.exe to PATH'.")
    [Console]::Error.WriteLine("Si solo aparecen alias de la Microsoft Store, desactívelos en Configuración > Aplicaciones > Configuración avanzada de aplicaciones > Alias de ejecución de aplicaciones.")
    exit 1
}

$Entry = Join-Path $ProjectRoot "main.py"
if (-not (Test-Path -LiteralPath $Entry -PathType Leaf)) {
    [Console]::Error.WriteLine("Error: no se encuentra main.py en $ProjectRoot")
    exit 1
}

Write-Host "Python $($Interpreter.Version) ($($Interpreter.Exe))"
& $Interpreter.Exe @($Interpreter.Prefix) $Entry @args
exit $LASTEXITCODE
