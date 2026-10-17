param([int]$Port = 5000)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $projectPython)) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment. Install Python 3.11 or newer.' }
    }
    & $projectPython -c "import importlib.util,sys; sys.exit(0 if all(importlib.util.find_spec(m) for m in ['flask','waitress','pandas','sklearn','numpy','joblib']) else 1)"
    if ($LASTEXITCODE -ne 0) {
        & $projectPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. See README.md for manual setup.' }
    }
    & $projectPython app.py --demo --port $Port
    if ($LASTEXITCODE -ne 0) { throw 'PQConnect could not start. Check the error above.' }
} finally {
    Pop-Location
}
