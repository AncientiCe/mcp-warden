# The full gate suite (AGENTS.md §2) for Windows, where `make` is usually missing.
# Stops at the first red gate.
$ErrorActionPreference = 'Stop'

$gates = @(
    @('fmt', 'cargo', 'fmt', '--all', '--', '--check'),
    @('clippy', 'cargo', 'clippy', '--all-targets', '--all-features', '--workspace', '--', '-D', 'warnings'),
    @('test', 'cargo', 'test', '--workspace'),
    @('audit', 'cargo', 'audit'),
    @('build', 'cargo', 'build', '--workspace', '--locked')
)

foreach ($gate in $gates) {
    $name = $gate[0]
    $exe = $gate[1]
    $gateArgs = $gate[2..($gate.Length - 1)]
    Write-Host "==> $name" -ForegroundColor Cyan
    & $exe @gateArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "gate '$name' failed" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}
Write-Host 'all gates green' -ForegroundColor Green
