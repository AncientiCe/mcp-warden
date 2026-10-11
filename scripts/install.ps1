$ErrorActionPreference = "Stop"

$Repo = if ($env:MCP_WARDEN_REPO) { $env:MCP_WARDEN_REPO } else { "AncientiCe/mcp-warden" }
$InstallDir = if ($env:MCP_WARDEN_INSTALL_DIR) { $env:MCP_WARDEN_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\mcp-warden\bin" }
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mcp-warden-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

function Get-Target {
    # PowerShell 5.1's .NET Framework may not expose RuntimeInformation.OSArchitecture,
    # so fall back to the PROCESSOR_ARCHITECTURE environment variable.
    $arch = $null
    try {
        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch { }
    if (-not $arch) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($arch) {
        "^(X64|AMD64)$" { return "x86_64-pc-windows-msvc" }
        default { throw "Unsupported architecture: '$arch' (only 64-bit x86 Windows binaries are shipped today; build from source with cargo install --git https://github.com/$Repo --locked otherwise)" }
    }
}

# GitHub occasionally answers with transient 5xx errors; retry before giving up.
function Invoke-WithRetry([scriptblock]$Action) {
    $attempt = 1
    while ($true) {
        try {
            return & $Action
        } catch {
            if ($attempt -ge 5) { throw }
            Write-Host "Request failed ($($_.Exception.Message)); retrying ($attempt/4)..."
            Start-Sleep -Seconds (2 * $attempt)
            $attempt++
        }
    }
}

try {
    $Target = Get-Target

    $VersionOverride = if ($env:MCP_WARDEN_VERSION) { $env:MCP_WARDEN_VERSION } else { $null }
    $LocalArchive = if ($env:MCP_WARDEN_LOCAL_ARCHIVE) { $env:MCP_WARDEN_LOCAL_ARCHIVE } else { $null }

    if ($VersionOverride -eq "local") {
        if (-not $LocalArchive) {
            throw "MCP_WARDEN_LOCAL_ARCHIVE is required when MCP_WARDEN_VERSION=local"
        }
        $Archive = $LocalArchive
    } else {
        if ($VersionOverride) {
            $Tag = $VersionOverride
        } else {
            $Release = Invoke-WithRetry { Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" }
            $Tag = $Release.tag_name
        }
        $Version = $Tag.TrimStart("v")
        $Asset = "mcp-warden-$Version-$Target.zip"
        $Archive = Join-Path $TempDir $Asset
        $Checksum = Join-Path $TempDir "mcp-warden-$Target.sha256"
        Invoke-WithRetry { Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Tag/$Asset" -OutFile $Archive }
        Invoke-WithRetry { Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$Tag/mcp-warden-$Target.sha256" -OutFile $Checksum }

        $Expected = ((Get-Content $Checksum | Select-Object -First 1) -split "\s+")[0]
        $Actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
        if ($Actual -ne $Expected.ToLowerInvariant()) {
            throw "Checksum mismatch for $Asset"
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Expand-Archive -Path $Archive -DestinationPath $TempDir -Force
    $Binary = Get-ChildItem -Path $TempDir -Recurse -Filter "mcp-warden.exe" | Select-Object -First 1
    if (-not $Binary) {
        throw "Archive did not contain mcp-warden.exe"
    }
    Copy-Item $Binary.FullName (Join-Path $InstallDir "mcp-warden.exe") -Force

    # Add the install dir to the *user* PATH in the registry (never use `setx PATH "...;%PATH%"`:
    # PowerShell does not expand %PATH%, and setx would overwrite the user PATH with a literal string).
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $UserParts = if ($UserPath) { ($UserPath -split ";") | Where-Object { $_ } } else { @() }
    if ($UserParts -notcontains $InstallDir) {
        $NewUserPath = if ($UserPath) { ($UserPath.TrimEnd(";") + ";" + $InstallDir) } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
        Write-Host "Added $InstallDir to your user PATH. Restart your terminal to pick it up."
    }
    if ((($env:PATH -split ";") | Where-Object { $_ }) -notcontains $InstallDir) {
        $env:PATH = "$InstallDir;$env:PATH"
    }

    Write-Host "mcp-warden installed to $InstallDir\mcp-warden.exe"
    Write-Host "Next: mcp-warden install   # protect Claude Code, Codex and Cursor"
    Write-Host "Or wrap one MCP server: mcp-warden --server-id github -- github-mcp-server stdio"
} finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
