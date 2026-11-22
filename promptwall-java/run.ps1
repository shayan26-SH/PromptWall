$ErrorActionPreference = "Stop"
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match "^\s*[^#].*=.*" } | ForEach-Object {
        $name, $value = $_ -split "=", 2
        [Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
    }
}

$output = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $output | Out-Null
javac -d $output (Get-ChildItem (Join-Path $PSScriptRoot "src\com\promptwall") -Filter "*.java").FullName
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$port = if ($env:PORT) { $env:PORT } else { "8080" }
$url = "http://127.0.0.1:$port"
$securityPort = "8000"
$securityUrl = "http://127.0.0.1:$securityPort"

$securityStarted = $false
$security = $null
try {
    Invoke-WebRequest -UseBasicParsing "$securityUrl/health" -TimeoutSec 1 | Out-Null
} catch {
    $securityDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) "security-service"
    $security = Start-Process python -ArgumentList "-m uvicorn app:app --host 127.0.0.1 --port $securityPort" -WorkingDirectory $securityDirectory -PassThru
    $securityStarted = $true

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 200
        try {
            Invoke-WebRequest -UseBasicParsing "$securityUrl/health" -TimeoutSec 1 | Out-Null
            break
        } catch {
            if ($security.HasExited) {
                throw "PromptWall security service exited before becoming ready."
            }
        }
    }
}

Write-Host "PromptWall proxy starting on $url"

$server = Start-Process java -ArgumentList "-cp `"$output`" com.promptwall.PromptWallServer" -PassThru
try {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Milliseconds 200
        try {
            $health = Invoke-WebRequest -UseBasicParsing "$url/health" -TimeoutSec 1
            if ($health.StatusCode -eq 200) {
                Start-Process $url
                break
            }
        } catch {
            if ($server.HasExited) {
                throw "PromptWall server exited before becoming ready."
            }
        }
    }

    if (-not $health -or $health.StatusCode -ne 200) {
        throw "PromptWall server did not become ready at $url."
    }

    Wait-Process -Id $server.Id
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id
    }
    if ($securityStarted -and $security -and -not $security.HasExited) {
        Stop-Process -Id $security.Id
    }
}

