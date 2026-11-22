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
Write-Host "PromptWall proxy starting on http://127.0.0.1:$port"
java -cp $output com.promptwall.PromptWallServer

