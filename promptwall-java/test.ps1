$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$output = Join-Path $root "out-test"
New-Item -ItemType Directory -Force -Path $output | Out-Null
$sources = Get-ChildItem (Join-Path $root "src") -Recurse -Filter "*.java" | ForEach-Object { $_.FullName }
javac -d $output $sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
java -cp $output com.promptwall.PromptWallSelfTest

