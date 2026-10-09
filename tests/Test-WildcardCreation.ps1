[CmdletBinding()]
param([string]$ApplicationPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($ApplicationPath)) {
    $ApplicationPath = Join-Path $root 'TinyWall\bin\Release\TinyWall.exe'
}
$app = [IO.Path]::GetFullPath($ApplicationPath)
if (-not (Test-Path -LiteralPath $app)) { throw "Build the application first: $app" }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio or its MSBuild build tools first.' }
$compiler = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\Current\Bin\Roslyn\csc.exe' | Select-Object -First 1
if (-not $compiler) { throw 'The .NET Framework C# compiler was not found.' }
$output = Join-Path $PSScriptRoot 'bin'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$test = Join-Path $output 'WildcardCreationTests.exe'
& $compiler /nologo /target:exe /optimize+ /langversion:9 "/out:$test" (Join-Path $PSScriptRoot 'WildcardCreationTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Wildcard creation regression harness compilation failed.' }
Copy-Item -LiteralPath ($app + '.config') -Destination ($test + '.config') -Force
$before = (Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash
& $test $app
if ($LASTEXITCODE -ne 0) { throw 'Compiled wildcard creation regression checks failed.' }
if ((Get-FileHash -LiteralPath $app -Algorithm SHA256).Hash -ne $before) { throw 'Test unexpectedly changed the application binary.' }
Write-Host 'No UI, service, firewall configuration, or network state was changed by this test.'
