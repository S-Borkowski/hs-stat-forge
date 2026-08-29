param([string]$Configuration = "Release")

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$MinHook = Join-Path $Root "third_party\minhook"
$Bin = Join-Path $Root "bin"
$Build = Join-Path $Root "build"
$Output = Join-Path $Bin "HSStatForgeDensity.dll"

if (-not (Test-Path -LiteralPath (Join-Path $MinHook "include\MinHook.h"))) {
    throw "MinHook source was not found at $MinHook"
}
New-Item -ItemType Directory -Path $Bin -Force | Out-Null
New-Item -ItemType Directory -Path $Build -Force | Out-Null

$VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $VsWhere)) { throw "vswhere.exe not found" }
$VisualStudio = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $VisualStudio) { throw "Visual Studio C++ build tools not found" }
$DevCmd = Join-Path $VisualStudio "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path -LiteralPath $DevCmd)) { throw "vcvars64.bat not found" }

$Sources = @(
    (Join-Path $Root "HSStatForgeDensity.cpp"),
    (Join-Path $MinHook "src\buffer.c"),
    (Join-Path $MinHook "src\hook.c"),
    (Join-Path $MinHook "src\trampoline.c"),
    (Join-Path $MinHook "src\hde\hde64.c")
)
$QuotedSources = ($Sources | ForEach-Object { "`"$_`"" }) -join " "
$Include = Join-Path $MinHook "include"
$BuildObjectDirectory = $Build.Replace("\", "/") + "/"
$Command = "call `"$DevCmd`" >nul 2>nul && cl /nologo /std:c++20 /EHsc /O2 /W4 /LD /I`"$Include`" $QuotedSources /Fe:`"$Output`" /Fo`"$BuildObjectDirectory`" /link /INCREMENTAL:NO"

$Previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
cmd.exe /d /s /c $Command
$ExitCode = $LASTEXITCODE
$ErrorActionPreference = $Previous
if ($ExitCode -ne 0) { throw "Density runtime build failed with exit code $ExitCode" }
Get-Item -LiteralPath $Output | Select-Object FullName, Length, LastWriteTime
