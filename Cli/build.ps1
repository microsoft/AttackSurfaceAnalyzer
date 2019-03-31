param (
    [string]$release = "Debug"
)

if ($release -eq "Debug"){
    dotnet build
}
if ($release -eq "Release"){
    dotnet publish -c Release -r win10-x64 --self-contained true --output bin\win
    if ($?) {
		$version = (nbgv get-version -v AssemblyInformationalVersion)
        Rename-Item -Path "bin\win\Cli" -NewName "AttackSurfaceAnalyzerCli-windows-$version"
    }
}