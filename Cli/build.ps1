param (
    [string]$release = "Debug"
)

if ($release -eq "Debug"){
    dotnet build
}
if ($release -eq "Release"){
    dotnet publish -c Release -r win10-x64 --self-contained true
    if ($?) {
		$version = (nbgv get-version -v AssemblyInformationalVersion)
        ..\Tools\windows-x64.warp-packer.exe --arch windows-x64 --input_dir bin\Release\netcoreapp2.1\win10-x64\publish\ --exec AttackSurfaceAnalyzerCli.exe --output bin\AttackSurfaceAnalyzerCli-windows-$version.exe
    }
}