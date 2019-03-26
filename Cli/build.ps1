 param (
    [string]$release = "Debug"
 )

if ($release -eq "Debug"){
    dotnet build
}
if ($release -eq "Release"){
    dotnet publish -r win10-x64 --self-contained true
    if ($?) {
        ..\Tools\warp-packer.exe --arch windows-x64 --input_dir bin\Debug\netcoreapp2.1\win10-x64\publish\ --exec AttackSurfaceAnalyzerCli.exe --output AttackSurfaceAnalyzerCli.exe
    }
}

