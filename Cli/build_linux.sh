release = "Debug"

while [ "$1" != "" ]; do
    case $1 in
        -r | --release )           shift
                                release=$1
    esac
    shift
done

if ["$release" = "Debug"); then
    dotnet build
fi
if ["$release" = "Release"]; then
    dotnet publish -c Release -r linux-x64 --self-contained true && ../Tools/linux-x64.warp-packer --arch linux-x64 --input_dir bin/Release/netcoreapp2.1/linux-x64/publish/ --exec AttackSurfaceAnalyzerCli --output AttackSurfaceAnalyzerCli
    chmod +x AttackSurfaceAnalyzerCli
fi