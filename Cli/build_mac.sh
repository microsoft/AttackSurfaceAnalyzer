release="Debug"

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
	version=`nbgv get-version -v AssemblyInformationalVersion`
    dotnet publish -c Release -r osx-x64 --self-contained true && ../Tools/macos-x64.warp-packer --arch macos-x64 --input_dir bin/Release/netcoreapp2.1/osx-x64/publish/ --exec AttackSurfaceAnalyzerCli --output bin/AttackSurfaceAnalyzerCli-macos-$version.bin
    chmod +x AttackSurfaceAnalyzerCli
fi