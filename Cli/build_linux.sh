#!/bin/bash

RELEASE="Debug"
while [ "$1" != "" ]; do
    case "$1" in
        -r | --release )
           shift
           RELEASE="$1"
    esac
    shift
done

if [ "$RELEASE" == "Debug" ]; then
    dotnet build
elif [ "$RELEASE" == "Release" ]; then
    VERSION=$(nbgv get-version -v AssemblyInformationalVersion)
    dotnet publish -c "$RELEASE" -r linux-x64 --self-contained true && ../Tools/linux-x64.warp-packer --arch linux-x64 --input_dir bin/Release/netcoreapp2.2/linux-x64/publish/ --exec AttackSurfaceAnalyzerCli --output bin/AttackSurfaceAnalyzerCli-linux-$VERSION.bin
    chmod +x bin/AttackSurfaceAnalyzerCli-linux-$VERSION.bin
    echo "Build completed, result is located at bin/AttackSurfaceAnalyzerCli-linux-$VERSION.bin"
fi
