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
    dotnet publish -c "$RELEASE" -r osx-x64 --self-contained true && ../Tools/macos-x64.warp-packer --arch macos-x64 --input_dir bin/Release/netcoreapp2.2/osx-x64/publish/ --exec AttackSurfaceAnalyzerCli --output bin/AttackSurfaceAnalyzerCli-macos-$VERSION.bin
    chmod +x bin/AttackSurfaceAnalyzerCli-macos-$VERSION.bin
    echo "Build completed, result is located at bin/AttackSurfaceAnalyzerCli-macos-$VERSION.bin"
fi
