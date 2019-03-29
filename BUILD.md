# Build How-to

## Pre-requisites

### CLI:
- .NET Core 2.1.9 SDK
- Latest Visual Studio 2017

### GUI: 
- Latest Node.js 
- .NET Core 2.1.9 SDK
- Latest Visual Studio 2017
- Electron.NET CLI tool (Execute ```dotnet tool install ElectronNET.CLI -g --version 0.0.11-custom --add-source packages``` in the Tools directory)

## Building

### CLI:
Run these commands in the CLI directory.

#### Building a Debug version

```
dotnet build
```

#### Building a Release version

Windows
```
.\build.ps1 -release Release
```

Linux
```
sh build-linux.sh -r Release
```

Mac
```
sh build-mac.sh -r Release
```

### GUI

Run these commands in the GUI directory.

#### Running

```
electronize start
```

#### Building

Windows
```
electronize build /target win /package-json package.json /relative-path bin
```

Linux
```
electronize build /target linux /package-json package.json /relative-path bin
```

Mac
```
electronize build /target macos /package-json package.json /relative-path bin
```

Will create the Electron application in ```AttackSurfaceAnalyzer\Gui\bin\```
