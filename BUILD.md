# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core 2.1.9 SDK
- Latest Visual Studio 2017
- GitVersioning

### GUI: 
- Electron.NET CLI tool 

## Installing Pre-requisites

### NBGV
In the root source directory run ```dotnet tool install -g nbgv```

### ElectronNet.CLI
In the Tools directory run ```dotnet tool install ElectronNET.CLI -g --version 0.0.11-custom --add-source packages```

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

Run the following commands in the GUI directory.

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
