# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core 2.2.3 SDK
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

Windows
```
dotnet clean
dotnet build
```

Linux/Mac
```
make
```

#### Building a Release version

Windows
```
dotnet publish -c Release -r win10-x64
```

Linux/Mac
```
make release
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

## Debugging

This project uses NLog with a helper class implemented in the library. To see your debug statements on the console run in --verbose mode. Projects compiled in Debug mode automatically output Debug prints into "asa.debug.txt".
