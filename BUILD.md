# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core 2.2.3 SDK (https://dotnet.microsoft.com/download)
- Latest Visual Studio 2017
- GitVersioning (see below)

### GUI: 
- Node.js (https://nodejs.org/en/)
- Electron.NET CLI tool (see below)

## Installing Pre-requisites

### GitVersioning
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
