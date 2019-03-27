# Build How-to

## Pre-requisites

### CLI:
- .NET Core 2.1 SDK
- Visual Studio 2017

### GUI: 
- Node.js 
- .NET Core 2.1 SDK
- Visual Studio 2017. 
- Electron.NET CLI tool - ```dotnet tool install ElectronNET.CLI -g```

## Building

### CLI:

#### Building a Debug version

```
dotnet build
```

#### Building a Release version
On Windows you can use the script at Cli\Build.ps1 to build the release package.
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

#### Running
```
electronize start
```

#### Building

```
electronize build /target win
```
Will create the Electron application in ```AttackSurfaceAnalyzer\Gui\bin\desktop```
