# Build How-to

## Pre-requisites

### All Components:
- Latest .NET Core SDK 5.0 (https://dotnet.microsoft.com/download)
- GitVersioning (```dotnet tool install -g nbgv```)

### GUI: 
- Make sure to select ```ASP.NET Components``` in Visual Studio (You will otherwise receive an error opening this project)

## Building

Run these commands in the appropriate project directory.  For example, ```Cli``` for the Cli and Gui.

### Building a Debug version
Note that `dotnet build` is only supported with the Debug configuration.

```
dotnet build -c Debug
```

### Publishing a Release version
Note that `dotnet publish` is only supported with the Release configuration

Windows
```
dotnet publish -c Release -r win-x86
```

Linux
```
dotnet publish -c Release -r linux-x64
```

Mac
```
dotnet publish -c Release -r osx-x64
```

Framework Dependent .NET Core App
```
dotnet publish -c Release
```
