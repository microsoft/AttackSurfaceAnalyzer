# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core SDK 2.2.105 or better (https://dotnet.microsoft.com/download)
- GitVersioning (```dotnet tool install -g nbgv```)

### GUI: 
- Make sure to select ```ASP.NET Components``` in Visual Studio (You will otherwise receive an error opening this project)

## Building

Run these commands in the appropriate project directory.  For example, ```Cli``` for the Cli and Gui.

### Building a Debug version

```
dotnet build
```

### Building a Release version

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