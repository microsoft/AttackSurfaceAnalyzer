# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core SDK 2.2.105 or better (https://dotnet.microsoft.com/download)
- GitVersioning (```dotnet tool install -g nbgv```)

### GUI: 
- Make sure to select ```ASP.NET Components``` in Visual Studio (You will otherwise receive an error opening this project)

## Building

Run these commands in the ```Asa``` directory.

### Building a Debug version

Windows
```
dotnet build
```

Linux/Mac
```
make
```

### Building a Release version

Windows
```
dotnet publish -c Release -r win10-x64
```

Linux/Mac
```
make release
```
