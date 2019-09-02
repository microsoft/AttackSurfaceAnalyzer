# Build How-to

## Pre-requisites

### CLI + GUI:
- .NET Core SDK 2.2.105 or better* (https://dotnet.microsoft.com/download)
- GitVersioning (see below)

### GUI: 
- Node.js (https://nodejs.org/en/)
- Electron.NET CLI tool (see below)
- ASP.NET Components in Visual Studio (You will otherwise receive an error opening this project)

## Installing Pre-requisites

## .NET Core SDK - Note for Visual Studio Users
If you are using Visual Studio 2017, you must use the latest release that explicitly supports Visual Studio 2017.  It appears that releases in the 2.2.1* series are okay, but after 2.2.202 they stop being compatible.

If you are using Visual Studio 2019, use the latest release.

### GitVersioning
In the root source directory run ```dotnet tool install -g nbgv```

## Building

### CLI/Slim GUI:
Run these commands in the CLI/GUI directory.

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

### GUI (Electron Packaged)

Run the following commands in the GUI directory.

#### Running

```
electronize start
```

#### Building

Windows
```
electronize build /target win /package-json package.json
```

Linux
```
electronize build /target linux /package-json package.json
```

Mac
```
electronize build /target macos /package-json package.json
```

Will create the output in ```bin\{platform}-unpacked```.
