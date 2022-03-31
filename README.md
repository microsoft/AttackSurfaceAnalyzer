# Attack Surface Analyzer 
Attack Surface Analyzer is a [Microsoft](https://github.com/microsoft/) developed open source security tool that analyzes the attack 
surface of a target system and reports on potential security vulnerabilities introduced during
the installation of software or system misconfiguration. 

## Getting Attack Surface Analyzer
[![CodeQL](https://github.com/microsoft/AttackSurfaceAnalyzer/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/microsoft/AttackSurfaceAnalyzer/actions/workflows/codeql-analysis.yml) [![Nuget](https://img.shields.io/nuget/dt/Microsoft.CST.AttackSurfaceAnalyzer.CLI)](https://www.nuget.org/packages/Microsoft.CST.AttackSurfaceAnalyzer.CLI) ![Nuget](https://img.shields.io/nuget/v/Microsoft.CST.AttackSurfaceAnalyzer.CLI)

If you have the [.NET SDK](https://dotnet.microsoft.com/download) installed you can install Attack Surface Analyzer with `dotnet tool install -g Microsoft.CST.AttackSurfaceAnalyzer.CLI`.

Platform specific binaries for Attack Surface Analyzer are distributed via our GitHub [releases](https://github.com/Microsoft/AttackSurfaceAnalyzer/releases/latest) page.

## Dependencies

On linux you may need to install some utilities ASA uses to gather data before running ASA.

```
apt-get update && apt-get install -y \
    coreutils \
    iproute2
```

## Documentation

Documentation is available on the [Wiki](https://github.com/Microsoft/AttackSurfaceAnalyzer/wiki/).

Documentation for the [API](https://microsoft.github.io/AttackSurfaceAnalyzer/api/) is available on GitHub Pages.

## New Features in 2.3

- New Blazor GUI with Rule Authoring and Testing Sandbox
- New Collectors
- Improved collection and analysis performance.
- Support for C# 10/.NET 6

## Overview

Attack Surface Analyzer 2 replaces the original Attack Surface Analyzer tool, released publicly in 2012.

Potential users of Attack Surface Analyzer include:

* DevOps Engineers - View changes to the system attack surface introduced when your software is installed.
* IT Security Auditors - Evaluate risk presented by when third-party software is installed.

## Core Features

The core feature of Attack Surface Analyzer is the ability to "diff" an operating system's security configuration, before and after a software component is installed and to run arbitrary complex rules on the results to surface interesting findings. This is important because most installation processes require elevated privileges, and once granted, can lead to unintended system configuration changes.

Attack Surface Analyzer currently reports on changes to the following operating system components:

- File system (static snapshot and live monitoring available)
- User accounts
- Services
- Network Ports
- Certificates
- Registry
- COM Objects
- Event Logs
- Firewall Settings
- Wifi Networks
- Cryptographic Keys
- Processes
- TPM Information

All data collected is stored in a set of local SQLite databases.

## How to Use Attack Surface Analyzer

Run the following commands in an Administrator Shell (or as root).  Replace ```asa``` with ```asa.exe``` as appropriate for your platform.

### CLI Mode
To start a default all collectors run: ```asa collect -a```

To compare the last two collection runs: ```asa export-collect```

For other commands run: ```asa --help```

### GUI Mode
For the GUI interface run: ```asa gui``` and a browser window should open directed at ```http://localhost:5000``` with the web based interface.

Detailed information on how to use Attack Surface Analyzer can be found on our
[wiki](https://github.com/Microsoft/AttackSurfaceAnalyzer/wiki).

## Building

To build Attack Surface Analyzer, see [BUILD](https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/main/BUILD.md).

## Versions
The latest public version of Attack Surface Analyzer with public builds is 2.3 (see [Release\v2.3](https://github.com/Microsoft/AttackSurfaceAnalyzer/tree/release/v2.3)).  

2.4 is now in development on the `main` branch.  You can see the features coming [here](https://github.com/microsoft/attacksurfaceanalyzer/issues?q=is%3Aissue+milestone%3Av2.4+).

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to 
agree to a Contributor License Agreement (CLA) declaring that you have the right to, 
and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you 
need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply 
follow the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Reporting Security Issues

Security issues and bugs should be reported privately, via email, to the Microsoft Security
Response Center (MSRC) at [secure@microsoft.com](mailto:secure@microsoft.com). You should
receive a response within 24 hours. If for some reason you do not, please follow up via
email to ensure we received your original message. Further information, including the
[MSRC PGP](https://technet.microsoft.com/en-us/security/dn606155) key, can be found in
the [Security TechCenter](https://technet.microsoft.com/en-us/security/default).

## License

Attack Surface Analyzer 2 is licensed under the
[MIT license](https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/main/LICENSE).
