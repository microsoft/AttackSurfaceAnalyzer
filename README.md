# Attack Surface Analyzer 

## Version 2.1

Attack Surface Analyzer was first released for the general audience starting in version 2.0 (see Release\v2.0).  Subsequent versions on master are meant to advance the general features and issues fixed.

## Overview

Attack Surface Analyzer is a Microsoft-developed open source security tool that analyzes the attack 
surface of a target system and reports on potential security vulnerabilities introduced during
the installation of software or system misconfiguration. 

Attack Surface Analyzer 2.0 replaces the original [Attack Surface Analzyer](https://www.microsoft.com/en-us/download/details.aspx?id=24487) tool, released publicly in 2012.

Potential users of Attack Surface Analyzer include:

* DevOps Engineers - View changes to the system attack surface introduced when your software is installed.
* IT Security Auditors - Evaluate risk presented by when third-party software is installed.

## Core Features

The core feature of Attack Surface Analyzer is the ability to "diff" an operating system's security configuration, 
before and after a software component is installed. This is important because most installation processes require
elevated privileges, and once granted, can lead to unintended system configuration changes.

Attack Surface Analyzer currently reports on changes to the following operating system components:

- File system (static snapshot and live monitoring available)
- User accounts
- Services
- Network Ports
- Certificates
- Registry (Windows only)

All data collected is stored in a local SQLite database called `asa.sqlite`.

## How to Use Attack Surface Analyzer

Information on how to use Attack Surface Analyzer can be found on our
[wiki](https://github.com/Microsoft/AttackSurfaceAnalyzer/wiki).

## Future Plans (tentative)

We plan on adding additional features to Attack Surface Analyzer, including those from the list below: 

- Code signing info
- Drivers (partially covered presently via file system monitoring)
- Firewall settings
- Redistributable installations
- Network traffic (live monitoring)
- Registry (live monitoring)
- Requested features which existed in the original Attack Surface Analyzer.

If you have feedback on these or other features, please
[open an issue](https://github.com/Microsoft/AttackSurfaceAnalyzer/issues).

## Installation

Attack Surface Analzyer runs on Windows, Linux, and MacOS, and is built using [.NET Core](https://dotnet.microsoft.com/). It has both a command-line interface and [ElectronNET](https://github.com/ElectronNET/Electron.NET) GUI option available. Neither version currently has an installer.

Packages are available on our [releases](https://github.com/Microsoft/AttackSurfaceAnalyzer/releases) page as compressed archives.

## Building

To build Attack Surface Analyzer, see [BUILD](https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/master/BUILD.md).

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

Attack Surface Analyzer 2.0 is licensed under the
[MIT license](https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/master/LICENSE).


