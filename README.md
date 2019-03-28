# Attack Surface Analyzer 

## Version 2.0

The current version is a Pre-release suitable for testing core features.  Check future release notes here to see what's new.  A final release is planned for late April of 2019.

## Overview

Attack Surface Analyzer (ASA) is a Microsoft-developed open source security tool 
located at https://github.com/microsoft/AttackSurfaceAnalyzer that analyzes the attack 
surface of a target system and reports on potential security vulnerabilities introduced by 
the installation of software or by misconfiguration. 

ASA 2.0 replaces the older ASA classic version of the tool released by Microsoft in 2012 
as a downloadable https://www.microsoft.com/en-us/download/details.aspx?id=24487 
that is outdated, no longer supported and was limited to versions of Microsoft Windows 
prior to Windows 10.  

The application works by taking a snapshot before and after software installation for 
comparing key security impactful changes.

ASA analysis has proven to be valuable in identifying additional items to be 
considered in a threat model and detecting specific areas for additional fuzz testing.

Example users of ASA include:
* DevOps Engineers - view changes to the system attack surface introduced by your 
software.
* IT Security Auditors - evaluate risk presented by select software before general 
distribution and use.

Ideally, you would install the tool on a clean system with just the OS, the
Attack Surface Analyzer and software you plan to analyze.

## Features

- Files (static snapshot and live monitoring available)
- User accounts
- Services
- Network Ports
- Certificates
- Registry (Windows)

Future planned features:
- Code signing info
- Drivers (partially covered presently under files)
- Firewall settings
- Redistributable installations
- Requested features which existed in ASA Classic
- Network traffic live monitoring
- Registry modifications (Windows) live monitoring

## Installation

ATSAN runs on Windows, Linux, and macOS using .NET Core and has both CLI and 
Electron .NET runtime options.  There is no setup per se.

The GUI version will work without installing the .NET framework, but the CLI will not*.  
Both must be run as Administrator to function properly.  It is planned to package it 
so it does not require the framework to be installed before any public release.
See https://dotnet.microsoft.com/download, if you need the framework to run apps (not the SDK).

## Building

To build ASA from source see the BUILD.md project file.

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to 
agree to a Contributor License Agreement (CLA) declaring that you have the right to, 
and actually do, grant us the rights to use your contribution. For details, visit 
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you 
need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply 
follow the instructions provided by the bot. You will only need to do this once across all 
repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct]
(https://opensource.microsoft.com/codeofconduct/).

For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Use

See project wiki

## License

Attack Surface Analyzer 2.0 or ASA is licensed under the MIT license.
