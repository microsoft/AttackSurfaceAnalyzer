# Attack Surface Analyzer 

## Version 2.0-preview

The current version is a Preview suitable for testing core features.  Check future release notes here to see what's new.  A final release is planned for late April of 2019.

## Overview

Attack Surface Analyzer is a Microsoft-developed open source security tool 
available at https://github.com/microsoft/AttackSurfaceAnalyzer that analyzes the attack 
surface of a target system and reports on potential security vulnerabilities introduced by 
the installation of software or by system misconfiguration. 

Attack Surface Analyzer 2.0 replaces the classic version of the Attack Surface Analyzer tool released by Microsoft in 2012 
as a downloadable https://www.microsoft.com/en-us/download/details.aspx?id=24487 
which is no longer supported and lacks Windows 10 support.  

Example users of ASA include:
* DevOps Engineers - view changes to the system attack surface introduced by your 
software.
* IT Security Auditors - evaluate risk presented by select software before general 
distribution and use.

## Features

- Files (static snapshot and live monitoring available)
- User accounts
- Services
- Network Ports
- Certificates
- Registry (Windows)

## Future planned features:
- Code signing info
- Drivers (partially covered presently under files)
- Firewall settings
- Redistributable installations
- Requested features which existed in ASA Classic
- Network traffic live monitoring
- Registry modifications (Windows) for Live monitoring

## Installation

ASA runs on Windows, Linux, and macOS and is built on .NET Core.  It has both CLI and 
Electron .NET runtime options.  There is currently no installer.

## Building

To build ASA from source see the BUILD.md project file.

## Misc Notes
The release version of the CLI is a [Warp Package](https://github.com/dgiagio/warp), and on first run may take a few seconds to expand.

By default data is stored in a database in your current directory named "asa.sqlite".

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

See project wiki located on this site

## License

Attack Surface Analyzer 2.0 or ASA is licensed under the MIT license.

## Security Support

For any issues affecting the code base or product release bits that you believe includes a critical security vulnerability, please contact us at email address: secure@microsoft.com and include "Microsoft Attack Surface Analyzer" with a detailed explaination of the concern rather than post it on the Issues page of this site.  Thank you!
