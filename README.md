# Attack Surface Analyzer 2019

Attack Surface Analyzer (ATSAN) is a Microsoft-developed open source security tool 
located at https://GitHub/microsoft/AttackSurfaceAnalyzer that analyzes the attack 
surface of a target system and reports on potential security vulnerabilities introduced by 
the installation of software or by misconfiguration. 

ATSAN replaces the older ASA classic version of the tool released by Microsoft in 2012 
as a downloadable https://www.microsoft.com/en-us/download/details.aspx?id=24487 
that is outdated, no longer supported and was limited to versions of Microsoft Windows 
prior to Windows 10.  

The application works by taking a snapshot before and after software installation for 
comparing key security impactful changes.

ATSAN analysis has proven to be valuable in identifying additional items to be 
considered in a threat model and detecting specific areas for additional fuzz testing.

Typical users of ATSAN include:
•	DevOps Engineers - view changes to the system attack surface introduced by your 
software.
•	IT Security Auditors - evaluate risk presented by select software before general 
distribution and use.

## Features

Files (static snapshot and live monitoring available)
User accounts
Services
Network Ports
Registry (Windows)

Future planned features:
Certificate store
Code signing info
Drivers (partially covered presently under files)
Firewall settings
Redistributable installations
Requested features which existed in ASA Classic
Network traffic live monitoring
Registry modifications (Windows) live monitoring

## Installation

ATSAN runs on Windows, Linux, and macOS using .NET Core and has both CLI and 
Electron .NET runtime options.  There is no setup per se but the package folder includes 
both of these dependencies.  

The current version is an Alpha internal only release on build version of 0.10. Check 
future release notes (docs/release-notes/0.10/release-0.10.md) to see what's new.  The 
full release is expected sometime in late April of 2019.

## Building

To build ATSAN from source please visit our future developers guide (docs/project-
docs/developer-guide.md) once available.

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

The CLI version of the tool comes with built-in help using a help parameter i.e. ATSAN 
/help for specifying specific collections to capture and other options.  

For future additional assistance using the Electron.NET GUI see our wiki at 
https://github.com/microsoft/AttackSurfaceAnalyzer/wiki once it becomes available.

## Notes and FAQ

-When comparing the results of two runs against one another the CLI this will output a 
results.html file whereas the GUI provides in application comparison.
-Collecting files is slow, due to the number of items processed.
-Collecting registry entries is slow, due to the number of items processed.
-Comparing large runs is slow.

GUI:

-Switching tabs in the GUI while an action is underway may make the application 
unresponsive to further input.  This is being resolved in the next version.
-Status reporting in the collect tab is manual and requires pressing the get status button.
-Sometimes when collecting files in the GUI the option to get status may be 
unresponsive.
-Debug output is enabled in the GUI in this version.
-The GUI is *not final* and is in the process of being updated.

For future assistance with use please see our FAQ list once it is available at 
https://github.com/microsoft/AttackSurfaceAnalyzer/wiki 

## License

Attack Surface Analyzer 2019 or ATSAN is licensed under the MIT license.
