// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.ComponentModel.DataAnnotations;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects data about the local ports open.
    /// </summary>
    public class OpenPortCollector : BaseCollector
    {
        public OpenPortCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteOsX(cancellationToken);
            }
        }

        /* Examples
// Sockets
Netid State  Recv-Q Send-Q                                      Local Address:Port        Peer Address:PortProcess                                                                                     
u_str LISTEN 0      4096                          /run/libvirt/virtlockd-sock 26200                  * 0    users:(("systemd",pid=1,fd=77))                                                            

// Ports
Netid State  Recv-Q Send-Q                              Local Address:Port        Peer Address:PortProcess                                                          
nl    UNCONN 0      0                                               0:530                     *                                                                     
*/
        // See https://github.com/microsoft/AttackSurfaceAnalyzer/issues/649 for discussion on this regex and potential other solutions parsing sock files directly.
        private static Regex LinuxSsParsingRegex { get; } = new Regex(
            "^([\\S]+)\\s+([\\S]+)\\s+([\\S]+)\\s+([\\S]+)\\s+([\\S]+)[\\s:]([\\S]+)\\s+([\\S]+)(?:([\\s:]([\\S]+))?\\s+([\\S]+))?\\s*$",
        RegexOptions.Compiled);
        
        
        /// <summary>
        ///     Executes the OpenPortCollector on Linux. Calls out to the `ss` command and parses the output,
        ///     sending the output to the database.
        /// </summary>
        internal void ExecuteLinux(CancellationToken cancellationToken)
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("ss", "-lnp");
                foreach (var _line in result.Split('\n')[1..])
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

                    var line = _line;
                    if (!line.Contains("LISTEN", StringComparison.InvariantCultureIgnoreCase))
                    {
                        continue;
                    }

                    var ssParts = LinuxSsParsingRegex.Match(line);
                    if (!ssParts.Success)
                    {
                        continue;       // Not long enough, must be an error
                    }

                    var address = ssParts.Groups[5].Value;
                    var port = ssParts.Groups[6].Value;
                    if (int.TryParse(port, out int portInt))
                    {
                        var transport = ssParts.Groups[1].Value.ToUpperInvariant().Equals("TCP") ? TRANSPORT.TCP : ssParts.Groups[1].Value.ToUpperInvariant().Equals("UDP") ? TRANSPORT.UDP : TRANSPORT.UNKNOWN;
                        var family = address.Contains('.') ? ADDRESS_FAMILY.InterNetwork : address.Contains(':') ? ADDRESS_FAMILY.InterNetworkV6 : ADDRESS_FAMILY.Unknown;
                        if (!string.IsNullOrWhiteSpace(ssParts.Groups[10].Value))
                        {
                            var processNameMatches = Regex.Matches(ssParts.Groups[10].Value, @"""(.*?)"",pid=([0-9]*)");
                            foreach(Match match in processNameMatches)
                            {
                                int? pid = int.TryParse(match.Groups[2].Value, out int thePid) ? thePid : null;
                                var obj = new OpenPortObject(portInt, transport, family)
                                {
                                    Address = address,
                                    ProcessName = match.Groups[1].Value,
                                    ProcessId = pid
                                };
                                HandleChange(obj);
                            }
                        }
                        else
                        {
                            var obj = new OpenPortObject(portInt, transport, family)
                            {
                                Address = address
                            };
                            HandleChange(obj);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Warning(Strings.Get("Err_Iproute2"));
                Log.Debug(e, "");
            }
        }

        /// <summary>
        ///     Executes the OpenPortCollector on OS X. Calls out to the `lsof` command and parses the output,
        ///     sending the output to the database.
        /// </summary>
        internal void ExecuteOsX(CancellationToken cancellationToken)
        {
            try
            {
                string result = ExternalCommandRunner.RunExternalCommand("lsof", "-Pn -i4 -i6");

                foreach (var _line in result.Split('\n'))
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

                    var line = _line.ToUpperInvariant();
                    if (!line.Contains("LISTEN"))
                    {
                        continue; // Skip any lines which aren't open listeners
                    }
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length <= 9)
                    {
                        continue; // Not long enough
                    }

                    var addressMatches = Regex.Match(parts[8], @"^(.*):(\d+)$");
                    if (addressMatches.Success)
                    {
                        var address = addressMatches.Groups[1].ToString();
                        var port = addressMatches.Groups[2].ToString();
                        if (int.TryParse(port, out int portInt))
                        {
                            var transport = parts[7].ToUpperInvariant().Equals("TCP") ? TRANSPORT.TCP : parts[7].ToUpperInvariant().Equals("TCP") ? TRANSPORT.UDP : TRANSPORT.UNKNOWN;
                            var family = ADDRESS_FAMILY.Unknown;

                            switch (parts[4])
                            {
                                case "IPv4":
                                    family = ADDRESS_FAMILY.InterNetwork;
                                    break;

                                case "IPv6":
                                    family = ADDRESS_FAMILY.InterNetworkV6;
                                    break;

                                default:
                                    family = ADDRESS_FAMILY.Unknown;
                                    break;
                            }

                            var obj = new OpenPortObject(portInt, transport, family)
                            {
                                Address = address,
                                ProcessName = parts[0]
                            };

                            HandleChange(obj);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Error(e, Strings.Get("Err_Lsof"));
            }
        }

        /// <summary>
        ///     Executes the OpenPortCollector on Windows. Uses the .NET Core APIs to gather active TCP and
        ///     UDP listeners and writes them to the database.
        /// </summary>
        internal void ExecuteWindows(CancellationToken cancellationToken)
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                if (cancellationToken.IsCancellationRequested) { return; }

                var obj = new OpenPortObject(endpoint.Port, TRANSPORT.TCP, (ADDRESS_FAMILY)endpoint.AddressFamily)
                {
                    Address = endpoint.Address.ToString(),
                    ProcessName = Win32ProcessPorts.ProcessPortMap.Find(x => x.PortNumber == endpoint.Port)?.ProcessName,
                    ProcessId = Win32ProcessPorts.ProcessPortMap.Find(x => x.PortNumber == endpoint.Port)?.ProcessId
                };
                HandleChange(obj);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject(endpoint.Port, TRANSPORT.UDP, (ADDRESS_FAMILY)endpoint.AddressFamily)
                {
                    Address = endpoint.Address.ToString(),
                    ProcessName = Win32ProcessPorts.ProcessPortMap.Find(x => x.PortNumber == endpoint.Port)?.ProcessName,
                    ProcessId = Win32ProcessPorts.ProcessPortMap.Find(x => x.PortNumber == endpoint.Port)?.ProcessId
                };

                HandleChange(obj);
            }
        }
    }
}