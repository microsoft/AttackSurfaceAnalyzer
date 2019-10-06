// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects data about the local ports open.
    /// </summary>
    public class OpenPortCollector : BaseCollector
    {

        private HashSet<string> processedObjects;

        public OpenPortCollector(string runId)
        {
            this.RunId = runId;
            this.processedObjects = new HashSet<string>();
        }

        public override bool CanRunOnPlatform()
        {
            try
            {
                var osRelease = File.ReadAllText("/proc/sys/kernel/osrelease") ?? "";
                osRelease = osRelease.ToUpperInvariant();
                if (osRelease.Contains("MICROSOFT") || osRelease.Contains("WSL"))
                {
                    Log.Error("OpenPortCollector cannot run on WSL until https://github.com/Microsoft/WSL/issues/2249 is fixed.");
                    return false;
                }
            }
            catch (Exception)
            {
                /* OK to ignore, expecting this on non-Linux platforms. */
            };

            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteOsX();
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Windows. Uses the .NET Core
        /// APIs to gather active TCP and UDP listeners and writes them 
        /// to the database.
        /// </summary>
        public void ExecuteWindows()
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var endpoint in properties.GetActiveTcpListeners())
            {
                var obj = new OpenPortObject()
                {
                    Family = endpoint.AddressFamily.ToString(),
                    Address = endpoint.Address.ToString(),
                    Port = endpoint.Port.ToString(CultureInfo.InvariantCulture),
                    Type = "tcp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.ProcessName = p.ProcessName;
                }

                DatabaseManager.Write(obj, this.RunId);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject()
                {
                    Family = endpoint.AddressFamily.ToString(),
                    Address = endpoint.Address.ToString(),
                    Port = endpoint.Port.ToString(CultureInfo.InvariantCulture),
                    Type = "udp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.ProcessName = p.ProcessName;
                }

                DatabaseManager.Write(obj, this.RunId);
            }
        }

        /// <summary>
        /// Executes the OpenPortCollector on Linux. Calls out to the `ss`
        /// command and parses the output, sending the output to the database.
        /// </summary>
        private void ExecuteLinux()
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("ss", "-ln");

                foreach (var _line in result.Split('\n'))
                {
                    var line = _line;
                    line = line.ToUpperInvariant();
                    if (!line.Contains("LISTEN"))
                    {
                        continue;
                    }
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length < 5)
                    {
                        continue;       // Not long enough, must be an error
                    }
                    string address = null;
                    string port = null;

                    var addressMatches = Regex.Match(parts[4], @"^(.*):(\d+)$");
                    if (addressMatches.Success)
                    {
                        address = addressMatches.Groups[1].ToString();
                        port = addressMatches.Groups[2].ToString();

                        var obj = new OpenPortObject()
                        {
                            Family = parts[0],//@TODO: Determine IPV4 vs IPv6 via looking at the address
                            Address = address,
                            Port = port,
                            Type = parts[0]
                        };
                        DatabaseManager.Write(obj, this.RunId);
                    }
                }
            }
            catch (Exception e)
            {
                Log.Warning(Strings.Get("Err_Iproute2"));
                Log.Debug(e,"");
            }

        }

        /// <summary>
        /// Executes the OpenPortCollector on OS X. Calls out to the `lsof`
        /// command and parses the output, sending the output to the database.
        /// The 'ss' command used on Linux isn't available on OS X.
        /// </summary>
        private void ExecuteOsX()
        {
            try
            {
                var result = ExternalCommandRunner.RunExternalCommand("sudo", "lsof -Pn -i4 -i6");

                foreach (var _line in result.Split('\n'))
                {
                    var line = _line.ToUpperInvariant();
                    if (!line.Contains("LISTEN"))
                    {
                        continue; // Skip any lines which aren't open listeners
                    }
                    var parts = Regex.Split(line, @"\s+");
                    if (parts.Length <= 9)
                    {
                        continue;       // Not long enough
                    }
                    string address = null;
                    string port = null;

                    var addressMatches = Regex.Match(parts[8], @"^(.*):(\d+)$");
                    if (addressMatches.Success)
                    {
                        address = addressMatches.Groups[1].ToString();
                        port = addressMatches.Groups[2].ToString();

                        var obj = new OpenPortObject()
                        {
                            // Assuming family means IPv6 vs IPv4
                            Family = parts[4],
                            Address = address,
                            Port = port,
                            Type = parts[7],
                            ProcessName = parts[0]
                        };

                        DatabaseManager.Write(obj, this.RunId);
                    }
                }
            }
            catch (Exception e)
            {
                Log.Error(e,Strings.Get("Err_Lsof"));
            }
        }
    }
}
