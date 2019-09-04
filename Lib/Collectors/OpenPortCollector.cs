// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using AttackSurfaceAnalyzer.Objects;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class OpenPortCollector : BaseCollector
    {

        private HashSet<string> processedObjects;

        public OpenPortCollector(string runId)
        {
            if (runId == null)
            {
                throw new ArgumentException("runIdentifier may not be null.");
            }
            this.runId = runId;
            this.processedObjects = new HashSet<string>();
        }

        /**
         * Can this check run on the current platform?
         */
        public override bool CanRunOnPlatform()
        {
            try
            {
                var osRelease = File.ReadAllText("/proc/sys/kernel/osrelease") ?? "";
                osRelease = osRelease.ToLower();
                if (osRelease.Contains("microsoft") || osRelease.Contains("wsl"))
                {
                    Log.Debug("OpenPortCollector cannot run on WSL until https://github.com/Microsoft/WSL/issues/2249 is fixed.");
                    return false;
                }
            }
            catch (Exception)
            { 
                /* OK to ignore, expecting this on non-Linux platforms. */
            };

            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            if (!this.CanRunOnPlatform())
            {
                return;
            }

            Start();
            _ = DatabaseManager.Transaction;

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
            else
            {
                Log.Warning("OpenPortCollector is not available on {0}", RuntimeInformation.OSDescription);
            }
            DatabaseManager.Commit();
            Stop();
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
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "tcp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                DatabaseManager.Write(obj, this.runId);
            }

            foreach (var endpoint in properties.GetActiveUdpListeners())
            {
                var obj = new OpenPortObject()
                {
                    family = endpoint.AddressFamily.ToString(),
                    address = endpoint.Address.ToString(),
                    port = endpoint.Port.ToString(),
                    type = "udp"
                };
                foreach (ProcessPort p in Win32ProcessPorts.ProcessPortMap.FindAll(x => x.PortNumber == endpoint.Port))
                {
                    obj.processName = p.ProcessName;
                }

                DatabaseManager.Write(obj, this.runId);
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
                    line = line.ToLower();
                    if (!line.Contains("listen"))
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
                            family = parts[0],//@TODO: Determine IPV4 vs IPv6 via looking at the address
                            address = address,
                            port = port,
                            type = parts[0]
                        };
                        DatabaseManager.Write(obj, this.runId);
                    }
                }
            }
            catch(Exception e)
            {
                Log.Warning(Strings.Get("Err_Iproute2"));
                Logger.DebugException(e);
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
                    var line = _line.ToLower();
                    if (!line.Contains("listen"))
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
                            family = parts[4],
                            address = address,
                            port = port,
                            type = parts[7],
                            processName = parts[0]
                        };
                        try
                        {
                            DatabaseManager.Write(obj, this.runId);

                        }
                        catch (Exception e)
                        {
                            Logger.DebugException(e);
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Log.Error(Strings.Get("Err_Lsof"));
                Logger.DebugException(e);
            }
        }
    }
}
