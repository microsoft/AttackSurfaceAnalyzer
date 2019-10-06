// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using WindowsFirewallHelper;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects metadata from the local firewall.
    /// </summary>
    public class FirewallCollector : BaseCollector
    {
        public FirewallCollector(string runId)
        {
            this.RunId = runId;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        /// <summary>
        /// Uses a library to access the Windows Firewall.
        /// </summary>
        public void ExecuteWindows()
        {
            foreach (IFirewallRule rule in FirewallManager.Instance.Rules.ToArray())
            {
                try
                {
                    var obj = new FirewallObject()
                    {
                        Action = rule.Action,
                        ApplicationName = rule.ApplicationName,
                        Direction = rule.Direction,
                        FriendlyName = rule.FriendlyName,
                        IsEnable = rule.IsEnable,
                        LocalPortType = rule.LocalPortType,
                        Name = rule.Name,
                        Profiles = rule.Profiles,
                        Protocol = rule.Protocol.ProtocolNumber.ToString(CultureInfo.InvariantCulture),
                        Scope = rule.Scope,
                        ServiceName = rule.ServiceName
                    };
                    obj.LocalAddresses.AddRange(rule.LocalAddresses.ToList().ConvertAll(address => address.ToString()));
                    obj.LocalPorts.AddRange(rule.LocalPorts.ToList().ConvertAll(port => port.ToString(CultureInfo.InvariantCulture)));
                    obj.RemoteAddresses.AddRange(rule.RemoteAddresses.ToList().ConvertAll(address => address.ToString()));
                    obj.RemotePorts.AddRange(rule.RemotePorts.ToList().ConvertAll(port => port.ToString(CultureInfo.InvariantCulture)));
                    DatabaseManager.Write(obj, RunId);
                }
                catch (Exception e)
                {
                    Log.Debug(e,rule.FriendlyName);
                }
            }
        }

        /// <summary>
        /// Dumps from iptables.
        /// </summary>
        public void ExecuteLinux()
        {
            var result = ExternalCommandRunner.RunExternalCommand("iptables", "-S");

            var lines = new List<string>(result.Split('\n'));

            Dictionary<string, FirewallAction> defaultPolicies = new Dictionary<string, FirewallAction>();

            foreach (var line in lines)
            {
                if (line.StartsWith("-P"))
                {
                    var chainName = line.Split(' ')[1];
                    defaultPolicies.Add(chainName, line.Contains("ACCEPT") ? FirewallAction.Allow : FirewallAction.Block);
                    var obj = new FirewallObject()
                    {
                        Action = defaultPolicies[chainName],
                        FriendlyName = $"Default {chainName} policy",
                        Name = $"Default {chainName} policy",
                        Scope = FirewallScope.All
                    };
                    if (!chainName.Equals("FORWARD"))
                    {
                        obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                    }

                    DatabaseManager.Write(obj, RunId);
                }
                else if (line.StartsWith("-A"))
                {
                    var splits = line.Split(' ');
                    var chainName = splits[1];


                    var obj = new FirewallObject()
                    {
                        Action = (splits[Array.IndexOf(splits, "-j") + 1] == "ACCEPT") ? FirewallAction.Allow : FirewallAction.Block,
                        FriendlyName = line,
                        Name = line,
                        Scope = FirewallScope.All,
                        Protocol = splits[Array.IndexOf(splits, "-p") + 1]
                    };

                    if (Array.IndexOf(splits, "--dport") > 0)
                    {
                        obj.RemotePorts.Add(splits[Array.IndexOf(splits, "--dport") + 1]);
                    }

                    if (Array.IndexOf(splits, "-d") > 0)
                    {
                        obj.RemoteAddresses.Add(splits[Array.IndexOf(splits, "-d") + 1]);
                    }

                    if (Array.IndexOf(splits, "-s") > 0)
                    {
                        obj.LocalAddresses.Add(splits[Array.IndexOf(splits, "-s") + 1]);
                    }

                    if (Array.IndexOf(splits, "--sport") > 0)
                    {
                        obj.LocalPorts.Add(splits[Array.IndexOf(splits, "--sport") + 1]);
                    }

                    if (!chainName.Equals("FORWARD"))
                    {
                        obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                    }

                    DatabaseManager.Write(obj, RunId);
                }
            }
        }

        /// <summary>
        /// Talks to socketfilterfw
        /// </summary>
        public void ExecuteMacOs()
        {
            // Example output: "Firewall is enabled. (State = 1)"
            var result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate");
            var enabled = result.Contains("1");
            var obj = new FirewallObject()
            {
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Inbound,
                IsEnable = enabled,
                FriendlyName = "Firewall Enabled",
                Name = "Firewall Enabled",
                Scope = FirewallScope.All
            };
            DatabaseManager.Write(obj, RunId);

            // Example output: "Stealth mode disabled"
            result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate");
            obj = new FirewallObject()
            {
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Contains("enabled"),
                FriendlyName = "Stealth Mode",
                Name = "Stealth Mode",
                Scope = FirewallScope.All
            };
            DatabaseManager.Write(obj, RunId);

            /* Example Output:
             * Automatically allow signed built-in software ENABLED
             * Automatically allow downloaded signed software ENABLED */
            result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getallowsigned");
            obj = new FirewallObject()
            {
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Split('\n')[0].Contains("ENABLED"),
                FriendlyName = "Allow signed built-in software",
                Name = "Allow signed built-in software",
                Scope = FirewallScope.All
            };
            DatabaseManager.Write(obj, RunId);

            obj = new FirewallObject()
            {
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Split('\n')[1].Contains("ENABLED"),
                FriendlyName = "Allow downloaded signed software",
                Name = "Allow downloaded signed software",
                Scope = FirewallScope.All
            };
            DatabaseManager.Write(obj, RunId);

            /* Example Output:
ALF: total number of apps = 2 

1 :  /Applications/AppName.app 
 ( Allow incoming connections ) 

2 :  /Applications/AppName2.app 
 ( Block incoming connections ) */
            result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps");
            string appName = "";
            Regex startsWithNumber = new Regex("^[1-9]");
            var lines = new List<string>(result.Split('\n'));
            if (lines.Any())
            {
                lines = lines.Skip(2).ToList();
                foreach (var line in lines)
                {
                    if (startsWithNumber.IsMatch(line))
                    {
                        appName = line.Substring(line.IndexOf('/'));
                    }
                    else if (line.Contains("incoming connections"))
                    {
                        obj = new FirewallObject()
                        {
                            Action = (line.Contains("Allow")) ? FirewallAction.Allow : FirewallAction.Block,
                            Direction = FirewallDirection.Inbound,
                            FriendlyName = appName,
                            Name = appName,
                            Scope = FirewallScope.All
                        };
                        DatabaseManager.Write(obj, RunId);
                    }
                }
            }
        }

        public override void ExecuteInternal()
        {
if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux();
            }
        }
    }
}

