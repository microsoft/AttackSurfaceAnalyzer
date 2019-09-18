// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
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
            this.runId = runId;
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
                        LocalAddresses = rule.LocalAddresses.ToList().ConvertAll(address => address.ToString()),
                        LocalPorts = rule.LocalPorts.ToList().ConvertAll(port => port.ToString()),
                        LocalPortType = rule.LocalPortType,
                        Name = rule.Name,
                        Profiles = rule.Profiles,
                        Protocol = rule.Protocol.ProtocolNumber.ToString(),
                        RemoteAddresses = rule.RemoteAddresses.ToList().ConvertAll(address => address.ToString()),
                        RemotePorts = rule.RemotePorts.ToList().ConvertAll(port => port.ToString()),
                        Scope = rule.Scope,
                        ServiceName = rule.ServiceName
                    };
                    DatabaseManager.Write(obj, runId);
                }
                catch(Exception e)
                {
                    Logger.DebugException(e);
                    Log.Debug(rule.FriendlyName);
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
                        FriendlyName = string.Format("Default {0} policy", chainName),
                        Name = string.Format("Default {0} policy", chainName),
                        Scope = FirewallScope.All
                    };
                    if (!chainName.Equals("FORWARD"))
                    {
                        obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                    }

                    DatabaseManager.Write(obj, runId);
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
                        obj.RemotePorts = new List<string>() { splits[Array.IndexOf(splits, "--dport") + 1] };
                    }

                    if (Array.IndexOf(splits, "-d") > 0)
                    {
                        obj.RemoteAddresses = new List<string>() { splits[Array.IndexOf(splits, "-d") + 1] };
                    }

                    if (Array.IndexOf(splits, "-s") > 0)
                    {
                        obj.LocalAddresses = new List<string>() { splits[Array.IndexOf(splits, "-s") + 1] };
                    }

                    if (Array.IndexOf(splits, "--sport") > 0)
                    {
                        obj.LocalPorts = new List<string>() { splits[Array.IndexOf(splits, "--sport") + 1] };
                    }

                    if (!chainName.Equals("FORWARD"))
                    {
                        obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                    }

                    DatabaseManager.Write(obj, runId);
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
            DatabaseManager.Write(obj, runId);

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
            DatabaseManager.Write(obj, runId);

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
            DatabaseManager.Write(obj, runId);

            obj = new FirewallObject()
            {
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Split('\n')[1].Contains("ENABLED"),
                FriendlyName = "Allow downloaded signed software",
                Name = "Allow downloaded signed software",
                Scope = FirewallScope.All
            };
            DatabaseManager.Write(obj, runId);

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
            if (lines.Count() > 0)
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
                        DatabaseManager.Write(obj, runId);
                    }
                }
            }
        }

        public override void ExecuteInternal()
        {
            if (!CanRunOnPlatform())
            {
                return;
            }

            _ = DatabaseManager.Transaction;


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

            DatabaseManager.Commit();
        }
    }
}

