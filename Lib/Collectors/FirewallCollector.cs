// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Linq;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Utils;
using AttackSurfaceAnalyzer.Objects;
using WindowsFirewallHelper;
using System.Collections.Generic;
using System.Text.RegularExpressions;

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
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            {
                return;
            }

            Start();
            _ = DatabaseManager.Transaction;


            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                foreach (IFirewallRule rule in FirewallManager.Instance.Rules.ToArray())
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
                        Protocol = int.Parse(rule.Protocol.ProtocolNumber.ToString()),
                        RemoteAddresses = rule.RemoteAddresses.ToList().ConvertAll(address => address.ToString()),
                        RemotePorts = rule.RemotePorts.ToList().ConvertAll(port => port.ToString()),
                        Scope = rule.Scope,
                        ServiceName = rule.ServiceName
                    };
                    DatabaseManager.Write(obj, runId);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
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
                                Action = (line.Contains("Allow"))?FirewallAction.Allow:FirewallAction.Block,
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

            DatabaseManager.Commit();
            Stop();
        }
    }
}
 
 