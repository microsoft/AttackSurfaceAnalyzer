// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects metadata from the local firewall.
    /// </summary>
    public class FirewallCollector : BaseCollector
    {
        public FirewallCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ExecuteWindows(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                ExecuteMacOs(cancellationToken);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                ExecuteLinux(cancellationToken);
            }
        }

        /// <summary>
        ///     Dumps from iptables.
        /// </summary>
        internal void ExecuteLinux(CancellationToken cancellationToken)
        {
            if (ExternalCommandRunner.RunExternalCommand("iptables", "-S", out string result, out string _) == 0)
            {
                var lines = new List<string>(result.Split('\n'));

                Dictionary<string, FirewallAction> defaultPolicies = new Dictionary<string, FirewallAction>();

                foreach (var line in lines)
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

                    if (line.StartsWith("-P"))
                    {
                        var chainName = line.Split(' ')[1];
                        defaultPolicies.Add(chainName, line.Contains("ACCEPT") ? FirewallAction.Allow : FirewallAction.Block);
                        var obj = new FirewallObject($"Default {chainName} policy")
                        {
                            Action = defaultPolicies[chainName],
                            FriendlyName = $"Default {chainName} policy",
                            Scope = FirewallScope.All
                        };
                        if (!chainName.Equals("FORWARD"))
                        {
                            obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                        }

                        HandleChange(obj);
                    }
                    else if (line.StartsWith("-A"))
                    {
                        var splits = line.Split(' ');
                        var chainName = splits[1];

                        var obj = new FirewallObject(line)
                        {
                            Action = (splits[Array.IndexOf(splits, "-j") + 1] == "ACCEPT") ? FirewallAction.Allow : FirewallAction.Block,
                            FriendlyName = line,
                            Scope = FirewallScope.All,
                            Protocol = splits[Array.IndexOf(splits, "-p") + 1]
                        };

                        if (Array.IndexOf(splits, "--dport") > 0)
                        {
                            obj.RemotePorts = splits[Array.IndexOf(splits, "--dport") + 1].OfType<string>().ToList();
                        }

                        if (Array.IndexOf(splits, "-d") > 0)
                        {
                            obj.RemoteAddresses = splits[Array.IndexOf(splits, "-d") + 1].OfType<string>().ToList();
                        }

                        if (Array.IndexOf(splits, "-s") > 0)
                        {
                            obj.LocalAddresses = splits[Array.IndexOf(splits, "-s") + 1].OfType<string>().ToList();
                        }

                        if (Array.IndexOf(splits, "--sport") > 0)
                        {
                            obj.LocalPorts = splits[Array.IndexOf(splits, "--sport") + 1].OfType<string>().ToList();
                        }

                        if (!chainName.Equals("FORWARD"))
                        {
                            obj.Direction = chainName.Equals("INPUT") ? FirewallDirection.Inbound : FirewallDirection.Outbound;
                        }

                        HandleChange(obj);
                    }
                }
            }
        }

        /// <summary>
        ///     Talks to socketfilterfw
        /// </summary>
        internal void ExecuteMacOs(CancellationToken cancellationToken)
        {
            // Example output: "Firewall is enabled. (State = 1)"
            var result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate");
            var enabled = result.Contains("1");
            var obj = new FirewallObject("Firewall Enabled")
            {
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Inbound,
                IsEnable = enabled,
                FriendlyName = "Firewall Enabled",
                Scope = FirewallScope.All
            };
            HandleChange(obj);

            // Example output: "Stealth mode disabled"
            result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate");
            obj = new FirewallObject("Stealth Mode")
            {
                Action = FirewallAction.Block,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Contains("enabled"),
                FriendlyName = "Stealth Mode",
                Scope = FirewallScope.All
            };
            HandleChange(obj);

            /* Example Output:
             * Automatically allow signed built-in software ENABLED
             * Automatically allow downloaded signed software ENABLED */
            result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getallowsigned");
            obj = new FirewallObject("Allow signed built-in software")
            {
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Split('\n')[0].Contains("ENABLED"),
                FriendlyName = "Allow signed built-in software",
                Scope = FirewallScope.All
            };
            HandleChange(obj);

            obj = new FirewallObject("Allow downloaded signed software")
            {
                Action = FirewallAction.Allow,
                Direction = FirewallDirection.Inbound,
                IsEnable = result.Split('\n')[1].Contains("ENABLED"),
                FriendlyName = "Allow downloaded signed software",
                Scope = FirewallScope.All
            };
            HandleChange(obj);

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
                    if (cancellationToken.IsCancellationRequested) { return; }

                    if (startsWithNumber.IsMatch(line))
                    {
                        appName = line.Substring(line.IndexOf('/'));
                    }
                    else if (line.Contains("incoming connections"))
                    {
                        obj = new FirewallObject(appName)
                        {
                            Action = (line.Contains("Allow")) ? FirewallAction.Allow : FirewallAction.Block,
                            Direction = FirewallDirection.Inbound,
                            FriendlyName = appName,
                            Scope = FirewallScope.All
                        };
                        HandleChange(obj);
                    }
                }
            }
        }

        /// <summary>
        ///     Uses a library to access the Windows Firewall.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "The specific exceptions thrown by this library are not documented.")]
        internal void ExecuteWindows(CancellationToken cancellationToken)
        {
            try
            {
                foreach (IFirewallRule rule in FirewallManager.Instance.Rules)
                {
                    if (cancellationToken.IsCancellationRequested) { return; }

                    try
                    {
                        var obj = new FirewallObject(rule.Name)
                        {
                            Action = rule.Action,
                            ApplicationName = rule.ApplicationName,
                            Direction = rule.Direction,
                            FriendlyName = rule.FriendlyName,
                            IsEnable = rule.IsEnable,
                            LocalPortType = rule.LocalPortType,
                            Profiles = rule.Profiles,
                            Protocol = rule.Protocol.ProtocolNumber.ToString(CultureInfo.InvariantCulture),
                            Scope = rule.Scope,
                            ServiceName = rule.ServiceName
                        };
                        obj.LocalAddresses = rule.LocalAddresses.ToList().ConvertAll(address => address.ToString());
                        obj.LocalPorts = rule.LocalPorts.ToList().ConvertAll(port => port.ToString(CultureInfo.InvariantCulture));
                        obj.RemoteAddresses = rule.RemoteAddresses.ToList().ConvertAll(address => address.ToString());
                        obj.RemotePorts = rule.RemotePorts.ToList().ConvertAll(port => port.ToString(CultureInfo.InvariantCulture));
                        HandleChange(obj);
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e, "Exception hit while processing Firewall rules");
                    }
                }
            }
            catch (Exception e) when (
                e is COMException ||
                e is NotSupportedException)
            {
                Log.Warning(Strings.Get("CollectorNotSupportedOnPlatform"), GetType().ToString());
            }
        }
    }
}