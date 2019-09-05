// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Linq;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Utils;
using AttackSurfaceAnalyzer.Objects;
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
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
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

            DatabaseManager.Commit();
            Stop();
        }
    }
}