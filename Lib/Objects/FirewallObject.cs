// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Types;
using WindowsFirewallHelper;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FirewallObject : CollectObject
    {
        //
        // Summary:
        //     Gets or sets the action that the rules defines
        public FirewallAction Action { get; set; }
        //
        // Summary:
        //     Gets or sets the name of the application that this rule is about
        public string ApplicationName { get; set; }
        //
        // Summary:
        //     Gets or sets the data direction that the rule applies to
        public FirewallDirection Direction { get; set; }
        //
        // Summary:
        //     Gets or sets the resolved name of the rule
        public string FriendlyName { get; set; }
        //
        // Summary:
        //     Gets or sets a Boolean value indicating if this rule is active
        public bool IsEnable { get; set; }
        //
        // Summary:
        //     Gets or sets the local addresses that the rule applies to
        public List<string> LocalAddresses { get; set; }
        //
        // Summary:
        //     Gets or sets the local ports that the rule applies to
        public List<string> LocalPorts { get; set; }
        //
        // Summary:
        //     Gets or sets the type of local ports that the rules applies to
        public FirewallPortType LocalPortType { get; set; }
        //
        // Summary:
        //     Gets or sets the name of the rule in native format w/o auto string resolving
        public string Name { get; set; }
        //
        // Summary:
        //     Gets the profiles that this rule belongs to
        public FirewallProfiles Profiles { get; set; }
        //
        // Summary:
        //     Gets or sets the protocol that the rule applies to
        public int Protocol { get; set; }
        //
        // Summary:
        //     Gets or sets the remote addresses that the rule applies to
        public List<string> RemoteAddresses { get; set; }
        //
        // Summary:
        //     Gets or sets the remote ports that the rule applies to
        public List<string> RemotePorts { get; set; }
        //
        // Summary:
        //     Gets or sets the scope that the rule applies to
        public FirewallScope Scope { get; set; }
        //
        // Summary:
        //     Gets or sets the name of the service that this rule is about
        public string ServiceName { get; set; }

        public FirewallObject()
        {
            ResultType = RESULT_TYPE.FIREWALL;
        }

        public override string Identity
        {
            get
            {
                return String.Format("{0} - {1} - {2} - {3} - {4} - {5}", FriendlyName, Direction, Protocol, ApplicationName, Profiles, Name);
            }
        }
    }
}
