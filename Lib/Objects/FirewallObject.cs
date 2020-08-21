// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class FirewallObject : CollectObject
    {
        public FirewallObject(string Name)
        {
            ResultType = RESULT_TYPE.FIREWALL;
            this.Name = Name;
        }

        /// <summary>
        ///     Gets or sets the action that the rules defines
        /// </summary>
        public FirewallAction? Action { get; set; }

        /// <summary>
        ///     Gets or sets the name of the application that this rule is about
        /// </summary>
        public string? ApplicationName { get; set; }

        /// <summary>
        ///     Gets or sets the data direction that the rule applies to
        /// </summary>
        public FirewallDirection? Direction { get; set; }

        /// <summary>
        ///     Gets or sets the resolved name of the rule
        /// </summary>
        public string? FriendlyName { get; set; }

        /// <summary>
        ///     $"{FriendlyName} - {Direction} - {Protocol} - {ApplicationName} - {Profiles} - {Name}
        /// </summary>
        public override string Identity
        {
            get
            {
                return $"{FriendlyName} - {Direction} - {Protocol} - {ApplicationName} - {Profiles} - {Name}";
            }
        }

        /// <summary>
        ///     Gets or sets a Boolean value indicating if this rule is active
        /// </summary>
        public bool? IsEnable { get; set; }

        /// <summary>
        ///     Gets or sets the local addresses that the rule applies to
        /// </summary>
        public List<string>? LocalAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the local ports that the rule applies to
        /// </summary>
        public List<string>? LocalPorts { get; set; }

        /// <summary>
        ///     Gets or sets the type of local ports that the rules applies to
        /// </summary>
        public FirewallPortType? LocalPortType { get; set; }

        /// <summary>
        ///     Gets or sets the name of the rule in native format w/o auto string resolving
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        ///     Gets the profiles that this rule belongs to
        /// </summary>
        public FirewallProfiles? Profiles { get; set; }

        /// <summary>
        ///     Gets or sets the protocol that the rule applies to
        /// </summary>
        public string? Protocol { get; set; }

        /// <summary>
        ///     Gets or sets the remote addresses that the rule applies to
        /// </summary>
        public List<string>? RemoteAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the remote ports that the rule applies to
        /// </summary>
        public List<string>? RemotePorts { get; set; }

        /// <summary>
        ///     Gets or sets the scope that the rule applies to
        /// </summary>
        public FirewallScope? Scope { get; set; }

        /// <summary>
        ///     Gets or sets the name of the service that this rule is about
        /// </summary>
        public string? ServiceName { get; set; }
    }
}