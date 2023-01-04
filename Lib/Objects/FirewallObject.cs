// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;
using MessagePack;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class FirewallObject : CollectObject
    {
        public FirewallObject(string Name)
        {
            this.Name = Name;
        }

        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.FIREWALL;
        
        /// <summary>
        ///     Gets or sets the action that the rules defines
        /// </summary>
        [Key(1)]
        public FirewallAction? Action { get; set; }

        /// <summary>
        ///     Gets or sets the name of the application that this rule is about
        /// </summary>
        [Key(2)]
        public string? ApplicationName { get; set; }

        /// <summary>
        ///     Gets or sets the data direction that the rule applies to
        /// </summary>
        [Key(3)]
        public FirewallDirection? Direction { get; set; }

        /// <summary>
        ///     Gets or sets the resolved name of the rule
        /// </summary>
        [Key(4)]
        public string? FriendlyName { get; set; }

        /// <summary>
        ///     $"{FriendlyName} - {Direction} - {Protocol} - {ApplicationName} - {Profiles} - {Name}
        /// </summary>
        [IgnoreMember]
        public override string Identity => $"{FriendlyName} - {Direction} - {Protocol} - {ApplicationName} - {Profiles} - {Name}";

        /// <summary>
        ///     Gets or sets a Boolean value indicating if this rule is active
        /// </summary>
        [Key(5)]
        public bool? IsEnable { get; set; }

        /// <summary>
        ///     Gets or sets the local addresses that the rule applies to
        /// </summary>
        [Key(6)]
        public List<string>? LocalAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the local ports that the rule applies to
        /// </summary>
        [Key(7)]
        public List<string>? LocalPorts { get; set; }

        /// <summary>
        ///     Gets or sets the type of local ports that the rules applies to
        /// </summary>
        [Key(8)]
        public FirewallPortType? LocalPortType { get; set; }

        /// <summary>
        ///     Gets or sets the name of the rule in native format w/o auto string resolving
        /// </summary>
        [Key(0)]
        public string Name { get; set; }

        /// <summary>
        ///     Gets the profiles that this rule belongs to
        /// </summary>
        [Key(9)]
        public FirewallProfiles? Profiles { get; set; }

        /// <summary>
        ///     Gets or sets the protocol that the rule applies to
        /// </summary>
        [Key(10)]
        public string? Protocol { get; set; }

        /// <summary>
        ///     Gets or sets the remote addresses that the rule applies to
        /// </summary>
        [Key(11)]
        public List<string>? RemoteAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the remote ports that the rule applies to
        /// </summary>
        [Key(12)]
        public List<string>? RemotePorts { get; set; }

        /// <summary>
        ///     Gets or sets the scope that the rule applies to
        /// </summary>
        [Key(13)]
        public FirewallScope? Scope { get; set; }

        /// <summary>
        ///     Gets or sets the name of the service that this rule is about
        /// </summary>
        [Key(14)]
        public string? ServiceName { get; set; }
    }
}