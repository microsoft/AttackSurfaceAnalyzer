// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System.Collections.Generic;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class FirewallObject : CollectObject
    {
        public FirewallObject(string Name)
        {
            this.Name = Name;
        }

        public override RESULT_TYPE ResultType => RESULT_TYPE.FIREWALL;


        /// <summary>
        ///     Gets or sets the action that the rules defines
        /// </summary>
        [ProtoMember(1)]
        public FirewallAction? Action { get; set; }

        /// <summary>
        ///     Gets or sets the name of the application that this rule is about
        /// </summary>
        [ProtoMember(2)]
        public string? ApplicationName { get; set; }

        /// <summary>
        ///     Gets or sets the data direction that the rule applies to
        /// </summary>
        [ProtoMember(3)]
        public FirewallDirection? Direction { get; set; }

        /// <summary>
        ///     Gets or sets the resolved name of the rule
        /// </summary>
        [ProtoMember(4)]
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
        [ProtoMember(5)]
        public bool? IsEnable { get; set; }

        /// <summary>
        ///     Gets or sets the local addresses that the rule applies to
        /// </summary>
        [ProtoMember(6)]
        public List<string>? LocalAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the local ports that the rule applies to
        /// </summary>
        [ProtoMember(7)]
        public List<string>? LocalPorts { get; set; }

        /// <summary>
        ///     Gets or sets the type of local ports that the rules applies to
        /// </summary>
        [ProtoMember(8)]
        public FirewallPortType? LocalPortType { get; set; }

        /// <summary>
        ///     Gets or sets the name of the rule in native format w/o auto string resolving
        /// </summary>
        [ProtoMember(9)]
        public string Name { get; set; }

        /// <summary>
        ///     Gets the profiles that this rule belongs to
        /// </summary>
        [ProtoMember(10)]
        public FirewallProfiles? Profiles { get; set; }

        /// <summary>
        ///     Gets or sets the protocol that the rule applies to
        /// </summary>
        [ProtoMember(11)]
        public string? Protocol { get; set; }

        /// <summary>
        ///     Gets or sets the remote addresses that the rule applies to
        /// </summary>
        [ProtoMember(12)]
        public List<string>? RemoteAddresses { get; set; }

        /// <summary>
        ///     Gets or sets the remote ports that the rule applies to
        /// </summary>
        [ProtoMember(13)]
        public List<string>? RemotePorts { get; set; }

        /// <summary>
        ///     Gets or sets the scope that the rule applies to
        /// </summary>
        [ProtoMember(14)]
        public FirewallScope? Scope { get; set; }

        /// <summary>
        ///     Gets or sets the name of the service that this rule is about
        /// </summary>
        [ProtoMember(15)]
        public string? ServiceName { get; set; }
    }
}