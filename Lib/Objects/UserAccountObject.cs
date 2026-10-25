// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System.Collections.Generic;
using System.Globalization;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class UserAccountObject : CollectObject
    {
        public UserAccountObject(string Name)
        {
            this.Name = Name;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.USER;

        [ProtoMember(1)]
        public string? AccountType { get; set; }
        [ProtoMember(2)]
        public string? Caption { get; set; }
        [ProtoMember(3)]
        public string? Description { get; set; }
        [ProtoMember(4)]
        public string? Disabled { get; set; }
        [ProtoMember(5)]
        public string? Domain { get; set; }
        [ProtoMember(6)]
        public string? FullName { get; set; }
        [ProtoMember(7)]
        public string? GID { get; set; }
        [ProtoMember(8)]
        public List<string> Groups { get; set; } = new List<string>();
        [ProtoMember(9)]
        public bool? Hidden { get; set; }
        [ProtoMember(10)]
        public string? HomeDirectory { get; set; }

        public override string Identity
        {
            get
            {
                return string.Format(CultureInfo.InvariantCulture, "{0}{1}", "User: ", (Domain == null) ? Name : $"{Domain}\\{Name}");
            }
        }

        [ProtoMember(11)]
        public string? Inactive { get; set; }
        [ProtoMember(12)]
        public string? InstallDate { get; set; }
        [ProtoMember(13)]
        public string? LocalAccount { get; set; }
        [ProtoMember(14)]
        public string? Lockout { get; set; }
        [ProtoMember(15)]
        public string Name { get; set; }
        [ProtoMember(16)]
        public string? PasswordChangeable { get; set; }
        [ProtoMember(17)]
        public string? PasswordExpires { get; set; }
        [ProtoMember(18)]
        public string? PasswordRequired { get; set; }
        [ProtoMember(19)]
        public string? PasswordStorageAlgorithm { get; set; }
        [ProtoMember(20)]
        public bool? Privileged { get; set; }
        [ProtoMember(21)]
        public Dictionary<string, string>? Properties { get; set; }
        [ProtoMember(22)]
        public string? Shell { get; set; }
        [ProtoMember(23)]
        public string? SID { get; set; }
        [ProtoMember(24)]
        public string? UID { get; set; }
    }
}