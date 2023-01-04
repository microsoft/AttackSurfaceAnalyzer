// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;
using System.Globalization;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class UserAccountObject : CollectObject
    {
        public UserAccountObject(string Name)
        {
            this.Name = Name;
        }
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.USER;

        [Key(1)]
        public string? AccountType { get; set; }
        [Key(2)]
        public string? Caption { get; set; }
        [Key(3)]
        public string? Description { get; set; }
        [Key(4)]
        public string? Disabled { get; set; }
        [Key(5)]
        public string? Domain { get; set; }
        [Key(6)]
        public string? FullName { get; set; }
        [Key(7)]
        public string? GID { get; set; }
        [Key(8)]
        public List<string> Groups { get; set; } = new List<string>();
        [Key(9)]
        public bool? Hidden { get; set; }
        [Key(10)]
        public string? HomeDirectory { get; set; }

        [IgnoreMember]
        public override string Identity => string.Format(CultureInfo.InvariantCulture, "{0}{1}", "User: ", (Domain == null) ? Name : $"{Domain}\\{Name}");

        [Key(11)]
        public string? Inactive { get; set; }
        [Key(12)]
        public string? InstallDate { get; set; }
        [Key(13)]
        public string? LocalAccount { get; set; }
        [Key(14)]
        public string? Lockout { get; set; }
        [Key(0)]
        public string Name { get; set; }
        [Key(15)]
        public string? PasswordChangeable { get; set; }
        [Key(16)]
        public string? PasswordExpires { get; set; }
        [Key(17)]
        public string? PasswordRequired { get; set; }
        [Key(18)]
        public string? PasswordStorageAlgorithm { get; set; }
        [Key(19)]
        public bool? Privileged { get; set; }
        [Key(20)]
        public Dictionary<string, string>? Properties { get; set; }
        [Key(21)]
        public string? Shell { get; set; }
        [Key(22)]
        public string? SID { get; set; }
        [Key(23)]
        public string? UID { get; set; }
    }
}