// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class GroupAccountObject : CollectObject
    {
        public GroupAccountObject(string Name)
        {
            this.Name = Name;
        }
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.GROUP;
        [Key(1)]
        public string? Caption { get; set; }
        [Key(2)]
        public string? Description { get; set; }
        [Key(3)]
        public string? Domain { get; set; }

        [IgnoreMember]
        public override string Identity => (Domain == null) ? Name : $"{Domain}\\{Name}";

        [Key(4)]
        public string? InstallDate { get; set; }
        [Key(5)]
        public bool? LocalAccount { get; set; }
        [Key(0)]
        public string Name { get; set; }
        [Key(6)]
        public Dictionary<string, string>? Properties { get; set; }
        [Key(7)]
        public string? SID { get; set; }
        [Key(8)]
        public int? SIDType { get; set; }
        [Key(9)]
        public string? Status { get; set; }
        [Key(10)]
        public List<string> Users { get; set; } = new List<string>();
    }
}