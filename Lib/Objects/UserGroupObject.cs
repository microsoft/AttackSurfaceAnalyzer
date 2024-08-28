// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class GroupAccountObject : CollectObject
    {
        public GroupAccountObject(string Name)
        {
            this.Name = Name;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.GROUP;

        [ProtoMember(1)]
        public string? Caption { get; set; }
        [ProtoMember(2)]
        public string? Description { get; set; }
        [ProtoMember(3)]
        public string? Domain { get; set; }

        public override string Identity
        {
            get
            {
                return (Domain == null) ? Name : $"{Domain}\\{Name}";
            }
        }

        [ProtoMember(4)]
        public string? InstallDate { get; set; }
        [ProtoMember(5)]
        public bool? LocalAccount { get; set; }
        [ProtoMember(6)]
        public string Name { get; set; }
        [ProtoMember(7)]
        public Dictionary<string, string>? Properties { get; set; }
        [ProtoMember(8)]
        public string? SID { get; set; }
        [ProtoMember(9)]
        public int? SIDType { get; set; }
        [ProtoMember(10)]
        public string? Status { get; set; }
        [ProtoMember(11)]
        public List<string> Users { get; set; } = new List<string>();
    }
}