// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract]
    public class DriverObject : CollectObject
    {
        public DriverObject(string Name)
        {
            this.Name = Name;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.DRIVER;
        [ProtoMember(1)]
        public bool? AcceptPause { get; set; }
        [ProtoMember(2)]
        public bool? AcceptStop { get; set; }
        [ProtoMember(3)]
        public string? Address { get; set; }
        [ProtoMember(4)]
        public string? Architecture { get; set; }
        [ProtoMember(5)]
        public long? BSS { get; set; }
        [ProtoMember(6)]
        public long? Code { get; set; }
        [ProtoMember(7)]
        public string? Description { get; set; }
        [ProtoMember(8)]
        public string? DisplayName { get; set; }
        [ProtoMember(9)]
        public string? DriverType { get; set; }

        public override string Identity
        {
            get
            {
                return Name;
            }
        }

        [ProtoMember(10)]
        public int? Index { get; set; }
        [ProtoMember(11)]
        public long? Init { get; set; }
        [ProtoMember(12)]
        public DateTime? LinkDate { get; set; }
        [ProtoMember(13)]
        public List<string>? LinkedAgainst { get; set; }
        [ProtoMember(14)]
        public string Name { get; set; }
        [ProtoMember(15)]
        public long? PagedPool { get; set; }
        [ProtoMember(16)]
        public string? Path { get; set; }
        [ProtoMember(17)]
        public Dictionary<string, string>? Properties { get; set; }
        [ProtoMember(18)]
        public int? Refs { get; set; }
        [ProtoMember(19)]
        public Signature? Signature { get; set; }
        [ProtoMember(20)]
        public string? Size { get; set; }
        [ProtoMember(21)]
        public string? StartMode { get; set; }
        [ProtoMember(22)]
        public string? State { get; set; }
        [ProtoMember(23)]
        public string? Status { get; set; }
        [ProtoMember(24)]
        public string? UUID { get; set; }
        [ProtoMember(25)]
        public string? Version { get; set; }
        [ProtoMember(26)]
        public string? Wired { get; set; }
    }
}