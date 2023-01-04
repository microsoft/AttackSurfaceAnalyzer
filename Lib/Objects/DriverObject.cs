// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class DriverObject : CollectObject
    {
        public DriverObject(string Name)
        {
            this.Name = Name;
        }
        
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.DRIVER;
        [Key(1)]
        public bool? AcceptPause { get; set; }
        [Key(2)]
        public bool? AcceptStop { get; set; }
        [Key(3)]
        public string? Address { get; set; }
        [Key(4)]
        public string? Architecture { get; set; }
        [Key(5)]
        public long? BSS { get; set; }
        [Key(6)]
        public long? Code { get; set; }
        [Key(7)]
        public string? Description { get; set; }
        [Key(8)]
        public string? DisplayName { get; set; }
        [Key(9)]
        public string? DriverType { get; set; }

        [IgnoreMember]
        public override string Identity => Name;

        [Key(10)]
        public int? Index { get; set; }
        [Key(11)]
        public long? Init { get; set; }
        [Key(12)]
        public DateTime? LinkDate { get; set; }
        [Key(13)]
        public List<string>? LinkedAgainst { get; set; }
        [Key(0)]
        public string Name { get; set; }
        [Key(14)]
        public long? PagedPool { get; set; }
        [Key(15)]
        public string? Path { get; set; }
        [Key(16)]
        public Dictionary<string, string>? Properties { get; set; }
        [Key(17)]
        public int? Refs { get; set; }
        [Key(18)]
        public Signature? Signature { get; set; }
        [Key(19)]
        public string? Size { get; set; }

        [Key(20)]
        public string? StartMode { get; set; }
        [Key(21)]
        public string? State { get; set; }
        [Key(22)]
        public string? Status { get; set; }
        [Key(23)]
        public string? UUID { get; set; }
        [Key(24)]
        public string? Version { get; set; }
        [Key(25)]
        public string? Wired { get; set; }
    }
}