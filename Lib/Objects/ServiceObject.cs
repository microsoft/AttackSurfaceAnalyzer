// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System;
using MessagePack;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class ServiceObject : CollectObject
    {
        [JsonConstructor]
        public ServiceObject(string Name)
        {
            this.Name = Name;
        }
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.SERVICE;
        [Key(1)]
        public bool? AcceptPause { get; set; }
        [Key(2)]
        public bool? AcceptStop { get; set; }
        [Key(3)]
        public string? Caption { get; set; }
        [Key(4)]
        public uint? CheckPoint { get; set; }
        [Key(5)]
        public string? CreationClassName { get; set; }
        [Key(6)]
        public bool? DelayedAutoStart { get; set; }
        [Key(7)]
        public string? Description { get; set; }
        [Key(8)]
        public bool? DesktopInteract { get; set; }
        [Key(9)]
        public string? DisplayName { get; set; }
        [Key(10)]
        public string? ErrorControl { get; set; }
        [Key(11)]
        public uint? ExitCode { get; set; }

        [IgnoreMember]
        public override string Identity => Name;

        [Key(12)]
        public DateTime InstallDate { get; set; }
        [Key(0)]
        public string Name { get; set; }
        [Key(13)]
        public string? PathName { get; set; }
        [Key(14)]
        public uint? ProcessId { get; set; }
        [Key(15)]
        public uint? ServiceSpecificExitCode { get; set; }
        [Key(16)]
        public string? ServiceType { get; set; }
        [Key(17)]
        public bool? Started { get; set; }
        [Key(18)]
        public string? StartMode { get; set; }
        [Key(19)]
        public string? StartName { get; set; }
        [Key(20)]
        public string? State { get; set; }
        [Key(21)]
        public string? Status { get; set; }
        [Key(22)]
        public string? SystemCreationClassName { get; set; }
        [Key(23)]
        public string? SystemName { get; set; }
        [Key(24)]
        public uint? TagId { get; set; }
        [Key(25)]
        public uint? WaitHint { get; set; }
    }
}