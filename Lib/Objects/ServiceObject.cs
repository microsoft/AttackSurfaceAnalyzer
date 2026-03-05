// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using ProtoBuf;
using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class ServiceObject : CollectObject
    {
        [JsonConstructor]
        public ServiceObject(string Name)
        {
            this.Name = Name;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.SERVICE;

        [ProtoMember(1)]
        public bool? AcceptPause { get; set; }
        [ProtoMember(2)]
        public bool? AcceptStop { get; set; }
        [ProtoMember(3)]
        public string? Caption { get; set; }
        [ProtoMember(4)]
        public uint? CheckPoint { get; set; }
        [ProtoMember(5)]
        public string? CreationClassName { get; set; }
        [ProtoMember(6)]
        public bool? DelayedAutoStart { get; set; }
        [ProtoMember(7)]
        public string? Description { get; set; }
        [ProtoMember(8)]
        public bool? DesktopInteract { get; set; }
        [ProtoMember(9)]
        public string? DisplayName { get; set; }
        [ProtoMember(10)]
        public string? ErrorControl { get; set; }
        [ProtoMember(11)]
        public uint? ExitCode { get; set; }

        public override string Identity
        {
            get
            {
                return Name;
            }
        }

        [ProtoMember(12)]
        public DateTime InstallDate { get; set; }
        [ProtoMember(13)]
        public string Name { get; set; }
        [ProtoMember(14)]
        public string? PathName { get; set; }
        [ProtoMember(15)]
        public uint? ProcessId { get; set; }
        [ProtoMember(16)]
        public uint? ServiceSpecificExitCode { get; set; }
        [ProtoMember(17)]
        public string? ServiceType { get; set; }
        [ProtoMember(18)]
        public bool? Started { get; set; }
        [ProtoMember(19)]
        public string? StartMode { get; set; }
        [ProtoMember(20)]
        public string? StartName { get; set; }
        [ProtoMember(21)]
        public string? State { get; set; }
        [ProtoMember(22)]
        public string? Status { get; set; }
        [ProtoMember(23)]
        public string? SystemCreationClassName { get; set; }
        [ProtoMember(24)]
        public string? SystemName { get; set; }
        [ProtoMember(25)]
        public uint? TagId { get; set; }
        [ProtoMember(26)]
        public uint? WaitHint { get; set; }
    }
}