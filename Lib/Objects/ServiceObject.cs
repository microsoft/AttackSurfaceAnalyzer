// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class ServiceObject : CollectObject
    {
        [JsonConstructor]
        public ServiceObject(string Name)
        {
            this.Name = Name;
            ResultType = RESULT_TYPE.SERVICE;
        }

        public bool? AcceptPause { get; set; }
        public bool? AcceptStop { get; set; }
        public string? Caption { get; set; }
        public uint? CheckPoint { get; set; }
        public string? CreationClassName { get; set; }
        public bool? DelayedAutoStart { get; set; }
        public string? Description { get; set; }
        public bool? DesktopInteract { get; set; }
        public string? DisplayName { get; set; }
        public string? ErrorControl { get; set; }
        public uint? ExitCode { get; set; }

        public override string Identity
        {
            get
            {
                return Name;
            }
        }

        public DateTime InstallDate { get; set; }
        public string Name { get; set; }
        public string? PathName { get; set; }
        public uint? ProcessId { get; set; }
        public uint? ServiceSpecificExitCode { get; set; }
        public string? ServiceType { get; set; }
        public bool? Started { get; set; }
        public string? StartMode { get; set; }
        public string? StartName { get; set; }
        public string? State { get; set; }
        public string? Status { get; set; }
        public string? SystemCreationClassName { get; set; }
        public string? SystemName { get; set; }
        public uint? TagId { get; set; }
        public uint? WaitHint { get; set; }
    }
}