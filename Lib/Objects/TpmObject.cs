// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using ProtoBuf;
using System;
using System.Collections.Generic;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [ProtoContract(SkipConstructor = true)]
    public class TpmObject : CollectObject
    {
        public TpmObject(string Location)
        {
            this.Location = Location;
        }
        public override RESULT_TYPE ResultType => RESULT_TYPE.TPM;

        [ProtoMember(1)]
        public List<AlgProperty> Algorithms { get; set; } = new List<AlgProperty>();
        [ProtoMember(2)]
        public List<TpmCc> Commands { get; set; } = new List<TpmCc>();

        public override string Identity
        {
            get
            {
                return Location;
            }
        }

        [ProtoMember(3)]
        public string Location { get; }
        [ProtoMember(4)]
        public string? Manufacturer { get; set; }
        [ProtoMember(5)]
        public List<AsaNvIndex> NV { get; set; } = new List<AsaNvIndex>();
        [ProtoMember(6)]
        public Dictionary<(TpmAlgId, uint), byte[]> PCRs { get; set; } = new Dictionary<(TpmAlgId, uint), byte[]>();
        [ProtoMember(7)]
        public List<CryptographicKeyObject> PersistentKeys { get; set; } = new List<CryptographicKeyObject>();
        [ProtoMember(8)]
        public List<CryptographicKeyObject> RandomKeys { get; set; } = new List<CryptographicKeyObject>();
        [ProtoMember(9)]
        public DateTime TpmSpecDate { get; set; }
        [ProtoMember(10)]
        public string? Version { get; set; }
    }
}