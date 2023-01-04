// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using MessagePack;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    [MessagePackObject]
    public class TpmObject : CollectObject
    {
        public TpmObject(string Location)
        {
            this.Location = Location;
        }
        [IgnoreMember]
        public override RESULT_TYPE ResultType => RESULT_TYPE.TPM;

        [Key(1)]
        public List<AlgProperty> Algorithms { get; set; } = new List<AlgProperty>();
        [Key(2)]
        public List<TpmCc> Commands { get; set; } = new List<TpmCc>();

        [IgnoreMember]
        public override string Identity => Location;

        [Key(0)]
        public string Location { get; }
        [Key(3)]
        public string? Manufacturer { get; set; }
        [Key(4)]
        public List<AsaNvIndex> NV { get; set; } = new List<AsaNvIndex>();
        [Key(5)]
        public Dictionary<(TpmAlgId, uint), byte[]> PCRs { get; set; } = new Dictionary<(TpmAlgId, uint), byte[]>();
        [Key(6)]
        public List<CryptographicKeyObject> PersistentKeys { get; set; } = new List<CryptographicKeyObject>();
        [Key(7)]
        public List<CryptographicKeyObject> RandomKeys { get; set; } = new List<CryptographicKeyObject>();
        [Key(8)]
        public DateTime TpmSpecDate { get; set; }
        [Key(9)]
        public string? Version { get; set; }
    }
}