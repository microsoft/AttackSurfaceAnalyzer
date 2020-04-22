// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Objects
{
    public class TpmObject : CollectObject
    {
        public Dictionary<byte[], object> NV { get; set; } = new Dictionary<byte[], object>();
        public Dictionary<(TpmAlgId, uint), byte[]> PCRs { get; set; } = new Dictionary<(TpmAlgId, uint), byte[]>();
        public List<CryptographicKeyObject> PersistentKeys { get; set; } = new List<CryptographicKeyObject>();
        public List<CryptographicKeyObject> RandomKeys { get; set; } = new List<CryptographicKeyObject>();
        public string? Manufacturer { get; set; }
        public DateTime TpmSpecDate { get; set; }
        public uint[] Version { get; }
        public string Location { get; set; }


        public TpmObject(uint[] Version, string Location)
        {
            ResultType = Types.RESULT_TYPE.TPM;
            this.Version = Version;
            this.Location = Location;
            // TODO: Transform the version into a readable string
        }

        public override string Identity
        {
            get
            {
                return Location;
            }
        }
    }
}