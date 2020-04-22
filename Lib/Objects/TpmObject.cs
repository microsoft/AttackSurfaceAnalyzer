// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Newtonsoft.Json;
using System.Collections.Generic;
using System;

namespace AttackSurfaceAnalyzer.Objects
{
    public class TpmObject : CollectObject
    {
        public Dictionary<string,byte[]> NV { get; set; }     
        public string Manufacturer { get; set; }
        public DateTime TpmSpecDate { get; set; }
        public uint[] Version { get; }

        public TpmObject(uint[] Version)
        {
            ResultType = Types.RESULT_TYPE.TPM;
            NV = new Dictionary<string, byte[]>();
            this.Version = Version;
            // TODO: Transform the version into a readable string
        }

        public override string Identity
        {
            get
            {
                return JsonConvert.SerializeObject(NV);
            }
        }
    }
}