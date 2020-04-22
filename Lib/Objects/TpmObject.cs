// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Objects
{
    public class TpmObject : CollectObject
    {
        public Dictionary<string,byte[]> NV { get; set; }     

        public TpmObject()
        {
            ResultType = Types.RESULT_TYPE.TPM;
            NV = new Dictionary<string, byte[]>();
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