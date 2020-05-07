// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Newtonsoft.Json;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class TpmObject : CollectObject
    {
        public Dictionary<string, byte[]> NV { get; set; }

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