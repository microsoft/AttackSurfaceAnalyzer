// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CollectObject
    {
        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(JsonConvert.SerializeObject(this));
            }
        }
    }
}
