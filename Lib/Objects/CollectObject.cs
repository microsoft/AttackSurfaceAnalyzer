// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Objects
{
    public abstract class CollectObject
    {
        public abstract RESULT_TYPE ResultType
        {
            get;
        }

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(JsonConvert.SerializeObject(this));
            }
        }

        public abstract string Identity {
            get;
        }
    }
}
