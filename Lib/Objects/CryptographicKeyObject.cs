// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CryptographicKeyObject : CollectObject
    {
        
        public string Source { get; set; }

        public CryptographicKeyObject(string Source)
        {
            this.Source = Source;
            ResultType = Types.RESULT_TYPE.KEY;
        }

        public override string Identity
        {
            get
            {
                return Source;
            }
        }
    }
}