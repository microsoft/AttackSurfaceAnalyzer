// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Objects
{
    public abstract class CollectObject
    {
        public RESULT_TYPE ResultType;

        public abstract string Identity { get; }
    }
}
