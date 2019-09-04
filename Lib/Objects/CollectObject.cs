// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public abstract class CollectObject
    {
        public RESULT_TYPE ResultType;
        public abstract string Identity { get; }
        public string Message { get; set; }
    }
}
