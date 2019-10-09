// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class Diff
    {
        public string Field { get; set; }
        public object Before { get; set; }
        public object After { get; set; }
    }
}
