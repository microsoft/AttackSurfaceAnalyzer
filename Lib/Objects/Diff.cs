// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public readonly struct Diff
    {
        public readonly string Field { get; }
        public readonly object? Before { get; }
        public readonly object? After { get; }

        public Diff(string FieldIn, object? BeforeIn = null, object? AfterIn = null)
        {
            Field = FieldIn;
            Before = BeforeIn;
            After = AfterIn;
        }
    }
}
