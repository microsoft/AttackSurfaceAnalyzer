// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class Diff
    {
        public Diff(string FieldIn, object? BeforeIn = null, object? AfterIn = null)
        {
            Field = FieldIn;
            Before = BeforeIn;
            After = AfterIn;
        }

        public object? After { get; }
        public object? Before { get; }
        public string Field { get; }
    }
}