// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
namespace AttackSurfaceAnalyzer.Objects
{
    public class Diff
    {
        #region Public Constructors

        public Diff(string FieldIn, object? BeforeIn = null, object? AfterIn = null)
        {
            Field = FieldIn;
            Before = BeforeIn;
            After = AfterIn;
        }

        #endregion Public Constructors

        #region Public Properties

        public object? After { get; }
        public object? Before { get; }
        public string Field { get; }

        #endregion Public Properties
    }
}