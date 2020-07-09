// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Clause
    {
        #region Public Constructors

        public Clause(string Field, OPERATION Operation)
        {
            this.Field = Field;
            this.Operation = Operation;
        }

        #endregion Public Constructors

        #region Public Properties

        public List<string>? Data { get; set; }
        public List<KeyValuePair<string, string>>? DictData { get; set; }
        public string Field { get; set; }
        public string? Label { get; set; }
        public OPERATION Operation { get; set; }
        public string? CustomOperation { get; set; }

        #endregion Public Properties
    }
}