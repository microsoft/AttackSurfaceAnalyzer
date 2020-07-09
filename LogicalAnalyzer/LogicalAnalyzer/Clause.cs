// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System.Collections.Generic;

namespace Microsoft.CST.LogicalAnalyzer
{
    public class Clause
    {
        public Clause(string Field, OPERATION Operation)
        {
            this.Field = Field;
            this.Operation = Operation;
        }

        public Clause(OPERATION Operation)
        {
            this.Operation = Operation;
        }

        public List<string>? Data { get; set; }
        public List<KeyValuePair<string, string>>? DictData { get; set; }
        public string? Field { get; set; }
        public string? Label { get; set; }
        public OPERATION Operation { get; set; }
        public string? CustomOperation { get; set; }
    }
}