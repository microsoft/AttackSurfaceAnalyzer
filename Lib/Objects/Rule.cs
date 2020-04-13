// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{

    public class Rule
    {
        public string Name { get; set; }
        public string? Description { get; set; }
        public ANALYSIS_RESULT_TYPE Flag { get; set; }
        public RESULT_TYPE ResultType { get; set; }
        public List<PLATFORM> Platforms { get; set; } = new List<PLATFORM>() { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS };
        public List<CHANGE_TYPE> ChangeTypes { get; set; } = new List<CHANGE_TYPE>() { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED };
        public List<Clause> Clauses { get; set; } = new List<Clause>();
        public string? Expression { get; set; }

        public Rule(string Name)
        {
            this.Name = Name;
        }
    }

    public class Clause
    {
        public string Field { get; set; }
        public OPERATION Operation { get; set; }
        public string? Label { get; set; }
        public List<string>? Data { get; set; }
        public List<KeyValuePair<string, string>>? DictData { get; set; }
        public Clause(string Field, OPERATION Operation)
        {
            this.Field = Field;
            this.Operation = Operation;
        }
    }
}
