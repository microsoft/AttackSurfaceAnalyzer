// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class AsaRule : Rule
    {
        public AsaRule(string Name) : base(Name) { }

        public List<CHANGE_TYPE> ChangeTypes { get; set; } = new List<CHANGE_TYPE>() { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED };
        public List<PLATFORM> Platforms { get; set; } = new List<PLATFORM>() { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS };
        public ANALYSIS_RESULT_TYPE Flag { get; set; }
        public RESULT_TYPE ResultType { get; set; }
    }

    public class Rule
    {
        public Rule(string Name)
        {
            this.Name = Name;
        }

        public List<Clause> Clauses { get; set; } = new List<Clause>();
        public string? Description { get; set; }
        public string? Expression { get; set; }
        public string Name { get; set; }
        public string Target { get; set; }
        public int Severity { get; set; }
    }
}