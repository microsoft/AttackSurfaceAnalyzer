// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System;
using System.Collections.Generic;

namespace Microsoft.CST.LogicalAnalyzer
{
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
        public string? Target { get; set; }
        public int Severity { get; set; }
        public string[] Tags { get; set; } = Array.Empty<string>();
    }
}