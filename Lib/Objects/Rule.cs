// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Rule
    {
        #region Public Constructors

        public Rule(string Name)
        {
            this.Name = Name;
        }

        #endregion Public Constructors

        #region Public Properties

        public List<CHANGE_TYPE> ChangeTypes { get; set; } = new List<CHANGE_TYPE>() { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED };
        public List<Clause> Clauses { get; set; } = new List<Clause>();
        public string? Description { get; set; }
        public string? Expression { get; set; }
        public ANALYSIS_RESULT_TYPE Flag { get; set; }
        public string Name { get; set; }
        public List<PLATFORM> Platforms { get; set; } = new List<PLATFORM>() { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS };
        public RESULT_TYPE ResultType { get; set; }

        #endregion Public Properties
    }
}