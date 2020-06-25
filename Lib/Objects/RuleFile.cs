// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class RuleFile
    {
        #region Public Constructors

        public RuleFile(Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>? DefaultLevels = null, List<Rule>? Rules = null)
        {
            if (DefaultLevels != null)
            {
                this.DefaultLevels = DefaultLevels;
            }
            this.Rules = Rules ?? new List<Rule>();
        }

        public RuleFile()
        {
            Rules = new List<Rule>();
        }

        #endregion Public Constructors

        #region Public Properties

        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels { get; set; } = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>()
        {
            { RESULT_TYPE.CERTIFICATE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.FILE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.PORT, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.REGISTRY, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.SERVICE, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.USER, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.UNKNOWN, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.GROUP, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.COM, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.LOG, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.KEY, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.TPM, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.PROCESS, ANALYSIS_RESULT_TYPE.INFORMATION },
            { RESULT_TYPE.DRIVER, ANALYSIS_RESULT_TYPE.INFORMATION }
        };

        public List<Rule> Rules { get; set; }

        #endregion Public Properties
    }
}