using AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    class RuleFile
    {
        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels { get; set; }
        public List<Rule> Rules { get; set; }

        public RuleFile(Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels, List<Rule> Rules)
        {
            this.DefaultLevels = DefaultLevels;
            this.Rules = Rules;
        }
    }
}
