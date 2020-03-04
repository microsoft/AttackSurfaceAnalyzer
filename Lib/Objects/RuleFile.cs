using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class RuleFile
    {
        public List<Rule> Rules { get; set; }
        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels { get; set; }

        public RuleFile(Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels, List<Rule> Rules)
        {
            this.DefaultLevels = DefaultLevels;
            this.Rules = Rules;
        }

        public RuleFile()
        {
            Rules = new List<Rule>();
            DefaultLevels = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>();
        }
    }
}
