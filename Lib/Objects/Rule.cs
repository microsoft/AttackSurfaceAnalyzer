using System.Collections.Generic;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.ObjectTypes;

namespace AttackSurfaceAnalyzer.Objects
{


    public class Rule
    {
        public string name;
        public string desc;
        public ANALYSIS_RESULT_TYPE flag;
        public List<PLATFORM> platforms;
        public RESULT_TYPE resultType;
        public List<Clause> clauses;
    }

    public class Clause
    {
        public string field;
        public OPERATION op;
        public List<string> data;
    }
}
