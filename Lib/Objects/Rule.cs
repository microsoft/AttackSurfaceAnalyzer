using AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.ComponentModel;

namespace AttackSurfaceAnalyzer.Objects
{

    public class Rule
    {
        [DefaultValue(new PLATFORM[] { PLATFORM.LINUX, PLATFORM.MACOS, PLATFORM.WINDOWS })]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public PLATFORM[] platforms;

        [DefaultValue(new CHANGE_TYPE[] { CHANGE_TYPE.CREATED, CHANGE_TYPE.DELETED, CHANGE_TYPE.MODIFIED })]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
        public CHANGE_TYPE[] changeTypes;

        public string name;
        public string desc;
        public ANALYSIS_RESULT_TYPE flag;
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
