using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Run
    {
        public RUN_TYPE Type { get; set; }
        public string RunId { get; set; }
        public string Timestamp { get; set; }
        public string Version { get; set; }
        public string Platform { get; set; }
        public Dictionary<RESULT_TYPE, bool> ResultTypes { get; set; }
    }
}
