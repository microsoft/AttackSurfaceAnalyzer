using System.Collections.Generic;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class Run
    {
        public RUN_TYPE Type;
        public string RunId;
        public string Timestamp;
        public string Version;
        public string Platform;
        public Dictionary<RESULT_TYPE, bool> ResultTypes;
    }
}
