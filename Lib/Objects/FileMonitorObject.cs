using System;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileMonitorObject : CollectObject
    {
        public string Path;
        public string OldPath;
        public string Name;
        public string OldName;
        public CHANGE_TYPE ChangeType;
        public string ExtendedResults;
        public string NotifyFilters;
        public string Serialized;
        public string Timestamp;

        public override string Identity
        {
            get
            {
                return Path;
            };
        }
    }
}
