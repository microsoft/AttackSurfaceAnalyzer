using AttackSurfaceAnalyzer.Types;
using System;
namespace AttackSurfaceAnalyzer.Objects
{
    public class OutputFileMonitorResult
    {
        public string? RowKey { get; set; }
        public string? Timestamp { get; set; }
        public string? OldPath { get; set; }
        public string Path { get; set; }
        public string? OldName { get; set; }
        public string? Name { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }

        public OutputFileMonitorResult(string PathIn)
        {
            Path = PathIn;
        }
    }
}
