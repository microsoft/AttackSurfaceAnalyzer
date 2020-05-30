// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileMonitorObject : CollectObject
    {
        public string Path { get; set; }
        public string? OldPath { get; set; }
        public string? Name { get; set; }
        public string? OldName { get; set; }
        public CHANGE_TYPE? ChangeType { get; set; }
        public string? ExtendedResults { get; set; }
        public string? NotifyFilters { get; set; }
        public string? Serialized { get; set; }
        public string? Timestamp { get; set; }
        public FileSystemObject? FileSystemObject { get; set; }

        public override string Identity
        {
            get
            {
                return Path;
            }
        }

        public FileMonitorObject(string PathIn)
        {
            Path = PathIn;
        }
    }
}
