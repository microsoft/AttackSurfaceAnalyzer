// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.IO;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class FileMonitorObject : MonitorObject
    {
        public FileMonitorObject(string PathIn)
        {
            Path = PathIn;
            ResultType = RESULT_TYPE.FILEMONITOR;
        }

        public string? ExtendedResults { get; set; }
        public FileSystemObject? FileSystemObject { get; set; }

        public override string Identity
        {
            get
            {
                return Path;
            }
        }

        public string? Name { get; set; }
        public NotifyFilters? NotifyFilters { get; set; }
        public string? OldName { get; set; }
        public string? OldPath { get; set; }
        public string Path { get; set; }
        public string? Timestamp { get; set; }
    }
}