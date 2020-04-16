// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileMonitorEvent
    {
        public CHANGE_TYPE ChangeType { get; set; }
        public string Path { get; set; }
        public string? OldPath { get; set; }
        public string? Name { get; set; }
        public string? OldName { get; set; }

        public FileMonitorEvent(string PathIn)
        {
            Path = PathIn;
        }
    }
}
