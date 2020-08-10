// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Types;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class OutputFileMonitorResult
    {
        public OutputFileMonitorResult(string PathIn)
        {
            Path = PathIn;
        }

        public CHANGE_TYPE ChangeType { get; set; }
        public string? Name { get; set; }
        public string? OldName { get; set; }
        public string? OldPath { get; set; }
        public string Path { get; set; }
        public string? RowKey { get; set; }
        public string? Timestamp { get; set; }
    }
}