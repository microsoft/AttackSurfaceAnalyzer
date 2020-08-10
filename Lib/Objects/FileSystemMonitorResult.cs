// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System.IO;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class FileSystemMonitorResult
    {
        public FileSystemMonitorResult(FileSystemEventArgs evtIn)
        {
            evt = evtIn;
        }

        public FileSystemEventArgs evt { get; set; }
        public NotifyFilters filter { get; set; }
    }
}