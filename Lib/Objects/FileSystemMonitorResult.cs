// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System.IO;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileSystemMonitorResult
    {
        #region Public Constructors

        public FileSystemMonitorResult(FileSystemEventArgs evtIn)
        {
            evt = evtIn;
        }

        #endregion Public Constructors

        #region Public Properties

        public FileSystemEventArgs evt { get; set; }
        public NotifyFilters filter { get; set; }

        #endregion Public Properties
    }
}