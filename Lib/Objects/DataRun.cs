// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class DataRunListModel
    {
        public IEnumerable<DataRunModel>? MonitorRuns { get; set; }
        public IEnumerable<DataRunModel>? Runs { get; set; }
        public string? SelectedBaseRunId { get; set; }
        public string? SelectedCompareRunId { get; set; }
        public string? SelectedMonitorRunId { get; set; }
    }

    public class DataRunModel
    {
        public DataRunModel(string KeyIn, string TextIn)
        {
            Key = KeyIn;
            Text = TextIn;
        }

        public string Key { get; }
        public string Text { get; }
    }
}