// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class DataRunModel
    {
        public string Key { get; }
        public string Text { get; }

        public DataRunModel(string KeyIn, string TextIn)
        {
            Key = KeyIn;
            Text = TextIn;
        }
    }

    public class DataRunListModel
    {
        public string? SelectedBaseRunId { get; set; }
        public string? SelectedCompareRunId { get; set; }
        public IEnumerable<DataRunModel>? Runs { get; set; }
        public string? SelectedMonitorRunId { get; set; }
        public IEnumerable<DataRunModel>? MonitorRuns { get; set; }
    }
}
