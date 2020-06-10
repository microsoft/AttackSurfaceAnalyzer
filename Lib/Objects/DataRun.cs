// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class DataRunListModel
    {
        #region Public Properties

        public IEnumerable<DataRunModel>? MonitorRuns { get; set; }
        public IEnumerable<DataRunModel>? Runs { get; set; }
        public string? SelectedBaseRunId { get; set; }
        public string? SelectedCompareRunId { get; set; }
        public string? SelectedMonitorRunId { get; set; }

        #endregion Public Properties
    }

    public class DataRunModel
    {
        #region Public Constructors

        public DataRunModel(string KeyIn, string TextIn)
        {
            Key = KeyIn;
            Text = TextIn;
        }

        #endregion Public Constructors

        #region Public Properties

        public string Key { get; }
        public string Text { get; }

        #endregion Public Properties
    }
}