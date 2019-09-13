using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Models
{
    public class DataRunModel
    {
        public string Key { get; set; }
        public string Text { get; set; }
    }

    public class DataRunListModel
    {
        public string SelectedBaseRunId { get; set; }
        public string SelectedCompareRunId { get; set; }
        public IEnumerable<DataRunModel> Runs { get; set; }
        public string SelectedMonitorRunId { get; set; }
        public IEnumerable<DataRunModel> MonitorRuns { get; set; }
    }

    public class DataResultModel
    {
        public string Key { get; set; }
        public string Text { get; set; }
    }
}
