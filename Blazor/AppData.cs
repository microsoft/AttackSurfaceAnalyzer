using Microsoft.CST.AttackSurfaceAnalyzer.Objects;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public class AppData
    {
        public CollectCommandOptions CollectOptions { get; set; } = new CollectCommandOptions();
        public MonitorCommandOptions MonitorOptions { get; set; } = new MonitorCommandOptions();
        public ExportCollectCommandOptions ExportCollectCommandOptions { get; set; } = new ExportCollectCommandOptions();

        public CompareCommandOptions CompareCommandOptions { 
            get
            {
                return new CompareCommandOptions(ExportCollectCommandOptions.FirstRunId, ExportCollectCommandOptions.SecondRunId)
                {
                    ApplySubObjectRulesToMonitor = true,
                    AnalysesFile = RuleFile.LoadEmbeddedFilters()
                };
            } 
        }
    }
}