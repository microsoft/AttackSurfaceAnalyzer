using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public class AppData
    {
        public CollectCommandOptions CollectOptions { get; set; } = new CollectCommandOptions();
        public MonitorCommandOptions MonitorOptions { get; set; } = new MonitorCommandOptions();
        public ExportCollectCommandOptions ExportCollectCommandOptions { get; set; } = new ExportCollectCommandOptions();
        public string FirstRunId
        {
            get
            {
                return $"{RunId}-before";
            }
        }

        public string SecondRunId
        {
            get
            {
                return $"{RunId}-after";
            }
        }

        public string MonitorRunId
        {
            get
            {
                return $"{RunId}-monitoring";
            }
        }

        public Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE> DefaultLevels = new Dictionary<RESULT_TYPE, ANALYSIS_RESULT_TYPE>();
        public List<AsaRule> Rules { get; set; } = new List<AsaRule>();
        public List<CollectObject> TestObjects { get; set; } = new List<CollectObject>();

        public string RunId { get; set; } = string.Empty;
        public CompareCommandOptions CompareCommandOptions { 
            get
            {
                return new CompareCommandOptions(ExportCollectCommandOptions.FirstRunId, ExportCollectCommandOptions.SecondRunId)
                {
                    ApplySubObjectRulesToMonitor = true,
                    AnalysesFile = RuleFile.LoadEmbeddedFilters(),
                    DatabaseFilename = ExportCollectCommandOptions.DatabaseFilename,
                    DisableAnalysis = ExportCollectCommandOptions.DisableAnalysis,
                    SaveToDatabase = ExportCollectCommandOptions.SaveToDatabase,
                    RunScripts = ExportCollectCommandOptions.RunScripts
                };
            } 
        }
    }
}