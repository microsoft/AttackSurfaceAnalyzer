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

        public enum Mode
        {
            None,
            Guided,
            Monitor,
            Scan
        }

        public Mode exclusiveMode { get; set; } = Mode.None;

        public enum ScanPageState
        {
            Options,
            Scanning,
            Finished,
            Error,
            Disabled
        }

        public ScanPageState scanPageState { get; set; } = ScanPageState.Options;

        public enum GuidedPageState
        {
            Options,
            Scanning,
            Monitoring,
            MonitorFlushing,
            Analyzing,
            Results,
            Error,
            Disabled
        }
        public MonitorPageState monitorPageState { get; set; } = MonitorPageState.Options;

        public enum MonitorPageState
        {
            Options,
            Monitoring,
            MonitorFlushing,
            Finished,
            Error,
            Disabled
        }

        public GuidedPageState guidedPageState { get; set; } = GuidedPageState.Options;

        public string MonitorRunId
        {
            get
            {
                return $"{RunId}-monitoring";
            }
        }

        public RuleFile RulesFile { get; set; } = new RuleFile();
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