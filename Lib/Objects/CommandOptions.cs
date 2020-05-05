// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using CommandLine;

namespace AttackSurfaceAnalyzer
{
    public class CommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; } = "asa.sqlite";

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

        [Option(Default = false, HelpText = "Decrease logging to Errors")]
        public bool Quiet { get; set; }
    }

    public class CompareCommandOptions : CommandOptions
    {
        [Option(HelpText = "First run (pre-install) identifier")]
        public string FirstRunId { get; set; }

        [Option(HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; }

        [Option(HelpText = "Set Enable/Disable Analysis.")]
        public bool Analyze { get; set; } = true;

        [Option(HelpText = "Custom analysis rules file.")]
        public string? AnalysesFile { get; set; }

        [Option(HelpText = "Save to internal database for review in GUI")]
        public bool SaveToDatabase { get; set; }

        public CompareCommandOptions(string FirstRunId, string SecondRunId)
        {
            this.FirstRunId = FirstRunId;
            this.SecondRunId = SecondRunId;
        }
    }
    [Verb("export-collect", HelpText = "Compare ASA executions and output a .json report")]
    public class ExportCollectCommandOptions : CommandOptions
    {
        [Option(HelpText = "First run (pre-install) identifier")]
        public string? FirstRunId { get; set; }

        [Option(HelpText = "Second run (post-install) identifier")]
        public string? SecondRunId { get; set; }

        [Option(HelpText = "Directory to output to")]
        public string? OutputPath { get; set; }

        [Option(HelpText = "Exploded output")]
        public bool ExplodedOutput { get; set; }

        [Option(HelpText = "Set Enable/Disable Analysis.")]
        public bool Analyze { get; set; } = true;

        [Option(HelpText = "Save to internal database for review in GUI")]
        public bool SaveToDatabase { get; set; }

        [Option(HelpText = "Custom analysis rules file.")]
        public string? AnalysesFile { get; set; }

    }
    [Verb("export-monitor", HelpText = "Output a .json report for a monitor run")]
    public class ExportMonitorCommandOptions : CommandOptions
    {
        [Option(HelpText = "Monitor run identifier")]
        public string? RunId { get; set; }

        [Option(HelpText = "Directory to output to")]
        public string? OutputPath { get; set; }

    }
    [Verb("collect", HelpText = "Collect operating system metrics")]
    public class CollectCommandOptions : CommandOptions
    {
        [Option(HelpText = "Identifies which run this is.")]
        public string? RunId { get; set; }

        [Option('c', "certificates", Required = false, HelpText = "Enable the certificate store collector")]
        public bool EnableCertificateCollector { get; set; }

        [Option('f', "file-system", Required = false, HelpText = "Enable the file system collector")]
        public bool EnableFileSystemCollector { get; set; }

        [Option('p', "network-port", Required = false, HelpText = "Enable the network port collector")]
        public bool EnableNetworkPortCollector { get; set; }

        [Option('r', "registry", Required = false, HelpText = "Enable the registry collector")]
        public bool EnableRegistryCollector { get; set; }

        [Option('s', "service", Required = false, HelpText = "Enable the service collector")]
        public bool EnableServiceCollector { get; set; }

        [Option('u', "user", Required = false, HelpText = "Enable the user and group account collector")]
        public bool EnableUserCollector { get; set; }

        [Option('F', "firewall", Required = false, HelpText = "Enable the firewall collector")]
        public bool EnableFirewallCollector { get; set; }

        [Option('C', "com", Required = false, HelpText = "Enable the COM object collector")]
        public bool EnableComObjectCollector { get; set; }

        [Option('l', "logs", Required = false, HelpText = "Enable the Log collector")]
        public bool EnableEventLogCollector { get; set; }

        [Option('t', "tpm", Required = false, HelpText = "Gather information about the TPM")]
        public bool EnableTpmCollector { get; set; }

        [Option('k', "keys", Required = false, HelpText = "Gather information about the cryptographic keys on the system.")]
        public bool EnableKeyCollector { get; set; }

        [Option('a', "all", Required = false, HelpText = "Enable all collectors")]
        public bool EnableAllCollectors { get; set; }

        [Option(HelpText = "Gather all levels in the Log collector. (Default: Only gather Error and Warning when possible.)")]
        public bool GatherVerboseLogs { get; set; }

        [Option("match-run-id", Required = false, HelpText = "Match the collectors used on another run id")]
        public string? MatchedCollectorId { get; set; }

        [Option('h', "gather-hashes", Required = false, HelpText = "Hashes every file when using the File Collector.  May dramatically increase run time of the scan.")]
        public bool GatherHashes { get; set; }

        [Option("directories", Required = false, HelpText = "Comma separated list of paths to scan with FileSystemCollector")]
        public string? SelectedDirectories { get; set; }

        [Option(HelpText = "Download files from thin Cloud Folders (like OneDrive) to check them.")]
        public bool DownloadCloud { get; set; }

        [Option(HelpText = "If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }

        [Option(HelpText = "Run parallelized collectors when available.")]
        public bool SingleThread { get; set; }

        [Option(HelpText = "Number of Database Shards to use.")]
        public int Shards { get; set; } = 7;
    }
    [Verb("monitor", HelpText = "Continue running and monitor activity")]
    public class MonitorCommandOptions : CommandOptions
    {
        [Option(HelpText = "Identifies which run this is. Monitor output can be combined with collect output, but doesn't need to be compared.", Default = "Timestamp")]
        public string? RunId { get; set; }

        [Option('f', "file-system", Required = false, HelpText = "Enable the file system monitor. Unless -d is specified will monitor the entire file system.")]
        public bool EnableFileSystemMonitor { get; set; }

        [Option('d', "directories", Required = false, HelpText = "Comma-separated list of directories to monitor.")]
        public string? MonitoredDirectories { get; set; }

        [Option('i', "interrogate-file-changes", Required = false, HelpText = "On a file create or change gather the post-change file size and security attributes (Linux/Mac only)")]
        public bool InterrogateChanges { get; set; }

        //[Option('r', "registry", Required = false, HelpText = "Monitor the registry for changes. (Windows Only)")]
        //public bool EnableRegistryMonitor { get; set; }

        [Option('D', "duration", Required = false, HelpText = "Duration, in minutes, to run for before automatically terminating.")]
        public int Duration { get; set; }

        [Option(Default = false, HelpText = "If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }
    }

    [Verb("config", HelpText = "Configure and query the database")]
    public class ConfigCommandOptions : CommandOptions
    {
        [Option("list-runs", Required = false, HelpText = "List runs in the database")]
        public bool ListRuns { get; set; }

        [Option("reset-database", Required = false, HelpText = "Delete the output database")]
        public bool ResetDatabase { get; set; }

        [Option("telemetry-opt-out", Required = false, HelpText = "Change your telemetry opt out setting")]
        public bool TelemetryOptOut { get; set; }

        [Option("delete-run", Required = false, HelpText = "Delete a specific run from the database")]
        public string? DeleteRunId { get; set; }

        [Option("trim-to-latest", HelpText = "Delete all runs except the latest.")]
        public bool TrimToLatest { get; set; }
    }

    [Verb("verify", HelpText = "Verify your analysis rules")]
    public class VerifyOptions : CommandOptions
    {
        [Option("filename", Required = false, HelpText = "Path to your analysis file")]
        public string? AnalysisFile { get; set; }
    }

    [Verb("gui", HelpText = "Launch the GUI in a browser")]
    public class GuiCommandOptions : CommandOptions
    { }
}