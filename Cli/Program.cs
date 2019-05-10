// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Collectors.FileSystem;
using AttackSurfaceAnalyzer.Collectors.OpenPorts;
using AttackSurfaceAnalyzer.Collectors.Registry;
using AttackSurfaceAnalyzer.Collectors.Service;
using AttackSurfaceAnalyzer.Collectors.UserAccount;
using AttackSurfaceAnalyzer.Collectors.Certificates;
using AttackSurfaceAnalyzer.Utils;
using CommandLine;
using Microsoft.Data.Sqlite;
using RazorLight;
using AttackSurfaceAnalyzer.ObjectTypes;
using Newtonsoft.Json;
using System.Reflection;
using Serilog;
using System.Resources;

namespace AttackSurfaceAnalyzer
{

    [Verb("compare", HelpText = "Compare ASA executions and output a .html summary")]
    public class CompareCommandOptions
    {
        [Option(HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(HelpText = "First run (pre-install) identifier", Default = "Timestamps")]
        public string FirstRunId { get; set; }

        [Option(HelpText = "Second run (post-install) identifier", Default = "Timestamps")]
        public string SecondRunId { get; set; }

        [Option(HelpText = "Base name of output file", Default = "output")]
        public string OutputBaseFilename { get; set; }

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("export-collect", HelpText = "Compare ASA executions and output a .json report")]
    public class ExportCollectCommandOptions
    {
        [Option(HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(HelpText = "First run (pre-install) identifier", Default = "Timestamps")]
        public string FirstRunId { get; set; }

        [Option(HelpText = "Second run (post-install) identifier", Default = "Timestamps")]
        public string SecondRunId { get; set; }

        [Option(HelpText = "Directory to output to", Default = ".")]
        public string OutputPath { get; set; }

        [Option(HelpText = "Exploded output")]
        public bool ExplodedOutput { get; set; }

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("export-monitor", HelpText = "Output a .json report for a monitor run")]
    public class ExportMonitorCommandOptions
    {
        [Option(HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(HelpText = "Monitor run identifier", Default = "Timestamp")]
        public string RunId { get; set; }

        [Option(HelpText = "Directory to output to", Default = ".")]
        public string OutputPath { get; set; }

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("collect", HelpText = "Collect operating system metrics")]
    public class CollectCommandOptions
    {
        [Option(HelpText = "Identifies which run this is (used during comparison)", Default = "Timestamp")]
        public string RunId { get; set; }

        [Option(HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

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

        [Option('u', "user", Required = false, HelpText = "Enable the user account collector")]
        public bool EnableUserCollector { get; set; }

        [Option('a', "all", Required = false, HelpText = "Enable all collectors")]
        public bool EnableAllCollectors { get; set; }

        [Option("match-run-id", Required = false, HelpText = "Match the collectors used on another run id")]
        public string MatchedCollectorId { get; set; }

        [Option("filter", Required = false, HelpText = "Provide a JSON filter file.", Default = "Use embedded filters.")]
        public string FilterLocation { get; set; }

        [Option("no-filters",HelpText = "Disables the embedded filters.")]
        public bool NoFilters { get; set; }

        [Option('h',"gather-hashes", Required = false, HelpText = "Hashes every file when using the File Collector.  May dramatically increase run time of the scan.")]
        public bool GatherHashes { get; set; }

        [Option("directories", Required = false, HelpText = "Comma separated list of paths to scan with FileSystemCollector")]
        public string SelectedDirectories { get; set; }

        [Option(HelpText ="If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(HelpText = "See all logging statements.")]
        public bool Verbose { get; set; }
    }
    [Verb("monitor", HelpText = "Continue running and monitor activity")]
    public class MonitorCommandOptions
    {
        [Option(HelpText = "Identifies which run this is. Monitor output can be combined with collect output, but doesn't need to be compared.", Default="Timestamp")]
        public string RunId { get; set; }

        [Option(HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option('f', "file-system", Required = false, HelpText = "Enable the file system monitor. Unless -d is specified will monitor the entire file system.")]
        public bool EnableFileSystemMonitor { get; set; }

        [Option('d', "directories", Required = false, HelpText = "Comma-separated list of directories to monitor.")]
        public string MonitoredDirectories { get; set; }

        [Option('i', "interrogate-file-changes", Required = false, HelpText = "On a file create or change gather the post-change file size and security attributes (Linux/Mac only)")]
        public bool InterrogateChanges { get; set; }

        [Option("filter", Required = false, HelpText = "Provide a JSON filter file.", Default = "filters.json")]
        public string FilterLocation { get; set; }

        //[Option('r', "registry", Required = false, HelpText = "Monitor the registry for changes. (Windows Only)")]
        //public bool EnableRegistryMonitor { get; set; }

        [Option('D', "duration", Required = false, HelpText = "Duration, in minutes, to run for before automatically terminating.")]
        public int Duration { get; set; }

        [Option(Default = false, HelpText = "If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite {get; set;}

        [Option(HelpText = "Show debug logging statements.")]
        public bool Debug { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }
    }

    [Verb("config", HelpText = "Configure and query the database")]
    public class ConfigCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option("list-runs", Required = false, HelpText = "List runs in the database")]
        public bool ListRuns { get; set; }

        [Option("reset-database", Required = false, HelpText = "Delete the output database")]
        public bool ResetDatabase { get; set; }

        [Option("telemetry-opt-out", Required = false, HelpText = "Change your telemetry opt out setting [True | False]")]
        public string TelemetryOptOut { get; set; }

        [Option("delete-run", Required = false, HelpText = "Delete a specific run from the database")]
        public string DeleteRunId { get; set; }

        [Option("trim-to-latest", HelpText = "Delete all runs except the latest.")]
        public bool TrimToLatest { get; set; }

    }

    public static class AttackSurfaceAnalyzerCLI
    {
        private static List<BaseCollector> collectors = new List<BaseCollector>();
        private static List<BaseMonitor> monitors = new List<BaseMonitor>();
        private static List<BaseCompare> comparators = new List<BaseCompare>();

        private static readonly string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private static readonly string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";
        private static readonly string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id";
        private static readonly string SQL_GET_RESULT_TYPES_SINGLE = "select * from runs where run_id = @run_id";

        private static readonly string SQL_GET_RUN = "select run_id from runs where run_id=@run_id";

        private static bool _isFirstRun = false;

        static void Main(string[] args)
        {

#if DEBUG
            Logger.Setup(true,false);
#else
            Logger.Setup(false,false);
#endif
            string version = (Assembly
                        .GetEntryAssembly()
                        .GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                        as AssemblyInformationalVersionAttribute[])[0].InformationalVersion;
            Log.Information("AttackSurfaceAnalyzerCli v.{0}",version);

            Strings.Setup();

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, CompareCommandOptions, MonitorCommandOptions, ExportMonitorCommandOptions, ExportCollectCommandOptions, ConfigCommandOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) => RunCollectCommand(opts),
                    (CompareCommandOptions opts) => RunCompareCommand(opts),
                    (MonitorCommandOptions opts) => RunMonitorCommand(opts),
                    (ExportCollectCommandOptions opts) => RunExportCollectCommand(opts),
                    (ExportMonitorCommandOptions opts) => RunExportMonitorCommand(opts),
                    (ConfigCommandOptions opts) => RunConfigCommand(opts),
                    errs => 1
                );
            
            Log.CloseAndFlush();
        }

        private static void CheckFirstRun()
        {
            if (DatabaseManager.IsFirstRun())
            {
                _isFirstRun = true;
                string exeStr = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "AttackSurfaceAnalyzerCli.exe config --telemetry-opt-out true" : "AttackSurfaceAnalyzerCli config --telemetry-opt-out true";
                Log.Information(Strings.Get("ApplicationHasTelemetry"));
                Log.Information(Strings.Get("ApplicationHasTelemetry2"), "https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/master/PRIVACY.md");
                Log.Information(Strings.Get("ApplicationHasTelemetry3"), exeStr);
            }
        }

        private static int RunConfigCommand(ConfigCommandOptions opts)
        {
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);

            if (opts.ResetDatabase)
            {
                DatabaseManager.CloseDatabase();
                try
                {
                    File.Delete(opts.DatabaseFilename);
                }
                catch (Exception e)
                {
                    Log.Fatal(e, Strings.Get("FailedToDeleteDatabase"), opts.DatabaseFilename, e.GetType().ToString(), e.Message);
                    Environment.Exit(-1);
                }
                Log.Information(Strings.Get("DeletedDatabaseAt"), opts.DatabaseFilename);
            }
            else
            {
                DatabaseManager.VerifySchemaVersion();

                if (opts.ListRuns)
                {
                    if (_isFirstRun)
                    {
                        Log.Warning(Strings.Get("FirstRunListRunsError"), opts.DatabaseFilename);
                    }
                    else
                    {
                        Log.Information(Strings.Get("DumpingDataFromDatabase"), opts.DatabaseFilename);
                        List<string> CollectRuns = GetRuns("collect");
                        if(CollectRuns.Count > 0)
                        {
                            Log.Information(Strings.Get("Begin") + " {0}", Strings.Get("EnumeratingCollectRunIds"));
                            foreach (string run in CollectRuns)
                            {
                                using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, DatabaseManager.Connection, DatabaseManager.Transaction))
                                {
                                    cmd.Parameters.AddWithValue("@run_id", run);
                                    using (var reader = cmd.ExecuteReader())
                                    {
                                        while (reader.Read())
                                        {
                                            Log.Information("RunId:{2} Timestamp:{0} AsaVersion:{1} ",
                                                                            reader["timestamp"],
                                                                            reader["version"],
                                                                            reader["run_id"]);
                                            List<RESULT_TYPE> resultTypes = new List<RESULT_TYPE>();
                                            if (int.Parse(reader["file_system"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.FILE);
                                            }
                                            if (int.Parse(reader["ports"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.PORT);
                                            }
                                            if (int.Parse(reader["users"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.USER);
                                            }
                                            if (int.Parse(reader["services"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.SERVICES);
                                            }
                                            if (int.Parse(reader["certificates"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.CERTIFICATE);
                                            }
                                            if (int.Parse(reader["registry"].ToString()) != 0)
                                            {
                                                resultTypes.Add(RESULT_TYPE.REGISTRY);
                                            }

                                            foreach (RESULT_TYPE type in resultTypes)
                                            {
                                                int num = DatabaseManager.GetNumResults(type, reader["run_id"].ToString());
                                                Log.Information("{0} : {1}", type, num);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            Log.Information(Strings.Get("NoCollectRuns"));
                        }
                        
                        List<string> MonitorRuns = GetRuns("monitor");
                        if (MonitorRuns.Count > 0)
                        {
                            Log.Information(Strings.Get("Begin") + " {0}", Strings.Get("EnumeratingMonitorRunIds"));

                            foreach (string monitorRun in MonitorRuns)
                            {
                                using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, DatabaseManager.Connection, DatabaseManager.Transaction))
                                {
                                    cmd.Parameters.AddWithValue("@run_id", monitorRun);
                                    using (var reader = cmd.ExecuteReader())
                                    {
                                        while (reader.Read())
                                        {
                                            string output = String.Format("{0} {1} {2} {3}",
                                                                            reader["timestamp"].ToString(),
                                                                            reader["version"].ToString(),
                                                                            reader["type"].ToString(),
                                                                            reader["run_id"].ToString());
                                            Log.Information(output);
                                            output = String.Format("{0} {1} {2} {3} {4} {5}",
                                                                    (int.Parse(reader["file_system"].ToString()) != 0) ? "FILES" : "",
                                                                    (int.Parse(reader["ports"].ToString()) != 0) ? "PORTS" : "",
                                                                    (int.Parse(reader["users"].ToString()) != 0) ? "USERS" : "",
                                                                    (int.Parse(reader["services"].ToString()) != 0) ? "SERVICES" : "",
                                                                    (int.Parse(reader["certificates"].ToString()) != 0) ? "CERTIFICATES" : "",
                                                                    (int.Parse(reader["registry"].ToString()) != 0) ? "REGISTRY" : "");
                                            Log.Information(output);

                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            Log.Information(Strings.Get("NoMonitorRuns"));
                        }
                    }
                }

                if (opts.TelemetryOptOut != null)
                {
                    Telemetry.SetOptOut(bool.Parse(opts.TelemetryOptOut));
                    Log.Information(Strings.Get("TelemetryOptOut"), (bool.Parse(opts.TelemetryOptOut)) ? "Opted out" : "Opted in");
                }
                if (opts.DeleteRunId != null)
                {
                    DatabaseManager.DeleteRun(opts.DeleteRunId);
                }
                if (opts.TrimToLatest)
                {
                    string GET_RUNS = "select run_id from runs order by timestamp desc;";

                    List<string> Runs = new List<string>();

                    var cmd = new SqliteCommand(GET_RUNS, DatabaseManager.Connection, DatabaseManager.Transaction);
                    using (var reader = cmd.ExecuteReader())
                    {
                        //Skip first row, that is the one we want to keep
                        reader.Read();

                        while (reader.Read())
                        {
                            DatabaseManager.DeleteRun((string)reader["run_id"]);
                        }
                    }
                }
            }
            
            return 0;
        }

        private static int RunExportCollectCommand(ExportCollectCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif

            Log.Debug("{0} RunExportCollectCommand", Strings.Get("Begin"));
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);
            DatabaseManager.VerifySchemaVersion();

            if (opts.FirstRunId == "Timestamps" || opts.SecondRunId == "Timestamps")
            {
                List<string> runIds = DatabaseManager.GetLatestRunIds(2, "collect");

                if (runIds.Count < 2)
                {
                    Log.Fatal(Strings.Get("Err_CouldntDetermineTwoRun"));
                    System.Environment.Exit(-1);
                }
                else
                {
                    opts.SecondRunId = runIds.First();
                    opts.FirstRunId = runIds.ElementAt(1);
                }
            }

            Log.Information(Strings.Get("Comparing"), opts.FirstRunId, opts.SecondRunId);

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("OutputPathSet", (opts.OutputPath != null).ToString());

            Telemetry.TrackEvent("{0} Export Compare", StartEvent);

            CompareCommandOptions options = new CompareCommandOptions();
            options.DatabaseFilename = opts.DatabaseFilename;
            options.FirstRunId = opts.FirstRunId;
            options.SecondRunId = opts.SecondRunId;

            var results = CompareRuns(options);
            JsonSerializer serializer = new JsonSerializer
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore
            };
            serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());


            if (opts.ExplodedOutput)
            {
                results.Add("metadata", Helpers.GenerateMetadata());
                string path = Path.Combine(opts.OutputPath, Helpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId));
                Directory.CreateDirectory(path);
                foreach(var key in results.Keys)
                {
                    string filePath = Path.Combine(path, Helpers.MakeValidFileName(key));
                    using (StreamWriter sw = new StreamWriter(filePath)) //lgtm[cs/path-injection]
                    {
                        using (JsonWriter writer = new JsonTextWriter(sw))
                        {
                            serializer.Serialize(writer, results[key]);
                        }
                    }
                }
                Log.Information(Strings.Get("OutputWrittenTo"), path);
            }
            else
            {
                string path = Path.Combine(opts.OutputPath, Helpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId + "_summary.json.txt"));
                var output = new Dictionary<string, Object>();
                output["results"] = results;
                output["metadata"] = Helpers.GenerateMetadata();
                using (StreamWriter sw = new StreamWriter(path)) //lgtm[cs/path-injection]
                {
                    using (JsonWriter writer = new JsonTextWriter(sw))
                    {
                        serializer.Serialize(writer, output);
                    }
                }
                Log.Information(Strings.Get("OutputWrittenTo"), path);
            }
            return 0;

        }

        public static void WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            string GET_COMPARISON_RESULTS = "select * from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type order by base_row_key;";
            string GET_SERIALIZED_RESULTS = "select serialized from @table_name where row_key = @row_key and run_id = @run_id";

            Log.Debug("{0} WriteScanJson", Strings.Get("Begin"));
            Log.Information("Write scan json");

            List<RESULT_TYPE> ToExport = new List<RESULT_TYPE> { (RESULT_TYPE)ResultType };
            Dictionary<RESULT_TYPE, int> actualExported = new Dictionary<RESULT_TYPE, int>();
            JsonSerializer serializer = new JsonSerializer
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore
            };
            if (ExportAll)
            {
                ToExport = new List<RESULT_TYPE> { RESULT_TYPE.FILE, RESULT_TYPE.CERTIFICATE, RESULT_TYPE.PORT, RESULT_TYPE.REGISTRY, RESULT_TYPE.SERVICES, RESULT_TYPE.USER };
            }


            foreach (RESULT_TYPE ExportType in ToExport)
            {
                Log.Information("Exporting {0}", ExportType);
                List<CompareResult> records = new List<CompareResult>();
                using (var inner_cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(ExportType)), DatabaseManager.Connection, DatabaseManager.Transaction))
                using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.Parameters.AddWithValue("@base_run_id", BaseId);
                    cmd.Parameters.AddWithValue("@compare_run_id", CompareId);
                    cmd.Parameters.AddWithValue("@data_type", ExportType);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string CompareString = "";
                            string BaseString = "";
                            CHANGE_TYPE ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString());

                            if (ChangeType == CHANGE_TYPE.CREATED || ChangeType == CHANGE_TYPE.MODIFIED)
                            {
                                inner_cmd.Parameters.Clear();
                                inner_cmd.Parameters.AddWithValue("@run_id", reader["compare_run_id"].ToString());
                                inner_cmd.Parameters.AddWithValue("@row_key", reader["compare_row_key"].ToString());
                                using (var inner_reader = inner_cmd.ExecuteReader())
                                {
                                    while (inner_reader.Read())
                                    {
                                        CompareString = inner_reader["serialized"].ToString();
                                    }
                                }
                            }
                            if (ChangeType == CHANGE_TYPE.DELETED || ChangeType == CHANGE_TYPE.MODIFIED)
                            {
                                inner_cmd.Parameters.Clear();
                                inner_cmd.Parameters.AddWithValue("@run_id", reader["base_run_id"].ToString());
                                inner_cmd.Parameters.AddWithValue("@row_key", reader["base_row_key"].ToString());
                                using (var inner_reader = inner_cmd.ExecuteReader())
                                {
                                    while (inner_reader.Read())
                                    {
                                        BaseString = inner_reader["serialized"].ToString();
                                    }
                                }
                            }
                        
                            CompareResult obj;
                            switch (ExportType)
                            {
                                case RESULT_TYPE.CERTIFICATE:
                                    obj = new CertificateResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<CertificateObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<CertificateObject>(CompareString)
                                    };
                                    break;
                                case RESULT_TYPE.FILE:
                                    obj = new FileSystemResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<FileSystemObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<FileSystemObject>(CompareString)
                                    };
                                    break;
                                case RESULT_TYPE.PORT:
                                    obj = new OpenPortResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<OpenPortObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<OpenPortObject>(CompareString)
                                    };
                                    break;
                                case RESULT_TYPE.USER:
                                    obj = new UserAccountResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<UserAccountObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<UserAccountObject>(CompareString)
                                    };
                                    break;
                                case RESULT_TYPE.SERVICES:
                                    obj = new ServiceResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<ServiceObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<ServiceObject>(CompareString)
                                    };
                                    break;
                                case RESULT_TYPE.REGISTRY:
                                    obj = new RegistryResult()
                                    {
                                        Base = JsonConvert.DeserializeObject<RegistryObject>(BaseString),
                                        Compare = JsonConvert.DeserializeObject<RegistryObject>(CompareString)
                                    };
                                    break;
                                default:
                                    obj = new CompareResult();
                                    break;
                            }

                            obj.BaseRowKey = reader["base_row_key"].ToString();
                            obj.CompareRowKey = reader["compare_row_key"].ToString();
                            obj.BaseRunId = reader["base_run_id"].ToString();
                            obj.CompareRunId = reader["compare_run_id"].ToString();
                            obj.ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString());
                            obj.ResultType = (RESULT_TYPE)int.Parse(reader["data_type"].ToString());

                            records.Add(obj);
                        }
                    }
                }

                actualExported.Add(ExportType, records.Count());


                if (records.Count > 0)
                {
                    //telemetry.GetMetric("ResultsExported").TrackValue(records.Count);

                    serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
                    var o = new Dictionary<string, Object>();
                    o["results"] = records;
                    o["metadata"] = Helpers.GenerateMetadata();
                    using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, Helpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_" + ExportType.ToString() + ".json.txt")))) //lgtm[cs/path-injection]
                    {
                        using (JsonWriter writer = new JsonTextWriter(sw))
                        {
                            serializer.Serialize(writer, o);
                        }
                    }
                }
            }

            serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
            var output = new Dictionary<string, Object>();
            output["results"] = actualExported;
            output["metadata"] = Helpers.GenerateMetadata();
            using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, Helpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_summary.json.txt")))) //lgtm[cs/path-injection]
            {
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    serializer.Serialize(writer, output);
                }
            }

        }

        private static int RunExportMonitorCommand(ExportMonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);
            DatabaseManager.VerifySchemaVersion();

            if (opts.RunId.Equals("Timestamp"))
            {

                List<string> runIds = DatabaseManager.GetLatestRunIds(1, "monitor");

                if (runIds.Count < 1)
                {
                    Log.Fatal(Strings.Get("Err_CouldntDetermineOneRun"));
                    System.Environment.Exit(-1);
                }
                else
                {
                    opts.RunId = runIds.First();
                }
            }

            Log.Information("{0} {1}", Strings.Get("Exporting"), opts.RunId);

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("OutputPathSet", (opts.OutputPath != null).ToString());

            Telemetry.TrackEvent("Begin Export Monitor", StartEvent);

            WriteMonitorJson(opts.RunId, (int)RESULT_TYPE.FILE, opts.OutputPath);

            return 0;
        }

        public static void WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();
            string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";


            using (var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                using (var reader = cmd.ExecuteReader())
                {

                    FileMonitorEvent obj;

                    while (reader.Read())
                    {
                        obj = JsonConvert.DeserializeObject<FileMonitorEvent>(reader["serialized"].ToString());
                        obj.ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString());
                        records.Add(obj);
                    }
                }
            }

            JsonSerializerSettings settings = new JsonSerializerSettings();
            settings.Formatting = Formatting.Indented;
            settings.NullValueHandling = NullValueHandling.Ignore;
            JsonSerializer serializer = JsonSerializer.Create(settings);
            serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
            var output = new Dictionary<string, Object>();
            output["results"] = records;
            output["metadata"] = Helpers.GenerateMetadata();
            string path = Path.Combine(OutputPath, Helpers.MakeValidFileName(RunId + "_Monitoring_" + ((RESULT_TYPE)ResultType).ToString() + ".json.txt"));

            using (StreamWriter sw = new StreamWriter(path)) //lgtm[cs/path-injection]
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    serializer.Serialize(writer, output);
                }

            Log.Information(Strings.Get("OutputWrittenTo"), path);

        }

        private static int RunMonitorCommand(MonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);
            DatabaseManager.VerifySchemaVersion();

            AdminOrQuit();
            Filter.LoadFilters(opts.FilterLocation);
            opts.RunId = opts.RunId.Trim();
            if (opts.RunId.Equals("Timestamp"))
            {
                opts.RunId = DateTime.Now.ToString("yyyy-MM-dd_HH:mm:ss");
            }
            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            Telemetry.TrackEvent("Begin monitoring", StartEvent);


            if (opts.Overwrite)
            {
                DatabaseManager.DeleteRun(opts.RunId);
            }
            else
            {
                var inner_cmd = new SqliteCommand(SQL_GET_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
                inner_cmd.Parameters.AddWithValue("@run_id", opts.RunId);
                using (var reader = inner_cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Log.Error(Strings.Get("Err_RunIdAlreadyUsed"));
                        return (int)ERRORS.UNIQUE_ID;
                    }
                }

            }

            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type, timestamp, version) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type, @timestamp, @version)";

            var cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", opts.RunId);
            cmd.Parameters.AddWithValue("@file_system", opts.EnableFileSystemMonitor);
            cmd.Parameters.AddWithValue("@ports", false);
            cmd.Parameters.AddWithValue("@users", false);
            cmd.Parameters.AddWithValue("@services", false);
            cmd.Parameters.AddWithValue("@registry", false);
            cmd.Parameters.AddWithValue("@certificates", false);
            cmd.Parameters.AddWithValue("@type", "monitor");
            cmd.Parameters.AddWithValue("@timestamp",DateTime.Now.ToString("yyyy-MM-dd_HH:mm:ss"));
            cmd.Parameters.AddWithValue("@version", Helpers.GetVersionString());
            try
            {
                cmd.ExecuteNonQuery();
                DatabaseManager.Commit();
            }
            catch (Exception e)
            {
                Log.Warning(e.StackTrace);
                Log.Warning(e.Message);
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
            int returnValue = 0;

            if (opts.EnableFileSystemMonitor)
            {
                List<String> directories = new List<string>();

                if (opts.MonitoredDirectories != null)
                {
                    var parts = opts.MonitoredDirectories.ToString().Split(',');
                    foreach (String part in parts)
                    {
                        directories.Add(part);
                    }
                }
                else
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        directories.Add("/");
                    }
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        directories.Add("C:\\");
                    }
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        directories.Add("/");
                    }
                }

                List<NotifyFilters> filterOptions = new List<NotifyFilters>
                {
                    NotifyFilters.Attributes, NotifyFilters.CreationTime, NotifyFilters.DirectoryName, NotifyFilters.FileName, NotifyFilters.LastAccess, NotifyFilters.LastWrite, NotifyFilters.Security, NotifyFilters.Size
                };

                foreach (String dir in directories)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        var newMon = new FileSystemMonitor(opts.RunId, dir, false);
                    }
                    else
                    {
                        foreach (NotifyFilters filter in filterOptions)
                        {
                            Log.Information("Adding Path {0} Filter Type {1}", dir, filter.ToString());
                            var newMon = new FileSystemMonitor(opts.RunId, dir, false, filter);
                            monitors.Add(newMon);
                        }
                    }
                }
            }

            //if (opts.EnableRegistryMonitor)
            //{
                //var monitor = new RegistryMonitor();
                //monitors.Add(monitor);
            //}

            if (monitors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoMonitors"));
                returnValue = 1;
            }

            var exitEvent = new ManualResetEvent(false);

            // If duration is set, we use the secondary timer.
            if (opts.Duration > 0)
            {
                Log.Information("{0} {1} {2}.", Strings.Get("MonitorStartedFor"),opts.Duration, Strings.Get("Minutes"));
                var aTimer = new System.Timers.Timer
                {
                    Interval = opts.Duration * 60 * 1000,
                    AutoReset = false,
                };
                aTimer.Elapsed += (source, e) => { exitEvent.Set(); };

                // Start the timer
                aTimer.Enabled = true;
            }

            foreach (FileSystemMonitor c in monitors)
            {

                Log.Information(Strings.Get("Begin")+" : {0}", c.GetType().Name);

                try
                {
                    c.Start();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, Strings.Get("Err_CollectingFrom"), c.GetType().Name, ex.Message, ex.StackTrace);
                    returnValue = 1;
                }
            }

            // Set up the event to capture CTRL+C
            Console.CancelKeyPress += (sender, eventArgs) => {
                eventArgs.Cancel = true;
                exitEvent.Set();
            };

            Console.Write(Strings.Get("MonitoringPressC"));

            // Write a spinner and wait until CTRL+C
            WriteSpinner(exitEvent);
            Log.Information("");

            foreach (var c in monitors)
            {
                Log.Information(Strings.Get("End"),c.GetType().Name);

                try
                {
                    c.Stop();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, " {0}: {1}", c.GetType().Name, ex.Message, Strings.Get("Err_Stopping"));
                    returnValue = 1;
                }
            }

            DatabaseManager.Commit();

            return returnValue;
        }

        public static List<BaseCollector> GetCollectors()
        {
            return collectors;
        }

        public static List<BaseMonitor> GetMonitors()
        {
            return monitors;
        }

        public static List<BaseCompare> GetComparators()
        {
            return comparators;
        }

        public static string ResultTypeToColumnName(RESULT_TYPE result_type)
        {
            switch (result_type)
            {
                case RESULT_TYPE.FILE:
                    return "file_system";
                case RESULT_TYPE.PORT:
                    return "ports";
                case RESULT_TYPE.REGISTRY:
                    return "registry";
                case RESULT_TYPE.CERTIFICATE:
                    return "certificates";
                case RESULT_TYPE.SERVICES:
                    return "services";
                case RESULT_TYPE.USER:
                    return "users";
                default:
                    return "null";
            }
        }

        private static bool HasResults(string BaseRunId, string CompareRunId, RESULT_TYPE type)
        {
            string GET_SERIALIZED_RESULTS = "select * from runs where run_id = @run_id or run_id=@run_id_2";
            int count = 0;
            var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@run_id", BaseRunId);
            cmd.Parameters.AddWithValue("@run_id", CompareRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    if (int.Parse(reader[ResultTypeToColumnName(type)].ToString()) == 1)
                    {
                        count++;
                    }
                }
            }
            return (count == 2) ? true : false;
        }

        public static Dictionary<string, object> CompareRuns(CompareCommandOptions opts)
        {
            using (var cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
                cmd.Parameters.AddWithValue("@status", RUN_STATUS.RUNNING);
                cmd.ExecuteNonQuery();
            }

            var results = new Dictionary<string, object>
            {
                ["BeforeRunId"] = opts.FirstRunId,
                ["AfterRunId"] = opts.SecondRunId
            };

            comparators = new List<BaseCompare>();

            Dictionary<string, int> count = new Dictionary<string, int>()
                {
                    { "File", 0 },
                    { "Certificate", 0 },
                    { "Registry", 0 },
                    { "Port", 0 },
                    { "Service", 0 },
                    { "User", 0 }
                };

            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                Log.Debug(Strings.Get("GettingResultTypes"));
                cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);

                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (int.Parse(reader["file_system"].ToString()) != 0)
                        {
                            count["File"]++;
                        }
                        if (int.Parse(reader["ports"].ToString()) != 0)
                        {
                            count["Port"]++;
                        }
                        if (int.Parse(reader["users"].ToString()) != 0)
                        {
                            count["User"]++;
                        }
                        if (int.Parse(reader["services"].ToString()) != 0)
                        {
                            count["Service"]++;
                        }
                        if (int.Parse(reader["registry"].ToString()) != 0)
                        {
                            count["Registry"]++;
                        }
                        if (int.Parse(reader["certificates"].ToString()) != 0)
                        {
                            count["Certificate"]++;
                        }
                    }
                }
            }

            foreach (KeyValuePair<string, int> entry in count)
            {
                if (entry.Value == 2)
                {
                    if (entry.Key.Equals("File"))
                    {
                        comparators.Add(new FileSystemCompare());
                    }
                    if (entry.Key.Equals("Certificate"))
                    {
                        comparators.Add(new CertificateCompare());
                    }
                    if (entry.Key.Equals("Registry"))
                    {
                        comparators.Add(new RegistryCompare());
                    }
                    if (entry.Key.Equals("Port"))
                    {
                        comparators.Add(new OpenPortCompare());
                    }
                    if (entry.Key.Equals("Service"))
                    {
                        comparators.Add(new ServiceCompare());
                    }
                    if (entry.Key.Equals("User"))
                    {
                        comparators.Add(new UserAccountCompare());
                    }
                }
            }

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();

            foreach ( BaseCompare c in comparators)
            {
                Log.Information(Strings.Get("Begin") + " : {0}", c.GetType().Name);
                if (!c.TryCompare(opts.FirstRunId, opts.SecondRunId))
                {
                    Log.Warning(Strings.Get("Err_Comparing") + " : {0}", c.GetType().Name);
                }
                c.Results.ToList().ForEach(x => results.Add(x.Key, x.Value));
                EndEvent.Add(c.GetType().ToString(), c.GetNumResults().ToString());
            }

            Telemetry.TrackEvent("End Command", EndEvent);

            using(var cmd = new SqliteCommand(UPDATE_RUN_IN_RESULT_TABLE, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
                cmd.Parameters.AddWithValue("@status", RUN_STATUS.COMPLETED);
                cmd.ExecuteNonQuery();
            }

            DatabaseManager.Commit();
            return results;
        }

        public static ERRORS RunGuiMonitorCommand(MonitorCommandOptions opts)
        {
            if (opts.EnableFileSystemMonitor)
            {
                List<String> directories = new List<string>();

                var parts = opts.MonitoredDirectories.ToString().Split(',');
                foreach (String part in parts)
                {
                    directories.Add(part);
                }


                foreach (String dir in directories)
                {
                    try
                    {
                        FileSystemMonitor newMon = new FileSystemMonitor(opts.RunId, dir, opts.InterrogateChanges);
                        monitors.Add(newMon);
                    }
                    catch (ArgumentException)
                    {
                        Log.Warning("{1}: {0}",dir, Strings.Get("InvalidPath"));
                        return ERRORS.INVALID_PATH;
                    }
                }
            }

            if (monitors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoMonitors"));
            }

            foreach (var c in monitors)
            {
                try
                {
                    c.Start();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, Strings.Get("Err_CollectingFrom"), c.GetType().Name, ex.Message, ex.StackTrace);
                }
            }

            return ERRORS.NONE;
        }

        public static int StopMonitors()
        {
            foreach (var c in monitors)
            {
                Log.Information(Strings.Get("End"), c.GetType().Name);

                try
                {
                    c.Stop();
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "{2} {0}: {1}", c.GetType().Name, ex.Message, Strings.Get("Err_Stopping"));
                }
            }

            DatabaseManager.Commit();

            return 0;
        }
        public static void AdminOrQuit()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (!Elevation.IsAdministrator())
                {
                    Log.Warning(Strings.Get("Err_RunAsAdmin"));
                    Environment.Exit(1);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Fatal(Strings.Get("Err_RunAsRoot"));
                    Environment.Exit(1);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Fatal(Strings.Get("Err_RunAsRoot"));
                    Environment.Exit(1);
                }
            }
        }

        public static int RunCollectCommand(CollectCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            AdminOrQuit();
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);
            DatabaseManager.VerifySchemaVersion();

            int returnValue = (int)ERRORS.NONE;
            opts.RunId = opts.RunId.Trim();
            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("Files", opts.EnableAllCollectors ? "True" : opts.EnableFileSystemCollector.ToString());
            StartEvent.Add("Ports", opts.EnableAllCollectors ? "True" : opts.EnableNetworkPortCollector.ToString());
            StartEvent.Add("Users", opts.EnableAllCollectors ? "True" : opts.EnableUserCollector.ToString());
            StartEvent.Add("Certificates", opts.EnableAllCollectors ? "True" : opts.EnableCertificateCollector.ToString());
            StartEvent.Add("Registry", opts.EnableAllCollectors ? "True" : opts.EnableRegistryCollector.ToString());
            StartEvent.Add("Service", opts.EnableAllCollectors ? "True" : opts.EnableServiceCollector.ToString());
            Telemetry.TrackEvent("Run Command", StartEvent);


            if (opts.RunId.Equals("Timestamp"))
            {
                opts.RunId = DateTime.Now.ToString("yyyy-MM-dd_HH:mm:ss");
            }

            if (opts.EnableFileSystemCollector || opts.EnableAllCollectors)
            {
                if (String.IsNullOrEmpty(opts.SelectedDirectories))
                {
                    collectors.Add(new FileSystemCollector(opts.RunId, enableHashing: opts.GatherHashes));
                }
                else
                {
                    collectors.Add(new FileSystemCollector(opts.RunId, enableHashing: opts.GatherHashes, directories: opts.SelectedDirectories));
                }
            }
            if (opts.EnableNetworkPortCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new OpenPortCollector(opts.RunId));
            }
            if (opts.EnableServiceCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new ServiceCollector(opts.RunId));
            }
            if (opts.EnableUserCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new UserAccountCollector(opts.RunId));
            }
            if (opts.EnableRegistryCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new RegistryCollector(opts.RunId));
            }
            if (opts.EnableCertificateCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new CertificateCollector(opts.RunId));
            }

            if (collectors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoCollectors"));
                return -1;
            }
            Log.Information(opts.FilterLocation);
            if (!opts.NoFilters)
            {
                if (opts.FilterLocation.Equals("Use embedded filters."))
                {
                    Filter.LoadEmbeddedFilters();
                }
                else
                {
                    Filter.LoadFilters(opts.FilterLocation);
                }
            }

            if (opts.Overwrite)
            {
                DatabaseManager.DeleteRun(opts.RunId);
            }
            else
            {
                var cmd = new SqliteCommand(SQL_GET_RUN, DatabaseManager.Connection);
                cmd.Parameters.AddWithValue("@run_id", opts.RunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Log.Error(Strings.Get("Err_RunIdAlreadyUsed"));
                        return (int)ERRORS.UNIQUE_ID;
                    }
                }
            }

            Log.Information("{0} {1}", Strings.Get("Begin"), opts.RunId);

            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type, timestamp, version) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type, @timestamp, @version)";

            using (var cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                if (opts.MatchedCollectorId != null)
                {
                    using (var inner_cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, DatabaseManager.Connection, DatabaseManager.Transaction))
                    {
                        inner_cmd.Parameters.AddWithValue("@run_id", opts.MatchedCollectorId);
                        using (var reader = inner_cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                opts.EnableFileSystemCollector = (int.Parse(reader["file_system"].ToString()) != 0);
                                opts.EnableNetworkPortCollector = (int.Parse(reader["ports"].ToString()) != 0);
                                opts.EnableUserCollector = (int.Parse(reader["users"].ToString()) != 0);
                                opts.EnableServiceCollector = (int.Parse(reader["services"].ToString()) != 0);
                                opts.EnableRegistryCollector = (int.Parse(reader["registry"].ToString()) != 0);
                                opts.EnableCertificateCollector = (int.Parse(reader["certificates"].ToString()) != 0);
                            }
                        }
                    }
                }
                else if (opts.EnableAllCollectors)
                {
                    opts.EnableFileSystemCollector = true;
                    opts.EnableNetworkPortCollector = true;
                    opts.EnableUserCollector = true;
                    opts.EnableServiceCollector = true;
                    opts.EnableRegistryCollector = true;
                    opts.EnableCertificateCollector = true;
                }

                cmd.Parameters.AddWithValue("@file_system", opts.EnableFileSystemCollector);
                cmd.Parameters.AddWithValue("@ports", opts.EnableNetworkPortCollector);
                cmd.Parameters.AddWithValue("@users", opts.EnableUserCollector);
                cmd.Parameters.AddWithValue("@services", opts.EnableServiceCollector);
                cmd.Parameters.AddWithValue("@registry", opts.EnableRegistryCollector);
                cmd.Parameters.AddWithValue("@certificates", opts.EnableCertificateCollector);
                

                cmd.Parameters.AddWithValue("@run_id", opts.RunId);

                cmd.Parameters.AddWithValue("@type", "collect");
                cmd.Parameters.AddWithValue("@timestamp", DateTime.Now.ToString("yyyy-MM-dd_HH:mm:ss"));
                cmd.Parameters.AddWithValue("@version", Helpers.GetVersionString());
                try
                {
                    cmd.ExecuteNonQuery();
                    DatabaseManager.Commit();
                }
                catch (Exception e)
                {
                    Log.Warning(e.StackTrace);
                    Log.Warning(e.Message);
                    returnValue = (int)ERRORS.UNIQUE_ID;
                    Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                }
            }
            Log.Information(Strings.Get("Starting"), collectors.Count.ToString(), Strings.Get("Collectors"));

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();
            foreach (BaseCollector c in collectors)
            {
                try
                {
                    c.Execute();
                    EndEvent.Add(c.GetType().ToString(), c.NumCollected().ToString());
                }
                catch (Exception ex)
                {
                    Log.Error(ex, Strings.Get("Err_CollectingFrom"), c.GetType().Name, ex.Message, ex.StackTrace);
                    returnValue = 1;
                }
            }

            Telemetry.TrackEvent("End Command", EndEvent);

            DatabaseManager.Commit();
            return returnValue;
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns("monitor");
        }

        public static List<string> GetRuns(string type)
        {
            string Select_Runs = "select distinct run_id from runs where type=@type order by timestamp asc;";

            List<string> Runs = new List<string>();

            var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@type", type);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add((string)reader["run_id"]);
                }
            }
            return Runs;
        }

        public static List<string> GetRuns()
        {
            return GetRuns("collect");
        }

        public static void ClearCollectors()
        {
            collectors = new List<BaseCollector>();
        }

        public static void ClearMonitors()
        {
            collectors = new List<BaseCollector>();
        }
        
        private static int RunCompareCommand(CompareCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Setup();
            CheckFirstRun();
            Telemetry.Setup(Gui: false);
            DatabaseManager.VerifySchemaVersion();

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();

            Telemetry.TrackEvent("Begin Compare Command", StartEvent);

            if (opts.FirstRunId == "Timestamps" || opts.SecondRunId == "Timestamps")
            {
                List<string> runIds = DatabaseManager.GetLatestRunIds(2, "collect");

                if (runIds.Count < 2)
                {
                    Log.Fatal(Strings.Get("Err_CouldntDetermineTwoRun"));
                    System.Environment.Exit(-1);
                }
                else
                {
                    opts.SecondRunId = runIds.First();
                    opts.FirstRunId = runIds.ElementAt(1);
                }
            }

            var results = CompareRuns(opts);

            var engine = new RazorLightEngineBuilder()
              .UseEmbeddedResourcesProject(typeof(AttackSurfaceAnalyzerCLI))
              .UseMemoryCachingProvider()
              .Build();

            var assembly = Assembly.GetExecutingAssembly();

            var result = engine.CompileRenderAsync("Output.Output.cshtml", results).Result;
            File.WriteAllText($"{opts.OutputBaseFilename}.html", result);
            Log.Information(Strings.Get("OutputWrittenTo"), opts.OutputBaseFilename + ".html");

            return 0;
        }

        // Used for monitors. This writes a little spinner animation to indicate that monitoring is underway
        static void WriteSpinner(ManualResetEvent untilDone)
        {
            int counter = 0;
            while (!untilDone.WaitOne(200))
            {
                counter++;
                switch (counter % 4)
                {
                    case 0: Console.Write("/"); break;
                    case 1: Console.Write("-"); break;
                    case 2: Console.Write("\\"); break;
                    case 3: Console.Write("|"); break;
                }
                if (Console.CursorLeft > 0)
                {
                    try
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                        Console.SetCursorPosition(0, Console.CursorTop);
                    }
                }
            }
        }

        public static string GetLatestRunId()
        {
            if (collectors.Count > 0)
            {
                return collectors[0].runId;
            }
            return "No run id";
        }
    }


}