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
using System.Diagnostics;
using Microsoft.ApplicationInsights.Extensibility;

namespace AttackSurfaceAnalyzer.Cli
{

    [Verb("compare", HelpText = "Compare ASA executions and output a .html summary")]
    public class CompareCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(Required = true, HelpText = "First run (pre-install) identifier")]
        public string FirstRunId { get; set; }

        [Option(Required = true, HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; }

        [Option(Required = false, HelpText = "Base name of output file", Default = "output")]
        public string OutputBaseFilename { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("export-collect", HelpText = "Compare ASA executions and output a .json report")]
    public class ExportCollectCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(Required = true, HelpText = "First run (pre-install) identifier")]
        public string FirstRunId { get; set; }

        [Option(Required = true, HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; }

        [Option(Required = false, HelpText = "Directory to output to", Default = ".")]
        public string OutputPath { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("export-monitor", HelpText = "Output a .json report for a monitor run")]
    public class ExportMonitorCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(Required = true, HelpText = "Monitor run identifier")]
        public string RunId { get; set; }

        [Option(Required = false, HelpText = "Directory to output to", Default = ".")]
        public string OutputPath { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("collect", HelpText = "Collect operating system metrics")]
    public class CollectCommandOptions
    {
        [Option(Required = true, HelpText = "Identifies which run this is (used during comparison)")]
        public string RunId { get; set; }

        [Option(Required = false, HelpText = "Name of output database", Default = "asa.sqlite")]
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

        [Option("filter", Required = false, HelpText = "Provide a JSON filter file.", Default = "filters.json")]
        public string FilterLocation { get; set; }

        [Option('h',"gather-hashes", Required = false, HelpText = "Hashes every file when using the File Collector.  May dramatically increase run time of the scan.")]
        public bool GatherHashes { get; set; }

        [Option(Default =false, HelpText ="If the specified runid already exists delete all data from that run before proceeding.")]
        public bool Overwrite { get; set; }

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }
    }
    [Verb("monitor", HelpText = "Continue running and monitor activity")]
    public class MonitorCommandOptions
    {
        [Option(Required = true, HelpText = "Identifies which run this is. Monitor output can be combined with collect output, but doesn't need to be compared.")]
        public string RunId { get; set; }

        [Option(Required = false, HelpText = "Name of output database", Default = "asa.sqlite")]
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

        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }
    }

    [Verb("config", HelpText = "List runs in the database")]
    public class ConfigCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option("list-runs", Required = false, HelpText = "List runs in the database")]
        public bool ListRuns { get; set; }

        [Option("reset-database", Required = false, HelpText = "Delete the output database")]
        public bool ResetDatabase { get; set; }

        [Option("telemetry-opt-out", Required = false, HelpText = "Change your telemetry opt out setting")]
        public string TelemetryOptOut { get; set; }

        [Option("delete-run", Required = false, HelpText = "Delete a specific run from the database")]
        public string DeleteRunId { get; set; }
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
        private static readonly string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]


        static void Main(string[] args)
        {
            Logger.Setup();
            string version = (Assembly
                        .GetEntryAssembly()
                        .GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                        as AssemblyInformationalVersionAttribute[])[0].InformationalVersion;
            Logger.Instance.Info("AttackSurfaceAnalyzerCli v." + version);
            Logger.Instance.Debug(version);

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, CompareCommandOptions, MonitorCommandOptions, ExportMonitorCommandOptions, ExportCollectCommandOptions, ConfigCommandOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) => RunCollectCommand(opts),
                    (CompareCommandOptions opts) => RunCompareCommand(opts),
                    (MonitorCommandOptions opts) => RunMonitorCommand(opts),
                    (ExportCollectCommandOptions opts) => RunExportCollectCommand(opts),
                    (ExportMonitorCommandOptions opts) => RunExportMonitorCommand(opts),
                    (ConfigCommandOptions opts) => SetupConfig(opts),
                    errs => 1
                );

            Logger.Instance.Info("Attack Surface Analyzer Complete.");
        }

        private static int SetupConfig(ConfigCommandOptions opts)
        {
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            if (opts.ResetDatabase)
            {
                DatabaseManager.CloseDatabase();
                File.Delete(opts.DatabaseFilename);
                Logger.Instance.Info("Deleted Database");
            }
            else
            {
                if (opts.ListRuns)
                {

                    Logger.Instance.Info("Begin Collect Run Ids");
                    List<string> CollectRuns = GetRuns("collect");
                    foreach (string run in CollectRuns)
                    {
                        using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, DatabaseManager.Connection, DatabaseManager.Transaction))
                        {
                            cmd.Parameters.AddWithValue("@run_id", run);
                            using (var reader = cmd.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    string output = String.Format("{0} {1} {2} {3}",
                                                                    reader["timestamp"].ToString(),
                                                                    reader["version"].ToString(),
                                                                    reader["type"].ToString(),
                                                                    reader["run_id"].ToString());
                                    Logger.Instance.Info(output);
                                    output = String.Format("{0} {1} {2} {3} {4} {5}",
                                                            (int.Parse(reader["file_system"].ToString()) != 0) ? "FILES" : "",
                                                            (int.Parse(reader["ports"].ToString()) != 0) ? "PORTS" : "",
                                                            (int.Parse(reader["users"].ToString()) != 0) ? "USERS" : "",
                                                            (int.Parse(reader["services"].ToString()) != 0) ? "SERVICES" : "",
                                                            (int.Parse(reader["certificates"].ToString()) != 0) ? "CERTIFICATES" : "",
                                                            (int.Parse(reader["registry"].ToString()) != 0) ? "REGISTRY" : "");
                                    Logger.Instance.Info(output);

                                }
                            }
                        }
                    }
                    Logger.Instance.Info("Begin monitor Run Ids");
                    List<string> MonitorRuns = GetRuns("monitor");
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
                                    Logger.Instance.Info(output);
                                    output = String.Format("{0} {1} {2} {3} {4} {5}",
                                                            (int.Parse(reader["file_system"].ToString()) != 0) ? "FILES" : "",
                                                            (int.Parse(reader["ports"].ToString()) != 0) ? "PORTS" : "",
                                                            (int.Parse(reader["users"].ToString()) != 0) ? "USERS" : "",
                                                            (int.Parse(reader["services"].ToString()) != 0) ? "SERVICES" : "",
                                                            (int.Parse(reader["certificates"].ToString()) != 0) ? "CERTIFICATES" : "",
                                                            (int.Parse(reader["registry"].ToString()) != 0) ? "REGISTRY" : "");
                                    Logger.Instance.Info(output);

                                }
                            }
                        }
                    }
                }

                if (opts.TelemetryOptOut != null)
                {
                    TelemetryConfiguration.Active.DisableTelemetry = bool.Parse(opts.TelemetryOptOut);


                    using (var cmd = new SqliteCommand(UPDATE_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@TelemetryOptOut", bool.Parse(opts.TelemetryOptOut).ToString());
                        cmd.ExecuteNonQuery();
                    }

                    DatabaseManager.Commit();

                    Logger.Instance.Info("Your current telemetry opt out setting is {0}.", (bool.Parse(opts.TelemetryOptOut)) ? "Opted out" : "Opted in");
                }
                if (opts.DeleteRunId != null)
                {
                    DatabaseManager.DeleteRun(opts.DeleteRunId);
                }
            }



            return 0;
        }

        private static int RunExportCollectCommand(ExportCollectCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(false, opts.Verbose);
#endif
            Logger.Instance.Debug("Entering RunExportCollectCommand");

            DatabaseManager.SqliteFilename = opts.DatabaseFilename;
            DatabaseManager.Commit();

            bool RunComparisons = true;
            //string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id";

            //var cmd = new SqliteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, DatabaseManager.Connection);
            //cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            //cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
            //using (var reader = cmd.ExecuteReader())
            //{
            //    while (reader.Read())
            //    {
            //        RunComparisons = false;
            //    }
            //}
            Logger.Instance.Debug("Halfway RunExportCollectCommand");

            CompareCommandOptions options = new CompareCommandOptions();
            options.DatabaseFilename = opts.DatabaseFilename;
            options.FirstRunId = opts.FirstRunId;
            options.SecondRunId = opts.SecondRunId;

            if (RunComparisons)
            {
                CompareRuns(options);
            }
            Logger.Instance.Debug("Done comparing RunExportCollectCommand");

            WriteScanJson(0, opts.FirstRunId, opts.SecondRunId, true, opts.OutputPath);

            return 0;

        }

        public static void WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            string GET_COMPARISON_RESULTS = "select * from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type order by base_row_key;";
            string GET_SERIALIZED_RESULTS = "select serialized from @table_name where row_key = @row_key and run_id = @run_id";

            Logger.Instance.Debug("Starting WriteScanJson");

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
                List<CompareResult> records = new List<CompareResult>();
                var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection);
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
                            var inner_cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(ExportType)), DatabaseManager.Connection);
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
                            var inner_cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(ExportType)), DatabaseManager.Connection);
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
                actualExported.Add(ExportType, records.Count());


                if (records.Count > 0)
                {
                    //telemetry.GetMetric("ResultsExported").TrackValue(records.Count);

                    serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());

                    using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, Helpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_" + ExportType.ToString() + ".json.txt")))) //lgtm[cs/path-injection]
                    {
                        using (JsonWriter writer = new JsonTextWriter(sw))
                        {
                            serializer.Serialize(writer, records);
                        }
                    }
                }
            }

            serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());

            using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, Helpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_summary.json.txt")))) //lgtm[cs/path-injection]
            {
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    serializer.Serialize(writer, actualExported);
                }
            }

        }

        private static int RunExportMonitorCommand(ExportMonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(false, opts.Verbose);
#endif
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            WriteMonitorJson(opts.RunId, (int)RESULT_TYPE.FILE, opts.OutputPath);
            return 0;
        }

        public static void WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();
            string GET_SERIALIZED_RESULTS = "select change_type,serialized from file_system_monitored where run_id = @run_id";


            var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, DatabaseManager.Connection);
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

            JsonSerializerSettings settings = new JsonSerializerSettings();
            settings.Formatting = Formatting.Indented;
            settings.NullValueHandling = NullValueHandling.Ignore;
            JsonSerializer serializer = JsonSerializer.Create(settings);
            serializer.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());

            using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, Helpers.MakeValidFileName(RunId + "_Monitoring_" + ((RESULT_TYPE)ResultType).ToString() + ".json.txt")))) //lgtm[cs/path-injection]
            {
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    serializer.Serialize(writer, records);
                }
            }
        }

        private static int RunMonitorCommand(MonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(false, opts.Verbose);
#endif
            AdminOrQuit();
            Filter.LoadFilters(opts.FilterLocation);

            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

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
                        Logger.Instance.Error("That runid was already used. Must use a unique runid for each run. Use --overwrite to discard previous run information.");
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
            cmd.Parameters.AddWithValue("@timestamp",DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            cmd.Parameters.AddWithValue("@version", Helpers.GetVersionString());
            try
            {
                cmd.ExecuteNonQuery();
                DatabaseManager.Commit();
            }
            catch (Exception e)
            {
                Logger.Instance.Warn(e.StackTrace);
                Logger.Instance.Warn(e.Message);
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
                    foreach (NotifyFilters filter in filterOptions)
                    {
                        var newMon = new FileSystemMonitor(opts.RunId, dir, (filter != NotifyFilters.LastAccess) && opts.InterrogateChanges, filter);
                        monitors.Add(newMon);
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
                Logger.Instance.Warn("No monitors have been defined.");
                returnValue = 1;
            }

            var exitEvent = new ManualResetEvent(false);

            // If duration is set, we use the secondary timer.
            if (opts.Duration > 0)
            {
                Logger.Instance.Info("Monitor started for " + opts.Duration + " minute(s).");
                var aTimer = new System.Timers.Timer
                {
                    Interval = opts.Duration * 60 * 1000,
                    AutoReset = false,
                };
                aTimer.Elapsed += (source, e) => { exitEvent.Set(); };

                // Start the timer
                aTimer.Enabled = true;
            }

            foreach (var c in monitors)
            {
                Logger.Instance.Info("Executing: {0}", c.GetType().Name);

                try
                {
                    c.Start();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1} {2}", c.GetType().Name, ex.Message, ex.StackTrace);
                    returnValue = 1;
                }
            }

            // Set up the event to capture CTRL+C
            Console.CancelKeyPress += (sender, eventArgs) => {
                eventArgs.Cancel = true;
                exitEvent.Set();
            };

            Console.Write("Monitoring, press CTRL+C to stop...  ");

            // Write a spinner and wait until CTRL+C
            WriteSpinner(exitEvent);
            Logger.Instance.Info("");

            foreach (var c in monitors)
            {
                Logger.Instance.Info("Stopping: {0}", c.GetType().Name);

                try
                {
                    c.Stop();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error stopping {0}: {1}", c.GetType().Name, ex.Message);
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
            var results = new Dictionary<string, object>
            {
                ["BeforeRunId"] = opts.FirstRunId,
                ["AfterRunId"] = opts.SecondRunId
            };

            comparators = new List<BaseCompare>();

            Logger.Instance.Debug("Getting result types");

            var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, DatabaseManager.Connection);
            cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);

            var count = new Dictionary<string, int>()
            {
                { "File", 0 },
                { "Certificate", 0 },
                { "Registry", 0 },
                { "Port", 0 },
                { "Service", 0 },
                { "User", 0 }
            };

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
            Logger.Instance.Debug("Inserting run into results table as running");

            cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
            cmd.Parameters.AddWithValue("@status", RUN_STATUS.RUNNING);
            cmd.ExecuteNonQuery();

            foreach (var c in comparators)
            {
                Logger.Instance.Info("Starting {0}", c.GetType());
                if (!c.TryCompare(opts.FirstRunId, opts.SecondRunId))
                {
                    Logger.Instance.Warn("Error when comparing {0}", c.GetType().FullName);
                }
                c.Results.ToList().ForEach(x => results.Add(x.Key, x.Value));
            }
            cmd = new SqliteCommand(UPDATE_RUN_IN_RESULT_TABLE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
            cmd.Parameters.AddWithValue("@status", RUN_STATUS.COMPLETED);
            cmd.ExecuteNonQuery();

            DatabaseManager.Commit();
            return results;
        }

        public static int RunGuiMonitorCommand(MonitorCommandOptions opts)
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
                    FileSystemMonitor newMon = new FileSystemMonitor(opts.RunId, dir, opts.InterrogateChanges);
                    monitors.Add(newMon);
                }
            }

            if (monitors.Count == 0)
            {
                Logger.Instance.Warn("No monitors have been defined.");
            }

            foreach (var c in monitors)
            {
                try
                {
                    c.Start();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1} {2}", c.GetType().Name, ex.Message, ex.StackTrace);
                }
            }

            return 0;
        }

        public static int StopMonitors()
        {
            foreach (var c in monitors)
            {
                Logger.Instance.Info("Stopping: {0}", c.GetType().Name);

                try
                {
                    c.Stop();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error stopping {0}: {1}", c.GetType().Name, ex.Message);
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
                    Logger.Instance.Warn("Attack Surface Enumerator must be run as Administrator.");
                    Environment.Exit(1);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Logger.Instance.Fatal("Attack Surface Enumerator must be run as root.");
                    Environment.Exit(1);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Logger.Instance.Fatal("Attack Surface Enumerator must be run as root.");
                    Environment.Exit(1);
                }
            }
        }

        public static int RunCollectCommand(CollectCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(false, opts.Verbose);
#endif
            AdminOrQuit();
            Filter.LoadFilters(opts.FilterLocation);

            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            int returnValue = (int)ERRORS.NONE;

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
                        Logger.Instance.Error("That runid was already used. Must use a unique runid for each run. Use --overwrite to discard previous run information.");
                        return (int)ERRORS.UNIQUE_ID;
                    }
                }
            }


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
                cmd.Parameters.AddWithValue("@timestamp", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                cmd.Parameters.AddWithValue("@version", Helpers.GetVersionString());
                try
                {
                    cmd.ExecuteNonQuery();
                    DatabaseManager.Commit();
                }
                catch (Exception e)
                {
                    Logger.Instance.Warn(e.StackTrace);
                    Logger.Instance.Warn(e.Message);
                    returnValue = (int)ERRORS.UNIQUE_ID;
                }
            }




            if (opts.EnableFileSystemCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FileSystemCollector(opts.RunId, enableHashing:opts.GatherHashes));
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
                Logger.Instance.Warn("No collectors have been defined.");
                returnValue = 1;
            }

            Logger.Instance.Info("Started {0} collectors",collectors.Count.ToString());

            foreach (BaseCollector c in collectors)
            {
                // c.Filters = read filters in here
                Logger.Instance.Info("Executing: {0}", c.GetType().Name);
                try
                {
                    c.Execute();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1} {2}", c.GetType().Name, ex.Message, ex.StackTrace);
                    returnValue = 1;
                }
                Logger.Instance.Info("Completed: {0}", c.GetType().Name);
            }

            DatabaseManager.Commit();
            return returnValue;
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns("monitor");
        }

        public static List<string> GetRuns(string type)
        {
            string Select_Runs = "select distinct run_id from runs where type=@type;";

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
            Logger.Setup(false, opts.Verbose);
#endif
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            Logger.Instance.Debug("Starting CompareRuns");
            var results = CompareRuns(opts);

            var engine = new RazorLightEngineBuilder()
              .UseFilesystemProject(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location))
              .UseMemoryCachingProvider()
              .Build();

            var result = engine.CompileRenderAsync("Output" + Path.DirectorySeparatorChar + "Output.cshtml", results).Result;
            File.WriteAllText($"{opts.OutputBaseFilename}.html", result);

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
    }
}