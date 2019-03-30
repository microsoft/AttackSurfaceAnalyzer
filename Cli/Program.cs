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

namespace AttackSurfaceAnalyzer.Cli
{

    [Verb("compare", HelpText = "Compare ASA executions")]
    public class CompareCommandOptions
    {
        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option(Required = true, HelpText = "First run (pre-install) identifier")]
        public string FirstRunId { get; set; }

        [Option(Required = true, HelpText = "Second run (post-install) identifier")]
        public string SecondRunId { get; set; }

        [Option(Required = false, HelpText = "Base name of output file (default: output)", Default = "output")]
        public string OutputBaseFilename { get; set; }

        // Omitting long name, defaults to name of property, ie "--verbose"
        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }
    [Verb("collect", HelpText = "Collect operating system metrics")]
    public class CollectCommandOptions
    {
        [Option(Required = true, HelpText = "Identifies which run this is (used during comparison)")]
        public string RunId { get; set; }

        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
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

        [Option('h',"gather-hashes", Required = false, HelpText = "Hashes every file when using the File Collector.  May dramatically increase run time of the scan.")]
        public bool GatherHashes { get; set; }

        // Omitting long name, defaults to name of property, ie "--verbose"
        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }
    }
    [Verb("monitor", HelpText = "Continue running and monitor activity")]
    public class MonitorCommandOptions
    {
        [Option(Required = true, HelpText = "Identifies which run this is. Monitor output can be combined with collect output, but doesn't need to be compared.")]
        public string RunId { get; set; }

        [Option(Required = false, HelpText = "Name of output database (default: asa.sqlite)", Default = "asa.sqlite")]
        public string DatabaseFilename { get; set; }

        [Option('f', "file-system", Required = false, HelpText = "Enable the file system monitor. Unless -d is specified will monitor the entire file system.")]
        public bool EnableFileSystemMonitor { get; set; }

        [Option('d', "directories", Required = false, HelpText = "Comma-separated list of directories to monitor.")]
        public string MonitoredDirectories { get; set; }

        [Option('i', "interrogate-file-changes", Required = false, HelpText = "On a file create or change gather the post-change file size and security attributes")]
        public bool InterrogateChanges { get; set; }

        [Option('r', "registry", Required = false, HelpText = "Monitor the registry for changes. (Windows Only)")]
        public bool EnableRegistryMonitor { get; set; }

        // Omitting long name, defaults to name of property, ie "--verbose"
        [Option(Default = false, HelpText = "Increase logging verbosity")]
        public bool Verbose { get; set; }

    }

    public static class AttackSurfaceAnalyzerCLI
    {
        private static List<BaseCollector> collectors = new List<BaseCollector>();
        private static List<BaseMonitor> monitors = new List<BaseMonitor>();
        private static List<BaseCompare> comparators = new List<BaseCompare>();

        private static readonly string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private static readonly string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";
        private static readonly string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id";
        private static readonly string SQL_GET_RUN = "select run_id from runs where run_id=@run_id";



        static void Main(string[] args)
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

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, CompareCommandOptions, MonitorCommandOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) => RunCollectCommand(opts),
                    (CompareCommandOptions opts) => RunCompareCommand(opts),
                    (MonitorCommandOptions opts) => RunMonitorCommand(opts),
                    errs => 1
                );

            Logger.Instance.Info("Attack Surface Analyzer Complete.");
        }

        private static int RunMonitorCommand(MonitorCommandOptions opts)
        {
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            var cmd = new SqliteCommand(SQL_GET_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", opts.RunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Logger.Instance.Error("That runid was already used. Must use a unique runid for each run.");
                    return (int)ERRORS.UNIQUE_ID;
                }
            }

            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type)";

            cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", opts.RunId);
            cmd.Parameters.AddWithValue("@file_system", opts.EnableFileSystemMonitor);
            cmd.Parameters.AddWithValue("@ports", false);
            cmd.Parameters.AddWithValue("@users", false);
            cmd.Parameters.AddWithValue("@services", false);
            cmd.Parameters.AddWithValue("@registry", false);
            cmd.Parameters.AddWithValue("@certificates", false);
            cmd.Parameters.AddWithValue("@type", "monitor");
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

            if (opts.EnableRegistryMonitor)
            {
                var monitor = new RegistryMonitor();
                monitors.Add(monitor);
            }

            if (monitors.Count == 0)
            {
                Logger.Instance.Warn("No monitors have been defined.");
                returnValue = 1;
            }


            foreach (var c in monitors)
            {
                Logger.Instance.Info("Executing: {0}", c.GetType().Name);

                try
                {
                    // How to capture when we should start?
                    // Re use the code from ASE-Console here
                    c.Start();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1}", c.GetType().Name, ex.Message);
                    returnValue = 1;
                }
            }

            var exitEvent = new ManualResetEvent(false);

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
            var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction);
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

            var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, DatabaseManager.Connection, DatabaseManager.Transaction);
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
            
            cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
            cmd.Parameters.AddWithValue("@status", RUN_STATUS.RUNNING);
            cmd.ExecuteNonQuery();

            foreach (var c in comparators)
            {
                Logger.Instance.Debug(c.GetType());
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
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1}", c.GetType().Name, ex.Message);
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

        public static int RunCollectCommand(CollectCommandOptions opts)
        {
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

            int returnValue = (int)ERRORS.NONE;

            var cmd = new SqliteCommand(SQL_GET_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", opts.RunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Logger.Instance.Error("That runid was already used. Must use a unique runid for each run.");
                    return (int)ERRORS.UNIQUE_ID;
                }
            }

            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type)";

            cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);


            if (opts.EnableAllCollectors)
            {
                cmd.Parameters.AddWithValue("@file_system", true);
                cmd.Parameters.AddWithValue("@ports", true);
                cmd.Parameters.AddWithValue("@users", true);
                cmd.Parameters.AddWithValue("@services", true);
                cmd.Parameters.AddWithValue("@registry", true);
                cmd.Parameters.AddWithValue("@certificates", true);
            }
            else
            {
                cmd.Parameters.AddWithValue("@file_system", opts.EnableFileSystemCollector);
                cmd.Parameters.AddWithValue("@ports", opts.EnableNetworkPortCollector);
                cmd.Parameters.AddWithValue("@users", opts.EnableUserCollector);
                cmd.Parameters.AddWithValue("@services", opts.EnableServiceCollector);
                cmd.Parameters.AddWithValue("@registry", opts.EnableRegistryCollector);
                cmd.Parameters.AddWithValue("@certificates", opts.EnableCertificateCollector);
            }

            cmd.Parameters.AddWithValue("@run_id", opts.RunId);

            cmd.Parameters.AddWithValue("@type", "collect");
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
                Logger.Instance.Info("Executing: {0}", c.GetType().Name);
                try
                {
                    c.Execute();
                }
                catch (Exception ex)
                {
                    Logger.Instance.Info(ex.Message);
                    Logger.Instance.Error(ex, "Error collecting from {0}: {1}", c.GetType().Name, ex.Message);
                    returnValue = 1;
                }
                Logger.Instance.Info("Completed: {0}", c.GetType().Name);
            }

            DatabaseManager.Commit();
            return returnValue;
        }

        public static List<string> GetRuns()
        {
            string Select_Runs = "select distinct run_id from runs;";

            List<string> Runs = new List<string>();

            var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add((string)reader["run_id"]);
                }
            }

            return Runs;
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
            DatabaseManager.SqliteFilename = opts.DatabaseFilename;

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
                    Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                }
            }
        }
    }
}