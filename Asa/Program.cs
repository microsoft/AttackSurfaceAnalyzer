// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using CommandLine;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer
{ 
    public static class AttackSurfaceAnalyzerClient
    {
        private static List<BaseCollector> collectors = new List<BaseCollector>();
        private static List<BaseMonitor> monitors = new List<BaseMonitor>();
        private static List<BaseCompare> comparators = new List<BaseCompare>();

        static void Main(string[] args)
        {
#if DEBUG
            Logger.Setup(true, false);
#else
            Logger.Setup(false,false);
#endif
            string version = (Assembly
                        .GetEntryAssembly()
                        .GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                        as AssemblyInformationalVersionAttribute[])[0].InformationalVersion;
            Log.Information("AttackSurfaceAnalyzer v.{0}", version);

            Strings.Setup();

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, MonitorCommandOptions, ExportMonitorCommandOptions, ExportCollectCommandOptions, ConfigCommandOptions, GuiCommandOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) => RunCollectCommand(opts),
                    (MonitorCommandOptions opts) => RunMonitorCommand(opts),
                    (ExportCollectCommandOptions opts) => RunExportCollectCommand(opts),
                    (ExportMonitorCommandOptions opts) => RunExportMonitorCommand(opts),
                    (ConfigCommandOptions opts) => RunConfigCommand(opts),
                    (GuiCommandOptions opts) => RunGuiCommand(opts),
                    errs => 1
                );

            Log.CloseAndFlush();
        }

        private static int RunGuiCommand(GuiCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif
            DatabaseManager.Setup(opts.DatabaseFilename);
            AsaTelemetry.Setup();

            var server = WebHost.CreateDefaultBuilder(Array.Empty<string>())
                    .UseStartup<Asa.Startup>()
                    .UseKestrel(options => {
                        options.Listen(IPAddress.Loopback, 5000); //HTTP port
                    })
                    .Build();

            ((Action)(async () =>
            {
                await Task.Run(() => SleepAndOpenBrowser(1500)).ConfigureAwait(false);
            }))();

            server.Run();
            return 0;
        }

        private static void SleepAndOpenBrowser(int sleep)
        {
            Thread.Sleep(sleep);
            AsaHelpers.OpenBrowser(new System.Uri("http://localhost:5000")); /*DevSkim: ignore DS137138*/
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2241:Provide correct arguments to formatting methods", Justification = "<Pending>")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>")]
        private static int RunConfigCommand(ConfigCommandOptions opts)
        {
            DatabaseManager.Setup(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();

            if (opts.ResetDatabase)
            {
                DatabaseManager.CloseDatabase();
                try
                {
                    File.Delete(opts.DatabaseFilename);
                }
                catch (IOException e)
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
                    if (DatabaseManager.FirstRun)
                    {
                        Log.Warning(Strings.Get("FirstRunListRunsError"), opts.DatabaseFilename);
                    }
                    else
                    {
                        Log.Information(Strings.Get("DumpingDataFromDatabase"), opts.DatabaseFilename);
                        List<string> CollectRuns = DatabaseManager.GetRuns("collect");
                        if (CollectRuns.Count > 0)
                        {
                            Log.Information(Strings.Get("Begin"), Strings.Get("EnumeratingCollectRunIds"));
                            foreach (string runId in CollectRuns)
                            {
                                var run = DatabaseManager.GetRun(runId);
                                Log.Information("RunId:{2} Timestamp:{0} AsaVersion:{1} ",
                                    run.Timestamp,
                                    run.Version,
                                    run.RunId);

                                var resultTypesAndCounts = DatabaseManager.GetResultTypesAndCounts(run.RunId);

                                foreach (var kvPair in resultTypesAndCounts)
                                {
                                    Log.Information("{0} : {1}", kvPair.Key, kvPair.Value);
                                }
                            }
                        }
                        else
                        {
                            Log.Information(Strings.Get("NoCollectRuns"));
                        }

                        List<string> MonitorRuns = DatabaseManager.GetRuns("monitor");
                        if (MonitorRuns.Count > 0)
                        {
                            Log.Information(Strings.Get("Begin"), Strings.Get("EnumeratingMonitorRunIds"));

                            foreach (string monitorRun in MonitorRuns)
                            {
                                var run = DatabaseManager.GetRun(monitorRun);

                                if (run != null)
                                {
                                    string output = $"{run.RunId} {run.Timestamp} {run.Version} {run.Type}";
                                    Log.Information(output);
                                    Log.Information(string.Join(',', run.ResultTypes.Keys.Where(x => run.ResultTypes[x])));
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
                    AsaTelemetry.SetOptOut(bool.Parse(opts.TelemetryOptOut));
                    Log.Information(Strings.Get("TelemetryOptOut"), (bool.Parse(opts.TelemetryOptOut)) ? "Opted out" : "Opted in");
                }
                if (opts.DeleteRunId != null)
                {
                    DatabaseManager.DeleteRun(opts.DeleteRunId);
                }
                if (opts.TrimToLatest)
                {
                    DatabaseManager.TrimToLatest();
                }
            }

            return 0;
        }

        private static int RunExportCollectCommand(ExportCollectCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif

            if (opts.OutputPath != null && !Directory.Exists(opts.OutputPath))
            {
                Log.Fatal(Strings.Get("Err_OutputPathNotExist"), opts.OutputPath);
                return 0;
            }

            DatabaseManager.Setup(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();
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
            StartEvent.Add("OutputPathSet", (opts.OutputPath != null).ToString(CultureInfo.InvariantCulture));

            AsaTelemetry.TrackEvent("{0} Export Compare", StartEvent);

            CompareCommandOptions options = new CompareCommandOptions()
            {
                DatabaseFilename = opts.DatabaseFilename,
                FirstRunId = opts.FirstRunId,
                SecondRunId = opts.SecondRunId,
                AnalysesFile = opts.AnalysesFile,
                Analyze = opts.Analyze,
                SaveToDatabase = opts.SaveToDatabase
            };

            Dictionary<string, object> results = CompareRuns(options);

            JsonSerializer serializer = JsonSerializer.Create(new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                Converters = new List<JsonConverter>() { new StringEnumConverter() },
                ContractResolver = new AsaExportContractResolver()
            });

            if (opts.ExplodedOutput)
            {
                results.Add("metadata", AsaHelpers.GenerateMetadata());
                string path = Path.Combine(opts.OutputPath, AsaHelpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId));
                Directory.CreateDirectory(path);
                foreach (var key in results.Keys)
                {
                    string filePath = Path.Combine(path, AsaHelpers.MakeValidFileName(key));
                    using (StreamWriter sw = new StreamWriter(filePath)) //lgtm[cs/path-injection]
                    {
                        using (JsonWriter writer = new JsonTextWriter(sw))
                        {
                            serializer.Serialize(writer, results[key]);
                        }
                    }
                }
                Log.Information(Strings.Get("OutputWrittenTo"), (new DirectoryInfo(path)).FullName);
            }
            else
            {
                string path = Path.Combine(opts.OutputPath, AsaHelpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId + "_summary.json.txt"));
                var output = new Dictionary<string, Object>();
                output["results"] = results;
                output["metadata"] = AsaHelpers.GenerateMetadata();
                using (StreamWriter sw = new StreamWriter(path)) //lgtm[cs/path-injection]
                {
                    using (JsonWriter writer = new JsonTextWriter(sw))
                    {
                        serializer.Serialize(writer, output);
                    }
                }
                Log.Information(Strings.Get("OutputWrittenTo"), (new FileInfo(path)).FullName);
            }
            return 0;

        }

        private class AsaExportContractResolver : DefaultContractResolver
        {
            public static readonly AsaExportContractResolver Instance = new AsaExportContractResolver();

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                JsonProperty property = base.CreateProperty(member, memberSerialization);

                if (property.DeclaringType == typeof(RegistryObject))
                {
                    if (property.PropertyName == "Subkeys" || property.PropertyName == "Values")
                    {
                        property.ShouldSerialize = _ => { return false; };
                    }
                }

                if (property.DeclaringType == typeof(Rule))
                {
                    if (property.PropertyName != "Name" && property.PropertyName != "Description" && property.PropertyName != "Flag")
                    {
                        property.ShouldSerialize = _ => { return false; };
                    }
                }

                return property;
            }
        }

        public static void WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            List<RESULT_TYPE> ToExport = new List<RESULT_TYPE> { (RESULT_TYPE)ResultType };
            Dictionary<RESULT_TYPE, int> actualExported = new Dictionary<RESULT_TYPE, int>();
            JsonSerializer serializer = JsonSerializer.Create(new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                Converters = new List<JsonConverter>() { new StringEnumConverter() }
            });
            if (ExportAll)
            {
                ToExport = new List<RESULT_TYPE> { RESULT_TYPE.FILE, RESULT_TYPE.CERTIFICATE, RESULT_TYPE.PORT, RESULT_TYPE.REGISTRY, RESULT_TYPE.SERVICE, RESULT_TYPE.USER };
            }

            foreach (RESULT_TYPE ExportType in ToExport)
            {
                Log.Information("Exporting {0}", ExportType);
                List<CompareResult> records = DatabaseManager.GetComparisonResults(AsaHelpers.RunIdsToCompareId(BaseId, CompareId), ExportType);

                actualExported.Add(ExportType, records.Count);

                if (records.Count > 0)
                {
                    serializer.Converters.Add(new StringEnumConverter());
                    var o = new Dictionary<string, Object>();
                    o["results"] = records;
                    o["metadata"] = AsaHelpers.GenerateMetadata();
                    using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, AsaHelpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_" + ExportType.ToString() + ".json.txt")))) //lgtm[SM00414]
                    {
                        using (JsonWriter writer = new JsonTextWriter(sw))
                        {
                            serializer.Serialize(writer, o);
                        }
                    }
                }
            }

            serializer.Converters.Add(new StringEnumConverter());
            var output = new Dictionary<string, Object>();
            output["results"] = actualExported;
            output["metadata"] = AsaHelpers.GenerateMetadata();
            using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, AsaHelpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_summary.json.txt")))) //lgtm[SM00414]
            {
                using (JsonWriter writer = new JsonTextWriter(sw))
                {
                    serializer.Serialize(writer, output);
                }
            }

        }

        private static void CheckFirstRun()
        {
            if (DatabaseManager.FirstRun)
            {
                string exeStr = $"config --telemetry-opt-out true";
                Log.Information(Strings.Get("ApplicationHasTelemetry"));
                Log.Information(Strings.Get("ApplicationHasTelemetry2"), "https://github.com/Microsoft/AttackSurfaceAnalyzer/blob/master/PRIVACY.md");
                Log.Information(Strings.Get("ApplicationHasTelemetry3"), exeStr);
            }
        }

        private static int RunExportMonitorCommand(ExportMonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            if (opts.OutputPath != null && !Directory.Exists(opts.OutputPath))
            {
                Log.Fatal(Strings.Get("Err_OutputPathNotExist"), opts.OutputPath);
                return 0;
            }

            DatabaseManager.Setup(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();
            DatabaseManager.VerifySchemaVersion();

            if (opts.RunId.Equals("Timestamp", StringComparison.InvariantCulture))
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
            StartEvent.Add("OutputPathSet", (opts.OutputPath != null).ToString(CultureInfo.InvariantCulture));

            AsaTelemetry.TrackEvent("Begin Export Monitor", StartEvent);

            WriteMonitorJson(opts.RunId, (int)RESULT_TYPE.FILE, opts.OutputPath);

            return 0;
        }

        public static void WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            List<FileMonitorEvent> records = DatabaseManager.GetSerializedMonitorResults(RunId);

            JsonSerializer serializer = JsonSerializer.Create(new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                Converters = new List<JsonConverter>() { new StringEnumConverter() }
            });
            var output = new Dictionary<string, Object>();
            output["results"] = records;
            output["metadata"] = AsaHelpers.GenerateMetadata();
            string path = Path.Combine(OutputPath, AsaHelpers.MakeValidFileName(RunId + "_Monitoring_" + ((RESULT_TYPE)ResultType).ToString() + ".json.txt"));

            using (StreamWriter sw = new StreamWriter(path)) //lgtm[SM00414]
            using (JsonWriter writer = new JsonTextWriter(sw))
            {
                serializer.Serialize(writer, output);
            }

            Log.Information(Strings.Get("OutputWrittenTo"), (new FileInfo(path)).FullName);

        }

        private static int RunMonitorCommand(MonitorCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose);
#else
            Logger.Setup(opts.Debug, opts.Verbose);
#endif
            AdminOrQuit();

            DatabaseManager.Setup(opts.DatabaseFilename);
            AsaTelemetry.Setup();

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("Files", opts.EnableFileSystemMonitor.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Admin", AsaHelpers.IsAdmin().ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("Begin monitoring", StartEvent);

            CheckFirstRun();
            DatabaseManager.VerifySchemaVersion();

            Filter.LoadFilters(opts.FilterLocation);

            opts.RunId = opts.RunId.Trim();

            if (opts.RunId.Equals("Timestamp", StringComparison.InvariantCulture))
            {
                opts.RunId = DateTime.Now.ToString("o", CultureInfo.InvariantCulture);
            }

            if (opts.Overwrite)
            {
                DatabaseManager.DeleteRun(opts.RunId);
            }
            else
            {
                if (DatabaseManager.GetRun(opts.RunId) != null)
                {
                    Log.Error(Strings.Get("Err_RunIdAlreadyUsed"));
                    return (int)GUI_ERROR.UNIQUE_ID;
                }
            }

            DatabaseManager.InsertRun(opts.RunId, new Dictionary<RESULT_TYPE, bool>() { { RESULT_TYPE.FILEMONITOR, true } });

            int returnValue = 0;

            if (opts.EnableFileSystemMonitor)
            {
                List<String> directories = new List<string>();

                if (opts.MonitoredDirectories != null)
                {
                    var parts = opts.MonitoredDirectories.Split(',');
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
                        monitors.Add(newMon);
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

            using var exitEvent = new ManualResetEvent(false);

            // If duration is set, we use the secondary timer.
            if (opts.Duration > 0)
            {
                Log.Information("{0} {1} {2}.", Strings.Get("MonitorStartedFor"), opts.Duration, Strings.Get("Minutes"));
                using var aTimer = new System.Timers.Timer
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

                Log.Information(Strings.Get("Begin"), c.GetType().Name);

                try
                {
                    c.StartRun();
                }
                catch (SqliteException ex)
                {
                    Log.Error(Strings.Get("Err_CollectingFrom"), c.GetType().Name, ex.Message, ex.StackTrace);
                    returnValue = 1;
                }
            }

            // Set up the event to capture CTRL+C
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                exitEvent.Set();
            };

            Console.Write(Strings.Get("MonitoringPressC"));

            // Write a spinner and wait until CTRL+C
            WriteSpinner(exitEvent);
            Log.Information("");

            foreach (var c in monitors)
            {
                Log.Information(Strings.Get("End"), c.GetType().Name);

                try
                {
                    c.StopRun();
                    if (c is FileSystemMonitor)
                    {
                        ((FileSystemMonitor)c).Dispose();
                    }
                }
                catch (SqliteException ex)
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

        public static Dictionary<string, object> CompareRuns(CompareCommandOptions opts)
        {
            if (opts is null)
            {
                throw new ArgumentNullException(nameof(opts));
            }

            if (opts.SaveToDatabase)
            {
                DatabaseManager.InsertCompareRun(opts.FirstRunId, opts.SecondRunId, RUN_STATUS.RUNNING);
            }

            var results = new Dictionary<string, object>();

            comparators = new List<BaseCompare>();

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();
            BaseCompare c = new BaseCompare();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            if (!c.TryCompare(opts.FirstRunId, opts.SecondRunId))
            {
                Log.Warning(Strings.Get("Err_Comparing") + " : {0}", c.GetType().Name);
            }

            c.Results.ToList().ForEach(x => results.Add(x.Key, x.Value));

            watch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);

            Log.Information(Strings.Get("Completed"), "Comparing", answer);

            if (opts.Analyze)
            {
                watch = System.Diagnostics.Stopwatch.StartNew();
                Analyzer analyzer;

                analyzer = new Analyzer(DatabaseManager.RunIdToPlatform(opts.FirstRunId), opts.AnalysesFile);

                if (results.Count > 0)
                {
                    foreach (var key in results.Keys)
                    {
                        try
                        {
                            Parallel.ForEach(results[key] as ConcurrentQueue<CompareResult>, (result) =>
                            {
                                result.Analysis = analyzer.Analyze(result);
                            });
                        }
                        catch (ArgumentNullException)
                        {

                        }
                    }
                }

                watch.Stop();
                t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
                answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                        t.Hours,
                                        t.Minutes,
                                        t.Seconds,
                                        t.Milliseconds);
                Log.Information(Strings.Get("Completed"), "Analysis", answer);
            }

            watch = System.Diagnostics.Stopwatch.StartNew();


            if (opts.SaveToDatabase)
            {
                foreach (var key in results.Keys)
                {
                    try
                    {
                        foreach (var result in (results[key] as ConcurrentQueue<CompareResult>))
                        {
                            DatabaseManager.InsertAnalyzed(result);
                        }
                    }
                    catch (NullReferenceException)
                    {
                        Log.Debug(key);
                    }
                }
            }


            watch.Stop();
            t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Information(Strings.Get("Completed"), "Flushing", answer);

            if (opts.SaveToDatabase)
            {
                DatabaseManager.UpdateCompareRun(opts.FirstRunId, opts.SecondRunId, RUN_STATUS.COMPLETED);
            }

            DatabaseManager.Commit();
            AsaTelemetry.TrackEvent("End Command", EndEvent);
            return results;
        }

        public static GUI_ERROR RunGuiMonitorCommand(MonitorCommandOptions opts)
        {
            if (opts is null)
            {
                return GUI_ERROR.NO_COLLECTORS;
            }
            if (opts.EnableFileSystemMonitor)
            {
                List<String> directories = new List<string>();

                var parts = opts.MonitoredDirectories.Split(',');
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
                        Log.Warning("{1}: {0}", dir, Strings.Get("InvalidPath"));
                        return GUI_ERROR.INVALID_PATH;
                    }
                }
            }

            if (monitors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoMonitors"));
            }

            foreach (var c in monitors)
            {
                c.StartRun();
            }

            return GUI_ERROR.NONE;
        }

        public static int StopMonitors()
        {
            foreach (var c in monitors)
            {
                Log.Information(Strings.Get("End"), c.GetType().Name);

                c.StopRun();
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
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Warning(Strings.Get("Err_RunAsRoot"));
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Warning(Strings.Get("Err_RunAsRoot"));
                }
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Acceptable tradeoff with telemetry (to identify issues) to lessen severity of individual collector crashes.")]
        public static int RunCollectCommand(CollectCommandOptions opts)
        {
            if (opts == null) { return -1; }
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif
            DatabaseManager.Setup(opts.DatabaseFilename);
            AsaTelemetry.Setup();

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("Files", opts.EnableAllCollectors ? "True" : opts.EnableFileSystemCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Ports", opts.EnableNetworkPortCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Users", opts.EnableUserCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Certificates", opts.EnableCertificateCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Registry", opts.EnableRegistryCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Service", opts.EnableServiceCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Firewall", opts.EnableFirewallCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("ComObject", opts.EnableComObjectCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("EventLog", opts.EnableEventLogCollector.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Admin", AsaHelpers.IsAdmin().ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("Run Command", StartEvent);

            AdminOrQuit();

            CheckFirstRun();
            DatabaseManager.VerifySchemaVersion();

            int returnValue = (int)GUI_ERROR.NONE;
            opts.RunId = opts.RunId.Trim();

            if (opts.RunId.Equals("Timestamp", StringComparison.InvariantCulture))
            {
                opts.RunId = DateTime.Now.ToString("o", CultureInfo.InvariantCulture);
            }

            if (opts.MatchedCollectorId != null)
            {
                var resultTypes = DatabaseManager.GetResultTypes(opts.MatchedCollectorId);
                foreach (var resultType in resultTypes)
                {
                    switch (resultType.Key)
                    {
                        case RESULT_TYPE.FILE:
                            opts.EnableFileSystemCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.PORT:
                            opts.EnableNetworkPortCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.CERTIFICATE:
                            opts.EnableCertificateCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.COM:
                            opts.EnableComObjectCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.FIREWALL:
                            opts.EnableFirewallCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.LOG:
                            opts.EnableEventLogCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.SERVICE:
                            opts.EnableServiceCollector = resultType.Value;
                            break;
                        case RESULT_TYPE.USER:
                            opts.EnableUserCollector = resultType.Value;
                            break;
                    }
                }
            }

            var dict = new Dictionary<RESULT_TYPE, bool>();

            if (opts.EnableFileSystemCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FileSystemCollector(opts.RunId, enableHashing: opts.GatherHashes, directories: opts.SelectedDirectories, downloadCloud: opts.DownloadCloud, examineCertificates: opts.CertificatesFromFiles, parallel: opts.Parallelization));
                dict.Add(RESULT_TYPE.FILE, true);
            }
            if (opts.EnableNetworkPortCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new OpenPortCollector(opts.RunId));
                dict.Add(RESULT_TYPE.PORT, true);
            }
            if (opts.EnableServiceCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new ServiceCollector(opts.RunId));
                dict.Add(RESULT_TYPE.SERVICE, true);
            }
            if (opts.EnableUserCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new UserAccountCollector(opts.RunId));
                dict.Add(RESULT_TYPE.USER, true);
            }
            if (opts.EnableRegistryCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new RegistryCollector(opts.RunId, opts.Parallelization));
                dict.Add(RESULT_TYPE.REGISTRY, true);
            }
            if (opts.EnableCertificateCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new CertificateCollector(opts.RunId));
                dict.Add(RESULT_TYPE.CERTIFICATE, true);
            }
            if (opts.EnableFirewallCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FirewallCollector(opts.RunId));
                dict.Add(RESULT_TYPE.FIREWALL, true);
            }
            if (opts.EnableComObjectCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new ComObjectCollector(opts.RunId));
                dict.Add(RESULT_TYPE.COM, true);
            }
            if (opts.EnableEventLogCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new EventLogCollector(opts.RunId, opts.GatherVerboseLogs));
                dict.Add(RESULT_TYPE.LOG, true);
            }

            if (collectors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoCollectors"));
                return (int)GUI_ERROR.NO_COLLECTORS;
            }

            if (!opts.NoFilters)
            {
                if (opts.FilterLocation.Equals("Use embedded filters.", StringComparison.InvariantCulture))
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
                if(DatabaseManager.GetRun(opts.RunId) != null)
                {
                    Log.Error(Strings.Get("Err_RunIdAlreadyUsed"));
                    return (int)GUI_ERROR.UNIQUE_ID;
                }
            }
            Log.Information(Strings.Get("Begin"), opts.RunId);

            DatabaseManager.InsertRun(opts.RunId, dict);
            
            Log.Information(Strings.Get("StartingN"), collectors.Count.ToString(CultureInfo.InvariantCulture), Strings.Get("Collectors"));

            Console.CancelKeyPress += delegate {
                Log.Information("Cancelling collection. Rolling back transaction. Please wait to avoid corrupting database.");
                DatabaseManager.RollBack();
                Environment.Exit(0);
            };

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();
            foreach (BaseCollector c in collectors)
            {
                try
                {
                    c.Execute();
                    EndEvent.Add(c.GetType().ToString(), c.NumCollected().ToString(CultureInfo.InvariantCulture));
                }
                catch (Exception e)
                {
                    Log.Error(Strings.Get("Err_CollectingFrom"), c.GetType().Name, e.Message, e.StackTrace);
                    Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                    ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                    ExceptionEvent.Add("Stack Trace", e.StackTrace);
                    ExceptionEvent.Add("Message", e.Message);
                    AsaTelemetry.TrackEvent("CollectorCrashRogueException", ExceptionEvent);
                    returnValue = 1;
                }
            }
            AsaTelemetry.TrackEvent("End Command", EndEvent);

            DatabaseManager.Commit();
            return returnValue;
        }

        public static void ClearCollectors()
        {
            collectors = new List<BaseCollector>();
        }

        public static void ClearMonitors()
        {
            collectors = new List<BaseCollector>();
        }

        // Used for monitors. This writes a little spinner animation to indicate that monitoring is underway
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "These symbols won't be localized")]
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
                return collectors[0].RunId;
            }
            return "No run id";
        }
    }
}