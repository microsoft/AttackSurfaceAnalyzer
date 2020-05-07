// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using CommandLine;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Cli
{
    public static class AttackSurfaceAnalyzerClient
    {
        private static List<BaseCollector> collectors = new List<BaseCollector>();
        private static readonly List<BaseMonitor> monitors = new List<BaseMonitor>();
        private static List<BaseCompare> comparators = new List<BaseCompare>();

        private static void Main(string[] args)
        {
#if DEBUG
            Logger.Setup(true, false);
#else
            Logger.Setup(false, false);
#endif
            var version = (Assembly
                        .GetEntryAssembly()?
                        .GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false) as AssemblyInformationalVersionAttribute[])?
                        [0].InformationalVersion ?? "Unknown";

            Log.Information("AttackSurfaceAnalyzer v.{0}", version);

            Strings.Setup();

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, MonitorCommandOptions, ExportMonitorCommandOptions, ExportCollectCommandOptions, ConfigCommandOptions, GuiCommandOptions, VerifyOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) => RunCollectCommand(opts),
                    (MonitorCommandOptions opts) => RunMonitorCommand(opts),
                    (ExportCollectCommandOptions opts) => RunExportCollectCommand(opts),
                    (ExportMonitorCommandOptions opts) => RunExportMonitorCommand(opts),
                    (ConfigCommandOptions opts) => RunConfigCommand(opts),
                    (GuiCommandOptions opts) => RunGuiCommand(opts),
                    (VerifyOptions opts) => RunVerifyRulesCommand(opts),
                    errs => 1
                );

            Log.CloseAndFlush();
            Environment.Exit(argsResult);
        }

        private static int RunVerifyRulesCommand(VerifyOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif
            var analyzer = new Analyzer(AsaHelpers.GetPlatform(), opts.AnalysisFile);
            var violations = analyzer.VerifyRules();

            if (violations.Any())
            {
                foreach (var violation in violations)
                {
                    Log.Warning(violation);
                }
                Log.Error("Encountered {0} issues with rule at {1}", violations.Count, opts.AnalysisFile ?? "Embedded");
                return (int)ASA_ERROR.INVALID_RULES;
            }
            return (int)ASA_ERROR.NONE;
        }

        private static void SetupOrDie(string path, DBSettings? dbSettingsIn = null)
        {
            var errorCode = DatabaseManager.Setup(path, dbSettingsIn);

            if (errorCode != ASA_ERROR.NONE)
            {
                Log.Fatal(Strings.Get("CouldNotSetupDatabase"));
                Environment.Exit((int)errorCode);
            }
        }

        private static int RunGuiCommand(GuiCommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif
            SetupOrDie(opts.DatabaseFilename);

            AsaTelemetry.Setup();

            var server = WebHost.CreateDefaultBuilder(Array.Empty<string>())
                    .UseStartup<Startup>()
                    .UseKestrel(options =>
                    {
                        options.Listen(IPAddress.Loopback, 5000);
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
            SetupOrDie(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();

            if (opts.ResetDatabase)
            {
                var filename = DatabaseManager.SqliteFilename;
                DatabaseManager.Destroy();
                Log.Information(Strings.Get("DeletedDatabaseAt"), filename);
            }
            else
            {
                if (opts.ListRuns)
                {
                    if (DatabaseManager.FirstRun)
                    {
                        Log.Warning(Strings.Get("FirstRunListRunsError"), opts.DatabaseFilename);
                    }
                    else
                    {
                        Log.Information(Strings.Get("DumpingDataFromDatabase"), opts.DatabaseFilename);
                        List<string> CollectRuns = DatabaseManager.GetRuns(RUN_TYPE.COLLECT);
                        if (CollectRuns.Count > 0)
                        {
                            Log.Information(Strings.Get("Begin"), Strings.Get("EnumeratingCollectRunIds"));
                            foreach (string runId in CollectRuns)
                            {
                                var run = DatabaseManager.GetRun(runId);

                                if (run is AsaRun)
                                {
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
                        }
                        else
                        {
                            Log.Information(Strings.Get("NoCollectRuns"));
                        }

                        List<string> MonitorRuns = DatabaseManager.GetRuns(RUN_TYPE.MONITOR);
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
                                    Log.Information(string.Join(',', run.ResultTypes.Where(x => run.ResultTypes.Contains(x))));
                                }
                            }
                        }
                        else
                        {
                            Log.Information(Strings.Get("NoMonitorRuns"));
                        }
                    }
                }

                AsaTelemetry.SetEnabled(opts.TelemetryOptOut);
                Log.Information(Strings.Get("TelemetryOptOut"), opts.TelemetryOptOut ? "Opted out" : "Opted in");

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

            SetupOrDie(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();

            if (opts.FirstRunId is null || opts.SecondRunId is null)
            {
                Log.Information("Provided null run Ids using latest two runs.");
                List<string> runIds = DatabaseManager.GetLatestRunIds(2, RUN_TYPE.COLLECT);

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

            if (opts.FirstRunId is null || opts.SecondRunId is null)
            {
                return (int)ASA_ERROR.INVALID_ID;
            }
            Log.Information(Strings.Get("Comparing"), opts.FirstRunId, opts.SecondRunId);

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("OutputPathSet", (opts.OutputPath != null).ToString(CultureInfo.InvariantCulture));

            AsaTelemetry.TrackEvent("{0} Export Compare", StartEvent);

            CompareCommandOptions options = new CompareCommandOptions(opts.FirstRunId, opts.SecondRunId)
            {
                DatabaseFilename = opts.DatabaseFilename,
                AnalysesFile = opts.AnalysesFile,
                Analyze = opts.Analyze,
                SaveToDatabase = opts.SaveToDatabase
            };

            var results = CompareRuns(options).Select(x => new KeyValuePair<string, object>($"{x.Key.Item1}_{x.Key.Item2}", x.Value)).ToDictionary(x => x.Key, x => x.Value);
            JsonSerializer serializer = JsonSerializer.Create(new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore,
                DefaultValueHandling = DefaultValueHandling.Ignore,
                Converters = new List<JsonConverter>() { new StringEnumConverter() },
                ContractResolver = new AsaExportContractResolver()
            });
            var outputPath = opts.OutputPath;
            if (outputPath is null)
            {
                outputPath = Directory.GetCurrentDirectory();
            }
            if (opts.ExplodedOutput)
            {
                results.Add("metadata", AsaHelpers.GenerateMetadata());

                string path = Path.Combine(outputPath, AsaHelpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId));
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
                string path = Path.Combine(outputPath, AsaHelpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId + "_summary.json.txt"));
                var output = new Dictionary<string, object>();
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
                    using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, AsaHelpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_" + ExportType.ToString() + ".json.txt")))) //lgtm [cs/path-injection]
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
            using (StreamWriter sw = new StreamWriter(Path.Combine(OutputPath, AsaHelpers.MakeValidFileName(BaseId + "_vs_" + CompareId + "_summary.json.txt")))) //lgtm [cs/path-injection]
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
                string exeStr = $"config --telemetry-opt-out";
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
            var outPath = opts.OutputPath ?? Directory.GetCurrentDirectory();
            if (!Directory.Exists(outPath))
            {
                Log.Fatal(Strings.Get("Err_OutputPathNotExist"), opts.OutputPath);
                return 0;
            }

            SetupOrDie(opts.DatabaseFilename);
            CheckFirstRun();
            AsaTelemetry.Setup();

            if (opts.RunId is null)
            {
                List<string> runIds = DatabaseManager.GetLatestRunIds(1, RUN_TYPE.MONITOR);

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

            WriteMonitorJson(opts.RunId, (int)RESULT_TYPE.FILE, opts.OutputPath ?? "monitor.json");

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

            using (StreamWriter sw = new StreamWriter(path)) //lgtm [cs/path-injection]
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

            SetupOrDie(opts.DatabaseFilename);
            AsaTelemetry.Setup();

            Dictionary<string, string> StartEvent = new Dictionary<string, string>();
            StartEvent.Add("Files", opts.EnableFileSystemMonitor.ToString(CultureInfo.InvariantCulture));
            StartEvent.Add("Admin", AsaHelpers.IsAdmin().ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("Begin monitoring", StartEvent);

            CheckFirstRun();

            if (opts.RunId is string)
            {
                opts.RunId = opts.RunId.Trim();
            }
            else
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
                    return (int)ASA_ERROR.UNIQUE_ID;
                }
            }
            var run = new AsaRun(RunId: opts.RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.FILEMONITOR }, RUN_TYPE.MONITOR);

            DatabaseManager.InsertRun(run);

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
                returnValue = (int)ASA_ERROR.NO_COLLECTORS;
            }

            using var exitEvent = new ManualResetEvent(false);

            // If duration is set, we use the secondary timer.
            if (opts.Duration > 0)
            {
                Log.Information("{0} {1} {2}.", Strings.Get("MonitorStartedFor"), opts.Duration, Strings.Get("Minutes"));
                using var aTimer = new System.Timers.Timer
                {
                    Interval = opts.Duration * 60 * 1000, //lgtm [cs/loss-of-precision]
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
                catch (Exception ex)
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
                catch (Exception ex)
                {
                    Log.Error(ex, " {0}: {1}", c.GetType().Name, ex.Message, Strings.Get("Err_Stopping"));
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

        public static ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), List<CompareResult>> CompareRuns(CompareCommandOptions opts)
        {
            if (opts is null)
            {
                throw new ArgumentNullException(nameof(opts));
            }

            if (opts.SaveToDatabase)
            {
                DatabaseManager.InsertCompareRun(opts.FirstRunId, opts.SecondRunId, RUN_STATUS.RUNNING);
            }

            comparators = new List<BaseCompare>();

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();
            BaseCompare c = new BaseCompare();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            if (!c.TryCompare(opts.FirstRunId, opts.SecondRunId))
            {
                Log.Warning(Strings.Get("Err_Comparing") + " : {0}", c.GetType().Name);
            }

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
                watch = Stopwatch.StartNew();
                Analyzer analyzer = new Analyzer(DatabaseManager.RunIdToPlatform(opts.FirstRunId), opts.AnalysesFile);

                var violations = analyzer.VerifyRules();

                if (violations.Any())
                {
                    foreach (var violation in violations)
                    {
                        Log.Warning(violation);
                    }
                    Log.Error("Encountered {0} issues with rules in {1}. Skipping analysis.", violations.Count, opts.AnalysesFile ?? "Embedded");
                }
                else
                {
                    if (c.Results.Count > 0)
                    {
                        foreach (var key in c.Results.Keys)
                        {
                            if (c.Results[key] is List<CompareResult> queue)
                            {
                                queue.AsParallel().ForAll(res =>
                                {
                                    res.Rules = analyzer.Analyze(res);
                                    res.Analysis = res.Rules.Count > 0 ? res.Rules.Max(x => x.Flag) : analyzer.DefaultLevels[res.ResultType];
                                });
                            }
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

            watch = Stopwatch.StartNew();

            if (opts.SaveToDatabase)
            {
                foreach (var key in c.Results.Keys)
                {
                    if (c.Results.TryGetValue(key, out List<CompareResult>? obj))
                    {
                        if (obj is List<CompareResult> Queue)
                        {
                            foreach (var result in Queue)
                            {
                                DatabaseManager.InsertAnalyzed(result);
                            }
                        }
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
            return c.Results;
        }

        public static ASA_ERROR RunGuiMonitorCommand(MonitorCommandOptions opts)
        {
            if (opts is null)
            {
                return ASA_ERROR.NO_COLLECTORS;
            }
            if (opts.EnableFileSystemMonitor)
            {
                List<string> directories = new List<string>();

                var parts = opts.MonitoredDirectories?.Split(',') ?? Array.Empty<string>();

                foreach (string part in parts)
                {
                    directories.Add(part);
                }

                foreach (string dir in directories)
                {
                    try
                    {
                        FileSystemMonitor newMon = new FileSystemMonitor(opts.RunId ?? DateTime.Now.ToString("o", CultureInfo.InvariantCulture), dir, opts.InterrogateChanges);
                        monitors.Add(newMon);
                    }
                    catch (ArgumentException)
                    {
                        Log.Warning("{1}: {0}", dir, Strings.Get("InvalidPath"));
                        return ASA_ERROR.INVALID_PATH;
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

            return ASA_ERROR.NONE;
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
            var dbSettings = new DBSettings()
            {
                ShardingFactor = opts.Shards
            };
            SetupOrDie(opts.DatabaseFilename, dbSettings);
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

            int returnValue = (int)ASA_ERROR.NONE;
            opts.RunId = opts.RunId?.Trim() ?? DateTime.Now.ToString("o", CultureInfo.InvariantCulture);

            if (opts.MatchedCollectorId != null)
            {
                var matchedRun = DatabaseManager.GetRun(opts.MatchedCollectorId);
                if (matchedRun is AsaRun)
                {
                    foreach (var resultType in matchedRun.ResultTypes)
                    {
                        switch (resultType)
                        {
                            case RESULT_TYPE.FILE:
                                opts.EnableFileSystemCollector = true;
                                break;
                            case RESULT_TYPE.PORT:
                                opts.EnableNetworkPortCollector = true;
                                break;
                            case RESULT_TYPE.CERTIFICATE:
                                opts.EnableCertificateCollector = true;
                                break;
                            case RESULT_TYPE.COM:
                                opts.EnableComObjectCollector = true;
                                break;
                            case RESULT_TYPE.FIREWALL:
                                opts.EnableFirewallCollector = true;
                                break;
                            case RESULT_TYPE.LOG:
                                opts.EnableEventLogCollector = true;
                                break;
                            case RESULT_TYPE.SERVICE:
                                opts.EnableServiceCollector = true;
                                break;
                            case RESULT_TYPE.USER:
                                opts.EnableUserCollector = true;
                                break;
                        }
                    }
                }
            }

            var dict = new List<RESULT_TYPE>();

            if (opts.EnableFileSystemCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FileSystemCollector(opts));
                dict.Add(RESULT_TYPE.FILE);
            }
            if (opts.EnableNetworkPortCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new OpenPortCollector());
                dict.Add(RESULT_TYPE.PORT);
            }
            if (opts.EnableServiceCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new ServiceCollector());
                dict.Add(RESULT_TYPE.SERVICE);
            }
            if (opts.EnableUserCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new UserAccountCollector());
                dict.Add(RESULT_TYPE.USER);
            }
            if (opts.EnableRegistryCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new RegistryCollector(opts));
                dict.Add(RESULT_TYPE.REGISTRY);
            }
            if (opts.EnableCertificateCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new CertificateCollector());
                dict.Add(RESULT_TYPE.CERTIFICATE);
            }
            if (opts.EnableFirewallCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FirewallCollector());
                dict.Add(RESULT_TYPE.FIREWALL);
            }
            if (opts.EnableComObjectCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new ComObjectCollector(opts));
                dict.Add(RESULT_TYPE.COM);
            }
            if (opts.EnableEventLogCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new EventLogCollector(opts.GatherVerboseLogs));
                dict.Add(RESULT_TYPE.LOG);
            }

            if (collectors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoCollectors"));
                return (int)ASA_ERROR.NO_COLLECTORS;
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
                    return (int)ASA_ERROR.UNIQUE_ID;
                }
            }
            Log.Information(Strings.Get("Begin"), opts.RunId);

            var run = new AsaRun(RunId: opts.RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), ResultTypes: dict, Type: RUN_TYPE.COLLECT);

            DatabaseManager.InsertRun(run);

            Log.Information(Strings.Get("StartingN"), collectors.Count.ToString(CultureInfo.InvariantCulture), Strings.Get("Collectors"));

            Console.CancelKeyPress += delegate
            {
                Log.Information("Cancelling collection. Rolling back transaction. Please wait to avoid corrupting database.");
                DatabaseManager.CloseDatabase();
                Environment.Exit(-1);
            };

            Dictionary<string, string> EndEvent = new Dictionary<string, string>();
            foreach (BaseCollector c in collectors)
            {
                try
                {
                    DatabaseManager.BeginTransaction();

                    Task.Run(() => c.Execute());

                    Thread.Sleep(1);

                    while (c.RunStatus == RUN_STATUS.RUNNING)
                    {
                        var items = new CollectObject[1000];
                        while (c.Results.Count > 0)
                        {
                            var count = Math.Min(1000, c.Results.Count);
                            // Take doesn't actually remove, it returns an thin IEnumerable
                            
                            var actual = c.Results.TryPopRange(items);
                            items.Take(actual).AsParallel().ForAll(result =>
                            {
                                DatabaseManager.Write(result, opts.RunId);
                            });
                        }
                        Thread.Sleep(1);
                    }

                    c.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, opts.RunId));

                    var prevFlush = DatabaseManager.QueueSize;
                    var totFlush = prevFlush;

                    var printInterval = new TimeSpan(0,0,10);
                    var now = DateTime.Now;
                    var then = DateTime.Now;

                    var StopWatch = Stopwatch.StartNew();
                    TimeSpan t = new TimeSpan();
                    string answer = string.Empty;
                    bool warnedToIncreaseShards = false;

                    while (DatabaseManager.HasElements)
                    {
                        Thread.Sleep(100);
                        if (!DatabaseManager.HasElements)
                        {
                            break;
                        }
                        if (!warnedToIncreaseShards && StopWatch.ElapsedMilliseconds > 10000 && dbSettings.ShardingFactor < 7)
                        {
                            Log.Information("It is taking a while to flush results to the database.  Try increasing the sharding level to improve performance.");
                            warnedToIncreaseShards = true;
                        }
                        now = DateTime.Now;
                        if (now - then > printInterval)
                        {
                            var actualDuration = now - then;
                            var sample = DatabaseManager.QueueSize;
                            var curRate = prevFlush - sample;
                            var totRate = (double)(totFlush - sample) / StopWatch.ElapsedMilliseconds;

                            try
                            {
                                t = (curRate > 0) ? TimeSpan.FromMilliseconds(actualDuration.TotalMilliseconds * sample / curRate) : TimeSpan.FromMilliseconds(99999999); //lgtm[cs/loss-of-precision]
                                answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                                        t.Hours,
                                                        t.Minutes,
                                                        t.Seconds,
                                                        t.Milliseconds);
                                Log.Debug("Flushing {0} results. ({1}/{4}s {2:0.00}/s overall {3} ETA)", sample, curRate, totRate * 1000, answer, actualDuration);
                            }
                            catch (Exception e) when (
                                e is OverflowException)
                            {
                                Log.Debug($"Overflowed: {curRate} {totRate} {sample} {t} {answer}");
                                Log.Debug("Flushing {0} results. ({1}/s {2:0.00}/s)", sample, curRate, totRate * 1000);
                            }

                            then = now;
                            prevFlush = sample;
                        }
                    }

                    StopWatch.Stop();
                    t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
                    answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                            t.Hours,
                                            t.Minutes,
                                            t.Seconds,
                                            t.Milliseconds);
                    Log.Debug("Completed flushing in {0}", answer);

                    DatabaseManager.Commit();
                }
                catch (Exception e)
                {
                    Log.Error(Strings.Get("Err_CollectingFrom"), c.GetType().Name, e.Message, e.StackTrace);
                    Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                    ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                    ExceptionEvent.Add("Stack Trace", e.StackTrace ?? string.Empty);
                    ExceptionEvent.Add("Message", e.Message);
                    AsaTelemetry.TrackEvent("CollectorCrashRogueException", ExceptionEvent);
                    returnValue = 1;
                }
            }
            AsaTelemetry.TrackEvent("End Command", EndEvent);

            DatabaseManager.Commit();
            DatabaseManager.CloseDatabase();
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
        private static void WriteSpinner(ManualResetEvent untilDone)
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