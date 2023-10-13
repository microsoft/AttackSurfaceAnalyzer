// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using CommandLine;
using Microsoft.AspNetCore.Hosting;
using Microsoft.CodeAnalysis.Sarif;
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.CST.OAT;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Serilog;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Cli
{
    public static class AttackSurfaceAnalyzerClient
    {
        private static List<BaseCollector> collectors = new();
        private static readonly List<BaseMonitor> monitors = new();
        private static List<BaseCompare> comparators = new();

        public static DatabaseManager? DatabaseManager { get; private set; }

        private static void SetupLogging(CommandOptions opts)
        {
#if DEBUG
            Logger.Setup(true, opts.Verbose, opts.Quiet);
#else
            Logger.Setup(opts.Debug, opts.Verbose, opts.Quiet);
#endif
        }

        private static void SetupDatabase(CommandOptions opts)
        {
            var dbSettings = new DBSettings()
            {
                ShardingFactor = opts.Shards,
                LowMemoryUsage = opts.LowMemoryUsage
            };
            SetupOrDie(opts.DatabaseFilename, dbSettings);
        }

        private static void Main(string[] args)
        {
#if DEBUG
            AttackSurfaceAnalyzer.Utils.Logger.Setup(true, false);
#else
            AttackSurfaceAnalyzer.Utils.Logger.Setup(false, false);
#endif
            var version = (Assembly
                        .GetEntryAssembly()?
                        .GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false) as AssemblyInformationalVersionAttribute[])?
                        [0].InformationalVersion ?? "Unknown";

            Log.Information("AttackSurfaceAnalyzer v.{0}", version);

            AttackSurfaceAnalyzer.Utils.Strings.Setup();

            var argsResult = Parser.Default.ParseArguments<CollectCommandOptions, MonitorCommandOptions, ExportMonitorCommandOptions, ExportCollectCommandOptions, ConfigCommandOptions, GuiCommandOptions, VerifyOptions, GuidedModeCommandOptions>(args)
                .MapResult(
                    (CollectCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunCollectCommand(opts);
                    },
                    (MonitorCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunMonitorCommand(opts);
                    },
                    (ExportCollectCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunExportCollectCommand(opts);
                    },
                    (ExportMonitorCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunExportMonitorCommand(opts);
                    },
                    (ExportGuidedCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunExportGuidedCommand(opts);
                    },
                    (ConfigCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        return RunConfigCommand(opts);
                    },
                    (GuiCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunGuiCommand(opts);
                    },
                    (VerifyOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunVerifyRulesCommand(opts);
                    },
                    (GuidedModeCommandOptions opts) =>
                    {
                        SetupLogging(opts);
                        SetupDatabase(opts);
                        return RunGuidedModeCommand(opts);
                    },
                    errs => ASA_ERROR.UNKNOWN
                );
            DatabaseManager?.CloseDatabase();
            Log.CloseAndFlush();
            Environment.Exit((int)argsResult);
        }

        /// <summary>
        /// Loads the rules from the provided file, if it is not null or empty.  Or falls back to the embedded rules if it is.
        /// </summary>
        /// <param name="analysisFile"></param>
        /// <returns>The loaded RuleFile</returns>
        private static RuleFile LoadRulesFromFileOrEmbedded(string? analysisFile) => string.IsNullOrEmpty(analysisFile) ? RuleFile.LoadEmbeddedFilters() : RuleFile.FromFile(analysisFile);
        
        internal static string GuidedRunIdToFirstCollectRunId(string guidedRunId) => $"{guidedRunId}-baseline";
        internal static string GuidedRunIdToSecondCollectRunId(string guidedRunId) => $"{guidedRunId}-after";
        internal static string GuidedRunIdToMonitorRunId(string guidedRunId) => $"{guidedRunId}-monitoring";


        private static ASA_ERROR RunGuidedModeCommand(GuidedModeCommandOptions opts)
        {
            opts.RunId = opts.RunId?.Trim() ?? DateTime.Now.ToString("o", CultureInfo.InvariantCulture);

            var firstCollectRunId = GuidedRunIdToFirstCollectRunId(opts.RunId);
            var secondCollectRunId = GuidedRunIdToSecondCollectRunId(opts.RunId);
            var monitorRunId = GuidedRunIdToMonitorRunId(opts.RunId);

            var collectorOpts = CollectCommandOptions.FromCollectorOptions(opts);

            collectorOpts.RunId = firstCollectRunId;

            RunCollectCommand(collectorOpts);

            var monitorOpts = new MonitorCommandOptions()
            {
                Duration = opts.Duration,
                MonitoredDirectories = opts.MonitoredDirectories,
                EnableFileSystemMonitor = opts.EnableFileSystemMonitor,
                GatherHashes = opts.GatherHashes,
                FileNamesOnly = opts.FileNamesOnly,
                RunId = monitorRunId,
            };

            RunMonitorCommand(monitorOpts);

            collectorOpts.RunId = secondCollectRunId;

            RunCollectCommand(collectorOpts);

            RuleFile analysisFile = LoadRulesFromFileOrEmbedded(opts.AnalysesFile);
            if (!analysisFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return ASA_ERROR.INVALID_RULES;
            }
            var results = AnalyzeGuided(opts, analysisFile);

            var exportOpts = new ExportGuidedCommandOptions()
            {
                ExplodedOutput = opts.ExplodedOutput,
                OutputSarif = opts.ExportSarif,
                OutputPath = opts.OutputPath,
                ApplySubObjectRulesToMonitor = opts.ApplySubObjectRulesToMonitor,
                SingleThreadAnalysis = opts.SingleThreadAnalysis
            };
            var first = GuidedRunIdToFirstCollectRunId(opts.RunId);
            var second = GuidedRunIdToSecondCollectRunId(opts.RunId);
            var analysesHash = analysisFile.GetHash();

            return ExportCompareResults(results, exportOpts, AsaHelpers.MakeValidFileName($"{first}_vs_{second}"), analysesHash, analysisFile.Rules);
        }

        private static ASA_ERROR RunExportGuidedCommand(ExportGuidedCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunExportCollectCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
            if (opts.OutputPath != null && !Directory.Exists(opts.OutputPath))
            {
                Log.Fatal(Strings.Get("Err_OutputPathNotExist"), opts.OutputPath);
                return ASA_ERROR.INVALID_PATH;
            }

            if (opts.RunId is null)
            {
                Log.Fatal("Provided null run id is null.");
                return ASA_ERROR.INVALID_ID;
            }

            var ruleFile = LoadRulesFromFileOrEmbedded(opts.AnalysesFile);
            if (!ruleFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return ASA_ERROR.INVALID_RULES;
            }

            var first = GuidedRunIdToFirstCollectRunId(opts.RunId);
            var second = GuidedRunIdToSecondCollectRunId(opts.RunId);
            var monitor = GuidedRunIdToMonitorRunId(opts.RunId);
            Log.Information(Strings.Get("Comparing"), first, second);

            CompareCommandOptions options = new(first, second)
            {
                DatabaseFilename = opts.DatabaseFilename,
                AnalysesFile = ruleFile,
                DisableAnalysis = opts.DisableAnalysis,
                SaveToDatabase = opts.SaveToDatabase,
                RunScripts = opts.RunScripts
            };

            var GuidedOptions = new GuidedModeCommandOptions()
            {
                RunId = opts.RunId,
                RunScripts = opts.RunScripts,
                ApplySubObjectRulesToMonitor = opts.ApplySubObjectRulesToMonitor,
                SaveToDatabase = opts.SaveToDatabase,
                DisableAnalysis = opts.DisableAnalysis
            };

            var results = AnalyzeGuided(GuidedOptions, ruleFile);
            var analysesHash = options.AnalysesFile.GetHash();
            if (opts.ResultLevels.Any())
            {
                foreach (var kvp in results)
                {
                    results[kvp.Key] = new ConcurrentBag<CompareResult>(kvp.Value.Where(x => opts.ResultLevels.Contains(x.Analysis)));
                }
            }
            var exportOptions = new ExportOptions()
            {
                OutputSarif = opts.OutputSarif,
                OutputPath = opts.OutputPath,
                ExplodedOutput = opts.ExplodedOutput
            };

            return ExportCompareResults(results, exportOptions, AsaHelpers.MakeValidFileName($"{first}_vs_{second}"), analysesHash, options.AnalysesFile.Rules);
        }

        static ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> AnalyzeGuided(GuidedModeCommandOptions opts, RuleFile analysisFile)
        {
            if (opts.RunId is null)
            {
                Log.Warning(Strings.Get("Err_RunIdNull"));
                return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            }
            if (!analysisFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            }

            var firstCollectRunId = GuidedRunIdToFirstCollectRunId(opts.RunId);
            var secondCollectRunId = GuidedRunIdToSecondCollectRunId(opts.RunId);
            var monitorRunId = GuidedRunIdToMonitorRunId(opts.RunId);

            var compareOpts = new CompareCommandOptions(firstCollectRunId, secondCollectRunId)
            {
                DisableAnalysis = opts.DisableAnalysis,
                AnalysesFile = analysisFile,
                RunScripts = opts.RunScripts,
                SingleThreadAnalysis = opts.SingleThreadAnalysis
            };

            var results = CompareRuns(compareOpts);

            if (opts.SaveToDatabase)
            {
                InsertCompareResults(results, firstCollectRunId, secondCollectRunId, analysisFile.GetHash());
            }

            var monitorCompareOpts = new CompareCommandOptions(null, monitorRunId)
            {
                DisableAnalysis = opts.DisableAnalysis,
                AnalysesFile = analysisFile,
                ApplySubObjectRulesToMonitor = opts.ApplySubObjectRulesToMonitor,
                RunScripts = opts.RunScripts,
                SingleThreadAnalysis = opts.SingleThreadAnalysis
            };

            var monitorResult = AnalyzeMonitored(monitorCompareOpts);

            if (opts.SaveToDatabase)
            {
                InsertCompareResults(monitorResult, null, monitorRunId, analysisFile.GetHash());
            }

            Parallel.ForEach(monitorResult.Keys, key =>
            {
                results.TryAdd(key, monitorResult[key]);
            });

            return results;
        }

        public static ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> AnalyzeMonitored(CompareCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "InsertCompareResults");
                return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            }
            if (opts is null || opts.SecondRunId is null) { return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>(); }
            var analyzer = new AsaAnalyzer(new AnalyzerOptions(opts.RunScripts));
            return AnalyzeMonitored(opts, analyzer, DatabaseManager.GetMonitorResults(opts.SecondRunId), opts.AnalysesFile ?? throw new ArgumentNullException(nameof(opts.AnalysesFile)));
        }

        public static ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> AnalyzeMonitored(CompareCommandOptions opts, AsaAnalyzer analyzer, IEnumerable<MonitorObject> collectObjects, RuleFile ruleFile)
        {
            if (opts is null) { return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>(); }
            var results = new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            var analysesHash = ruleFile.GetHash();
            Parallel.ForEach(collectObjects, monitorResult =>
            {
                var shellResult = new CompareResult()
                {
                    Compare = monitorResult,
                    CompareRunId = opts.SecondRunId
                };

                shellResult.Rules = analyzer.Analyze(ruleFile.Rules, shellResult).ToList();
                shellResult.AnalysesHash = analysesHash;

                if (opts.ApplySubObjectRulesToMonitor)
                {
                    switch (monitorResult)
                    {
                        case FileMonitorObject fmo:
                            var innerShell = new CompareResult()
                            {
                                Compare = fmo.FileSystemObject,
                                CompareRunId = opts.SecondRunId
                            };
                            shellResult.Rules.AddRange(analyzer.Analyze(ruleFile.Rules, innerShell));
                            break;
                    }
                }

                shellResult.Analysis = shellResult.Rules.Count > 0 ? shellResult.Rules.Max(x => ((AsaRule)x).Flag) : ruleFile.GetDefaultLevel(shellResult.ResultType);
                results.TryAdd((monitorResult.ResultType, monitorResult.ChangeType), new ConcurrentBag<CompareResult>());
                results[(monitorResult.ResultType, monitorResult.ChangeType)].Add(shellResult);
            });
            return results;
        }

        private static ASA_ERROR RunVerifyRulesCommand(VerifyOptions opts)
        {
            var analyzer = new AsaAnalyzer(new AnalyzerOptions(opts.RunScripts));
            var ruleFile = LoadRulesFromFileOrEmbedded(opts.AnalysisFile);
            if (!ruleFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return ASA_ERROR.INVALID_RULES;
            }
            var violations = analyzer.EnumerateRuleIssues(ruleFile.Rules);
            OAT.Utils.Strings.Setup();
            OAT.Utils.Helpers.PrintViolations(violations);
            if (violations.Any())
            {
                Log.Error("Encountered {0} issues with rules at {1}", violations.Count(), opts.AnalysisFile ?? "Embedded");
                return ASA_ERROR.INVALID_RULES;
            }
            Log.Information("{0} Rules successfully verified. ✅", ruleFile.Rules.Count());
            return ASA_ERROR.NONE;
        }

        internal static void InsertCompareResults(ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> results, string? FirstRunId, string SecondRunId, string AnalysesHash)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "InsertCompareResults");
                return;
            }
            DatabaseManager.InsertCompareRun(FirstRunId, SecondRunId, AnalysesHash, RUN_STATUS.RUNNING);
            foreach (var key in results.Keys)
            {
                if (results.TryGetValue(key, out ConcurrentBag<CompareResult>? obj))
                {
                    if (obj is ConcurrentBag<CompareResult> Queue)
                    {
                        foreach (var result in Queue)
                        {
                            DatabaseManager.InsertAnalyzed(result);
                        }
                    }
                }
            }
            DatabaseManager.UpdateCompareRun(FirstRunId, SecondRunId, RUN_STATUS.COMPLETED);

            DatabaseManager.Commit();
        }

        private static void SetupOrDie(string path, DBSettings? dbSettingsIn = null)
        {
            DatabaseManager = new SqliteDatabaseManager(path, dbSettingsIn);
            var errorCode = DatabaseManager.Setup();

            if (errorCode != ASA_ERROR.NONE)
            {
                Log.Fatal(Strings.Get("CouldNotSetupDatabase"));
                Environment.Exit((int)errorCode);
            }
        }
        
        private static ASA_ERROR RunGuiCommand(GuiCommandOptions opts)
        {
            IHostBuilder server = Host.CreateDefaultBuilder(Array.Empty<string>());
            var assemblyLocation = Directory.GetParent(Assembly.GetExecutingAssembly().Location)?.FullName;
            if (assemblyLocation is null)
            {
                Log.Error("Couldn't get directory containing assembly, unable to set content root.");
                return ASA_ERROR.FAILED_TO_LOCATE_GUI_ASSETS;
            }
            
            // We have to set the content root to the folder with the assemblies to function properly
            server.UseContentRoot(assemblyLocation);

            // If we are running from debug or from a dotnet publish the wwwroot will be adjacent to the assemblies
            var wwwrootLocation = Path.Combine(assemblyLocation, "wwwroot");
            var webRoot = wwwrootLocation;
            
            // If the expected wwwroot doesn't exist, we can also check if we are installed as a dotnet tool
            if (!Directory.Exists(wwwrootLocation))
            {
                // If we are installed as a tool the assembly will be located in a folder structure that looks like this
                //      <toolname>\<version>\tools\<framework>\<platform>\
                // The wwwroot is in a folder called "staticwebassets" in the <version> folder, so we want to go 3 levels up.
                var toolRootInstallDirectory = new DirectoryInfo(assemblyLocation)?.Parent?.Parent?.Parent;
                if (toolRootInstallDirectory is { })
                {
                    var staticWebAssetsLocation = Path.Combine(toolRootInstallDirectory.FullName, "staticwebassets");
                    if (Directory.Exists(staticWebAssetsLocation))
                    {
                        webRoot = staticWebAssetsLocation;
                    }
                    else
                    {
                        Log.Warning("Could not find static web assets. GUI likely will not load properly");
                    }
                }
            }
            var url = $"http://localhost:{opts.Port}";

            var host = server.ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseWebRoot(webRoot);
                    webBuilder.UseStartup<Startup>();
                    webBuilder.UseUrls(url);
                })
                .Build();

            if (!opts.NoLaunch)
            {
                ((Action)(async () =>
                {
                    await Task.Run(() => SleepAndOpenBrowser(1500, url)).ConfigureAwait(false);
                }))();
            }

            host.Run();

            return ASA_ERROR.NONE;
        }

        private static void SleepAndOpenBrowser(int sleep, string url)
        {
            Thread.Sleep(sleep);
            AsaHelpers.OpenBrowser(new System.Uri(url));
        }

        private static ASA_ERROR RunConfigCommand(ConfigCommandOptions opts)
        {
            if (opts.ResetDatabase)
            {
                var filename = opts.DatabaseFilename;
                DatabaseManager.Destroy(opts.DatabaseFilename);
                Log.Information(Strings.Get("DeletedDatabaseAt"), filename);
            }
            else
            {
                SetupDatabase(opts);
                if (DatabaseManager is null)
                {
                    Log.Error("Err_DatabaseManagerNull", "RunConfigCommand");
                    return ASA_ERROR.DATABASE_NULL;
                }
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

                if (opts.DeleteRunId != null)
                {
                    DatabaseManager.DeleteRun(opts.DeleteRunId);
                }
                if (opts.TrimToLatest)
                {
                    DatabaseManager.TrimToLatest();
                }
            }
            return ASA_ERROR.NONE;
        }

        private static ASA_ERROR RunExportCollectCommand(ExportCollectCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunExportCollectCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
            if (opts.OutputPath != null && !Directory.Exists(opts.OutputPath))
            {
                Log.Fatal(Strings.Get("Err_OutputPathNotExist"), opts.OutputPath);
                return 0;
            }

            if (opts.ExportSingleRun)
            {
                if (opts.SecondRunId is null)
                {
                    Log.Information("Provided null second run id using latest run.");
                    List<string> runIds = DatabaseManager.GetLatestRunIds(1, RUN_TYPE.COLLECT);
                    if (runIds.Count < 1)
                    {
                        Log.Fatal(Strings.Get("Err_CouldntDetermineOneRun"));
                        return ASA_ERROR.INVALID_ID;
                    }
                    else
                    {
                        // If you ask for single run everything is "Created"
                        opts.SecondRunId = runIds.First();
                        opts.FirstRunId = null;
                    }
                }
            }
            else if (opts.FirstRunId is null || opts.SecondRunId is null)
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

            var ruleFile = LoadRulesFromFileOrEmbedded(opts.AnalysesFile);
            if (!ruleFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return ASA_ERROR.INVALID_RULES;
            }
            
            CompareCommandOptions options = new(opts.FirstRunId, opts.SecondRunId)
            {
                DatabaseFilename = opts.DatabaseFilename,
                AnalysesFile = ruleFile,
                DisableAnalysis = opts.DisableAnalysis,
                SaveToDatabase = opts.SaveToDatabase,
                RunScripts = opts.RunScripts,
                SingleThreadAnalysis = opts.SingleThreadAnalysis
            };

            var analysesHash = options.AnalysesFile.GetHash();
            var results =
                new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            if (opts.ReadFromSavedComparisons &&
                DatabaseManager.GetComparisonCompleted(opts.FirstRunId, opts.SecondRunId, analysesHash))
            {
                Log.Information(Strings.Get("LoadingSavedComparison"), opts.FirstRunId, opts.SecondRunId, analysesHash);

                foreach (RESULT_TYPE resultType in Enum.GetValues(typeof(RESULT_TYPE)))
                {
                    foreach (CHANGE_TYPE changeType in Enum.GetValues(typeof(CHANGE_TYPE)))
                    {
                        results[(resultType, changeType)] = new ConcurrentBag<CompareResult>();
                    }
                }

                foreach (RESULT_TYPE resultType in Enum.GetValues(typeof(RESULT_TYPE)))
                {
                    var resultsForType =
                        DatabaseManager.GetComparisonResults(opts.FirstRunId, opts.SecondRunId, analysesHash,
                            resultType);
                    foreach (var result in resultsForType)
                    {
                        results[(result.ResultType, result.ChangeType)].Add(result);
                    }
                }

                foreach (var key in results.Keys)
                {
                    if (results[key].IsEmpty)
                    {
                        results.Remove(key, out _);
                    }
                }
                
            }
            else
            {
                Log.Information(Strings.Get("Comparing"), opts.FirstRunId, opts.SecondRunId);
                
                results = CompareRuns(options);
            
                if (opts.SaveToDatabase)
                {
                    InsertCompareResults(results, opts.FirstRunId, opts.SecondRunId, analysesHash);
                }
            }
            // Filter by specified analysis levels
            if (opts.ResultLevels.Any())
            {
                foreach (var kvp in results)
                {
                    results[kvp.Key] = new ConcurrentBag<CompareResult>(kvp.Value.Where(x => opts.ResultLevels.Contains(x.Analysis)));
                }
            }
            return ExportCompareResults(results, opts, AsaHelpers.MakeValidFileName(opts.FirstRunId + "_vs_" + opts.SecondRunId), analysesHash, ruleFile.Rules);
        }

        internal static ASA_ERROR ExportCompareResults(ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> resultsIn, ExportOptions opts, string baseFileName, string analysesHash, IEnumerable<AsaRule> rules)
        {
            var results = resultsIn.Select(x => new KeyValuePair<string, object>($"{x.Key.Item1}_{x.Key.Item2}", x.Value)).ToDictionary(x => x.Key, x => x.Value);
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
            var metadata = AsaHelpers.GenerateMetadata();
            metadata.Add("analyses-hash", analysesHash);
            if (opts.ExplodedOutput)
            {
                results.Add("metadata", metadata);

                string path = Path.Combine(outputPath, AsaHelpers.MakeValidFileName(baseFileName));
                Directory.CreateDirectory(path);
                foreach (var key in results.Keys)
                {
                    string filePath = Path.Combine(path, AsaHelpers.MakeValidFileName(key));
                    if (opts.OutputSarif)
                    {
                        WriteSarifLog(new Dictionary<string, object>() { { key, results[key] } }, rules, filePath);
                    }
                    else
                    {
                        using StreamWriter sw = new(filePath); //lgtm[cs/path-injection]
                        using JsonWriter writer = new JsonTextWriter(sw);
                        serializer.Serialize(writer, results[key]);
                    }
                }
                Log.Information(Strings.Get("OutputWrittenTo"), (new DirectoryInfo(path)).FullName);
            }
            else
            {
                string path = Path.Combine(outputPath, AsaHelpers.MakeValidFileName(baseFileName + "_summary.json.txt"));
                var output = new Dictionary<string, object>();
                output["results"] = results;
                output["metadata"] = metadata;

                if (opts.OutputSarif)
                {
                    string pathSarif = Path.Combine(outputPath, AsaHelpers.MakeValidFileName(baseFileName + "_summary.Sarif"));
                    WriteSarifLog(output, rules, pathSarif);
                    Log.Information(Strings.Get("OutputWrittenTo"), (new FileInfo(pathSarif)).FullName);
                }
                else
                {

                    using (StreamWriter sw = new(path)) //lgtm[cs/path-injection]
                    {
                        using JsonWriter writer = new JsonTextWriter(sw);
                        serializer.Serialize(writer, output);
                    }
                    Log.Information(Strings.Get("OutputWrittenTo"), (new FileInfo(path)).FullName);
                }
            }
            return ASA_ERROR.NONE;
        }

        /// <summary>
        /// Write log in Sarif format
        /// </summary>
        /// <param name="output">output of the analyzer result</param>
        /// <param name="rules">list of rules used</param>
        /// <param name="outputFilePath">file path of the Sarif log</param>
        public static void WriteSarifLog(Dictionary<string, object> output, IEnumerable<AsaRule> rules, string outputFilePath)
        {
            var log = GenerateSarifLog(output, rules);

            var settings = new JsonSerializerSettings()
            {
                Formatting = Formatting.Indented,
            };

            File.WriteAllText(outputFilePath, JsonConvert.SerializeObject(log, settings));
        }

        public static SarifLog GenerateSarifLog(Dictionary<string, object> output, IEnumerable<AsaRule> rules)
        {
            var metadata = (Dictionary<string, string>)output["metadata"];
            var results = (Dictionary<string, object>)output["results"];
            var version = metadata["compare-version"];

            var log = new SarifLog();
            SarifVersion sarifVersion = SarifVersion.Current;
            log.SchemaUri = sarifVersion.ConvertToSchemaUri();
            log.Version = sarifVersion;
            log.Runs = new List<Run>();
            var run = new Run();
            var artifacts = new List<Artifact>();
            run.Tool = new Tool
            {
                Driver = new ToolComponent
                {
                    Name = $"Attack Surface Analyzer",
                    InformationUri = new Uri("https://github.com/microsoft/AttackSurfaceAnalyzer/"),
                    Organization = "Microsoft",
                    Version = version,
                }
            };

            var reportingDescriptors = new List<ReportingDescriptor>();

            foreach (var rule in rules)
            {
                if (!reportingDescriptors.Any(r => r.Id == rule.Name))
                {
                    var reportingDescriptor = new ReportingDescriptor()
                    {
                        FullDescription = new MultiformatMessageString() { Text = rule.Description },
                        Id = rule.Name,
                    };
                    reportingDescriptor.DefaultConfiguration = new ReportingConfiguration()
                    {
                        Level = GetSarifFailureLevel((ANALYSIS_RESULT_TYPE)rule.Severity)
                    };
                    reportingDescriptor.SetProperty("ChangeTypes", string.Join(',', rule.ChangeTypes));
                    reportingDescriptor.SetProperty("Platforms", string.Join(',', rule.Platforms));
                    reportingDescriptor.SetProperty("ResultType", rule.ResultType.ToString());
                    reportingDescriptors.Add(reportingDescriptor);
                }
            }

            run.Tool.Driver.Rules = new List<ReportingDescriptor>(reportingDescriptors);

            var sarifResults = new List<Result>();

            foreach (var item in results)
            {
                var compareResults = (IEnumerable<CompareResult>)item.Value;
                foreach (var compareResult in compareResults)
                {
                    var artifact = new Artifact
                    {
                        Location = new ArtifactLocation()
                        {
                            Index = artifacts.Count,
                            Description = new Message() { Text = compareResult.Identity }
                        }
                    };

                    if (Uri.TryCreate(compareResult.Identity, UriKind.RelativeOrAbsolute, out Uri? outUri))
                    {
                        artifact.Location.Uri = outUri;
                    }

                    artifact.SetProperty("Analysis", compareResult.Analysis);

                    if (compareResult.Base != null)
                    {
                        artifact.SetProperty("Base", compareResult.Base);
                    }

                    if (!string.IsNullOrWhiteSpace(compareResult.BaseRunId))
                    {
                        artifact.SetProperty("BaseRunId", compareResult.BaseRunId);
                    }

                    artifact.SetProperty("ChangeType", compareResult.ChangeType);

                    if (compareResult.Compare != null)
                    {
                        artifact.SetProperty("Compare", compareResult.Compare);
                    }

                    if (!string.IsNullOrWhiteSpace(compareResult.CompareRunId))
                    {
                        artifact.SetProperty("CompareRunId", compareResult.CompareRunId);
                    }

                    if (compareResult.Diffs.Count > 0)
                    {
                        artifact.SetProperty("Diffs", compareResult.Diffs);
                    }

                    artifact.SetProperty("ResultType", compareResult.ResultType);

                    artifacts.Add(artifact);
                    int index = artifacts.Count - 1;
                    if (compareResult.Rules.Any())
                    {
                        foreach (var rule in compareResult.Rules)
                        {
                            var sarifResult = new Result();
                            sarifResult.Locations = new List<Location>()
                            {
                                new Location() {
                                    PhysicalLocation = new PhysicalLocation()
                                    {
                                        ArtifactLocation = new ArtifactLocation()
                                        {
                                            Index = index
                                        }
                                    }
                                }
                            };

                            sarifResult.Level = GetSarifFailureLevel((ANALYSIS_RESULT_TYPE)rule.Severity);

                            if (!string.IsNullOrWhiteSpace(rule.Name))
                            {
                                sarifResult.RuleId = rule.Name;
                            }

                            sarifResult.Message = new Message() { Text = string.Format("{0}: {1} ({2})", rule.Name, compareResult.Identity, compareResult.ChangeType) };
                        
                            sarifResults.Add(sarifResult);
                        }
                    }
                    else
                    {
                        var sarifResult = new Result();
                        sarifResult.Locations = new List<Location>()
                        {
                            new Location() {
                                PhysicalLocation = new PhysicalLocation()
                                {
                                    ArtifactLocation = new ArtifactLocation()
                                    {
                                        Index = index
                                    }
                                }
                            }
                        };

                        sarifResult.Level = GetSarifFailureLevel(compareResult.Analysis);

                        sarifResult.RuleId = "Default Level";

                        sarifResult.Message = new Message() { Text = string.Format("Default Level: {0} ({1})", compareResult.Identity, compareResult.ChangeType) };
                        
                        sarifResults.Add(sarifResult);
                    }
                }
            }

            run.Results = sarifResults;
            run.Artifacts = artifacts;

            run.SetProperty("compare-os", metadata["compare-os"]);
            run.SetProperty("compare-osversion", metadata["compare-osversion"]);
            run.SetProperty("analyses-hash", metadata["analyses-hash"]);

            log.Runs.Add(run);

            return log;
        }

        private static FailureLevel GetSarifFailureLevel(ANALYSIS_RESULT_TYPE type)
        {
            return type switch
            {
                ANALYSIS_RESULT_TYPE.NONE or
                ANALYSIS_RESULT_TYPE.VERBOSE or
                ANALYSIS_RESULT_TYPE.DEBUG or
                ANALYSIS_RESULT_TYPE.INFORMATION => FailureLevel.Note,
                ANALYSIS_RESULT_TYPE.WARNING => FailureLevel.Warning,
                ANALYSIS_RESULT_TYPE.ERROR or ANALYSIS_RESULT_TYPE.FATAL => FailureLevel.Error,
                _ => FailureLevel.None,
            };
        }

        private class AsaExportContractResolver : DefaultContractResolver
        {
            public static readonly AsaExportContractResolver Instance = new();

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                JsonProperty property = base.CreateProperty(member, memberSerialization);

                if (property.DeclaringType == typeof(RegistryObject))
                {
                    if (property.PropertyName is "Subkeys" or "Values")
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

                if (property.DeclaringType == typeof(CompareResult))
                {
                    if (property.PropertyName == "AnalysesHash")
                    {
                        property.ShouldSerialize = _ => { return false; };
                    }
                }

                return property;
            }
        }

        private static ASA_ERROR RunExportMonitorCommand(ExportMonitorCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunExportMonitorCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
            if (opts.RunId is null)
            {
                var runIds = DatabaseManager.GetLatestRunIds(1, RUN_TYPE.MONITOR);
                if (runIds.Any())
                {
                    opts.RunId = runIds.First();
                }
                else
                {
                    Log.Fatal(Strings.Get("Err_CouldntDetermineOneRun"));
                    return ASA_ERROR.INVALID_ID;
                }
            }

            var ruleFile = LoadRulesFromFileOrEmbedded(opts.AnalysesFile);
            if (!ruleFile.Rules.Any())
            {
                Log.Warning(Strings.Get("Err_NoRules"));
                return ASA_ERROR.INVALID_RULES;
            }
            var monitorCompareOpts = new CompareCommandOptions(null, opts.RunId)
            {
                DisableAnalysis = opts.DisableAnalysis,
                AnalysesFile = ruleFile,
                ApplySubObjectRulesToMonitor = opts.ApplySubObjectRulesToMonitor,
                RunScripts = opts.RunScripts,
                SingleThreadAnalysis = opts.SingleThreadAnalysis
            };

            var monitorResult = AnalyzeMonitored(monitorCompareOpts);
            
            var analysesHash = monitorCompareOpts.AnalysesFile.GetHash();

            if (opts.SaveToDatabase)
            {
                InsertCompareResults(monitorResult, null, opts.RunId, analysesHash);
            }
            if (opts.ResultLevels.Any())
            {
                foreach (var kvp in monitorResult)
                {
                    monitorResult[kvp.Key] = new ConcurrentBag<CompareResult>(kvp.Value.Where(x => opts.ResultLevels.Contains(x.Analysis)));
                }
            }

            return ExportCompareResults(monitorResult, opts, AsaHelpers.MakeValidFileName(opts.RunId), analysesHash, ruleFile.Rules);
        }

        public static void WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "WriteMonitorJson");
                return;
            }
            var invalidFileNameChars = Path.GetInvalidPathChars().ToList();
            OutputPath = new string(OutputPath.Select(ch => invalidFileNameChars.Contains(ch) ? Convert.ToChar(invalidFileNameChars.IndexOf(ch) + 65) : ch).ToArray());

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

            using (StreamWriter sw = new(path)) //lgtm [cs/path-injection]
            using (JsonWriter writer = new JsonTextWriter(sw))
            {
                serializer.Serialize(writer, output);
            }

            Log.Information(Strings.Get("OutputWrittenTo"), (new FileInfo(path)).FullName);
        }

        private static ASA_ERROR RunMonitorCommand(MonitorCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunMonitorCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
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
                    return ASA_ERROR.UNIQUE_ID;
                }
            }
            var run = new AsaRun(RunId: opts.RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.FILEMONITOR }, RUN_TYPE.MONITOR);

            DatabaseManager.InsertRun(run);

            var returnValue = ASA_ERROR.NONE;

            if (opts.EnableFileSystemMonitor)
            {
                monitors.Add(new FileSystemMonitor(opts, x => DatabaseManager.Write(x, opts.RunId)));
            }

            if (monitors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoMonitors"));
                returnValue = ASA_ERROR.NO_COLLECTORS;
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
                    returnValue = ASA_ERROR.UNKNOWN;
                }
            }

            void consoleCancelDelegate(object? sender, ConsoleCancelEventArgs args)
            {
                args.Cancel = true;
                exitEvent.Set();
            };
            // Set up the event to capture CTRL+C
            Console.CancelKeyPress += consoleCancelDelegate;

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

            FlushResults();

            DatabaseManager.Commit();

            Console.CancelKeyPress -= consoleCancelDelegate;

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

        public static ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>> CompareRuns(CompareCommandOptions opts)
        {
            if (opts is null)
            {
                throw new ArgumentNullException(nameof(opts));
            }
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "CompareRuns");
                return new ConcurrentDictionary<(RESULT_TYPE, CHANGE_TYPE), ConcurrentBag<CompareResult>>();
            }
            comparators = new List<BaseCompare>();

            Dictionary<string, string> EndEvent = new();
            BaseCompare c = new();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            if (!c.TryCompare(opts.FirstRunId, opts.SecondRunId, DatabaseManager))
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

            if (!opts.DisableAnalysis)
            {
                if (opts.AnalysesFile is not null)
                {
                    watch = Stopwatch.StartNew();
                    var analyzer = new AsaAnalyzer(new AnalyzerOptions(opts.RunScripts, !opts.SingleThreadAnalysis));
                    var platform = DatabaseManager.RunIdToPlatform(opts.SecondRunId);
                    var violations = analyzer.EnumerateRuleIssues(opts.AnalysesFile.Rules);
                    var analysesHash = opts.AnalysesFile.GetHash();
                    OAT.Utils.Strings.Setup();
                    OAT.Utils.Helpers.PrintViolations(violations);
                    if (violations.Any())
                    {
                        Log.Error("Encountered {0} issues with rules in {1}. Skipping analysis.", violations.Count(), opts.AnalysesFile?.Source ?? "Embedded");
                    }
                    else
                    {
                        if (!c.Results.IsEmpty)
                        {
                            foreach ((RESULT_TYPE, CHANGE_TYPE) key in c.Results.Keys)
                            {
                                if (c.Results[key] is IEnumerable<CompareResult> queue)
                                {
                                    IEnumerable<AsaRule> platformRules = opts.AnalysesFile.Rules.Where(rule => rule.Platforms == null || rule.Platforms.Contains(platform));
                                    if (opts.SingleThreadAnalysis)
                                    {
                                        foreach(CompareResult res in queue)
                                        {
                                            PopulateAnalysisForResult(res);
                                        }
                                    }
                                    else
                                    {
                                        queue.AsParallel().ForAll(PopulateAnalysisForResult);
                                    }

                                    void PopulateAnalysisForResult(CompareResult res)
                                    {
                                        // Select rules with the appropriate change type and target (ResultType)
                                        // - Target is also checked inside Analyze, but this shortcuts repeatedly
                                        // checking rules which don't apply
                                        var selectedRules = platformRules.Where((rule) =>
                                            (rule.ChangeTypes == null || rule.ChangeTypes.Contains(res.ChangeType))
                                                && (rule.ResultType == res.ResultType)).ToList();
                                        if (res is null)
                                        {
                                            return;
                                        }
                                        Log.Verbose("Type: {0}", res.ResultType);
                                        Log.Verbose("Base: {0}", JsonConvert.SerializeObject(res.Base));
                                        Log.Verbose("Compare: {0}", JsonConvert.SerializeObject(res.Compare));
                                        Log.Verbose("Num Rules: {0}", selectedRules.Count());
                                        try 
                                        {
                                            res.Rules = analyzer.Analyze(selectedRules, res.Base, res.Compare).ToList();
                                        }
                                        catch(Exception ex)
                                        {
                                            Log.Debug("Exception while analyzing object {3}. Use --verbose for object details. {0}:{1}. {2}.", ex.GetType().Name, ex.Message, ex.StackTrace, res.Identity);
                                        }
                                        Log.Verbose("Applied Rules: {0}", res.Rules);

                                        res.Analysis = res.Rules.Count
                                                        > 0 ? res.Rules.Max(x => ((AsaRule)x).Flag) : opts.AnalysesFile.GetDefaultLevel(res.ResultType);
                                        res.AnalysesHash = analysesHash;
                                    };
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
                else
                {
                    Log.Error(Strings.Get("Err_AnalysisNull"));
                }
            }

            return c.Results;
        }

        public static ASA_ERROR RunGuiMonitorCommand(MonitorCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunGuiMonitorCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
            if (opts is null)
            {
                return ASA_ERROR.NO_COLLECTORS;
            }
            var setResultTypes = new List<RESULT_TYPE>();
            if (opts.EnableFileSystemMonitor)
            {
                monitors.Add(new FileSystemMonitor(opts, x => DatabaseManager.Write(x, opts.RunId)));
                setResultTypes.Add(RESULT_TYPE.FILEMONITOR);
            }

            if (monitors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoMonitors"));
            }
            var run = new AsaRun(RunId: opts?.RunId ?? string.Empty, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), ResultTypes: setResultTypes, Type: RUN_TYPE.MONITOR);

            DatabaseManager.InsertRun(run);
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

            FlushResults();

            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunGuiMonitorCommand");
                return (int)ASA_ERROR.DATABASE_NULL;
            }

            DatabaseManager.Commit();

            return 0;
        }

        public static void AdminOrWarn()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (!Elevation.IsAdministrator())
                {
                    Log.Information(Strings.Get("Err_RunAsAdmin"));
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Information(Strings.Get("Err_RunAsRoot"));
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (!Elevation.IsRunningAsRoot())
                {
                    Log.Information(Strings.Get("Err_RunAsRoot"));
                }
            }
        }

        public static ASA_ERROR RunCollectCommand(CollectCommandOptions opts)
        {
            if (DatabaseManager is null)
            {
                Log.Error("Err_DatabaseManagerNull", "RunCollectCommand");
                return ASA_ERROR.DATABASE_NULL;
            }
            if (opts == null) { return ASA_ERROR.NO_COLLECTORS; }
            collectors.Clear();
            AdminOrWarn();

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

                            case RESULT_TYPE.KEY:
                                opts.EnableKeyCollector = true;
                                break;

                            case RESULT_TYPE.TPM:
                                opts.EnableTpmCollector = true;
                                break;

                            case RESULT_TYPE.PROCESS:
                                opts.EnableProcessCollector = true;
                                break;

                            case RESULT_TYPE.DRIVER:
                                opts.EnableDriverCollector = true;
                                break;

                            case RESULT_TYPE.WIFI:
                                opts.EnableWifiCollector = true;
                                break;
                        }
                    }
                }
            }

            Action<CollectObject> defaultChangeHandler = x => DatabaseManager.Write(x, opts.RunId);

            var dict = new List<RESULT_TYPE>();

            if (opts.EnableFileSystemCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FileSystemCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.FILE);
            }
            if (opts.EnableNetworkPortCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new OpenPortCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.PORT);
            }
            if (opts.EnableServiceCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new ServiceCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.SERVICE);
            }
            if (opts.EnableUserCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new UserAccountCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.USER);
            }
            if (opts.EnableRegistryCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new RegistryCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.REGISTRY);
            }
            if (opts.EnableCertificateCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new CertificateCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.CERTIFICATE);
            }
            if (opts.EnableFirewallCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new FirewallCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.FIREWALL);
            }
            if (opts.EnableComObjectCollector || (opts.EnableAllCollectors && RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new ComObjectCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.COM);
            }
            if (opts.EnableEventLogCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new EventLogCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.LOG);
            }
            if (opts.EnableTpmCollector || (opts.EnableAllCollectors && (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))))
            {
                collectors.Add(new TpmCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.TPM);
            }
            if (opts.EnableKeyCollector || opts.EnableAllCollectors && (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)))
            {
                collectors.Add(new CryptographicKeyCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.KEY);
            }
            if (opts.EnableProcessCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new ProcessCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.PROCESS);
            }
            if (opts.EnableDriverCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new DriverCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.DRIVER);
            }
            if (opts.EnableWifiCollector || opts.EnableAllCollectors)
            {
                collectors.Add(new WifiCollector(opts, defaultChangeHandler));
                dict.Add(RESULT_TYPE.WIFI);
            }

            if (collectors.Count == 0)
            {
                Log.Warning(Strings.Get("Err_NoCollectors"));
                return ASA_ERROR.NO_COLLECTORS;
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
                    return ASA_ERROR.UNIQUE_ID;
                }
            }
            Log.Information(Strings.Get("Begin"), opts.RunId);

            var run = new AsaRun(RunId: opts.RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), ResultTypes: dict, Type: RUN_TYPE.COLLECT);

            DatabaseManager.InsertRun(run);

            Log.Information(Strings.Get("StartingN"), collectors.Count.ToString(CultureInfo.InvariantCulture), Strings.Get("Collectors"));

            using CancellationTokenSource source = new();
            CancellationToken token = source.Token;

            void cancelKeyDelegate(object? sender, ConsoleCancelEventArgs args)
            {
                Log.Information("Cancelling collection. Rolling back transaction. Please wait to avoid corrupting database.");
                source.Cancel();

                if (DatabaseManager is null)
                {
                    Log.Error("Err_DatabaseManagerNull", "InsertCompareResults");
                }
                else
                {
                    DatabaseManager.CloseDatabase();
                }
                Environment.Exit((int)ASA_ERROR.CANCELLED);
            }
            Console.CancelKeyPress += cancelKeyDelegate;

            Dictionary<string, string> EndEvent = new();
            foreach (BaseCollector c in collectors)
            {
                try
                {
                    DatabaseManager.BeginTransaction();

                    c.TryExecute(token);

                    FlushResults();

                    DatabaseManager.Commit();
                }
                catch (Exception e)
                {
                    Log.Error(Strings.Get("Err_CollectingFrom"), c.GetType().Name, e.Message, e.StackTrace);

                    Console.CancelKeyPress -= cancelKeyDelegate;

                    return ASA_ERROR.FAILED_TO_COMMIT;
                }
            }

            DatabaseManager.Commit();
            Console.CancelKeyPress -= cancelKeyDelegate;

            return ASA_ERROR.NONE;
        }

        private static void FlushResults()
        {
            if (DatabaseManager is null)
            {
                return;
            }
            var prevFlush = DatabaseManager.QueueSize;
            var totFlush = prevFlush;

            var printInterval = new TimeSpan(0, 0, 10);
            var then = DateTime.Now;

            var StopWatch = Stopwatch.StartNew();
            TimeSpan t = new();
            string answer = string.Empty;
            bool warnedToIncreaseShards = false;
            var settings = DatabaseManager.GetCurrentSettings();

            while (DatabaseManager.HasElements)
            {
                Thread.Sleep(100);
                if (!DatabaseManager.HasElements)
                {
                    break;
                }
                if (!warnedToIncreaseShards && StopWatch.ElapsedMilliseconds > 10000 && settings.ShardingFactor < 7)
                {
                    Log.Information("It is taking a while to flush results to the database.  Try increasing the sharding level to improve performance.");
                    warnedToIncreaseShards = true;
                }
                var now = DateTime.Now;
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