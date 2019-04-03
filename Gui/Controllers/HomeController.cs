// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using AttackSurfaceAnalyzer.Cli;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Utils;
using AttackSurfaceAnalyzer.Models;
using AttackSurfaceAnalyzer.ObjectTypes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using System.Threading.Tasks;
using Microsoft.ApplicationInsights.Extensibility;
using System.Runtime.InteropServices;
using Microsoft.ApplicationInsights;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {
        private TelemetryClient telemetry = new TelemetryClient();
        private List<BaseCollector> collectors = new List<BaseCollector>();
        private List<BaseMonitor> monitors = new List<BaseMonitor>();

        private static readonly string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id"; //lgtm [cs/literal-as-local]
        private static readonly string SQL_QUERY_ANALYZED = "select * from results where status = @status"; //lgtm [cs/literal-as-local]
        private static readonly string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private static readonly string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;"; //lgtm [cs/literal-as-local]
        private static readonly string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id"; //lgtm [cs/literal-as-local]
        private static readonly string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type)"; //lgtm [cs/literal-as-local]
        private static readonly string GET_COMPARISON_RESULTS = "select * from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type order by base_row_key limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private static readonly string GET_SERIALIZED_RESULTS = "select serialized from @table_name where row_key = @row_key and run_id = @run_id"; //lgtm [cs/literal-as-local]
        private static readonly string GET_RESULT_COUNT = "select count(*) from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type"; //lgtm [cs/literal-as-local]
        private static readonly string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]

        public HomeController()
        {
            DatabaseManager.Setup();
        }

        public IActionResult Index()
        {
            return View();
        }

        public ActionResult WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            AttackSurfaceAnalyzerCLI.WriteMonitorJson(RunId, ResultType, OutputPath);

            return Json(true);
        }

        public ActionResult CheckAdmin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                if (Elevation.IsAdministrator())
                {
                    telemetry.TrackEvent("LaunchedAsAdmin");
                    return Json(true);
                }
            }
            else if ((RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) && Elevation.IsRunningAsRoot())
            {
                telemetry.TrackEvent("LaunchedAsAdmin");
                return Json(true);
            }
            telemetry.TrackEvent("LaunchedAsNormal");
            return Json(false);
        }

        public ActionResult WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            AttackSurfaceAnalyzerCLI.WriteScanJson(ResultType, BaseId, CompareId, ExportAll, OutputPath);
            return Json(true);
        }

        public ActionResult GetMonitorResults(string RunId, int ResultType, int Offset, int NumResults)
        {

            var results = new List<OutputFileMonitorResult>();




            using (var cmd = new SqliteCommand(GET_MONITOR_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                cmd.Parameters.AddWithValue("@offset", Offset);
                cmd.Parameters.AddWithValue("@limit", NumResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {

                        var obj = new OutputFileMonitorResult()
                        {
                            RowKey = reader["row_key"].ToString(),
                            Timestamp = reader["timestamp"].ToString(),
                            Path = reader["path"].ToString(),
                            OldPath = reader["old_path"].ToString(),
                            Name = reader["path"].ToString(),
                            OldName = reader["old_path"].ToString(),
                            ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString()),
                        };
                        results.Add(obj);

                    }
                }
            }

            Dictionary<string, object> output = new Dictionary<string, object>();
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT_MONITORED, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        result_count = int.Parse(reader["count(*)"].ToString());
                    }
                }

                output["Results"] = results;
                output["TotalCount"] = result_count;
                output["Offset"] = Offset;
                output["Requested"] = NumResults;
                output["Actual"] = results.Count;
            }
            return Json(JsonConvert.SerializeObject(output));

        }

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {

            var results = new List<OutputCompareResult>();

            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", BaseId);
                cmd.Parameters.AddWithValue("@compare_run_id", CompareId);
                cmd.Parameters.AddWithValue("@data_type", ResultType);
                cmd.Parameters.AddWithValue("@offset", Offset);
                cmd.Parameters.AddWithValue("@limit", NumResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new OutputCompareResult()
                        {
                            BaseRowKey = reader["base_row_key"].ToString(),
                            CompareRowKey = reader["compare_row_key"].ToString(),
                            BaseRunId = reader["base_run_id"].ToString(),
                            CompareRunId = reader["compare_run_id"].ToString(),
                            ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString()),
                            ResultType = (RESULT_TYPE)int.Parse(reader["data_type"].ToString())
                        };
                        results.Add(obj);
                    }
                }
            }

            foreach (var obj in results)
            {
                if (obj.ChangeType == CHANGE_TYPE.CREATED || obj.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    using (var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", obj.CompareRunId);
                        cmd.Parameters.AddWithValue("@row_key", obj.CompareRowKey);
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                obj.SerializedCompare = reader["serialized"].ToString();
                            }
                        }
                    }
                }
                if (obj.ChangeType == CHANGE_TYPE.DELETED || obj.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    using (var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", obj.BaseRunId);
                        cmd.Parameters.AddWithValue("@row_key", obj.BaseRowKey);
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                obj.SerializedBase = reader["serialized"].ToString();
                            }
                        }
                    }
                }
            }

            Dictionary<string, object> output = new Dictionary<string, object>();
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", BaseId);
                cmd.Parameters.AddWithValue("@compare_run_id", CompareId);
                cmd.Parameters.AddWithValue("@data_type", ResultType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        result_count = int.Parse(reader["count(*)"].ToString());
                    }
                }

                output["Results"] = results;
                output["TotalCount"] = result_count;
                output["Offset"] = Offset;
                output["Requested"] = NumResults;
                output["Actual"] = results.Count;
                return Json(JsonConvert.SerializeObject(output));
            }

        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {
       
            var json_out = new Dictionary<string, bool>(){
                { "File", false },
                { "Certificate", false },
                { "Registry", false },
                { "Port", false },
                { "Service", false },
                { "User", false }
            };

            var count = new Dictionary<string, int>()
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
                cmd.Parameters.AddWithValue("@base_run_id", BaseId?.ToString());
                cmd.Parameters.AddWithValue("@compare_run_id", CompareId?.ToString());
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
                    json_out[entry.Key] = true;
                }
            }
            return Json(json_out);
        }
        
        public ActionResult GetCollectors()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseCollector c in AttackSurfaceAnalyzerCLI.GetCollectors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Count()-1], c.IsRunning());
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }

        public ActionResult GetMonitorStatus()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseMonitor c in AttackSurfaceAnalyzerCLI.GetMonitors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Count() - 1], c.RunStatus());
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }

        public ActionResult GetComparators()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseCompare c in AttackSurfaceAnalyzerCLI.GetComparators())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Count() - 1], c.IsRunning());
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }
        

        public ActionResult StartCollection(string Id, bool File, bool Port, bool Service, bool User, bool Registry, bool Certificates)
        {
            CollectCommandOptions opts = new CollectCommandOptions();
            opts.RunId = Id;
            opts.EnableFileSystemCollector = File;
            opts.EnableNetworkPortCollector = Port;
            opts.EnableServiceCollector = Service;
            opts.EnableRegistryCollector = Registry;
            opts.EnableUserCollector = User;
            opts.EnableCertificateCollector = Certificates;
            opts.DatabaseFilename = "asa.sqlite";

            Dictionary<string, bool> dict = new Dictionary<string, bool>();
            foreach (BaseCollector c in AttackSurfaceAnalyzerCLI.GetCollectors())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection.
                // We won't start new collections while existing ones are ongoing.
                if (c.IsRunning() == RUN_STATUS.RUNNING)
                {
                    return Json(false);
                }
            }
            AttackSurfaceAnalyzerCLI.ClearCollectors();
            string Select_Runs = "select run_id from runs where run_id=@run_id";

            using (var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", Id);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        return Json(ERRORS.UNIQUE_ID);
                    }
                }
            }
            Task.Factory.StartNew<int>(() => AttackSurfaceAnalyzerCLI.RunCollectCommand(opts));
            return Json(ERRORS.NONE);
        }

        public IActionResult Collect()
        {
            return View();
        }

        public ActionResult ChangeTelemetryState(bool DisableTelemetry)
        {
            TelemetryConfiguration.Active.DisableTelemetry = DisableTelemetry;


            using (var cmd = new SqliteCommand(UPDATE_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@TelemetryOptOut", DisableTelemetry.ToString());
                cmd.ExecuteNonQuery();
            }

            DatabaseManager.Commit();

            return Json(true);
        }

        public ActionResult StartMonitoring(string RunId, string Directory, string Extension)
        {

            using (var cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                cmd.Parameters.AddWithValue("@file_system", true);
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
                    return Json((int)ERRORS.UNIQUE_ID);
                }
            }

            MonitorCommandOptions opts = new MonitorCommandOptions
            {
                RunId = RunId,
                EnableFileSystemMonitor = true,
                MonitoredDirectories = Directory,
            };
            AttackSurfaceAnalyzerCLI.ClearMonitors();
            return Json(AttackSurfaceAnalyzerCLI.RunGuiMonitorCommand(opts));
        }

        public ActionResult StopMonitoring()
        {
            return Json(AttackSurfaceAnalyzerCLI.StopMonitors());
        }

        public ActionResult RunAnalysis(string first_id, string second_id)
        {

            CompareCommandOptions opts = new CompareCommandOptions();
            opts.FirstRunId = first_id;
            opts.SecondRunId = second_id;
            foreach (BaseCompare c in AttackSurfaceAnalyzerCLI.GetComparators())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection.
                // We won't start new collections while existing ones are ongoing.
                if (c.IsRunning() == RUN_STATUS.RUNNING)
                {
                    return Json("Comparators already running!");
                }
            }


            using (var cmd = new SqliteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        return Json("Using cached comparison calculations.");
                    }
                }
            }

            Task.Factory.StartNew<Dictionary<string, object>>(() => AttackSurfaceAnalyzerCLI.CompareRuns(opts));
           
            return Json("Started Analysis");
        }

        public IActionResult Analyze()
        {
            var model = new DataRunListModel
            {
                SelectedBaseRunId = "-1",
                SelectedCompareRunId = "-1",
                Runs = GetRunModels(),
                SelectedMonitorRunId = "-1",
                MonitorRuns = GetMonitorRunModels(),
            };

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private IEnumerable<DataRunModel> GetMonitorRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerCLI.GetRuns("monitor");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count(); i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerCLI.GetRuns("collect");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0 ; i < Runs.Count() ; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetResultModels()
        {
            List<DataRunModel>  output = new List<DataRunModel>();

            using (var cmd = new SqliteCommand(SQL_QUERY_ANALYZED, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@status", RUN_STATUS.COMPLETED);

                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        output.Add(new DataRunModel { Key = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString(), Text = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString() });
                    }
                }
            }

            return output;
        }
    }
}