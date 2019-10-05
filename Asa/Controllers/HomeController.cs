// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Models;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.ApplicationInsights;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {
        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status"; //lgtm [cs/literal-as-local]

        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id"; //lgtm [cs/literal-as-local]
        private const string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type, timestamp, version, platform) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type, @timestamp, @version, @platform)"; //lgtm [cs/literal-as-local]
        private const string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id"; //lgtm [cs/literal-as-local]

        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;"; //lgtm [cs/literal-as-local]

        private const string GET_COMPARISON_RESULTS = "select * from findings where comparison_id=@comparison_id and result_type=@result_type order by level desc limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT = "select count(*) from findings where comparison_id=@comparison_id and result_type=@result_type"; //lgtm [cs/literal-as-local]

        public HomeController()
        {

        }

        public IActionResult Index()
        {
            return View();
        }

        public ActionResult WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            AttackSurfaceAnalyzerClient.WriteMonitorJson(RunId, ResultType, OutputPath);

            return Json(true);
        }

        public ActionResult WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            AttackSurfaceAnalyzerClient.WriteScanJson(ResultType, BaseId, CompareId, ExportAll, OutputPath);
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
                            ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString(), CultureInfo.InvariantCulture),
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
                        result_count = int.Parse(reader["count(*)"].ToString(), CultureInfo.InvariantCulture);
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
            var results = new List<CompareResult>();

            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", AsaHelpers.RunIdsToCompareId(BaseId, CompareId));
                cmd.Parameters.AddWithValue("@result_type", ResultType);
                cmd.Parameters.AddWithValue("@offset", Offset);
                cmd.Parameters.AddWithValue("@limit", NumResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = JsonConvert.DeserializeObject<CompareResult>(reader["serialized"].ToString());
                        results.Add(obj);
                    }
                }
            }


            Dictionary<string, object> output = new Dictionary<string, object>();
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", AsaHelpers.RunIdsToCompareId(BaseId, CompareId));
                cmd.Parameters.AddWithValue("@result_type", ResultType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        result_count = int.Parse(reader["count(*)"].ToString(), CultureInfo.InvariantCulture);
                    }
                }
            }

            output["Results"] = results;
            output["TotalCount"] = result_count;
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;
            return Json(JsonConvert.SerializeObject(output));
        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {

            var json_out = new Dictionary<string, bool>(){
                { "File", false },
                { "Certificate", false },
                { "Registry", false },
                { "Port", false },
                { "Service", false },
                { "User", false },
                { "Firewall", false },
                { "Com", false },
                { "Log", false }
            };

            var count = new Dictionary<string, int>()
            {
                { "File", 0 },
                { "Certificate", 0 },
                { "Registry", 0 },
                { "Port", 0 },
                { "Service", 0 },
                { "User", 0 },
                { "Firewall", 0 },
                { "ComObject", 0 },
                { "LogEntry", 0 }
            };
            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", BaseId?.ToString(CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@compare_run_id", CompareId?.ToString(CultureInfo.InvariantCulture));
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (int.Parse(reader["file_system"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["File"]++;
                        }
                        if (int.Parse(reader["ports"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["Port"]++;
                        }
                        if (int.Parse(reader["users"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["User"]++;
                        }
                        if (int.Parse(reader["services"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["Service"]++;
                        }
                        if (int.Parse(reader["registry"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["Registry"]++;
                        }
                        if (int.Parse(reader["certificates"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["Certificate"]++;
                        }
                        if (int.Parse(reader["firewall"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["Firewall"]++;
                        }
                        if (int.Parse(reader["comobjects"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["ComObject"]++;
                        }
                        if (int.Parse(reader["eventlogs"].ToString(), CultureInfo.InvariantCulture) != 0)
                        {
                            count["LogEntry"]++;
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
            string RunId = AttackSurfaceAnalyzerClient.GetLatestRunId();

            //TODO: Improve this to not have to change this variable on every loop, without having to call GetCollectors twice.
            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.IsRunning());
            }
            Dictionary<string, object> output = new Dictionary<string, object>();
            output.Add("RunId", RunId);
            output.Add("Runs", dict);
            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetLatestRunId()
        {
            return Json(AttackSurfaceAnalyzerClient.GetLatestRunId());
        }

        public ActionResult GetMonitorStatus()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseMonitor c in AttackSurfaceAnalyzerClient.GetMonitors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.RunStatus);
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }

        public ActionResult GetComparators()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseCompare c in AttackSurfaceAnalyzerClient.GetComparators())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.IsRunning());
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }


        public ActionResult StartCollection(string Id, bool File, bool Port, bool Service, bool User, bool Registry, bool Certificates, bool Com, bool Firewall, bool Log)
        {
            Contract.Requires<ArgumentNullException>(Id != null, nameof(Id));

            CollectCommandOptions opts = new CollectCommandOptions();
            opts.RunId = Id.Trim();
            opts.EnableFileSystemCollector = File;
            opts.EnableNetworkPortCollector = Port;
            opts.EnableServiceCollector = Service;
            opts.EnableRegistryCollector = Registry;
            opts.EnableUserCollector = User;
            opts.EnableCertificateCollector = Certificates;
            opts.EnableComObjectCollector = Com;
            opts.EnableFirewallCollector = Firewall;
            opts.EnableEventLogCollector = Log;

            opts.DatabaseFilename = DatabaseManager.SqliteFilename;
            opts.FilterLocation = "Use embedded filters.";

            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection.
                // We won't start new collections while existing ones are ongoing.
                if (c.IsRunning() == RUN_STATUS.RUNNING)
                {
                    return Json(ERRORS.ALREADY_RUNNING);
                }
            }
            AttackSurfaceAnalyzerClient.ClearCollectors();
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

            Task.Factory.StartNew<int>(() => AttackSurfaceAnalyzerClient.RunCollectCommand(opts));
            return Json(ERRORS.NONE);
        }

        public IActionResult Collect()
        {
            return View();
        }

        public ActionResult ChangeTelemetryState(bool DisableTelemetry)
        {
            AsaTelemetry.SetOptOut(DisableTelemetry);

            return Json(true);
        }

        public ActionResult StartMonitoring(string RunId, string Directory, string Extension)
        {
            if (RunId != null)
            {
                using (var cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", RunId.Trim());
                    cmd.Parameters.AddWithValue("@file_system", true);
                    cmd.Parameters.AddWithValue("@ports", false);
                    cmd.Parameters.AddWithValue("@users", false);
                    cmd.Parameters.AddWithValue("@services", false);
                    cmd.Parameters.AddWithValue("@registry", false);
                    cmd.Parameters.AddWithValue("@certificates", false);
                    cmd.Parameters.AddWithValue("@firewall", false);
                    cmd.Parameters.AddWithValue("@comobjects", false);
                    cmd.Parameters.AddWithValue("@type", "monitor");
                    cmd.Parameters.AddWithValue("@timestamp", DateTime.Now.ToString("o", CultureInfo.InvariantCulture));
                    cmd.Parameters.AddWithValue("@version", AsaHelpers.GetVersionString());
                    cmd.Parameters.AddWithValue("@platform", AsaHelpers.GetPlatformString());
                    try
                    {
                        cmd.ExecuteNonQuery();
                        DatabaseManager.Commit();
                    }
                    catch (SqliteException e)
                    {
                        Log.Warning(e.StackTrace);
                        Log.Warning(e.Message);
                        return Json((int)ERRORS.UNIQUE_ID);
                    }
                }

                MonitorCommandOptions opts = new MonitorCommandOptions
                {
                    RunId = RunId,
                    EnableFileSystemMonitor = true,
                    MonitoredDirectories = Directory,
                    FilterLocation = "filters.json"
                };
                AttackSurfaceAnalyzerClient.ClearMonitors();
                return Json((int)AttackSurfaceAnalyzerClient.RunGuiMonitorCommand(opts));
            }
            return Json(-1);
        }

        public ActionResult StopMonitoring()
        {
            return Json(AttackSurfaceAnalyzerClient.StopMonitors());
        }

        public ActionResult RunAnalysis(string firstId, string secondId)
        {

            CompareCommandOptions opts = new CompareCommandOptions();
            opts.FirstRunId = firstId;
            opts.SecondRunId = secondId;
            opts.Analyze = true;
            foreach (BaseCompare c in AttackSurfaceAnalyzerClient.GetComparators())
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

            Task.Factory.StartNew<Dictionary<string, object>>(() => AttackSurfaceAnalyzerClient.CompareRuns(opts));

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
            List<string> Runs = AttackSurfaceAnalyzerClient.GetRuns("monitor");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerClient.GetRuns("collect");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetResultModels()
        {
            List<DataRunModel> output = new List<DataRunModel>();

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