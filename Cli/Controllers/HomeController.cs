// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Cli;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Models;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {
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

        public ActionResult GetMonitorResults(string RunId, int Offset, int NumResults)
        {
            List<FileMonitorObject> results = DatabaseManager.GetMonitorResults(RunId, Offset, NumResults);

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = DatabaseManager.GetNumMonitorResults(RunId); ;
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;

            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {
            List<CompareResult> results = DatabaseManager.GetComparisonResults(AsaHelpers.RunIdsToCompareId(BaseId, CompareId), ResultType, Offset, NumResults);

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = DatabaseManager.GetComparisonResultsCount(AsaHelpers.RunIdsToCompareId(BaseId, CompareId), ResultType);
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;
            return Json(JsonConvert.SerializeObject(output));
        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {

            var json_out = DatabaseManager.GetCommonResultTypes(BaseId, CompareId);

            return Json(json_out);
        }

        public ActionResult GetCollectors()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            Dictionary<string, object> output = new Dictionary<string, object>();

            var RunId = DatabaseManager.GetLatestRunIds(1, RUN_TYPE.COLLECT);

            if (RunId.Count > 0)
            {
                foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
                {
                    var fullString = c.GetType().ToString();
                    var splits = fullString.Split('.');
                    dict.Add(splits[splits.Length - 1], c.RunStatus);
                }
                output.Add("RunId", RunId[0]);
                output.Add("Runs", dict);
            }

            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetLatestRunId()
        {
            return Json(HttpUtility.UrlEncode(DatabaseManager.GetLatestRunIds(1, RUN_TYPE.COLLECT)[0]));
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
            CollectCommandOptions opts = new CollectCommandOptions();
            opts.RunId = Id?.Trim();
            opts.EnableFileSystemCollector = File;
            opts.EnableNetworkPortCollector = Port;
            opts.EnableServiceCollector = Service;
            opts.EnableRegistryCollector = Registry;
            opts.EnableUserCollector = User;
            opts.EnableCertificateCollector = Certificates;
            opts.EnableComObjectCollector = Com;
            opts.EnableFirewallCollector = Firewall;
            opts.EnableEventLogCollector = Log;
            opts.Verbose = Logger.Verbose;
            opts.Debug = Logger.Debug;
            opts.Quiet = Logger.Quiet;

            opts.DatabaseFilename = DatabaseManager.SqliteFilename;

            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection.
                // We won't start new collections while existing ones are ongoing.
                if (c.RunStatus == RUN_STATUS.RUNNING)
                {
                    return Json(ASA_ERROR.ALREADY_RUNNING);
                }
            }

            if (Id is null)
            {
                return Json(ASA_ERROR.INVALID_ID);
            }

            if (DatabaseManager.GetRun(Id) != null)
            {
                return Json(ASA_ERROR.UNIQUE_ID);
            }

            _ = Task.Factory.StartNew(() => AttackSurfaceAnalyzerClient.RunCollectCommand(opts));
            return Json(ASA_ERROR.NONE);
        }

        public IActionResult Collect()
        {
            return View();
        }

        public ActionResult ChangeTelemetryState(bool EnableTelemetry)
        {
            AsaTelemetry.SetEnabled(EnableTelemetry);

            return Json(true);
        }

        public ActionResult StartMonitoring(string RunId, string Directory)
        {
            if (RunId != null)
            {
                if (DatabaseManager.GetRun(RunId) != null)
                {
                    return Json(ASA_ERROR.UNIQUE_ID);
                }

                var run = new AsaRun(RunId: RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.FILEMONITOR }, RUN_TYPE.MONITOR);
                DatabaseManager.InsertRun(run);

                MonitorCommandOptions opts = new MonitorCommandOptions
                {
                    RunId = RunId,
                    EnableFileSystemMonitor = true,
                    MonitoredDirectories = Directory,
                    Verbose = Logger.Verbose,
                    Debug = Logger.Debug,
                    Quiet = Logger.Quiet
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

        [HttpPost]
        public ActionResult RunAnalysisWithAnalyses(string SelectedBaseRunId, string SelectedCompareRunId, IFormFile AnalysisFilterFile)
        {
            var filePath = Path.GetTempFileName();

            CompareCommandOptions opts = new CompareCommandOptions(SelectedBaseRunId, SelectedCompareRunId)
            {
                Analyze = true,
                SaveToDatabase = true
            };

            if (AnalysisFilterFile != null)
            {
                using (var stream = System.IO.File.Create(filePath))
                {
                    AnalysisFilterFile.CopyTo(stream);
                }
                opts.AnalysesFile = filePath;
            }

            if (AttackSurfaceAnalyzerClient.GetComparators().Where(c => c.IsRunning() == RUN_STATUS.RUNNING).Any())
            {
                return Json("Comparators already running!");
            }

            if (DatabaseManager.GetComparisonCompleted(opts.FirstRunId, opts.SecondRunId))
            {
                return Json("Using cached comparison calculations.");

            }

            Task.Factory.StartNew(() => AttackSurfaceAnalyzerClient.CompareRuns(opts));

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

        private static IEnumerable<DataRunModel> GetMonitorRunModels()
        {
            List<string> Runs = DatabaseManager.GetRuns(RUN_TYPE.MONITOR);

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel(Runs[i], Runs[i]));
            }

            return runModels;
        }

        private static IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = DatabaseManager.GetRuns(RUN_TYPE.COLLECT);

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel(Runs[i], Runs[i]));
            }

            return runModels;
        }

        private static IEnumerable<DataRunModel> GetResultModels()
        {
            List<DataRunModel> DataModels = DatabaseManager.GetResultModels(RUN_STATUS.COMPLETED);

            return DataModels;
        }
    }
}