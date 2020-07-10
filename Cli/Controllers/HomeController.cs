// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
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

        public ActionResult ChangeTelemetryState(bool EnableTelemetry)
        {
            AsaTelemetry.SetEnabled(EnableTelemetry);

            return Json(true);
        }

        public IActionResult Collect()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public ActionResult GetCollectors()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            Dictionary<string, object> output = new Dictionary<string, object>();

            var RunId = AttackSurfaceAnalyzerClient.DatabaseManager.GetLatestRunIds(1, RUN_TYPE.COLLECT);

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

        public ActionResult GetLatestRunId()
        {
            return Json(HttpUtility.UrlEncode(AttackSurfaceAnalyzerClient.DatabaseManager.GetLatestRunIds(1, RUN_TYPE.COLLECT)[0]));
        }

        public ActionResult GetMonitorResults(string RunId, int Offset, int NumResults)
        {
            var results = AttackSurfaceAnalyzerClient.DatabaseManager.GetMonitorResults(RunId, Offset, NumResults);

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = AttackSurfaceAnalyzerClient.DatabaseManager.GetNumMonitorResults(RunId); ;
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count();

            return Json(JsonConvert.SerializeObject(output));
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

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {
            List<CompareResult> results = AttackSurfaceAnalyzerClient.DatabaseManager.GetComparisonResults(BaseId, CompareId, ResultType, Offset, NumResults);

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = AttackSurfaceAnalyzerClient.DatabaseManager.GetComparisonResultsCount(BaseId, CompareId, ResultType);
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;
            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {
            var json_out = AttackSurfaceAnalyzerClient.DatabaseManager.GetCommonResultTypes(BaseId, CompareId);

            return Json(json_out);
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult RunAnalysisWithAnalyses(string SelectedBaseRunId, string SelectedCompareRunId, IFormFile AnalysisFilterFile)
        {
            var filePath = Path.GetTempFileName();

            CompareCommandOptions opts = new CompareCommandOptions(SelectedBaseRunId, SelectedCompareRunId)
            {
                DisableAnalysis = false,
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

            if (AttackSurfaceAnalyzerClient.DatabaseManager.GetComparisonCompleted(opts.FirstRunId, opts.SecondRunId))
            {
                return Json("Using cached comparison calculations.");
            }

            Task.Factory.StartNew(() => {
                var results = AttackSurfaceAnalyzerClient.CompareRuns(opts);
                AttackSurfaceAnalyzerClient.InsertCompareResults(results, opts.FirstRunId, opts.SecondRunId);
            });

            return Json("Started Analysis");
        }

        public ActionResult StartCollection(string Id, bool File, bool Port, bool Service, bool User, bool Registry, bool Certificates, bool Com, bool Firewall, bool Log)
        {
            var opts = new CollectCommandOptions();
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

            opts.DatabaseFilename = AttackSurfaceAnalyzerClient.DatabaseManager.Location;

            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection. We won't start
                // new collections while existing ones are ongoing.
                if (c.RunStatus == RUN_STATUS.RUNNING)
                {
                    return Json(ASA_ERROR.ALREADY_RUNNING);
                }
            }

            if (Id is null)
            {
                return Json(ASA_ERROR.INVALID_ID);
            }

            if (AttackSurfaceAnalyzerClient.DatabaseManager.GetRun(Id) != null)
            {
                return Json(ASA_ERROR.UNIQUE_ID);
            }

            _ = Task.Factory.StartNew(() => AttackSurfaceAnalyzerClient.RunCollectCommand(opts));
            return Json(ASA_ERROR.NONE);
        }

        public ActionResult StartMonitoring(string RunId, string Directory)
        {
            if (RunId != null)
            {
                if (AttackSurfaceAnalyzerClient.DatabaseManager.GetRun(RunId) != null)
                {
                    return Json(ASA_ERROR.UNIQUE_ID);
                }

                var run = new AsaRun(RunId: RunId, Timestamp: DateTime.Now, Version: AsaHelpers.GetVersionString(), Platform: AsaHelpers.GetPlatform(), new List<RESULT_TYPE>() { RESULT_TYPE.FILEMONITOR }, RUN_TYPE.MONITOR);
                AttackSurfaceAnalyzerClient.DatabaseManager.InsertRun(run);

                MonitorCommandOptions opts = new MonitorCommandOptions
                {
                    RunId = RunId,
                    EnableFileSystemMonitor = true,
                    MonitoredDirectories = new string[] { Directory },
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

        private static IEnumerable<DataRunModel> GetMonitorRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerClient.DatabaseManager.GetRuns(RUN_TYPE.MONITOR);

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel(Runs[i], Runs[i]));
            }

            return runModels;
        }

        private static IEnumerable<DataRunModel> GetResultModels()
        {
            List<DataRunModel> DataModels = AttackSurfaceAnalyzerClient.DatabaseManager.GetResultModels(RUN_STATUS.COMPLETED);

            return DataModels;
        }

        private static IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerClient.DatabaseManager.GetRuns(RUN_TYPE.COLLECT);

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel(Runs[i], Runs[i]));
            }

            return runModels;
        }
    }
}