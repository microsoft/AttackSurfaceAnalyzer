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
using AttackSurfaceAnalyzer_Lib.Utils;
using Microsoft.ApplicationInsights.Extensibility;
using System.Runtime.InteropServices;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {

        private List<BaseCollector> collectors = new List<BaseCollector>();
        private List<BaseMonitor> monitors = new List<BaseMonitor>();

        private static readonly string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id";

        private static readonly string SQL_QUERY_ANALYZED = "select * from results where status = @status";

        public HomeController()
        {
            DatabaseManager.Setup();
        }

        public IActionResult Index()
        {
            return View();
        }

        public string ResultTypeToTableName(RESULT_TYPE result_type)
        {
            switch (result_type)
            {
                case RESULT_TYPE.FILE:
                    return "file_system";
                case RESULT_TYPE.PORT:
                    return "network_ports";
                case RESULT_TYPE.REGISTRY:
                    return "registry";
                case RESULT_TYPE.CERTIFICATE:
                    return "certificates";
                case RESULT_TYPE.SERVICES:
                    return "win_system_service";
                case RESULT_TYPE.USER:
                    return "user_account";
                default:
                    return "null";
            }
        }

        public ActionResult WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();
            string GET_SERIALIZED_RESULTS = "select change_type,serialized from file_system_monitored where run_id = @run_id";


            var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction);
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
            return Json(true);
        }

        public ActionResult CheckAdmin()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Elevation e = new Elevation();
                if (e.IsRunAsAdmin())
                {
                    return Json(true);
                }
            }
            else if ((RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) && Elevation.IsRunningAsRoot())
            {
                return Json(true);
            }
            return Json(false);
        }

        public ActionResult WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            List<CompareResult> records = new List<CompareResult>();
            string GET_COMPARISON_RESULTS = "select * from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type order by base_row_key;";
            string GET_SERIALIZED_RESULTS = "select serialized from @table_name where row_key = @row_key and run_id = @run_id";

            List<RESULT_TYPE> ToExport = new List<RESULT_TYPE> { (RESULT_TYPE)ResultType };

            if (ExportAll)
            {
                ToExport = new List<RESULT_TYPE> { RESULT_TYPE.FILE, RESULT_TYPE.CERTIFICATE, RESULT_TYPE.PORT, RESULT_TYPE.REGISTRY, RESULT_TYPE.SERVICES, RESULT_TYPE.USER };
            }

            foreach (RESULT_TYPE ExportType in ToExport)
            {
                records.Clear();
                var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@base_run_id", BaseId);
                cmd.Parameters.AddWithValue("@compare_run_id", CompareId);
                cmd.Parameters.AddWithValue("@data_type", ExportType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new CompareResult();

                        string CompareString = "";
                        string BaseString = "";
                        CHANGE_TYPE ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString());

                        if (ChangeType == CHANGE_TYPE.CREATED || ChangeType == CHANGE_TYPE.MODIFIED)
                        {
                            var inner_cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction);
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
                            var inner_cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction);
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

                        switch (ResultType)
                        {
                            case (int)RESULT_TYPE.CERTIFICATE:
                                obj = new CertificateResult()
                                {
                                    Base = JsonConvert.DeserializeObject<CertificateObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<CertificateObject>(CompareString)
                                };
                                break;
                            case (int)RESULT_TYPE.FILE:
                                obj = new FileSystemResult()
                                {
                                    Base = JsonConvert.DeserializeObject<FileSystemObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<FileSystemObject>(CompareString)
                                };
                                break;
                            case (int)RESULT_TYPE.PORT:
                                obj = new OpenPortResult()
                                {
                                    Base = JsonConvert.DeserializeObject<OpenPortObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<OpenPortObject>(CompareString)
                                };
                                break;
                            case (int)RESULT_TYPE.USER:
                                obj = new UserAccountResult()
                                {
                                    Base = JsonConvert.DeserializeObject<UserAccountObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<UserAccountObject>(CompareString)
                                };
                                break;
                            case (int)RESULT_TYPE.SERVICES:
                                obj = new ServiceResult()
                                {
                                    Base = JsonConvert.DeserializeObject<ServiceObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<ServiceObject>(CompareString)
                                };
                                break;
                            case (int)RESULT_TYPE.REGISTRY:
                                obj = new RegistryResult()
                                {
                                    Base = JsonConvert.DeserializeObject<RegistryObject>(BaseString),
                                    Compare = JsonConvert.DeserializeObject<RegistryObject>(CompareString)
                                };
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

                if ( records.Count > 0)
                {

                    JsonSerializer serializer = new JsonSerializer {
                        Formatting = Formatting.Indented,
                        NullValueHandling = NullValueHandling.Ignore
                    };

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

            return Json(true);
        }

        public ActionResult GetMonitorResults(string RunId, int ResultType, int Offset, int NumResults)
        {

            var results = new List<OutputFileMonitorResult>();

            string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;";
            string GET_RESULT_COUNT = "select count(*) from file_system_monitored where run_id=@run_id;";


            var cmd = new SqliteCommand(GET_MONITOR_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction);
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

            Dictionary<string, object> output = new Dictionary<string, object>();
            var result_count = 0;
            cmd = new SqliteCommand(GET_RESULT_COUNT, DatabaseManager.Connection, DatabaseManager.Transaction);
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
            string outputting = JsonConvert.SerializeObject(output);

            return Json(outputting);
        }

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {

            var results = new List<OutputCompareResult>();

            string GET_COMPARISON_RESULTS = "select * from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type order by base_row_key limit @offset,@limit;";
            string GET_SERIALIZED_RESULTS = "select serialized from @table_name where row_key = @row_key and run_id = @run_id";
            string GET_RESULT_COUNT = "select count(*) from compared where base_run_id=@base_run_id and compare_run_id=@compare_run_id and data_type=@data_type";


            var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction);
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

            foreach (var obj in results)
            {
                if (obj.ChangeType == CHANGE_TYPE.CREATED || obj.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction);
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
                if (obj.ChangeType == CHANGE_TYPE.DELETED || obj.ChangeType == CHANGE_TYPE.MODIFIED)
                {
                    cmd = new SqliteCommand(GET_SERIALIZED_RESULTS.Replace("@table_name", ResultTypeToTableName(obj.ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction);
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
            Dictionary<string, object> output = new Dictionary<string, object>();
            var result_count = 0;
            cmd = new SqliteCommand(GET_RESULT_COUNT, DatabaseManager.Connection, DatabaseManager.Transaction);
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
            string outputting = JsonConvert.SerializeObject(output);

            return Json(outputting);
        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {
            var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", BaseId.ToString());
            cmd.Parameters.AddWithValue("@compare_run_id", CompareId.ToString());

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

            var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", Id);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return Json(ERRORS.UNIQUE_ID);
                }
            }

            Task<int> task = Task.Factory.StartNew<int>(() => AttackSurfaceAnalyzerCLI.RunCollectCommand(opts));
            return Json(ERRORS.NONE);
        }

        public IActionResult Collect()
        {
            return View();
        }

        public ActionResult ChangeTelemetryState(bool DisableTelemetry)
        {
            TelemetryConfiguration.Active.DisableTelemetry = DisableTelemetry;

            string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)";
            var cmd = new SqliteCommand(UPDATE_TELEMETRY, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@TelemetryOptOut", DisableTelemetry.ToString());
            cmd.ExecuteNonQuery();
            DatabaseManager.Commit();

            return Json(true);
        }

        public ActionResult StartMonitoring(string RunId, string Directory, string Extension)
        {
            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type)";

            var cmd = new SqliteCommand(INSERT_RUN, DatabaseManager.Connection, DatabaseManager.Transaction);
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

            string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id";

            var cmd = new SqliteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", opts.FirstRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", opts.SecondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    return Json("Using cached comparison calculations.");
                }
            }

            Task<Dictionary<string, object>> task = Task.Factory.StartNew<Dictionary<string, object>>(() => AttackSurfaceAnalyzerCLI.CompareRuns(opts));
           
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
            string Select_Runs = "select distinct run_id from runs where type=@type;";

            List<string> Runs = new List<string>();

            var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@type", "monitor");
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add((string)reader["run_id"]);
                }
            }

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count(); i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetRunModels()
        {
            string Select_Runs = "select distinct run_id from runs where type=@type;";

            List<string> Runs = new List<string>();

            var cmd = new SqliteCommand(Select_Runs, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@type", "collect");
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add((string)reader["run_id"]);
                }
            }

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

            var cmd = new SqliteCommand(SQL_QUERY_ANALYZED, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@status", RUN_STATUS.COMPLETED);

            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    output.Add(new DataRunModel { Key = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString(), Text = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString() });
                }
            }
            
            return output;
        }
    }
}