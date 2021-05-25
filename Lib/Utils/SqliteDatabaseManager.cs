// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.OAT.Operations;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public class DBSettings
    {
        public int BatchSize { get; set; } = 100;
        public int FlushCount { get; set; } = -1;
        public string JournalMode { get; set; } = "DELETE";
        public string LockingMode { get; set; } = "NORMAL";
        public bool LowMemoryUsage { get; set; } = false;
        public int PageSize { get; set; } = 4096;
        public int ShardingFactor { get; set; } = 7;
        public string Synchronous { get; set; } = "OFF";
    }

    public class SqliteDatabaseManager : DatabaseManager
    {
        // Max number of elements to keep in Queue if LowMemoryUsage mode is enabled.
        public const int LOW_MEMORY_CUTOFF = 1000;

        public SqliteDatabaseManager(string filename, DBSettings? dbSettingsIn = null)
        {
            dbSettings = (dbSettingsIn == null) ? new DBSettings() : dbSettingsIn;

            if (filename != null)
            {
                if (Location != filename)
                {
                    if (Path.IsPathRooted(filename))
                    {
                        Location = filename;
                    }
                    else
                    {
                        Location = $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}{filename}";
                    }
                }
            }
            else
            {
                Location = $"{Directory.GetCurrentDirectory()}{Path.DirectorySeparatorChar}asa.sqlite";
            }
        }

        public List<SqlConnectionHolder> Connections { get; private set; } = new List<SqlConnectionHolder>();

        public override bool HasElements
        {
            get
            {
                {
                    return Connections.Any(x => x.WriteQueue.Count > 0 || x.IsWriting);
                }
            }
        }

        public SqlConnectionHolder? MainConnection
        {
            get
            {
                if (Connections.Any())
                    return Connections[0];
                return null;
            }
        }

        public override int QueueSize { get { return Connections.Sum(x => x.WriteQueue.Count); } }

        public override void BeginTransaction()
        {
            Connections.AsParallel().ForAll(cxn => cxn.BeginTransaction());
        }

        public override void CloseDatabase()
        {
            RollBack();
            Connections.AsParallel().ForAll(cxn =>
            {
                cxn.ShutDown();
            });
            Connections.RemoveAll(_ => true);
        }

        public override void Commit()
        {
            Connections.AsParallel().ForAll(x => x.Commit());
        }

        public override void DeleteRun(string runid)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using var truncateRunsTable = new SqliteCommand(SQL_TRUNCATE_RUN, MainConnection.Connection, MainConnection.Transaction);
            truncateRunsTable.Parameters.AddWithValue("@run_id", runid);
            truncateRunsTable.ExecuteNonQuery();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var truncateCollectTable = new SqliteCommand(SQL_DELETE_RUN, cxn.Connection, cxn.Transaction);
                truncateCollectTable.Parameters.AddWithValue("@run_id", runid);
                truncateCollectTable.ExecuteNonQuery();
            });
        }

        public override void DeleteCompareRun(string firstRunId, string secondRunId, string analysesHash)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using var deleteCompareRun = new SqliteCommand(SQL_DELETE_COMPARE_RUN, MainConnection.Connection, MainConnection.Transaction);
            deleteCompareRun.Parameters.AddWithValue("@first_run_id", firstRunId);
            deleteCompareRun.Parameters.AddWithValue("@second_run_id", secondRunId);
            deleteCompareRun.Parameters.AddWithValue("@analyses_hash", analysesHash);
            deleteCompareRun.ExecuteNonQuery();

            using var truncateRunsTable = new SqliteCommand(SQL_TRUNCATE_COMPARE_RUN, MainConnection.Connection, MainConnection.Transaction);
            truncateRunsTable.Parameters.AddWithValue("@first_run_id", firstRunId);
            truncateRunsTable.Parameters.AddWithValue("@second_run_id", secondRunId);
            truncateRunsTable.Parameters.AddWithValue("@analyses_hash", analysesHash);

            truncateRunsTable.ExecuteNonQuery();
        }


        public override void Destroy()
        {
            Connections.AsParallel().ForAll(x => x.Destroy());
            Connections.RemoveAll(x => true);
        }

        public bool EstablishMainConnection()
        {
            if (Connections.Count > 0)
            {
                return false;
            }
            else
            {
                Connections.Add(GenerateSqlConnection(0));
                return true;
            }
        }

        public override IEnumerable<WriteObject> GetAllMissing(string? firstRunId, string secondRunId)
        {
            var output = new ConcurrentQueue<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
            {
                if (string.IsNullOrEmpty(firstRunId))
                {
                    var res = GetResultsByRunid(secondRunId);
                    foreach (var result in res)
                    {
                        output.Enqueue(result);
                    }
                }
                else
                {
                    using var cmd = new SqliteCommand(SQL_GET_UNIQUE_BETWEEN_RUNS, cxn.Connection, cxn.Transaction);
                    cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                    cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var runId = reader["run_id"].ToString();
                            var resultTypeString = reader["result_type"].ToString();
                            if (runId != null && resultTypeString != null)
                            {
                                var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                                if (wo is WriteObject WO)
                                    output.Enqueue(WO);
                            }
                        }
                    }
                }
            });

            return output;
        }

        public IEnumerable<WriteObject> GetAllMissing2(string firstRunId, string secondRunId)
        {
            string SQL_GROUPED = "SELECT run_id, result_type, serialized FROM collect WHERE run_id = @first_run_id OR run_id = @second_run_id AND identity in (SELECT identity FROM collect WHERE run_id = @first_run_id OR run_id = @second_run_id GROUP BY identity HAVING COUNT(*) == 1);";
            var output = new ConcurrentQueue<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SqliteCommand(SQL_GROUPED, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (wo is WriteObject WO)
                                output.Enqueue(WO);
                        }
                    }
                }
            });

            return output;
        }

        public IEnumerable<WriteObject> GetAllMissingExplicit(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentQueue<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SqliteCommand(SQL_GET_UNIQUE_BETWEEN_RUNS_EXPLICIT, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (wo is WriteObject WO)
                                output.Enqueue(WO);
                        }
                    }
                }
            });

            return output;
        }

        public override bool GetComparisonCompleted(string? firstRunId, string secondRunId, string analysesHash)
        {
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@base_run_id", firstRunId ?? string.Empty);
                    cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                    cmd.Parameters.AddWithValue("@analyses_hash", analysesHash);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            return true;
                        }
                    }
                }
            }
            else
            {
                Log.Debug("Failed to GetComparisonCompleted because MainConnection is null.");
            }

            return false;
        }

        public override List<CompareResult> GetComparisonResults(string? baseId, string compareId, string analysesHash, RESULT_TYPE exportType)
        {
            List<CompareResult> records = new List<CompareResult>();
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@first_run_id", baseId ?? string.Empty);
                    cmd.Parameters.AddWithValue("@second_run_id", compareId);
                    cmd.Parameters.AddWithValue("@analyses_hash", analysesHash);
                    cmd.Parameters.AddWithValue("@result_type", exportType);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader["serialized"].ToString() is string serialized)
                                records.Add(JsonConvert.DeserializeObject<CompareResult>(serialized));
                        }
                    }
                }
            }
            return records;
        }

        public override List<CompareResult> GetComparisonResults(string? baseId, string? compareId, string analysesHash, RESULT_TYPE resultType, int offset, int numResults)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var results = new List<CompareResult>();
            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS_LIMIT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@first_run_id", baseId ?? string.Empty);
                cmd.Parameters.AddWithValue("@second_run_id", compareId ?? string.Empty);
                cmd.Parameters.AddWithValue("@analyses_hash", analysesHash);
                cmd.Parameters.AddWithValue("@result_type", (int)resultType);
                cmd.Parameters.AddWithValue("@offset", offset);
                cmd.Parameters.AddWithValue("@limit", numResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["meta_serialized"] is string meta_serialized)
                        {
                            CompareResult obj = JsonConvert.DeserializeObject<CompareResult>(meta_serialized);

                            if (reader["first_serialized"] is string first_serialized)
                            {
                                obj.Base = JsonUtils.Hydrate(first_serialized, (RESULT_TYPE)resultType);
                            }
                            if (reader["second_serialized"] is string second_serialized)
                            {
                                obj.Compare = JsonUtils.Hydrate(second_serialized, (RESULT_TYPE)resultType);
                            }

                            results.Add(obj);
                        }
                    }
                }
            }

            return results;
        }

        public override int GetComparisonResultsCount(string? baseId, string compareId, string analysesHash, int resultType)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@first_run_id", baseId ?? string.Empty);
                cmd.Parameters.AddWithValue("@second_run_id", compareId);
                cmd.Parameters.AddWithValue("@analyses_hash", analysesHash);
                cmd.Parameters.AddWithValue("@result_type", resultType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["count(*)"].ToString() is string integer)
                            result_count = int.Parse(integer, CultureInfo.InvariantCulture);
                    }
                }
            }
            return result_count;
        }

        public override DBSettings GetCurrentSettings()
        {
            return dbSettings;
        }

        public override List<string> GetLatestRunIds(int numberOfIds, RUN_TYPE type)
        {
            List<string> output = new List<string>();
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_SELECT_LATEST_N_RUNS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@type", type);
                    cmd.Parameters.AddWithValue("@limit", numberOfIds);
                    try
                    {
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                var str = reader["run_id"].ToString();
                                if (!string.IsNullOrEmpty(str))
                                    output.Add(str);
                            }
                        }
                    }
                    catch (SqliteException)
                    {
                        Log.Debug("Couldn't determine latest {0} run ids.", numberOfIds);
                    }
                }
            }
            else
            {
                Log.Debug("Failed to GetLatestRunIds because MainConnection is null.");
            }
            return output;
        }

        public override IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentQueue<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SqliteCommand(SQL_GET_COLLECT_MISSING_IN_B, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (wo is WriteObject WO)
                                output.Enqueue(WO);
                        }
                    }
                }
            });

            return output;
        }

        public override IEnumerable<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentQueue<(WriteObject, WriteObject)>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SqliteCommand(SQL_GET_COLLECT_MODIFIED, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    var aRunId = reader["a_run_id"].ToString();
                    var bRunId = reader["b_run_id"].ToString();
                    var aResultType = reader["a_result_type"].ToString();
                    var bResultType = reader["b_result_type"].ToString();

                    if (aRunId != null && bRunId != null && aResultType != null && bResultType != null)
                    {
                        if (reader["a_serialized"] is string a_serialized && reader["b_serialized"] is string b_serialized)
                        {
                            var val1 = WriteObject.FromString(a_serialized, (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), aResultType), aRunId);
                            var val2 = WriteObject.FromString(b_serialized, (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), bResultType), bRunId);

                            if (val1 is WriteObject V1 && val2 is WriteObject V2)
                            {
                                output.Enqueue((V1, V2));
                            }
                        }
                    }
                }
            });

            return output;
        }

        public override IEnumerable<FileMonitorObject> GetMonitorResults(string runId, int offset = 0, int numResults = -1)
        {
            var results = new List<FileMonitorObject>();
            if (MainConnection != null)
            {
                if (numResults == -1)
                {
                    using (var cmd = new SqliteCommand(GET_MONITOR_RESULTS_LIMIT, MainConnection.Connection, MainConnection.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", runId);
                        cmd.Parameters.AddWithValue("@offset", offset);
                        cmd.Parameters.AddWithValue("@limit", numResults);
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                if (reader["serialized"] is string serialized)
                                {
                                    var obj = JsonConvert.DeserializeObject<FileMonitorObject>(serialized);
                                    yield return obj;
                                }
                            }
                        }
                    }
                }
                else
                {
                    using (var cmd = new SqliteCommand(GET_MONITOR_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", runId); ;
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                if (reader["serialized"] is string serialized)
                                {
                                    var obj = JsonConvert.DeserializeObject<FileMonitorObject>(serialized);
                                    yield return obj;
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Log.Debug("Failed to GetMonitorResults. MainConnection was null.");
            }
        }

        public override int GetNumMonitorResults(string runId)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            using (var cmd = new SqliteCommand(GET_RESULT_COUNT_MONITORED, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["count(*)"].ToString() is string integer)
                            return int.Parse(integer, CultureInfo.InvariantCulture);
                    }
                }
            }

            return 0;
        }

        public override int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            try
            {
                if (MainConnection != null)
                {
                    using (var cmd = new SqliteCommand(SQL_GET_NUM_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", runId);
                        cmd.Parameters.AddWithValue("@result_type", ResultType.ToString());

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                return int.Parse(reader["the_count"].ToString() ?? "-1", CultureInfo.InvariantCulture);
                            }
                        }
                    }
                }
            }
            catch (SqliteException)
            {
                Log.Error(Strings.Get("Err_Sql"), MethodBase.GetCurrentMethod()?.Name);
            }
            return -1;
        }

        public override List<DataRunModel> GetResultModels(RUN_STATUS runStatus)
        {
            var output = new List<DataRunModel>();

            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_QUERY_ANALYZED, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@status", runStatus);

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            output.Add(new DataRunModel(KeyIn: reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString(), TextIn: reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString()));
                        }
                    }
                }
            }
            else
            {
                Log.Debug("Failed to GetResultModels, MainConnection is null");
            }
            return output;
        }

        public override IEnumerable<WriteObject> GetResultsByRunid(string runid)
        {
            foreach (var cxn in Connections)
            {
                using var cmd = new SqliteCommand(SQL_GET_RESULTS_BY_RUN_ID, cxn.Connection, cxn.Transaction);

                cmd.Parameters.AddWithValue("@run_id", runid);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (wo is WriteObject WO)
                            {
                                yield return WO;
                            }
                        }
                    }
                }
            }
        }

        public override Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var outDict = new Dictionary<RESULT_TYPE, int>() { };
            try
            {
                if (MainConnection != null)
                {
                    using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_COUNTS, MainConnection.Connection, MainConnection.Transaction))
                    {
                        cmd.Parameters.AddWithValue("@run_id", runId);

                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                if (Enum.TryParse(reader["result_type"].ToString(), out RESULT_TYPE result_type))
                                {
                                    outDict.TryAdd(result_type, int.Parse(reader["count"].ToString() ?? "-1", CultureInfo.InvariantCulture));
                                }
                            }
                        }
                    }
                }
            }
            catch (SqliteException)
            {
                Log.Error(Strings.Get("Err_ResultTypesCounts"));
            }
            return outDict;
        }

        public override AsaRun? GetRun(string RunId)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            using (var cmd = new SqliteCommand(SQL_GET_RUN, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["serialized"].ToString() is string serialized)
                            return JsonConvert.DeserializeObject<AsaRun>(serialized);
                    }
                }
            }
            return null;
        }

        public override List<(string firstRunId, string secondRunId, string analysesHash, RUN_STATUS runStatus)> GetCompareRuns()
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            var Runs = new List<(string firstRunId, string secondRunId, string analysesHash, RUN_STATUS runStatus)>();

            using var cmd = new SqliteCommand(SQL_SELECT_COMPARE_RUNS, MainConnection.Connection, MainConnection.Transaction);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add(((string)reader["base_run_id"], (string)reader["compare_run_id"], (string)reader["analyses_hash"], (RUN_STATUS)Enum.Parse(typeof(RUN_STATUS), (string)reader["status"])));
                }
            }
            return Runs;
        }
        public override List<string> GetRuns()
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            List<string> Runs = new List<string>();

            using var cmd = new SqliteCommand(SQL_SELECT_RUNS, MainConnection.Connection, MainConnection.Transaction);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    Runs.Add((string)reader["run_id"]);
                }
            }
            return Runs;
        }

        public override List<string> GetRuns(RUN_TYPE type)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            List<string> Runs = new List<string>();

            using var cmd = new SqliteCommand(SQL_SELECT_RUNS_BY_TYPE, MainConnection.Connection, MainConnection.Transaction);
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

        public override List<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        FileMonitorEvent obj;

                        while (reader.Read())
                        {
                            if (reader["serialized"].ToString() is string serialized)
                            {
                                obj = JsonConvert.DeserializeObject<FileMonitorEvent>(serialized);
                                obj.ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString() ?? "0", CultureInfo.InvariantCulture);
                                records.Add(obj);
                            }
                        }
                    }
                }
            }

            return records;
        }

        public override Settings? GetSettings()
        {
            try
            {
                using var getSettings = new SqliteCommand(SQL_GET_PERSISTED_SETTINGS, MainConnection?.Connection, MainConnection?.Transaction);
                getSettings.Parameters.AddWithValue("@id", "Persisted");
                using var reader = getSettings.ExecuteReader();

                // Settings exist, this isn't the first run
                if (reader.HasRows)
                {
                    while (reader.Read())
                    {
                        if (reader["serialized"].ToString() is string settings)
                        {
                            return JsonConvert.DeserializeObject<Settings>(settings);
                        }
                    }
                }
            }
            catch (Exception e) when (e is SqliteException || e is ArgumentNullException || e is NullReferenceException)
            {
                Log.Debug("Didn't find any settings in the database.");
                //Expected when the table doesn't exist (first run)
            }

            return null;
        }

        public override void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null && MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_INSERT_FINDINGS_RESULT, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@first_run_id", objIn.BaseRunId ?? string.Empty);
                    cmd.Parameters.AddWithValue("@second_run_id", objIn.CompareRunId);
                    cmd.Parameters.AddWithValue("@result_type", objIn.ResultType);
                    cmd.Parameters.AddWithValue("@level", objIn.Analysis);
                    cmd.Parameters.AddWithValue("@identity", objIn.Identity);
                    cmd.Parameters.AddWithValue("@first_serialized", JsonConvert.SerializeObject(objIn.Base));
                    cmd.Parameters.AddWithValue("@second_serialized", JsonConvert.SerializeObject(objIn.Compare));
                    cmd.Parameters.AddWithValue("@analyses_hash", objIn.AnalysesHash);
                    // Remove these because they don't deserialize properly
                    objIn.Base = null;
                    objIn.Compare = null;
                    cmd.Parameters.AddWithValue("@meta_serialized", JsonConvert.SerializeObject(objIn));
                    cmd.ExecuteNonQuery();
                }
            }
            else
            {
                Log.Debug("Failed to InsertAnalyzed because MainConnection was null");
            }
        }

        public override void InsertCompareRun(string? firstRunId, string secondRunId, string analysesHash, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId ?? string.Empty);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@analyses_hash", analysesHash);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public override void InsertRun(AsaRun run)
        {
            if (run == null)
            {
                return;
            }
            if (MainConnection != null)
            {
                using var cmd = new SqliteCommand(SQL_INSERT_RUN, MainConnection.Connection, MainConnection.Transaction);
                cmd.Parameters.AddWithValue("@run_id", run.RunId);
                cmd.Parameters.AddWithValue("@type", run.Type);
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(run));

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (SqliteException e)
                {
                    Log.Warning(e.StackTrace);
                    Log.Warning(e.Message);
                }
            }
            else
            {
                Log.Debug("Failed to InsertRun because MainConnection is null.");
            }
        }

        public int PopulateConnections()
        {
            var connectionsCreated = 0;
            for (int i = Connections.Count; i < dbSettings.ShardingFactor; i++)
            {
                Connections.Add(GenerateSqlConnection(i));
                connectionsCreated++;
            }
            return connectionsCreated;
        }

        public override void RollBack()
        {
            if (Connections != null)
            {
                Connections.AsParallel().ForAll(cxn =>
                {
                    try
                    {
                        cxn.Transaction?.Rollback();
                    }
                    catch (Exception e)
                    {
                        Log.Verbose("Failed to roll back {0} ({1}:{2})", cxn.Source, e.GetType(), e.Message);
                    }
                    cxn.Transaction = null;
                });
            }
        }

        public override PLATFORM RunIdToPlatform(string runid)
        {
            if (MainConnection != null)
            {
                var Run = GetRun(runid);
                if (Run != null)
                {
                    return Run.Platform;
                }
                else
                {
                    Log.Debug("Failed to get RunIdToPlatform. RunId was not found in database.");
                }
            }
            else
            {
                Log.Debug("Failed to get RunIdToPlatform. MainConnection was null.");
            }
            return PLATFORM.UNKNOWN;
        }

        public override void SetSettings(Settings settings)
        {
            if (MainConnection != null && MainConnection.Connection != null)
            {
                try
                {
                    using var cmd = new SqliteCommand(SQL_UPSERT_PERSISTED_SETTINGS, MainConnection?.Connection, MainConnection?.Transaction);
                    cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(settings));
                    cmd.Parameters.AddWithValue("@id", "Persisted");
                    cmd.ExecuteNonQuery();
                }
                catch (SqliteException)
                {
                    Log.Warning("Failed to save settings to database.");
                }
            }
            else
            {
                Log.Warning("Failed to save settings to database.");
            }
        }

        public override ASA_ERROR Setup()
        {
            // Clean up if we were already open.
            CloseDatabase();

            if (!EstablishMainConnection())
            {
                Log.Fatal(Strings.Get("FailedToEstablishMainConnection"), Location);
                return ASA_ERROR.FAILED_TO_ESTABLISH_MAIN_DB_CONNECTION;
            }

            var settingsFromDb = GetSettings();
            if (settingsFromDb != null)
            {
                FirstRun = false;

                if (SCHEMA_VERSION != settingsFromDb.SchemaVersion)
                {
                    Log.Fatal(Strings.Get("WrongSchema"), settingsFromDb.SchemaVersion, SCHEMA_VERSION);
                    return ASA_ERROR.MATCHING_SCHEMA;
                }

                if (settingsFromDb.ShardingFactor != dbSettings.ShardingFactor)
                {
                    Log.Information(Strings.Get("InvalidShardingRequest"), dbSettings.ShardingFactor, settingsFromDb.ShardingFactor);
                }

                dbSettings.ShardingFactor = settingsFromDb.ShardingFactor;
            }
            else
            {
                FirstRun = true;
            }

            PopulateConnections();

            if (MainConnection == null)
            {
                Log.Fatal(Strings.Get("FailedToEstablishMainConnection"), Location);
                return ASA_ERROR.FAILED_TO_ESTABLISH_MAIN_DB_CONNECTION;
            }

            if (FirstRun)
            {
                try
                {
                    BeginTransaction();

                    using var cmd2 = new SqliteCommand(SQL_CREATE_RUNS, MainConnection.Connection, MainConnection.Transaction);
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_RESULTS;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_FINDINGS_RESULTS;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_FINDINGS_LEVEL_INDEX;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_FINDINGS_IDENTITY_INDEX;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX;
                    cmd2.ExecuteNonQuery();

                    cmd2.CommandText = SQL_CREATE_PERSISTED_SETTINGS;
                    cmd2.ExecuteNonQuery();

                    SetSettings(new Settings()
                    {
                        SchemaVersion = SCHEMA_VERSION,
                        ShardingFactor = dbSettings.ShardingFactor,
                    });

                    Connections.AsParallel().ForAll(cxn =>
                    {
                        using (var innerCmd = new SqliteCommand(SQL_CREATE_COLLECT_RESULTS, cxn.Connection, cxn.Transaction))
                        {
                            innerCmd.ExecuteNonQuery();

                            innerCmd.CommandText = SQL_CREATE_COLLECT_RUN_ID_INDEX;
                            innerCmd.ExecuteNonQuery();

                            innerCmd.CommandText = SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX;
                            innerCmd.ExecuteNonQuery();

                            innerCmd.CommandText = SQL_CREATE_COLLECT_RUN_ID_IDENTITY_INDEX;
                            innerCmd.ExecuteNonQuery();
                        }
                    });
                }
                catch (SqliteException e)
                {
                    Log.Debug(e, "Failed to set up fresh database.");
                    return ASA_ERROR.FAILED_TO_CREATE_DATABASE;
                }
                finally
                {
                    Commit();
                }
            }
            return ASA_ERROR.NONE;
        }

        public void StallIfHighMemoryUsageAndLowMemoryModeEnabled()
        {
            if (dbSettings.LowMemoryUsage)
            {
                int stallCount = 0;
                while (QueueSize > LOW_MEMORY_CUTOFF)
                {
                    if (stallCount++ % 1000 == 0)
                    {
                        Log.Verbose("Stalling Collector with {0} results for Memory Usage", QueueSize);
                    }
                    Thread.Sleep(1);
                }
            }
        }

        public override void TrimToLatest()
        {
            if (MainConnection != null)
            {
                using var cmd = new SqliteCommand(GET_RUNS, MainConnection.Connection, MainConnection.Transaction);
                using (var reader = cmd.ExecuteReader())
                {
                    //Skip first row, that is the one we want to keep
                    reader.Read();

                    while (reader.Read())
                    {
                        DeleteRun((string)reader["run_id"]);
                    }
                }
            }
            else
            {
                Log.Debug("Failed to trim. MainConnection is null.");
            }
        }

        public override void UpdateCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SqliteCommand(UPDATE_RUN_IN_RESULT_TABLE, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId ?? string.Empty);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public override void Vacuum()
        {
            Connections.AsParallel().ForAll(cxn =>
            {
                using var inner_cmd = new SqliteCommand(SQL_VACUUM, cxn.Connection, cxn.Transaction);
                inner_cmd.ExecuteNonQuery();
            });
        }

        public override void Write(CollectObject? colObj, string? runId)
        {
            if (colObj != null && runId != null)
            {
                var objIn = new WriteObject(colObj, runId);
                Connections[ModuloString(objIn.Identity, shardingFactor: dbSettings.ShardingFactor)].WriteQueue.Push(objIn);
            }
        }

        private const string GET_COMPARISON_RESULTS = "select * from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and result_type=@result_type order by level desc;";
        private const string GET_COMPARISON_RESULTS_LIMIT = "select * from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and analyses_hash=@analyses_hash and result_type=@result_type order by level desc limit @offset,@limit;";
        private const string GET_MONITOR_RESULTS = "select * from collect where run_id=@run_id order by timestamp;";
        private const string GET_MONITOR_RESULTS_LIMIT = "select * from collect where run_id=@run_id order by timestamp limit @offset,@limit;";

        private const string GET_RESULT_COUNT = "select count(*) from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and analyses_hash=@analyses_hash and result_type=@result_type";

        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;";

        private const string GET_RUNS = "select run_id from runs order by ROWID desc;";
        private const string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";
        private const string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, analyses_hash, status) values (@base_run_id, @compare_run_id, @analyses_hash, @status);";
        private const int SCHEMA_VERSION = 12;
        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id and analyses_hash=@analyses_hash";
        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, identity text, row_key blob, timestamp text, serialized blob, UNIQUE(run_id, identity))";
        private const string SQL_CREATE_COLLECT_RUN_ID_IDENTITY_INDEX = "create index if not exists i_collect_collect_run_id_identity on collect(run_id, identity)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_collect_run_id on collect(run_id)";
        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_collect_runid_row_type on collect(run_id, identity, row_key, result_type)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";
        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";
        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";
        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (first_run_id text, second_run_id text, analyses_hash text, level int, result_type int, identity text, first_serialized text, second_serialized text, meta_serialized text)";
        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (id text, serialized text, unique(id))";
        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, analyses_hash text, status text);";
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, type string, serialized blob, unique(run_id))";
        private const string SQL_DELETE_RUN = "delete from collect where run_id=@run_id";
        private const string SQL_DELETE_COMPARE_RUN = "delete from results where base_run_id=@first_run_id and compare_run_id=@second_run_id and analyses_hash=@analyses_hash";
        private const string SQL_GET_COLLECT_MISSING_IN_B = "SELECT * FROM collect b WHERE b.run_id = @second_run_id AND b.identity NOT IN (SELECT identity FROM collect a WHERE a.run_id = @first_run_id);";

        private const string SQL_GET_COLLECT_MODIFIED = "select a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.run_id as 'a_run_id'," +
                                                            "b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.run_id as 'b_run_id'" +
                                                                " from collect a indexed by i_collect_collect_runid_row_type," +
                                                                    " collect b indexed by i_collect_collect_runid_row_type" +
                                                                        " where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and " +
                                                                            "a.row_key != b.row_key and a.result_type = b.result_type and a.serialized != b.serialized;";

        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PERSISTED_SETTINGS = "select serialized from persisted_settings where id=@id";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";
        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";
        private const string SQL_GET_RUN = "select * from runs where run_id = @run_id";
        private const string SQL_GET_UNIQUE_BETWEEN_RUNS = "SELECT run_id, result_type, serialized, COUNT (*) FROM collect WHERE run_id = @first_run_id or run_id = @second_run_id GROUP BY identity, result_type HAVING COUNT(*) == 1;";
        private const string SQL_GET_UNIQUE_BETWEEN_RUNS_EXPLICIT = "SELECT run_id, result_type, serialized, COUNT (*) FROM collect indexed by i_collect_collect_runid_row_type WHERE run_id = @first_run_id or run_id = @second_run_id GROUP BY identity, result_type HAVING COUNT(*) == 1;";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (first_run_id, second_run_id, analyses_hash, result_type, level, identity, first_serialized, second_serialized, meta_serialized) values (@first_run_id, @second_run_id, @analyses_hash, @result_type, @level, @identity, @first_serialized, @second_serialized, @meta_serialized)";
        private const string SQL_INSERT_RUN = "insert into runs (run_id, type, serialized) values (@run_id, @type, @serialized)";
        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status";
        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by ROWID desc limit 0,@limit;";
        private const string SQL_SELECT_RUNS_BY_TYPE = "select distinct run_id from runs where type=@type order by ROWID asc;";
        private const string SQL_SELECT_RUNS = "select distinct run_id from runs order by ROWID asc;";
        private const string SQL_SELECT_COMPARE_RUNS = "select * from results order by ROWID asc";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private const string SQL_TRUNCATE_COMPARE_RUN = "delete from findings where first_run_id=@first_run_id and second_run_id=@second_run_id and analyses_hash=@analyses_hash";
        private const string SQL_UPSERT_PERSISTED_SETTINGS = "insert or replace into persisted_settings (id, serialized) values (@id, @serialized)";

        private const string SQL_VACUUM = "VACUUM";

        private const string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";

        private DBSettings dbSettings = new DBSettings();

        private SqlConnectionHolder GenerateSqlConnection(int i)
        {
            if (i == 0)
            {
                return new SqlConnectionHolder(Location, dbSettings);
            }
            else
            {
                return new SqlConnectionHolder($"{Location}_{i}", dbSettings);
            }
        }
    }
}