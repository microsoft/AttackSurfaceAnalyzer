// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
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

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        // Max number of elements to keep in Queue if LowMemoryUsage mode is enabled.
        public const int LOW_MEMORY_CUTOFF = 1000;

        public static List<SqlConnectionHolder> Connections { get; private set; } = new List<SqlConnectionHolder>();
        public static bool FirstRun { get; private set; } = true;

        public static bool HasElements
        {
            get
            {
                {
                    return Connections.Any(x => x.WriteQueue.Count > 0 || x.IsWriting);
                }
            }
        }

        public static SqlConnectionHolder? MainConnection
        {
            get
            {
                if (Connections.Any())
                    return Connections[0];
                return null;
            }
        }

        public static int QueueSize { get { return Connections.Sum(x => x.WriteQueue.Count); } }
        public static string SqliteFilename { get; private set; } = "asa.Sqlite";

        public static void BeginTransaction()
        {
            Connections.AsParallel().ForAll(cxn => cxn.BeginTransaction());
        }

        public static void CloseDatabase()
        {
            RollBack();
            Connections.AsParallel().ForAll(cxn =>
            {
                cxn.ShutDown();
            });
            Connections.RemoveAll(_ => true);
        }

        public static void Commit()
        {
            Connections.AsParallel().ForAll(x => x.Commit());
        }

        public static void DeleteRun(string runid)
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

        public static void Destroy()
        {
            Connections.AsParallel().ForAll(x => x.Destroy());
            Connections.RemoveAll(x => true);
        }

        public static void Destroy(string sqliteFilename)
        {
            var directory = Path.GetDirectoryName(sqliteFilename);
            if (string.IsNullOrEmpty(directory))
            {
                directory = ".";
            }
            var toDelete = Directory.EnumerateFiles(directory, sqliteFilename);
            foreach (var file in toDelete)
            {
                File.Delete(file);
            }
        }

        public static bool EstablishMainConnection()
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

        public static IEnumerable<WriteObject> GetAllMissing(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentQueue<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
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
            });

            return output;
        }

        public static IEnumerable<WriteObject> GetAllMissing2(string firstRunId, string secondRunId)
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

        public static IEnumerable<WriteObject> GetAllMissingExplicit(string firstRunId, string secondRunId)
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

        public static List<RESULT_TYPE> GetCommonResultTypes(string baseId, string compareId)
        {
            var runOne = GetRun(baseId);
            var runTwo = GetRun(compareId);

            return runOne?.ResultTypes.Intersect(runTwo?.ResultTypes).ToList() ?? new List<RESULT_TYPE>();
        }

        public static bool GetComparisonCompleted(string? firstRunId, string secondRunId)
        {
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                    cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
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

        public static List<CompareResult> GetComparisonResults(string baseId, string compareId, RESULT_TYPE exportType)
        {
            List<CompareResult> records = new List<CompareResult>();
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@first_run_id", baseId);
                    cmd.Parameters.AddWithValue("@second_run_id", compareId);
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

        public static List<CompareResult> GetComparisonResults(string baseId, string compareId, int resultType, int offset, int numResults)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var results = new List<CompareResult>();
            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS_LIMIT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@first_run_id", baseId);
                cmd.Parameters.AddWithValue("@second_run_id", compareId);
                cmd.Parameters.AddWithValue("@result_type", resultType);
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
                                obj.Base = Deserialize(resultType, first_serialized);
                            }
                            if (reader["second_serialized"] is string second_serialized)
                            {
                                obj.Compare = Deserialize(resultType, second_serialized);
                            }

                            results.Add(obj);
                        }
                    }
                }
            }

            return results;
        }

        public static int GetComparisonResultsCount(string baseId, string compareId, int resultType)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@first_run_id", baseId);
                cmd.Parameters.AddWithValue("@second_run_id", compareId);
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

        public static DBSettings GetCurrentSettings()
        {
            return dbSettings;
        }

        public static List<string> GetLatestRunIds(int numberOfIds, RUN_TYPE type)
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

        public static IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId)
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

        public static IEnumerable<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId)
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
                        var val1 = WriteObject.FromString((string)reader["a_serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), aResultType), aRunId);
                        var val2 = WriteObject.FromString((string)reader["b_serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), bResultType), bRunId);

                        if (val1 is WriteObject V1 && val2 is WriteObject V2)
                        {
                            output.Enqueue((V1, V2));
                        }
                    }
                }
            });

            return output;
        }

        public static List<FileMonitorObject> GetMonitorResults(string runId, int offset, int numResults)
        {
            var results = new List<FileMonitorObject>();
            if (MainConnection != null)
            {
                using (var cmd = new SqliteCommand(GET_MONITOR_RESULTS, MainConnection.Connection, MainConnection.Transaction))
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
                                results.Add(obj);
                            }
                        }
                    }
                }
            }
            else
            {
                Log.Debug("Failed to GetMonitorResults. MainConnection was null.");
            }

            return results;
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns(RUN_TYPE.MONITOR);
        }

        public static int GetNumMonitorResults(string runId)
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

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
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

        public static List<DataRunModel> GetResultModels(RUN_STATUS runStatus)
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

        public static IEnumerable<WriteObject> GetResultsByRunid(string runid)
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

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
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

        public static AsaRun? GetRun(string RunId)
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

        public static List<string> GetRuns(RUN_TYPE type)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            List<string> Runs = new List<string>();

            using var cmd = new SqliteCommand(SQL_SELECT_RUNS, MainConnection.Connection, MainConnection.Transaction);
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

        public static List<string> GetRuns()
        {
            return GetRuns(RUN_TYPE.COLLECT);
        }

        public static List<FileMonitorEvent> GetSerializedMonitorResults(string runId)
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

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null && MainConnection != null)
            {
                using (var cmd = new SqliteCommand(SQL_INSERT_FINDINGS_RESULT, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@first_run_id", objIn.BaseRunId);
                    cmd.Parameters.AddWithValue("@second_run_id", objIn.CompareRunId);
                    cmd.Parameters.AddWithValue("@result_type", objIn.ResultType);
                    cmd.Parameters.AddWithValue("@level", objIn.Analysis);
                    cmd.Parameters.AddWithValue("@identity", objIn.Identity);
                    cmd.Parameters.AddWithValue("@first_serialized", JsonConvert.SerializeObject(objIn.Base));
                    cmd.Parameters.AddWithValue("@second_serialized", JsonConvert.SerializeObject(objIn.Compare));
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

        public static void InsertCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static void InsertRun(AsaRun run)
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

        public static int ModuloString(string identity, int shardingFactor) => identity.Sum(x => x) % shardingFactor;

        public static int PopulateConnections()
        {
            var connectionsCreated = 0;
            for (int i = Connections.Count; i < dbSettings.ShardingFactor; i++)
            {
                Connections.Add(GenerateSqlConnection(i));
                connectionsCreated++;
            }
            return connectionsCreated;
        }

        public static void RollBack()
        {
            if (Connections != null)
            {
                Connections.AsParallel().ForAll(cxn =>
                {
                    cxn.Transaction?.Rollback();
                    cxn.Transaction = null;
                });
            }
        }

        public static PLATFORM RunIdToPlatform(string runid)
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

        public static ASA_ERROR Setup(string filename, DBSettings? dbSettingsIn = null)
        {
            // Clean up if we were already open.
            CloseDatabase();

            dbSettings = (dbSettingsIn == null) ? new DBSettings() : dbSettingsIn;

            if (filename != null)
            {
                if (SqliteFilename != filename)
                {
                    SqliteFilename = filename;
                }
            }

            if (!EstablishMainConnection())
            {
                Log.Fatal(Strings.Get("FailedToEstablishMainConnection"), SqliteFilename);
                return ASA_ERROR.FAILED_TO_ESTABLISH_MAIN_DB_CONNECTION;
            }

            var settingsFromDb = GetSettings();
            if (settingsFromDb != null)
            {
                dbSettings.ShardingFactor = settingsFromDb.ShardingFactor;

                FirstRun = false;

                if (SCHEMA_VERSION != settingsFromDb.SchemaVersion)
                {
                    Log.Fatal(Strings.Get("WrongSchema"), settingsFromDb.SchemaVersion, SCHEMA_VERSION);
                    return ASA_ERROR.MATCHING_SCHEMA;
                }

                if (dbSettingsIn != null && settingsFromDb.ShardingFactor != dbSettingsIn.ShardingFactor)
                {
                    Log.Information(Strings.Get("InvalidShardingRequest"), dbSettingsIn.ShardingFactor, dbSettings.ShardingFactor);
                }
            }
            else
            {
                FirstRun = true;
            }

            PopulateConnections();

            if (MainConnection == null)
            {
                Log.Fatal(Strings.Get("FailedToEstablishMainConnection"), SqliteFilename);
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

                    cmd2.CommandText = SQL_CREATE_FILE_MONITORED;
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

        public static void StallIfHighMemoryUsageAndLowMemoryModeEnabled()
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

        public static void TrimToLatest()
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

        public static void UpdateCompareRun(string? firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SqliteCommand(UPDATE_RUN_IN_RESULT_TABLE, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static void Vacuum()
        {
            Connections.AsParallel().ForAll(cxn =>
            {
                using var inner_cmd = new SqliteCommand(SQL_VACUUM, cxn.Connection, cxn.Transaction);
                inner_cmd.ExecuteNonQuery();
            });
        }

        /// <summary>
        ///     Used for testing.
        /// </summary>
        public static void WaitUntilFlushed()
        {
            while (HasElements)
            {
                Thread.Sleep(1);
            }
        }

        public static void Write(CollectObject? colObj, string? runId)
        {
            if (colObj != null && runId != null)
            {
                var objIn = new WriteObject(colObj, runId);
                Connections[ModuloString(objIn.Identity, shardingFactor: dbSettings.ShardingFactor)].WriteQueue.Push(objIn);
            }
        }

        public static void WriteFileMonitor(FileMonitorObject fmo, string RunId)
        {
            if (fmo == null)
            {
                return;
            }
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using var cmd = new SqliteCommand(SQL_INSERT, MainConnection.Connection, MainConnection.Transaction);
            cmd.Parameters.AddWithValue("@run_id", RunId);
            cmd.Parameters.AddWithValue("@path", fmo.Path);
            cmd.Parameters.AddWithValue("@timestamp", fmo.Timestamp);
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(fmo));

            cmd.ExecuteNonQuery();
        }

        private const string GET_COMPARISON_RESULTS = "select * from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and result_type=@result_type order by level desc;";
        private const string GET_COMPARISON_RESULTS_LIMIT = "select * from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and result_type=@result_type order by level desc limit @offset,@limit;";
        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;";

        //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT = "select count(*) from findings where first_run_id = @first_run_id and second_run_id = @second_run_id and result_type=@result_type";

        //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;";

        private const string GET_RUNS = "select run_id from runs order by ROWID desc;";
        private const string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";
        private const string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private const int SCHEMA_VERSION = 10;
        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id";
        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, identity text, row_key blob, serialized blob, UNIQUE(run_id, identity))";
        private const string SQL_CREATE_COLLECT_RUN_ID_IDENTITY_INDEX = "create index if not exists i_collect_collect_run_id_identity on collect(run_id, identity)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_collect_run_id on collect(run_id)";
        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_collect_runid_row_type on collect(run_id, identity, row_key, result_type)";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, path text, timestamp text, serialized text)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";
        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";
        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";
        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (first_run_id text, second_run_id text, level int, result_type int, identity text, first_serialized text, second_serialized text, meta_serialized text)";
        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (id text, serialized text, unique(id))";
        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, status text);";
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, type string, serialized blob, unique(run_id))";
        private const string SQL_DELETE_RUN = "delete from collect where run_id=@run_id";
        private const string SQL_GET_COLLECT_MISSING_IN_B = "SELECT * FROM collect b WHERE b.run_id = @second_run_id AND b.identity NOT IN (SELECT identity FROM collect a WHERE a.run_id = @first_run_id);";

        private const string SQL_GET_COLLECT_MODIFIED = "select a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.run_id as 'a_run_id'," +
                                                            "b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.run_id as 'b_run_id'" +
                                                                " from collect a indexed by i_collect_collect_runid_row_type," +
                                                                    " collect b indexed by i_collect_collect_runid_row_type" +
                                                                        " where a.run_id=@first_run_id and b.run_id=@second_run_id and a.result_type = b.result_type and " +
                                                                            "a.identity = b.identity and a.row_key != b.row_key and a.serialized != b.serialized;";

        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PERSISTED_SETTINGS = "select serialized from persisted_settings where id=@id";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";
        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";
        private const string SQL_GET_RUN = "select * from runs where run_id = @run_id";
        private const string SQL_GET_UNIQUE_BETWEEN_RUNS = "SELECT run_id, result_type, serialized, COUNT (*) FROM collect WHERE run_id = @first_run_id or run_id = @second_run_id GROUP BY identity, result_type HAVING COUNT(*) == 1;";
        private const string SQL_GET_UNIQUE_BETWEEN_RUNS_EXPLICIT = "SELECT run_id, result_type, serialized, COUNT (*) FROM collect indexed by i_collect_collect_runid_row_type WHERE run_id = @first_run_id or run_id = @second_run_id GROUP BY identity, result_type HAVING COUNT(*) == 1;";
        private const string SQL_INSERT = "insert into file_system_monitored (run_id, path, timestamp, serialized) values (@run_id, @path, @timestamp, @serialized)";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (first_run_id, second_run_id, result_type, level, identity, first_serialized, second_serialized, meta_serialized) values (@first_run_id, @second_run_id, @result_type, @level, @identity, @first_serialized, @second_serialized, @meta_serialized)";
        private const string SQL_INSERT_RUN = "insert into runs (run_id, type, serialized) values (@run_id, @type, @serialized)";
        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status";
        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by ROWID desc limit 0,@limit;";
        private const string SQL_SELECT_RUNS = "select distinct run_id from runs where type=@type order by ROWID asc;";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private const string SQL_UPSERT_PERSISTED_SETTINGS = "insert or replace into persisted_settings (id, serialized) values (@id, @serialized)";

        //lgtm [cs/literal-as-local]
        private const string SQL_VACUUM = "VACUUM";

        private const string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";
        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]
        private static DBSettings dbSettings = new DBSettings();

        private static CollectObject? Deserialize(int resultType, string serialized)
        {
            switch ((RESULT_TYPE)resultType)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(serialized);

                case RESULT_TYPE.COM:
                    return JsonConvert.DeserializeObject<ComObject>(serialized);

                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(serialized);

                case RESULT_TYPE.FIREWALL:
                    return JsonConvert.DeserializeObject<FirewallObject>(serialized);

                case RESULT_TYPE.GROUP:
                    return JsonConvert.DeserializeObject<GroupAccountObject>(serialized);

                case RESULT_TYPE.LOG:
                    return JsonConvert.DeserializeObject<EventLogObject>(serialized);

                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(serialized);

                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(serialized);

                case RESULT_TYPE.SERVICE:
                    return JsonConvert.DeserializeObject<ServiceObject>(serialized);

                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(serialized);

                default:
                    return null;
            }
        }

        private static SqlConnectionHolder GenerateSqlConnection(int i)
        {
            if (i == 0)
            {
                return new SqlConnectionHolder(SqliteFilename, dbSettings);
            }
            else
            {
                return new SqlConnectionHolder($"{SqliteFilename}_{i}", dbSettings);
            }
        }

        private static Settings? GetSettings()
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

        private static void SetSettings(Settings settings)
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
    }

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
}