// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.Linq;
using System.Reflection;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class SystemSQLiteDatabaseManager
    {
        public static List<SystemSQLiteSqlConnectionHolder> Connections { get; private set; } = new List<SystemSQLiteSqlConnectionHolder>();
        public static bool FirstRun { get; private set; } = true;

        public static SystemSQLiteSqlConnectionHolder? MainConnection
        {
            get
            {
                if (Connections.Any())
                    return Connections[0];
                return null;
            }
        }

        public static string SQLiteFilename { get; private set; } = "asa.SQLite";

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
            using var truncateRunsTable = new SQLiteCommand(SQL_TRUNCATE_RUN, MainConnection.Connection, MainConnection.Transaction);
            truncateRunsTable.Parameters.AddWithValue("@run_id", runid);
            truncateRunsTable.ExecuteNonQuery();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var truncateCollectTable = new SQLiteCommand(SQL_DELETE_RUN, cxn.Connection, cxn.Transaction);
                truncateCollectTable.Parameters.AddWithValue("@run_id", runid);
                truncateCollectTable.ExecuteNonQuery();
            });
        }

        public static void Destroy()
        {
            Connections.AsParallel().ForAll(x => x.Destroy());
            Connections.RemoveAll(x => true);
        }

        public static List<RESULT_TYPE> GetCommonResultTypes(string baseId, string compareId)
        {
            var runOne = GetRun(baseId);
            var runTwo = GetRun(compareId);

            return runOne?.ResultTypes.Intersect(runTwo?.ResultTypes ?? new List<RESULT_TYPE>()).ToList() ?? runTwo?.ResultTypes ?? new List<RESULT_TYPE>();
        }

        public static bool GetComparisonCompleted(string firstRunId, string secondRunId)
        {
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, MainConnection.Connection, MainConnection.Transaction))
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

        public static List<CompareResult> GetComparisonResults(string compareId, RESULT_TYPE exportType)
        {
            List<CompareResult> records = new List<CompareResult>();
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(GET_COMPARISON_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@comparison_id", compareId);
                    cmd.Parameters.AddWithValue("@result_type", exportType);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            if (reader["serialized"].ToString() is string serialized)
                            {
                                try
                                {
                                    records.Add(JsonConvert.DeserializeObject<CompareResult>(serialized));
                                }
                                catch (Exception e)
                                {
                                    Log.Debug(e, "Couldn't deserialized into a CompareResult {0}", serialized);
                                }
                            }
                        }
                    }
                }
            }
            return records;
        }

        public static List<CompareResult> GetComparisonResults(string comparisonId, int resultType, int offset, int numResults)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var results = new List<CompareResult>();
            using (var cmd = new SQLiteCommand(GET_COMPARISON_RESULTS_LIMIT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", comparisonId);
                cmd.Parameters.AddWithValue("@result_type", resultType);
                cmd.Parameters.AddWithValue("@offset", offset);
                cmd.Parameters.AddWithValue("@limit", numResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        try
                        {
                            var thing = reader["serialized"];
                            if (thing is string result)
                            {
                                var obj = JsonConvert.DeserializeObject<CompareResult>(result);
                                results.Add(obj);
                            }
                        }
                        catch (Exception e)
                        {
                            Log.Debug(e, "Error deserializing {0}", reader["serialized"]);
                        }
                    }
                }
            }

            return results;
        }

        public static int GetComparisonResultsCount(string comparisonId, int resultType)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            var result_count = 0;
            using (var cmd = new SQLiteCommand(GET_RESULT_COUNT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", comparisonId);
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

        public static List<string> GetLatestRunIds(int numberOfIds, string type)
        {
            List<string> output = new List<string>();
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(SQL_SELECT_LATEST_N_RUNS, MainConnection.Connection, MainConnection.Transaction))
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
                    catch (SQLiteException)
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

        public static ConcurrentBag<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentBag<WriteObject>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SQLiteCommand(SQL_GET_COLLECT_MISSING_IN_B, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var wo = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (wo is WriteObject WO)
                            {
                                output.Add(WO);
                            }
                        }
                    }
            });

            return output;
        }

        public static ConcurrentBag<(WriteObject, WriteObject)> GetModified(string firstRunId, string secondRunId)
        {
            var output = new ConcurrentBag<(WriteObject, WriteObject)>();

            Connections.AsParallel().ForAll(cxn =>
            {
                using var cmd = new SQLiteCommand(SQL_GET_COLLECT_MODIFIED, cxn.Connection, cxn.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
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
                                output.Add((V1, V2));
                            }
                        }
                    }
                }
            });

            return output;
        }

        public static List<OutputFileMonitorResult> GetMonitorResults(string runId, int offset, int numResults)
        {
            var results = new List<OutputFileMonitorResult>();
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(GET_MONITOR_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);
                    cmd.Parameters.AddWithValue("@offset", offset);
                    cmd.Parameters.AddWithValue("@limit", numResults);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var path = reader["path"].ToString();
                            if (!string.IsNullOrEmpty(path))
                            {
                                var obj = new OutputFileMonitorResult(path)
                                {
                                    RowKey = reader["row_key"].ToString(),
                                    Timestamp = reader["timestamp"].ToString(),
                                    OldPath = reader["old_path"].ToString(),
                                    Name = reader["path"].ToString(),
                                    OldName = reader["old_path"].ToString(),
                                    ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString() ?? "Invalid", CultureInfo.InvariantCulture),
                                };
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
            return GetRuns("monitor");
        }

        public static int GetNumMonitorResults(string runId)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            using (var cmd = new SQLiteCommand(GET_RESULT_COUNT_MONITORED, MainConnection.Connection, MainConnection.Transaction))
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
                    using (var cmd = new SQLiteCommand(SQL_GET_NUM_RESULTS, MainConnection.Connection, MainConnection.Transaction))
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
            catch (SQLiteException)
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
                using (var cmd = new SQLiteCommand(SQL_QUERY_ANALYZED, MainConnection.Connection, MainConnection.Transaction))
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
                using var cmd = new SQLiteCommand(SQL_GET_RESULTS_BY_RUN_ID, cxn.Connection, cxn.Transaction);

                cmd.Parameters.AddWithValue("@run_id", runid);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var runId = reader["run_id"].ToString();
                        var resultTypeString = reader["result_type"].ToString();
                        if (runId != null && resultTypeString != null)
                        {
                            var val = WriteObject.FromString((string)reader["serialized"], (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), resultTypeString), runId);
                            if (val is WriteObject valid)
                                yield return valid;
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
                    using (var cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES_COUNTS, MainConnection.Connection, MainConnection.Transaction))
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
            catch (SQLiteException)
            {
                Log.Error(Strings.Get("Err_ResultTypesCounts"));
            }
            return outDict;
        }

        public static AsaRun? GetRun(string RunId)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            using (var cmd = new SQLiteCommand(SQL_GET_RUN, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (reader["serialized"]?.ToString() is string serialized)
                        {
                            return JsonConvert.DeserializeObject<AsaRun>(serialized);
                        }
                    }
                }
            }
            return null;
        }

        public static List<string> GetRuns(string type)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));

            string Select_Runs = "select distinct run_id from runs where type=@type order by timestamp asc;";

            List<string> Runs = new List<string>();

            using var cmd = new SQLiteCommand(Select_Runs, MainConnection.Connection, MainConnection.Transaction);
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
            return GetRuns("collect");
        }

        public static List<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(GET_SERIALIZED_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        FileMonitorEvent obj;

                        while (reader.Read())
                        {
                            if (reader["serialized"].ToString() is string serialized)
                            {
                                try
                                {
                                    obj = JsonConvert.DeserializeObject<FileMonitorEvent>(serialized);
                                    obj.ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString() ?? "0", CultureInfo.InvariantCulture);
                                    records.Add(obj);
                                }
                                catch (Exception e)
                                {
                                    Log.Debug(e, "Couldn't deserialized into a CompareResult {0}", serialized);
                                }
                            }
                        }
                    }
                }
            }

            return records;
        }

        public static bool HasElements()
        {
            return Connections.Any(x => !x.WriteQueue.IsEmpty);
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null && MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(SQL_INSERT_FINDINGS_RESULT, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@first_run_id", objIn.BaseRunId);
                    cmd.Parameters.AddWithValue("@second_run_id", objIn.CompareRunId);
                    cmd.Parameters.AddWithValue("@result_type", objIn.ResultType);
                    cmd.Parameters.AddWithValue("@level", objIn.Analysis);
                    cmd.Parameters.AddWithValue("@identity", objIn.Identity);
                    cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(objIn));
                    cmd.ExecuteNonQuery();
                }
            }
            else
            {
                Log.Debug("Failed to InsertAnalyzed because MainConnection was null");
            }
        }

        public static void InsertCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SQLiteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, MainConnection.Connection, MainConnection.Transaction))
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
                using var cmd = new SQLiteCommand(SQL_INSERT_RUN, MainConnection.Connection, MainConnection.Transaction);
                cmd.Parameters.AddWithValue("@run_id", run.RunId);
                cmd.Parameters.AddWithValue("@type", run.Type);
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(run));

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (SQLiteException e)
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
                    try
                    {
                        cxn.Transaction?.Rollback();
                    }
                    catch (NullReferenceException)
                    { }
                    finally
                    {
                        cxn.Transaction = null;
                    }
                });
            }
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            if (MainConnection != null)
            {
                using (var cmd = new SQLiteCommand(SQL_GET_PLATFORM_FROM_RUNID, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runid);
                    using (var reader = cmd.ExecuteReader())
                    {
                        reader.Read();
                        var platform = reader["platform"].ToString();
                        if (platform != null)
                        {
                            return (PLATFORM)Enum.Parse(typeof(PLATFORM), platform);
                        }
                    }
                }
            }
            else
            {
                Log.Debug("Failed to get RunIdToPlatform. MainConnection was null.");
            }
            return PLATFORM.UNKNOWN;
        }

        public static bool Setup(string filename, DBSettings? dbSettingsIn = null)
        {
            dbSettings = (dbSettingsIn == null) ? new DBSettings() : dbSettingsIn;

            if (filename != null)
            {
                if (SQLiteFilename != filename)
                {
                    SQLiteFilename = filename;
                }
            }

            if (Connections.Count > 0)
            {
                CloseDatabase();
            }

            if (Connections == null || Connections.Count == 0)
            {
                Connections = new List<SystemSQLiteSqlConnectionHolder>();

                PopulateConnections();

                var settings = GetSettings();
                if (settings != null)
                {
                    FirstRun = false;

                    if (SCHEMA_VERSION != settings.SchemaVersion)
                    {
                        Log.Fatal("Database has schema version {settings.SchemaVersion} but database has schema version {SCHEMA_VERSION}.");
                        Environment.Exit((int)ASA_ERROR.MATCHING_SCHEMA);
                    }

                    if (dbSettingsIn != null && settings.ShardingFactor != dbSettingsIn.ShardingFactor)
                    {
                        Log.Information($"Requested sharding level of {dbSettingsIn.ShardingFactor} but database was created with {settings.ShardingFactor}. Ignoring request and using {settings.ShardingFactor}.");
                    }

                    dbSettings.ShardingFactor = settings.ShardingFactor;
                }
                else
                {
                    FirstRun = true;
                }

                PopulateConnections();

                if (MainConnection == null)
                {
                    Log.Warning("Failed to set up Main Database connection. Cannot set up database.");
                    return false;
                }

                if (FirstRun)
                {
                    try
                    {
                        BeginTransaction();

                        using var cmd2 = new SQLiteCommand(SQL_CREATE_RUNS, MainConnection.Connection, MainConnection.Transaction);
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
                            using (var innerCmd = new SQLiteCommand(SQL_CREATE_COLLECT_RESULTS, cxn.Connection, cxn.Transaction))
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
                    catch (SQLiteException e)
                    {
                        Log.Debug(e, "Failed to set up fresh database.");
                        Environment.Exit((int)ASA_ERROR.FAILED_TO_CREATE_DATABASE);
                    }
                    finally
                    {
                        Commit();
                    }
                }

                return true;
            }
            return false;
        }

        public static void TrimToLatest()
        {
            if (MainConnection != null)
            {
                List<string> Runs = new List<string>();
                using var cmd = new SQLiteCommand(GET_RUNS, MainConnection.Connection, MainConnection.Transaction);
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

        public static void UpdateCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using (var cmd = new SQLiteCommand(UPDATE_RUN_IN_RESULT_TABLE, MainConnection.Connection, MainConnection.Transaction))
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
                using var inner_cmd = new SQLiteCommand(SQL_VACUUM, cxn.Connection, cxn.Transaction);
                inner_cmd.ExecuteNonQuery();
            });
        }

        public static void Write(CollectObject? colObj, string? runId)
        {
            if (colObj != null && runId != null)
            {
                var objIn = new WriteObject(colObj, runId);
                Connections[ModuloString(objIn.Identity, shardingFactor: dbSettings.ShardingFactor)].WriteQueue.Enqueue(objIn);
            }
        }

        public static void WriteFileMonitor(FileMonitorObject fmo, string RunId)
        {
            if (fmo == null)
            {
                return;
            }
            _ = MainConnection ?? throw new NullReferenceException(Strings.Get("MainConnection"));
            using var cmd = new SQLiteCommand(SQL_INSERT, MainConnection.Connection, MainConnection.Transaction);
            cmd.Parameters.AddWithValue("@run_id", RunId);
            cmd.Parameters.AddWithValue("@path", fmo.Path);
            cmd.Parameters.AddWithValue("@timestamp", fmo.Timestamp);
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(fmo));

            cmd.ExecuteNonQuery();
        }

        private const string GET_COMPARISON_RESULTS = "select * from findings where comparison_id = @comparison_id and result_type=@result_type order by level des;";
        private const string GET_COMPARISON_RESULTS_LIMIT = "select * from findings where comparison_id=@comparison_id and result_type=@result_type order by level desc limit @offset,@limit;";
        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;";

        //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT = "select count(*) from findings where comparison_id=@comparison_id and result_type=@result_type";

        //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;";

        private const string GET_RUNS = "select run_id from runs order by timestamp desc;";
        private const string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";
        private const string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private const int SCHEMA_VERSION = 8;
        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id";
        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, identity text, row_key blob, serialized blob)";
        private const string SQL_CREATE_COLLECT_RUN_ID_IDENTITY_INDEX = "create index if not exists i_collect_collect_run_id_identity on collect(run_id, identity)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_collect_run_id on collect(run_id)";
        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_collect_runid_row_type on collect(run_id, identity, row_key, result_type)";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";
        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";
        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";
        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (first_run_id text, second_run_id text, level int, result_type int, identity text, serialized text)";
        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (id text, serialized text, unique(id))";
        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, status text);";
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, serialized blob, unique(run_id))";
        private const string SQL_DELETE_RUN = "delete from collect where run_id=@run_id";
        private const string SQL_GET_COLLECT_MISSING_IN_B = "select * from collect b where b.run_id = @second_run_id and b.identity not in (select identity from collect a where a.run_id = @first_run_id);";

        private const string SQL_GET_COLLECT_MODIFIED = "select a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.run_id as 'a_run_id'," +
                                                            "b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.run_id as 'b_run_id'" +
                                                                " from collect a indexed by i_collect_collect_runid_row_type," +
                                                                    " collect b indexed by i_collect_collect_runid_row_type" +
                                                                        " where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and a.row_key != b.row_key and a.result_type = b.result_type;";

        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PERSISTED_SETTINGS = "select serialized from persisted_settings where id=@id";
        private const string SQL_GET_PLATFORM_FROM_RUNID = "select platform from runs where run_id = @run_id";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";
        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";
        private const string SQL_GET_RUN = "select * from runs where run_id = @run_id";
        private const string SQL_INSERT = "insert into file_system_monitored (run_id, row_key, timestamp, change_type, path, old_path, name, old_name, extended_results, notify_filters, serialized) values (@run_id, @row_key, @timestamp, @change_type, @path, @old_path, @name, @old_name, @extended_results, @notify_filters, @serialized)";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (first_run_id, second_run_id, result_type, level, identity, serialized) values (@first_run_id, @second_run_id, @result_type, @level, @identity, @serialized)";
        private const string SQL_INSERT_RUN = "insert into runs (run_id, type, serialized) values (@run_id, @type, @serialized)";
        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status";
        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by timestamp desc limit 0,@limit;";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private const string SQL_UPSERT_PERSISTED_SETTINGS = "insert or replace into persisted_settings (id, serialized) values (@id, @serialized)";
        private const string SQL_VACUUM = "VACUUM";
        private const string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";
        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]

        //lgtm [cs/literal-as-local]
        private static DBSettings dbSettings = new DBSettings();

        private static SystemSQLiteSqlConnectionHolder GenerateSqlConnection(int i)
        {
            if (i == 0)
            {
                return new SystemSQLiteSqlConnectionHolder(SQLiteFilename, dbSettings);
            }
            else
            {
                return new SystemSQLiteSqlConnectionHolder($"{SQLiteFilename}_{i}", dbSettings);
            }
        }

        private static Settings? GetSettings()
        {
            try
            {
                using var getSettings = new SQLiteCommand(SQL_GET_PERSISTED_SETTINGS, MainConnection?.Connection, MainConnection?.Transaction);
                getSettings.Parameters.AddWithValue("@id", "Persisted");
                using var reader = getSettings.ExecuteReader();

                // Settings exist, this isn't the first run
                if (reader.HasRows)
                {
                    while (reader.Read())
                    {
                        return JsonConvert.DeserializeObject<Settings>((string)reader["serialized"]);
                    }
                }
            }
            catch (Exception e) when (e is SQLiteException || e is ArgumentNullException || e is NullReferenceException)
            {
                //Expected when the table doesn't exist (first run)
            }

            return null;
        }

        private static void SetSettings(Settings settings)
        {
            try
            {
                using var cmd = new SQLiteCommand(SQL_UPSERT_PERSISTED_SETTINGS, MainConnection?.Connection, MainConnection?.Transaction);
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(settings));
                cmd.Parameters.AddWithValue("@id", "Persisted");
                cmd.ExecuteNonQuery();
            }
            catch (SQLiteException) { }
            // Main Connection is probably null
            catch (NullReferenceException) { }
        }
    }
}