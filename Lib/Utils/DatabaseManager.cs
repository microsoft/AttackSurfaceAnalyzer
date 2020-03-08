﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Mono.Unix;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Utf8Json;
using Utf8Json.Resolvers;
using System.Linq;
using System.IO;
using Microsoft.Data.Sqlite;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, firewall int, comobjects int, eventlogs int, type text, timestamp text, version text, platform text, unique(run_id))";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, identity text, row_key blob, serialized blob)";

        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_collect_run_id on collect(run_id)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_collect_runid_row_type on collect(run_id, identity, row_key, result_type)";

        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, status text);";

        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (comparison_id text, level int, result_type int, identity text, serialized text)";

        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";

        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";

        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";

        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (setting text, value text, unique(setting))";
        private const string SQL_CREATE_DEFAULT_SETTINGS = "insert or ignore into persisted_settings (setting, value) values ('telemetry_opt_out','false'),('schema_version',@schema_version),('sharding_factor',@sharding_factor)";

        private const string SQL_GET_RESULT_TYPES_SINGLE = "select * from runs where run_id = @run_id";

        private const string SQL_TRUNCATE_FILES_MONITORED = "delete from file_system_monitored where run_id=@run_id";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";

        private const string SQL_TRUNCATE_RESULTS = "delete from results where base_run_id=@run_id or compare_run_id=@run_id";

        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by timestamp desc limit 0,@limit;";

        private const string SQL_GET_SCHEMA_VERSION = "select value from persisted_settings where setting = 'schema_version' limit 0,1";
        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PLATFORM_FROM_RUNID = "select platform from runs where run_id = @run_id";

        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (comparison_id, result_type, level, identity, serialized) values (@comparison_id, @result_type, @level, @identity, @serialized)";

        private const string SQL_GET_COLLECT_MISSING_IN_B = "select * from collect b where b.run_id = @second_run_id and b.identity not in (select identity from collect a where a.run_id = @first_run_id);";
        private const string SQL_GET_COLLECT_MODIFIED = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.identity as 'a_identity', a.run_id as 'a_run_id'," +
                                                            " b.row_key as 'b_row_key', b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.identity as 'b_identity', b.run_id as 'b_run_id'" +
                                                                " from collect a indexed by i_collect_collect_runid_row_type," +
                                                                    " collect b indexed by i_collect_collect_runid_row_type" +
                                                                        " where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and a.row_key != b.row_key and a.result_type = b.result_type;";

        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";

        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";

        private const string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]
        private const string CHECK_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";
        private const string GET_SHARDING_FACTOR = "select value from persisted_settings where setting='sharding_factor'";


        private const string SQL_INSERT = "insert into file_system_monitored (run_id, row_key, timestamp, change_type, path, old_path, name, old_name, extended_results, notify_filters, serialized) values (@run_id, @row_key, @timestamp, @change_type, @path, @old_path, @name, @old_name, @extended_results, @notify_filters, @serialized)";

        private const string PRAGMAS = "PRAGMA main.auto_vacuum = 0; PRAGMA main.synchronous = OFF; PRAGMA main.journal_mode = OFF;";

        private const string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private const string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";

        private const string GET_COMPARISON_RESULTS = "select * from findings where comparison_id = @comparison_id and result_type=@result_type order by level des;";
        private const string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";

        private const string GET_RUNS = "select run_id from runs order by timestamp desc;";

        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status"; //lgtm [cs/literal-as-local]

        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id"; //lgtm [cs/literal-as-local]
        private const string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id"; //lgtm [cs/literal-as-local]

        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;"; //lgtm [cs/literal-as-local]

        private const string GET_COMPARISON_RESULTS_LIMIT = "select * from findings where comparison_id=@comparison_id and result_type=@result_type order by level desc limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT = "select count(*) from findings where comparison_id=@comparison_id and result_type=@result_type"; //lgtm [cs/literal-as-local]

        private const string SQL_DELETE_RUN = "delete from collect where run_id=@run_id"; //lgtm [cs/literal-as-local]

        private const string SQL_VACUUM = "VACUUM";

        private const string SQL_GET_SETTINGS = "select * from persisted_settings";

        private const string SCHEMA_VERSION = "7";

        private static int SHARDING_FACTOR = 1;

        public static SqlConnectionHolder MainConnection { get; private set; }

        public static List<SqlConnectionHolder> Connections { get; private set; }

        public static bool FirstRun { get; private set; } = true;

        public static bool Setup(string filename = null, int shardingFactor = 1)
        {
            JsonSerializer.SetDefaultResolver(StandardResolver.ExcludeNull);
            if (filename != null)
            {
                if (SqliteFilename != filename)
                {
                    if (MainConnection != null)
                    {
                        CloseDatabase();
                    }

                    SqliteFilename = filename;
                }
            }
            if (MainConnection == null)
            {
                Connections = new List<SqlConnectionHolder>();

                PopulateConnections();

                SHARDING_FACTOR = GetShardingFactor(shardingFactor);

                if (shardingFactor != SHARDING_FACTOR)
                {
                    Log.Information($"Requested sharding level of {shardingFactor} but database was created with {SHARDING_FACTOR}. Ignoring request and using {SHARDING_FACTOR}.");
                }

                PopulateConnections();

                try
                {
                    using var getSettings = new SqliteCommand(SQL_GET_SETTINGS, MainConnection.Connection, MainConnection.Transaction);
                    using var reader = getSettings.ExecuteReader();

                    while (reader.Read())
                    {
                        //Read settings in
                    }
                }
                catch (SqliteException) { }


                using var cmd = new SqliteCommand(PRAGMAS, MainConnection.Connection);
                cmd.ExecuteNonQuery();

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

                cmd2.CommandText = SQL_CREATE_DEFAULT_SETTINGS;
                cmd2.Parameters.AddWithValue("@schema_version", SCHEMA_VERSION);
                cmd2.Parameters.AddWithValue("@sharding_factor", shardingFactor);

                FirstRun &= cmd2.ExecuteNonQuery() != 0;
                
                for (int i = 0; i < Connections.Count; i++)
                {
                    var cxn = Connections[i];
                    using (var innerCmd = new SqliteCommand(SQL_CREATE_COLLECT_RESULTS, cxn.Connection, cxn.Transaction))
                    {
                        innerCmd.ExecuteNonQuery();

                        innerCmd.CommandText = SQL_CREATE_COLLECT_RUN_ID_INDEX;
                        innerCmd.ExecuteNonQuery();

                        innerCmd.CommandText = SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX;
                        innerCmd.ExecuteNonQuery();
                    }
                }

                Commit();

                return true;
            }
            return false;
        }

        public static int PopulateConnections()
        {
            var connectionsCreated = 0;
            for (int i = Connections.Count; i < SHARDING_FACTOR; i++)
            {
                Connections.Add(new SqlConnectionHolder(new SqliteConnection( i==0 ? "Data Source=SqliteFilename;" : $"Data Source={SqliteFilename}_{i};" )));
                Connections[i].Connection.Open();
                connectionsCreated++;
            }
            MainConnection = Connections[0];
            return connectionsCreated;
        }



        private static int GetShardingFactor(int defaultReturn = -1)
        {
            try
            {
                using var cmd = new SqliteCommand(GET_SHARDING_FACTOR, MainConnection.Connection, MainConnection.Transaction);
                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    return int.Parse(reader["value"].ToString());
                }
            }
            catch (SqliteException) { }

            return defaultReturn;            
        }

        public static void Destroy()
        {
            CloseDatabase();
            try
            {
                File.Delete(SqliteFilename);
                for (int i = 1; i < SHARDING_FACTOR; i++)
                {
                    File.Delete($"{SqliteFilename}_{i}");
                }
            }
            catch (IOException e)
            {
                Log.Fatal(e, Strings.Get("FailedToDeleteDatabase"), SqliteFilename, e.GetType().ToString(), e.Message);
                Environment.Exit(-1);
            }
        }

        public static List<DataRunModel> GetResultModels(RUN_STATUS runStatus)
        {
            var output = new List<DataRunModel>();
            using (var cmd = new SqliteCommand(SQL_QUERY_ANALYZED, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@status", runStatus);

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

        public static void TrimToLatest()
        {
            List<string> Runs = new List<string>();
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

        public static bool HasElements()
        {
            return Connections.Any(x => !x.WriteQueue.IsEmpty);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            using (var cmd = new SqliteCommand(SQL_GET_PLATFORM_FROM_RUNID, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runid);
                using (var reader = cmd.ExecuteReader())
                {
                    reader.Read();
                    return (PLATFORM)Enum.Parse(typeof(PLATFORM), reader["platform"].ToString());
                }
            }
        }

        public static List<RawCollectResult> GetResultsByRunid(string runid)
        {
            var output = new List<RawCollectResult>();
            SqliteCommand cmd;
            if (MainConnection.Transaction == null)
            {
                cmd = new SqliteCommand(SQL_GET_RESULTS_BY_RUN_ID, MainConnection.Connection);
            }
            else
            {
                cmd = new SqliteCommand(SQL_GET_RESULTS_BY_RUN_ID, MainConnection.Connection, MainConnection.Transaction);
            }
            cmd.Parameters.AddWithValue("@run_id", runid);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    output.Add(new RawCollectResult()
                    {
                        Identity = reader["identity"].ToString(),
                        RunId = reader["run_id"].ToString(),
                        ResultType = (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), reader["result_type"].ToString()),
                        RowKey = (byte[])reader["row_key"],
                        Serialized = (byte[])reader["serialized"]
                    });
                }
            }
            cmd.Dispose();
            return output;
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null)
            {
                using (var cmd = new SqliteCommand(SQL_INSERT_FINDINGS_RESULT, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@comparison_id", AsaHelpers.RunIdsToCompareId(objIn.BaseRunId, objIn.CompareRunId));
                    cmd.Parameters.AddWithValue("@result_type", objIn.ResultType);
                    cmd.Parameters.AddWithValue("@level", objIn.Analysis);
                    cmd.Parameters.AddWithValue("@identity", objIn.Identity);
                    cmd.Parameters.AddWithValue("@serialized", JsonSerializer.Serialize(objIn));
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public static void VerifySchemaVersion()
        {
            using (var cmd = new SqliteCommand(SQL_GET_SCHEMA_VERSION, MainConnection.Connection, MainConnection.Transaction))
            using (var reader = cmd.ExecuteReader())
            {
                reader.Read();
                if (!reader["value"].ToString().Equals(SCHEMA_VERSION))
                {
                    Log.Fatal("Schema version of database is {0} but {1} is required. Use config --reset-database to delete the incompatible database.", reader["value"].ToString(), SCHEMA_VERSION);
                    Environment.Exit(-1);
                }
            }
        }

        public static List<string> GetLatestRunIds(int numberOfIds, string type)
        {
            List<string> output = new List<string>();
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
                            output.Add(reader["run_id"].ToString());
                        }
                    }
                }
                catch (SqliteException)
                {
                    Log.Debug("Couldn't determine latest {0} run ids.", numberOfIds);
                }
            }
            return output;
        }

        public static List<CompareResult> GetComparisonResults(string compareId, RESULT_TYPE exportType)
        {
            List<CompareResult> records = new List<CompareResult>();
            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", compareId);
                cmd.Parameters.AddWithValue("@result_type", exportType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        records.Add(JsonSerializer.Deserialize<CompareResult>(reader["serialized"].ToString()));
                    }
                }
            }
            return records;
        }

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var outDict = new Dictionary<RESULT_TYPE, int>() { };
            try
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
                                outDict.TryAdd(result_type, int.Parse(reader["count"].ToString(), CultureInfo.InvariantCulture));
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

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            try
            {
                using (var cmd = new SqliteCommand(SQL_GET_NUM_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);
                    cmd.Parameters.AddWithValue("@result_type", ResultType.ToString());

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            return int.Parse(reader["the_count"].ToString(), CultureInfo.InvariantCulture);
                        }
                    }
                }
            }
            catch (SqliteException)
            {
                Log.Error(Strings.Get("Err_Sql"), MethodBase.GetCurrentMethod().Name);
            }
            return -1;
        }

        public static List<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();

            using (var cmd = new SqliteCommand(GET_SERIALIZED_RESULTS, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runId);
                using (var reader = cmd.ExecuteReader())
                {

                    FileMonitorEvent obj;

                    while (reader.Read())
                    {
                        obj = JsonSerializer.Deserialize<FileMonitorEvent>(reader["serialized"].ToString());
                        obj.ChangeType = (CHANGE_TYPE)int.Parse(reader["change_type"].ToString(), CultureInfo.InvariantCulture);
                        records.Add(obj);
                    }
                }
            }

            return records;
        }

        public static void BeginTransaction()
        {
            if (MainConnection.Transaction is null)
            {
                foreach(var cxn in Connections)
                {
                    cxn.Transaction = cxn.Connection.BeginTransaction();
                }
            }
        }

        public static void InsertRun(string runId, Dictionary<RESULT_TYPE, bool> dictionary)
        {
            if (dictionary == null)
            {
                return;
            }
            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, firewall, comobjects, eventlogs, type, timestamp, version, platform) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @firewall, @comobjects, @eventlogs, @type, @timestamp, @version, @platform)";

            using var cmd = new SqliteCommand(INSERT_RUN, MainConnection.Connection, MainConnection.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.Parameters.AddWithValue("@file_system", (dictionary.ContainsKey(RESULT_TYPE.FILE) && dictionary[RESULT_TYPE.FILE]) || (dictionary.ContainsKey(RESULT_TYPE.FILEMONITOR) && dictionary[RESULT_TYPE.FILEMONITOR]));
            cmd.Parameters.AddWithValue("@ports", (dictionary.ContainsKey(RESULT_TYPE.PORT) && dictionary[RESULT_TYPE.PORT]));
            cmd.Parameters.AddWithValue("@users", (dictionary.ContainsKey(RESULT_TYPE.USER) && dictionary[RESULT_TYPE.USER]));
            cmd.Parameters.AddWithValue("@services", (dictionary.ContainsKey(RESULT_TYPE.SERVICE) && dictionary[RESULT_TYPE.SERVICE]));
            cmd.Parameters.AddWithValue("@registry", (dictionary.ContainsKey(RESULT_TYPE.REGISTRY) && dictionary[RESULT_TYPE.REGISTRY]));
            cmd.Parameters.AddWithValue("@certificates", (dictionary.ContainsKey(RESULT_TYPE.CERTIFICATE) && dictionary[RESULT_TYPE.CERTIFICATE]));
            cmd.Parameters.AddWithValue("@firewall", (dictionary.ContainsKey(RESULT_TYPE.FIREWALL) && dictionary[RESULT_TYPE.FIREWALL]));
            cmd.Parameters.AddWithValue("@comobjects", (dictionary.ContainsKey(RESULT_TYPE.COM) && dictionary[RESULT_TYPE.COM]));
            cmd.Parameters.AddWithValue("@eventlogs", (dictionary.ContainsKey(RESULT_TYPE.LOG) && dictionary[RESULT_TYPE.LOG]));
            cmd.Parameters.AddWithValue("@type", (dictionary.ContainsKey(RESULT_TYPE.FILEMONITOR) && dictionary[RESULT_TYPE.FILEMONITOR]) ? "monitor" : "collect");
            cmd.Parameters.AddWithValue("@timestamp", DateTime.Now.ToString("o", CultureInfo.InvariantCulture));
            cmd.Parameters.AddWithValue("@version", AsaHelpers.GetVersionString());
            cmd.Parameters.AddWithValue("@platform", AsaHelpers.GetPlatformString());
            try
            {
                cmd.ExecuteNonQuery();
                Commit();
            }
            catch (SqliteException e)
            {
                Log.Warning(e.StackTrace);
                Log.Warning(e.Message);
                AsaTelemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
        }

        public static void Commit()
        {
            foreach (var cxn in Connections)
            {
                try
                {
                    cxn.Transaction.Commit();
                }
                catch(Exception)
                {
                    Log.Warning($"Failed to commit data to {cxn.Connection.ConnectionString}");
                }
                finally
                {
                    cxn.Transaction = null;
                }
            }
        }
        public static Dictionary<RESULT_TYPE, bool> GetResultTypes(string runId)
        {
            var output = new Dictionary<RESULT_TYPE, bool>();
            using (var inner_cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, MainConnection.Connection))
            {
                inner_cmd.Parameters.AddWithValue("@run_id", runId);
                using (var reader = inner_cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        output[RESULT_TYPE.FILE] = (int.Parse(reader["file_system"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.PORT] = (int.Parse(reader["ports"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.USER] = (int.Parse(reader["users"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.SERVICE] = (int.Parse(reader["services"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.REGISTRY] = (int.Parse(reader["registry"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.CERTIFICATE] = (int.Parse(reader["certificates"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.FIREWALL] = (int.Parse(reader["firewall"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.COM] = (int.Parse(reader["comobjects"].ToString(), CultureInfo.InvariantCulture) != 0);
                        output[RESULT_TYPE.LOG] = (int.Parse(reader["eventlogs"].ToString(), CultureInfo.InvariantCulture) != 0);
                    }
                }
            }
            return output;
        }

        public static string SqliteFilename { get; private set; } = "asa.Sqlite";

        public static void Vacuum()
        {
            using var cmd = new SqliteCommand(SQL_VACUUM, MainConnection.Connection, MainConnection.Transaction);
            cmd.ExecuteNonQuery();

            foreach(var cxn in Connections)
            {
                using var inner_cmd = new SqliteCommand(SQL_VACUUM, cxn.Connection, cxn.Transaction);
                inner_cmd.ExecuteNonQuery();
            }

        }

        public static void CloseDatabase()
        {
            RollBack();
            Vacuum();
            if (Connections != null)
            {
                foreach (var cxn in Connections.Where(x => x.Connection != null))
                {
                    try
                    {
                        cxn.KeepRunning = false;
                        cxn.Connection.Close();
                    }
                    catch (NullReferenceException)
                    {
                        // That's fine. We want Connection to be null.
                    }
                }
            }
            Connections = null;
            MainConnection = null;
        }

        public static void Write(CollectObject colObj, string runId)
        {
            if (colObj != null && runId != null)
            {
                var objIn = new WriteObject(colObj, runId);

                if (objIn.Shard >= 0)
                {
                    Connections[objIn.Shard].WriteQueue.Enqueue(objIn);
                }
            }
        }

        public static void InsertCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            using (var cmd = new SqliteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static int ModuloString(string identity) => identity.Sum(x => x) % SHARDING_FACTOR;

        public static List<RawCollectResult> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var output = new List<RawCollectResult>();


            for (int i = 0; i < SHARDING_FACTOR; i++)
            {
                using var cmd = new SqliteCommand(SQL_GET_COLLECT_MISSING_IN_B, Connections[i].Connection, Connections[i].Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        output.Add(new RawCollectResult()
                        {
                            Identity = reader["identity"].ToString(),
                            RunId = reader["run_id"].ToString(),
                            ResultType = (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), reader["result_type"].ToString()),
                            RowKey = (byte[])reader["row_key"],
                            Serialized = (byte[])reader["serialized"]
                        });
                    }
                }
            }

            return output;
        }

        public static List<RawModifiedResult> GetModified(string firstRunId, string secondRunId)
        {
            var output = new List<RawModifiedResult>();

            for (int i = 0; i < SHARDING_FACTOR; i++)
            {
                using var cmd = new SqliteCommand(SQL_GET_COLLECT_MODIFIED, Connections[i].Connection, Connections[i].Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        output.Add(new RawModifiedResult()
                        {
                            First = new RawCollectResult()
                            {
                                Identity = reader["a_identity"].ToString(),
                                RunId = reader["a_run_id"].ToString(),
                                ResultType = (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), reader["a_result_type"].ToString()),
                                RowKey = (byte[])reader["a_row_key"],
                                Serialized = (byte[])reader["a_serialized"]
                            },
                            Second = new RawCollectResult()
                            {
                                Identity = reader["b_identity"].ToString(),
                                RunId = reader["b_run_id"].ToString(),
                                ResultType = (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), reader["b_result_type"].ToString()),
                                RowKey = (byte[])reader["b_row_key"],
                                Serialized = (byte[])reader["b_serialized"]
                            }
                        }
                        );
                    }
                }
            }

            return output;
        }

        public static void UpdateCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            using (var cmd = new SqliteCommand(UPDATE_RUN_IN_RESULT_TABLE, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static void DeleteRun(string runid)
        {
            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runid);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_RUN, MainConnection.Connection, MainConnection.Transaction))
                        {
                            inner_cmd.Parameters.AddWithValue("@run_id", runid);
                            inner_cmd.ExecuteNonQuery();
                        }
                        if (reader["type"].ToString() == "monitor")
                        {
                            if ((int.Parse(reader["file_system"].ToString(), CultureInfo.InvariantCulture) != 0))
                            {
                                using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_FILES_MONITORED, MainConnection.Connection, MainConnection.Transaction))
                                {
                                    inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                    inner_cmd.ExecuteNonQuery();
                                }
                            }
                        }
                        else
                        {
                            using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_RESULTS, MainConnection.Connection, MainConnection.Transaction))
                            {
                                inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                inner_cmd.ExecuteNonQuery();
                            }
                        }
                    }
                }
                for (int i = 0; i < SHARDING_FACTOR; i++)
                {
                    using (var inner_cmd = new SqliteCommand(SQL_DELETE_RUN, Connections[i].Connection, Connections[i].Transaction))
                    {
                        inner_cmd.Parameters.AddWithValue("@run_id", runid);
                        inner_cmd.ExecuteNonQuery();
                    }
                }
            }
        }

        public static bool GetOptOut()
        {
            using (var cmd = new SqliteCommand(CHECK_TELEMETRY, MainConnection.Connection, MainConnection.Transaction))
            {
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        return bool.Parse(reader["value"].ToString());
                    }
                }
            }

            return false;
        }

        public static void SetOptOut(bool OptOut)
        {
            using (var cmd = new SqliteCommand(UPDATE_TELEMETRY, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@TelemetryOptOut", OptOut.ToString(CultureInfo.InvariantCulture));
                cmd.ExecuteNonQuery();
                Commit();
            }
        }

        public static void WriteFileMonitor(FileMonitorObject fmo, string RunId)
        {
            if (fmo == null)
            {
                return;
            }
            using var cmd = new SqliteCommand(SQL_INSERT, MainConnection.Connection, MainConnection.Transaction);
            cmd.Parameters.AddWithValue("@run_id", RunId);
            cmd.Parameters.AddWithValue("@path", fmo.Path);
            cmd.Parameters.AddWithValue("@timestamp", fmo.Timestamp);
            cmd.Parameters.AddWithValue("@serialized", JsonSerializer.Serialize(fmo));

            cmd.ExecuteNonQuery();
        }

        public static Run GetRun(string RunId)
        {
            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", RunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        return new Run()
                        {
                            Platform = reader["platform"].ToString(),
                            Timestamp = reader["timestamp"].ToString(),
                            Version = reader["version"].ToString(),
                            RunId = reader["run_id"].ToString(),
                            ResultTypes = GetResultTypes(RunId)
                        };

                    }
                }
            }
            return null;
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns("monitor");
        }

        public static List<string> GetRuns(string type)
        {
            string Select_Runs = "select distinct run_id from runs where type=@type order by timestamp asc;";

            List<string> Runs = new List<string>();

            using var cmd = new SqliteCommand(Select_Runs, MainConnection.Connection, MainConnection.Transaction);
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

        public static List<OutputFileMonitorResult> GetMonitorResults(string runId, int offset, int numResults)
        {
            var results = new List<OutputFileMonitorResult>();
            using (var cmd = new SqliteCommand(GET_MONITOR_RESULTS, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runId);
                cmd.Parameters.AddWithValue("@offset", offset);
                cmd.Parameters.AddWithValue("@limit", numResults);
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
            return results;
        }

        public static int GetNumMonitorResults(string runId)
        {
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT_MONITORED, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        return int.Parse(reader["count(*)"].ToString(), CultureInfo.InvariantCulture);
                    }
                }
            }

            return 0;
        }

        public static void RollBack()
        {
            if (Connections != null)
            {
                foreach (var cxn in Connections.Where(x => x.Transaction != null))
                {
                    try
                    {
                        cxn.Transaction.Rollback();
                    }
                    catch(NullReferenceException e)
                    { }
                    cxn.Transaction = null;
                }
            }
        }

        public static List<CompareResult> GetComparisonResults(string comparisonId, int resultType, int offset, int numResults)
        {
            var results = new List<CompareResult>();
            using (var cmd = new SqliteCommand(GET_COMPARISON_RESULTS_LIMIT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", comparisonId);
                cmd.Parameters.AddWithValue("@result_type", resultType);
                cmd.Parameters.AddWithValue("@offset", offset);
                cmd.Parameters.AddWithValue("@limit", numResults);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = JsonSerializer.Deserialize<CompareResult>(reader["serialized"].ToString());
                        results.Add(obj);
                    }
                }
            }

            return results;
        }

        public static int GetComparisonResultsCount(string comparisonId, int resultType)
        {
            var result_count = 0;
            using (var cmd = new SqliteCommand(GET_RESULT_COUNT, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@comparison_id", comparisonId);
                cmd.Parameters.AddWithValue("@result_type", resultType);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        result_count = int.Parse(reader["count(*)"].ToString(), CultureInfo.InvariantCulture);
                    }
                }
            }
            return result_count;
        }

        public static object GetCommonResultTypes(string baseId, string compareId)
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
            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES, MainConnection.Connection, MainConnection.Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", baseId?.ToString(CultureInfo.InvariantCulture));
                cmd.Parameters.AddWithValue("@compare_run_id", compareId?.ToString(CultureInfo.InvariantCulture));
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

            return json_out;
        }

        public static bool GetComparisonCompleted(string firstRunId, string secondRunId)
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

            return false;
        }
    }
}
