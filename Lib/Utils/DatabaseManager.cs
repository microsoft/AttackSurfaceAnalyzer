// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using Microsoft.Data.Sqlite;
using Mono.Unix;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, firewall int, comobjects int, eventlogs int, type text, timestamp text, version text, platform text, unique(run_id))";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, row_key text, identity text, serialized text)";

        private const string SQL_CREATE_COLLECT_ROW_KEY_INDEX = "create index if not exists i_collect_row_key on collect(row_key)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_run_id on collect(run_id)";
        private const string SQL_CREATE_COLLECT_RESULT_TYPE_INDEX = "create index if not exists i_collect_result_type on collect(result_type)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_COMBINED_INDEX = "create index if not exists i_collect_row_run on collect(run_id, row_key)";
        private const string SQL_CREATE_COLLECT_RUN_TYPE_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(run_id, result_type)";
        private const string SQL_CREATE_COLLECT_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(identity, row_key)";
        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_runid_row_type on collect(run_id, identity, row_key)";

        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, status text);";

        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (comparison_id text, level int, result_type int, identity text, serialized text)";

        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";
        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";

        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";

        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (setting text, value text, unique(setting))";
        private const string SQL_CREATE_DEFAULT_SETTINGS = "insert or ignore into persisted_settings (setting, value) values ('telemetry_opt_out','false'),('schema_version',@schema_version)";

        private const string SQL_GET_RESULT_TYPES_SINGLE = "select * from runs where run_id = @run_id";

        private const string SQL_TRUNCATE_COLLECT = "delete from collect where run_id=@run_id";
        private const string SQL_TRUNCATE_FILES_MONITORED = "delete from file_system_monitored where run_id=@run_id";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private const string SQL_TRUNCATE_RESULTS = "delete from results where base_run_id=@run_id or compare_run_id=@run_id";

        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by timestamp desc limit 0,@limit;";

        private const string SQL_GET_SCHEMA_VERSION = "select value from persisted_settings where setting = 'schema_version' limit 0,1";
        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PLATFORM_FROM_RUNID = "select platform from runs where run_id = @run_id";

        private const string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id, @result_type, @row_key, @identity, @serialized)";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (comparison_id, result_type, level, identity, serialized) values (@comparison_id, @result_type, @level, @identity, @serialized)";

        private const string SQL_GET_COLLECT_MISSING_IN_B = "select * from collect b where b.run_id = @second_run_id and b.identity not in (select identity from collect a where a.run_id = @first_run_id);";
        private const string SQL_GET_COLLECT_MODIFIED = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.identity as 'a_identity', a.run_id as 'a_run_id', b.row_key as 'b_row_key', b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.identity as 'b_identity', b.run_id as 'b_run_id' from collect a indexed by i_collect_runid_row_type, collect b indexed by i_collect_runid_row_type where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and a.row_key != b.row_key;";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";

        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";

        private const string PRAGMAS = "PRAGMA main.auto_vacuum = 1;";

        private const string SCHEMA_VERSION = "4";

        public static SqliteConnection Connection { get; set; }

        private static SqliteTransaction _transaction;

        private static ConcurrentQueue<WriteObject> WriteQueue { get; set; }

        public static bool FirstRun { get; private set; } = true;

        public static bool Setup()
        {
            if (Connection == null)
            {
                WriteQueue = new ConcurrentQueue<WriteObject>();
                Connection = new SqliteConnection($"Filename=" + _SqliteFilename);
                Connection.Open();

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    var unixFileInfo = new UnixFileInfo(_SqliteFilename);
                    // set file permission to 666
                    unixFileInfo.FileAccessPermissions =
                        FileAccessPermissions.UserRead | FileAccessPermissions.UserWrite
                        | FileAccessPermissions.GroupRead | FileAccessPermissions.GroupWrite
                        | FileAccessPermissions.OtherRead | FileAccessPermissions.OtherWrite;
                }

                using (var cmd = new SqliteCommand(SQL_CREATE_RUNS, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = PRAGMAS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RESULTS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_ROW_KEY_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RUN_ID_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RESULT_TYPE_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RUN_KEY_COMBINED_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RUN_TYPE_COMBINED_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_KEY_IDENTITY_COMBINED_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_RESULTS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FINDINGS_RESULTS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FINDINGS_LEVEL_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FINDINGS_IDENTITY_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_FILE_MONITORED;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_PERSISTED_SETTINGS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_DEFAULT_SETTINGS;
                    cmd.Parameters.AddWithValue("@schema_version", SCHEMA_VERSION);
                    FirstRun &= cmd.ExecuteNonQuery() != 0;
                }

                Commit();

                ((Action)(async () =>
                {
                    await Task.Run(() => KeepSleepAndFlushQueue()).ConfigureAwait(false);
                }))();
                return true;
            }
            return false;
        }

        public static bool HasElements()
        {
            return !WriteQueue.IsEmpty;
        }

        public static void KeepSleepAndFlushQueue()
        {
            while (true)
            {
                SleepAndFlushQueue();
            }
        }
        public static void SleepAndFlushQueue()
        {
            while (!WriteQueue.IsEmpty) { WriteNext(); }
            Thread.Sleep(500);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            using (var cmd = new SqliteCommand(SQL_GET_PLATFORM_FROM_RUNID, DatabaseManager.Connection, DatabaseManager.Transaction))
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

            using var cmd = new SqliteCommand(SQL_GET_RESULTS_BY_RUN_ID, DatabaseManager.Connection, DatabaseManager.Transaction);
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
                        RowKey = reader["row_key"].ToString(),
                        Serialized = reader["serialized"].ToString()
                    });
                }
            }

            return output;
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null)
            {
                using (var cmd = new SqliteCommand(SQL_INSERT_FINDINGS_RESULT, Connection, Transaction))
                {
                    cmd.Parameters.AddWithValue("@comparison_id", AsaHelpers.RunIdsToCompareId(objIn.BaseRunId, objIn.CompareRunId));
                    cmd.Parameters.AddWithValue("@result_type", objIn.ResultType);
                    cmd.Parameters.AddWithValue("@level", objIn.Analysis);
                    cmd.Parameters.AddWithValue("@identity", objIn.Identity);
                    cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(objIn));
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public static void VerifySchemaVersion()
        {
            using (var cmd = new SqliteCommand(SQL_GET_SCHEMA_VERSION, Connection, Transaction))
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
            using (var cmd = new SqliteCommand(SQL_SELECT_LATEST_N_RUNS, DatabaseManager.Connection, DatabaseManager.Transaction))
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

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var outDict = new Dictionary<RESULT_TYPE, int>() { };
            try
            {
                using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_COUNTS, DatabaseManager.Connection, DatabaseManager.Transaction))
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
                using (var cmd = new SqliteCommand(SQL_GET_NUM_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);
                    cmd.Parameters.AddWithValue("@result_type", ResultType.ToString());

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            return int.Parse(reader["the_count"].ToString(),CultureInfo.InvariantCulture);
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


        public static SqliteTransaction Transaction
        {
            get
            {
                if (_transaction == null)
                {
                    _transaction = Connection.BeginTransaction();
                }
                return _transaction;
            }
        }

        public static void Commit()
        {
            try
            {
                if (_transaction != null)
                {
                    _transaction.Commit();
                    _transaction = null;
                }
            }
            catch (Exception)
            {
                Log.Debug("Commit collision");
            }

            _transaction = null;
        }

        private static string _SqliteFilename = "asa.sqlite";

        public static string SqliteFilename
        {
            get
            {
                return _SqliteFilename;
            }
            set
            {
                if (_SqliteFilename != value)
                {

                    if (Connection != null)
                    {
                        CloseDatabase();
                    }

                    _SqliteFilename = value;

                    try
                    {
                        Setup();
                    }
                    catch (SqliteException e)
                    {
                        Log.Fatal(e, "'{0}' {0}:: {1}: {2}", value, System.Reflection.MethodBase.GetCurrentMethod().Name, e.GetType().ToString(), e.Message);
                    }
                }

            }
        }

        public static void CloseDatabase()
        {
            Commit();
            Connection.Close();
            Connection = null;
        }

        public static void Write(CollectObject objIn, string runId)
        {
            if (objIn != null && runId != null)
            {
                WriteQueue.Enqueue(new WriteObject() { ColObj = objIn, RunId = runId });
            }
        }

        public static void WriteNext()
        {
            WriteQueue.TryDequeue(out WriteObject objIn);
            try
            {
                using var cmd = new SqliteCommand(SQL_INSERT_COLLECT_RESULT, Connection, Transaction);
                cmd.Parameters.AddWithValue("@run_id", objIn.RunId);
                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(JsonConvert.SerializeObject(objIn.ColObj)));
                cmd.Parameters.AddWithValue("@identity", objIn.ColObj.Identity);
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(objIn.ColObj, Formatting.None, new JsonSerializerSettings() { DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore }));
                cmd.Parameters.AddWithValue("@result_type", objIn.ColObj.ResultType);
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException)
            {
                Log.Debug($"Error writing {objIn.ColObj.Identity} to database.");
            }
        }

        public static List<RawCollectResult> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var output = new List<RawCollectResult>();

            using var cmd = new SqliteCommand(SQL_GET_COLLECT_MISSING_IN_B, Connection, Transaction);
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
                        RowKey = reader["row_key"].ToString(),
                        Serialized = reader["serialized"].ToString()
                    });
                }
            }

            return output;
        }

        public static List<RawModifiedResult> GetModified(string firstRunId, string secondRunId)
        {
            var output = new List<RawModifiedResult>();

            using var cmd = new SqliteCommand(SQL_GET_COLLECT_MODIFIED, DatabaseManager.Connection, DatabaseManager.Transaction);
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
                            RowKey = reader["a_row_key"].ToString(),
                            Serialized = reader["a_serialized"].ToString()
                        },
                        Second = new RawCollectResult()
                        {
                            Identity = reader["b_identity"].ToString(),
                            RunId = reader["b_run_id"].ToString(),
                            ResultType = (RESULT_TYPE)Enum.Parse(typeof(RESULT_TYPE), reader["b_result_type"].ToString()),
                            RowKey = reader["b_row_key"].ToString(),
                            Serialized = reader["b_serialized"].ToString()
                        }
                    }
                    );
                }
            }

            return output;
        }

        public static void DeleteRun(string runid)
        {
            using (var cmd = new SqliteCommand(SQL_GET_RESULT_TYPES_SINGLE, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", runid);
                using (var reader = cmd.ExecuteReader())
                {
                    if (!reader.HasRows)
                    {
                        Log.Warning("That Run ID wasn't found in the database");
                        return;
                    }
                    while (reader.Read())
                    {
                        using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_RUN, DatabaseManager.Connection, DatabaseManager.Transaction))
                        {
                            inner_cmd.Parameters.AddWithValue("@run_id", runid);
                            inner_cmd.ExecuteNonQuery();
                        }
                        if (reader["type"].ToString() == "monitor")
                        {
                            if ((int.Parse(reader["file_system"].ToString(),CultureInfo.InvariantCulture) != 0))
                            {
                                using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_FILES_MONITORED, DatabaseManager.Connection, DatabaseManager.Transaction))
                                {
                                    inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                    inner_cmd.ExecuteNonQuery();
                                }
                            }
                        }
                        else
                        {
                            using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_RESULTS, DatabaseManager.Connection, DatabaseManager.Transaction))
                            {
                                inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                inner_cmd.ExecuteNonQuery();
                            }
                            using (var inner_cmd = new SqliteCommand(SQL_TRUNCATE_COLLECT, DatabaseManager.Connection, DatabaseManager.Transaction))
                            {
                                inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                inner_cmd.ExecuteNonQuery();
                            }
                        }
                    }
                }
            }
            DatabaseManager.Commit();
        }
    }
}
