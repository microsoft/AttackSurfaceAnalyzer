// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Objects;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private static readonly string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, type text, timestamp text, version text, platform text, unique(run_id))";
        private static readonly string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private static readonly string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, row_key text, identity text, serialized text)";

        private static readonly string SQL_CREATE_COLLECT_ROW_KEY_INDEX = "create index if not exists i_collect_row_key on collect(row_key)";
        private static readonly string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_run_id on collect(run_id)";
        private static readonly string SQL_CREATE_COLLECT_RESULT_TYPE_INDEX = "create index if not exists i_collect_result_type on collect(result_type)";

        private static readonly string SQL_CREATE_COLLECT_RUN_KEY_COMBINED_INDEX = "create index if not exists i_collect_row_run on collect(run_id, row_key)";
        private static readonly string SQL_CREATE_COLLECT_RUN_TYPE_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(run_id, result_type)";
        private static readonly string SQL_CREATE_COLLECT_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(identity, row_key)";

        private static readonly string SQL_CREATE_ANALYZED_TABLE = "create table if not exists results (base_run_id text, compare_run_id text, status int)";

        private static readonly string SQL_CREATE_COMPARE_RESULT_TABLE = "create table if not exists compared (base_run_id text, compare_run_id test, change_type int, base_row_key text, compare_row_key text, data_type int)";
        private static readonly string SQL_CREATE_RESULT_CHANGE_TYPE_INDEX = "create index if not exists i_compared_change_type_index on compared(change_type)";
        private static readonly string SQL_CREATE_RESULT_BASE_RUN_ID_INDEX = "create index if not exists i_compared_base_run_id on compared(base_run_id)";
        private static readonly string SQL_CREATE_RESULT_COMPARE_RUN_ID_INDEX = "create index if not exists i_compared_compare_run_id on compared(compare_run_id)";
        private static readonly string SQL_CREATE_RESULT_BASE_ROW_KEY_INDEX = "create index if not exists i_compared_base_row_key on compared(base_row_key)";
        private static readonly string SQL_CREATE_RESULT_DATA_TYPE_INDEX = "create index if not exists i_compared_data_type_index on compared(data_type)";

        private static readonly string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (setting text, value text, unique(setting))";
        private static readonly string SQL_CREATE_DEFAULT_SETTINGS = "insert or ignore into persisted_settings (setting, value) values ('telemetry_opt_out','false'),('schema_version',@schema_version)";

        private static readonly string SQL_GET_RESULT_TYPES_SINGLE = "select * from runs where run_id = @run_id";

        private static readonly string SQL_TRUNCATE_COLLECT = "delete from collect where run_id=@run_id";
        private static readonly string SQL_TRUNCATE_FILES_MONITORED = "delete from file_system_monitored where run_id=@run_id";
        private static readonly string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private static readonly string SQL_TRUNCATE_RESULTS = "delete from results where base_run_id=@run_id or compare_run_id=@run_id";

        private static readonly string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by timestamp desc limit 0,@limit;";

        private static readonly string SQL_GET_SCHEMA_VERSION = "select value from persisted_settings where setting = 'schema_version' limit 0,1";
        private static readonly string SQL_GET_NUM_RESULTS = "select count(*) as the_count from @table_name where run_id = @run_id";
        private static readonly string SQL_GET_PLATFORM_FROM_RUNID = "select platform from runs where run_id = @run_id";

        private static readonly string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, row_key, identity, serialized) values (@run_id, @row_key, @identity, @serialized)";

        private static readonly string PRAGMAS = "PRAGMA main.auto_vacuum = 1;";

        private static readonly string SCHEMA_VERSION = "2";

        public static SqliteConnection Connection;
        public static SqliteConnection ReadOnlyConnection;

        private static SqliteTransaction _transaction;

        private static bool _firstRun = true;

        public static bool Setup()
        {
            if (Connection == null)
            {
                Connection = new SqliteConnection($"Filename=" + _SqliteFilename);
                Connection.Open();

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

                    cmd.CommandText = SQL_CREATE_FILE_MONITORED;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_COMPARE_RESULT_TABLE;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_ANALYZED_TABLE;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_PERSISTED_SETTINGS;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_DEFAULT_SETTINGS;
                    cmd.Parameters.AddWithValue("@schema_version", SCHEMA_VERSION);
                    _firstRun &= cmd.ExecuteNonQuery() != 0;

                    cmd.CommandText = SQL_CREATE_RESULT_CHANGE_TYPE_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_RESULT_BASE_RUN_ID_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_RESULT_COMPARE_RUN_ID_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_RESULT_BASE_ROW_KEY_INDEX;
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = SQL_CREATE_RESULT_DATA_TYPE_INDEX;
                    cmd.ExecuteNonQuery();

                }

                Commit();
                return true;
            }
            return false;
        }

        public static bool IsFirstRun()
        {
            return _firstRun;
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

        public static void VerifySchemaVersion()
        {
            using (var cmd = new SqliteCommand(SQL_GET_SCHEMA_VERSION, DatabaseManager.Connection, DatabaseManager.Transaction))
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
                catch (Exception e)
                {
                    Log.Debug(e.GetType().ToString());
                    Log.Debug(e.Message);
                    Log.Debug("Couldn't determine latest {0} run ids.",numberOfIds);
                }
            }
            return output;
        }

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            try
            {
                using (var cmd = new SqliteCommand(SQL_GET_NUM_RESULTS.Replace("@table_name", Helpers.ResultTypeToTableName(ResultType)), DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", runId);

                    using (var reader = cmd.ExecuteReader())
                    {

                        while (reader.Read())
                        {
                            return int.Parse(reader["the_count"].ToString());
                        }
                    }
                }
            }
            catch(Exception e)
            {
                Log.Debug(e.GetType().ToString());
                Log.Debug(e.Message);
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
                }
            }
            catch (Exception)
            {
                Log.Debug("Commit collision");
            }

            _transaction = null;
        }

        private static string _SqliteFilename = "asa.sqlite";

        public static bool _ReadOnly;

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
                    try
                    {
                        if (Connection != null)
                        {
                            CloseDatabase();
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Debug("{0}:: {1}: {2}", System.Reflection.MethodBase.GetCurrentMethod().Name, e.GetType().ToString(), e.Message);
                    }

                    try
                    {
                        _SqliteFilename = value;
                        Setup();
                    }
                    catch (Exception e)
                    {
                        Log.Fatal(e, "'{0}' {0}:: {1}: {2}", value, System.Reflection.MethodBase.GetCurrentMethod().Name, e.GetType().ToString(), e.Message);
                    }
                }

            }
        }

        public static void CloseDatabase()
        {
            _transaction.Commit();
            Connection.Close();
            Connection = null;
        }

        public static void Write(CollectObject obj, string runId)
        {
            var cmd = new SqliteCommand(SQL_INSERT_COLLECT_RESULT, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.Parameters.AddWithValue("@row_key", obj.RowKey);
            cmd.Parameters.AddWithValue("@identity", obj.Identity);
            cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));

            cmd.ExecuteNonQuery();
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
                            if ((int.Parse(reader["file_system"].ToString()) != 0))
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

                cmd.CommandText = "VACUUM";
                cmd.ExecuteNonQuery();
            }
            DatabaseManager.Commit();
        }
    }
}
