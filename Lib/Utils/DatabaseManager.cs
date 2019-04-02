// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using Microsoft.Data.Sqlite;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        // Creates the run_id table, used to optimize the speed of query to determine which runs are available to select between.
        // Each of the file_system, ports, users, services variables can be considered booleans, which indicate if the type of collection is enabled or not. Type is between "collect" and "monitor".
        // TODO: Add timestamp
        private static readonly string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, type text, unique(run_id))";
        private static readonly string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private static readonly string SQL_CREATE_FILE_SYSTEM_COLLECTION = "create table if not exists file_system (run_id text, row_key text, path text, permissions text, size int, hash text, serialized text)";
        private static readonly string SQL_CREATE_OPEN_PORT_COLLECTION = "create table if not exists network_ports (run_id text, row_key text, family text, address text, type text, port int, process_name text, serialized text)";
        private static readonly string SQL_CREATE_SERVICE_COLLECTION = "create table if not exists win_system_service (run_id text, row_key text, service_name text, display_name text, start_type text, current_state text, serialized text)";
        private static readonly string SQL_CREATE_USER_COLLECTION = "create table if not exists user_account (run_id text, row_key text, account_type text, caption text, description text, disabled text, domain text, full_name text, install_date text, local_account text, lockout text, name text, password_changeable text, password_expires text, password_required text, sid text, uid text, gid text, inactive text, home_directory text, shell text, password_storage_algorithm text, properties text data_hash text, serialized text)";
        private static readonly string SQL_CREATE_REGISTRY_COLLECTION = "create table if not exists registry (run_id text, row_key text, key text, values text, permissions text, serialized text)";
        private static readonly string SQL_CREATE_CERTIFICATES_COLLECTION = "create table if not exists certificates (run_id text, row_key text, pkcs12 text, store_location text, store_name text, hash text, hash_plus_store text, cert text, cn text, serialized text)";

        private static readonly string SQL_CREATE_COMPARE_RESULT_TABLE = "create table if not exists compared (base_run_id text, compare_run_id test, change_type int, base_row_key text, compare_row_key text, data_type int)";

        private static readonly string SQL_CREATE_ANALYZED_TABLE = "create table if not exists results (base_run_id text, compare_run_id text, status int)";

        private static readonly string SQL_CREATE_FILE_SYSTEM_INDEX = "create index if not exists path_index on file_system(path)";
        private static readonly string SQL_CREATE_REGISTRY_INDEX = "create index if not exists path_index on registry(key)";

        private static readonly string SQL_CREATE_RESULT_CHANGE_TYPE_INDEX = "create index if not exists change_type_index on compared(change_type)";
        private static readonly string SQL_CREATE_RESULT_BASE_RUN_ID_INDEX = "create index if not exists base_run_index on compared(base_run_id)";
        private static readonly string SQL_CREATE_RESULT_COMPARE_RUN_ID_INDEX = "create index if not exists compare_run_index on compared(compare_run_id)";

        private static readonly string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (setting text, value text, unique(setting))";
        private static readonly string SQL_CREATE_DEFAULT_SETTINGS = "insert or ignore into persisted_settings (setting, value) values ('telemetry_opt_out','false')";

        public static SqliteConnection Connection;
        public static SqliteConnection ReadOnlyConnection;

        private static SqliteTransaction _transaction;

        public static void Setup()
        {
            if (Connection == null)
            {
                Connection = new SqliteConnection($"Filename=" + _SqliteFilename);
                Connection.Open();

                var cmd = new SqliteCommand(SQL_CREATE_RUNS, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_FILE_MONITORED, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_FILE_SYSTEM_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_OPEN_PORT_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_SERVICE_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_USER_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_REGISTRY_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_CERTIFICATES_COLLECTION, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_COMPARE_RESULT_TABLE, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_ANALYZED_TABLE, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_PERSISTED_SETTINGS, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_DEFAULT_SETTINGS, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_FILE_SYSTEM_INDEX, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_REGISTRY_INDEX, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_RESULT_CHANGE_TYPE_INDEX, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_RESULT_BASE_RUN_ID_INDEX, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();

                cmd = new SqliteCommand(SQL_CREATE_RESULT_COMPARE_RUN_ID_INDEX, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.ExecuteNonQuery();
                Commit();
            }
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
            if (_transaction != null)
            {
                _transaction.Commit();
                _transaction = null;
            }
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
                try
                {
                    if (_ReadOnly)
                    {
                        if (ReadOnlyConnection != null)
                        {
                            CloseDatabase();
                        }
                    }
                    else
                    {
                        if (Connection != null)
                        {
                            CloseDatabase();
                        }
                    }

                }
                catch (Exception)
                {
                    // OK to ignore
                }

                try
                {
                    _SqliteFilename = value;
                    //This doesn't work?
                    //_ReadOnly ? SetupReadOnly() : Setup();
                    if (_ReadOnly)
                    {
                        SetupReadOnly();
                    }
                    else
                    {
                        Setup();
                    }

                }
                catch (Exception ex)
                {
                    Logger.Instance.Warn(ex, "Unable to open SQLite connection to {0}: {1}", value, ex.Message);
                }
            }
        }

        private static void SetupReadOnly()
        {
            Connection = new SqliteConnection($"Filename=" + _SqliteFilename);
            Connection.Open();
        }

        static void CloseDatabase()
        {
            // Abandon any in-progress transaction
            _transaction = null;

            // Close and null
            Connection.Close();
            Connection = null;
        }
    }
}