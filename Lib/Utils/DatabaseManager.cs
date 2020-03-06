// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using System.Data.SQLite;
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

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, firewall int, comobjects int, eventlogs int, type text, timestamp text, version text, platform text, unique(run_id))";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, identity text, row_key blob, serialized blob)";

        private const string SQL_CREATE_COLLECT_ROW_KEY_INDEX = "create index if not exists i_collect_row_key on collect(row_key)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_run_id on collect(run_id)";

        private const string SQL_CREATE_COLLECT_RESULT_TYPE_INDEX = "create index if not exists i_collect_result_type on collect(result_type)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_COMBINED_INDEX = "create index if not exists i_collect_row_run on collect(run_id, row_key)";
        private const string SQL_CREATE_COLLECT_RUN_TYPE_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(run_id, result_type)";
        private const string SQL_CREATE_COLLECT_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(identity, row_key)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_runid_row_type on collect(run_id, identity, row_key, result_type)";

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
        private const string SQL_GET_COLLECT_MODIFIED = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.identity as 'a_identity', a.run_id as 'a_run_id', b.row_key as 'b_row_key', b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.identity as 'b_identity', b.run_id as 'b_run_id' from collect a indexed by i_collect_runid_row_type, collect b indexed by i_collect_runid_row_type where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and a.row_key != b.row_key and a.result_type = b.result_type;";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";

        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";

        private const string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]
        private const string CHECK_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";

        private const string SQL_INSERT = "insert into file_system_monitored (run_id, row_key, timestamp, change_type, path, old_path, name, old_name, extended_results, notify_filters, serialized) values (@run_id, @row_key, @timestamp, @change_type, @path, @old_path, @name, @old_name, @extended_results, @notify_filters, @serialized)";

        private const string PRAGMAS = "PRAGMA main.auto_vacuum = 0; PRAGMA main.synchronous = OFF; PRAGMA main.journal_mode = DELETE;";

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

        private const string SCHEMA_VERSION = "6";
        private static bool WriterStarted = false;

        public static SQLiteConnection Connection { get; private set; }

        public static ConcurrentQueue<WriteObject> WriteQueue { get; private set; }

        public static bool FirstRun { get; private set; } = true;

        public static bool Setup(string filename = null)
        {
            JsonSerializer.SetDefaultResolver(StandardResolver.ExcludeNull);
            if (filename != null)
            {
                if (_SqliteFilename != filename)
                {

                    if (Connection != null)
                    {
                        CloseDatabase();
                    }

                    _SqliteFilename = filename;
                }
            }
            if (Connection == null)
            {
                WriteQueue = new ConcurrentQueue<WriteObject>();
                Connection = new SQLiteConnection($"Data Source=" + _SqliteFilename);
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

                using (var cmd = new SQLiteCommand(SQL_CREATE_RUNS, Connection, Transaction))
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

                if (!WriterStarted)
                {
                    ((Action)(async () =>
                    {
                        await Task.Run(() => KeepSleepAndFlushQueue()).ConfigureAwait(false);
                    }))();
                    WriterStarted = true;
                }

                return true;
            }
            return false;
        }

        public static List<DataRunModel> GetResultModels(RUN_STATUS runStatus)
        {
            var output = new List<DataRunModel>();
            using (var cmd = new SQLiteCommand(SQL_QUERY_ANALYZED, Connection, Transaction))
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
            using var cmd = new SQLiteCommand(GET_RUNS, Connection, Transaction);
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
            while (!WriteQueue.IsEmpty)
            {
                WriteNext();
            }
            Thread.Sleep(100);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            using (var cmd = new SQLiteCommand(SQL_GET_PLATFORM_FROM_RUNID, Connection, Transaction))
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
            SQLiteCommand cmd;
            if (Transaction == null)
            {
                cmd = new SQLiteCommand(SQL_GET_RESULTS_BY_RUN_ID, Connection);
            }
            else
            {
                cmd = new SQLiteCommand(SQL_GET_RESULTS_BY_RUN_ID, Connection, Transaction);
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
                using (var cmd = new SQLiteCommand(SQL_INSERT_FINDINGS_RESULT, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(SQL_GET_SCHEMA_VERSION, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(SQL_SELECT_LATEST_N_RUNS, Connection, Transaction))
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
                catch (SQLiteException)
                {
                    Log.Debug("Couldn't determine latest {0} run ids.", numberOfIds);
                }
            }
            return output;
        }

        public static List<CompareResult> GetComparisonResults(string compareId, RESULT_TYPE exportType)
        {
            List<CompareResult> records = new List<CompareResult>();
            using (var cmd = new SQLiteCommand(GET_COMPARISON_RESULTS, Connection, Transaction))
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
                using (var cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES_COUNTS, Connection, Transaction))
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
            catch (SQLiteException)
            {
                Log.Error(Strings.Get("Err_ResultTypesCounts"));
            }
            return outDict;
        }

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            try
            {
                using (var cmd = new SQLiteCommand(SQL_GET_NUM_RESULTS, Connection, Transaction))
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
            catch (SQLiteException)
            {
                Log.Error(Strings.Get("Err_Sql"), MethodBase.GetCurrentMethod().Name);
            }
            return -1;
        }

        public static List<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();

            using (var cmd = new SQLiteCommand(GET_SERIALIZED_RESULTS, Connection, Transaction))
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
            if (Transaction is null)
            {
                Transaction = Connection.BeginTransaction();
            }
        }
        public static SQLiteTransaction Transaction { get; private set; }

        public static void InsertRun(string runId, Dictionary<RESULT_TYPE, bool> dictionary)
        {
            if (dictionary == null)
            {
                return;
            }
            string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, firewall, comobjects, eventlogs, type, timestamp, version, platform) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @firewall, @comobjects, @eventlogs, @type, @timestamp, @version, @platform)";

            using var cmd = new SQLiteCommand(INSERT_RUN, Connection, Transaction);
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
            catch (SQLiteException e)
            {
                Log.Warning(e.StackTrace);
                Log.Warning(e.Message);
                AsaTelemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
        }

        public static void Commit()
        {
            if (Transaction != null)
            {
                Transaction.Commit();
            }
            Transaction = null;
        }
        public static Dictionary<RESULT_TYPE, bool> GetResultTypes(string runId)
        {
            var output = new Dictionary<RESULT_TYPE, bool>();
            using (var inner_cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES_SINGLE, Connection))
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
        private static string _SqliteFilename = "asa.SQLite";

        public static string SqliteFilename
        {
            get
            {
                return _SqliteFilename;
            }
        }

        public static void CloseDatabase()
        {
            Commit();
            try
            {
                Connection.Close();
            }
            catch (NullReferenceException)
            {
                // That's fine. We want Connection to be null.
            }
            Connection = null;
        }

        public static void Write(CollectObject objIn, string runId)
        {
            if (objIn != null && runId != null)
            {
                WriteQueue.Enqueue(new WriteObject(objIn, runId));
            }
        }

        public static void InsertCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            using (var cmd = new SQLiteCommand(INSERT_RUN_INTO_RESULT_TABLE_SQL, Connection, Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static void WriteNext()
        {
            WriteQueue.TryDequeue(out WriteObject objIn);

            try
            {
                using var cmd = new SQLiteCommand(SQL_INSERT_COLLECT_RESULT, Connection, Transaction);
                cmd.Parameters.AddWithValue("@run_id", objIn.RunId);
                cmd.Parameters.AddWithValue("@row_key", objIn.GetRowKey());
                cmd.Parameters.AddWithValue("@identity", objIn.ColObj.Identity);
                cmd.Parameters.AddWithValue("@serialized", objIn.GetSerialized());
                cmd.Parameters.AddWithValue("@result_type", objIn.ColObj.ResultType);
                cmd.ExecuteNonQuery();
            }
            catch (SQLiteException e)
            {
                Log.Debug(exception: e, $"Error writing {objIn.ColObj.Identity} to database.");
            }
            catch (NullReferenceException)
            {
            }
        }

        public static List<RawCollectResult> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var output = new List<RawCollectResult>();

            using var cmd = new SQLiteCommand(SQL_GET_COLLECT_MISSING_IN_B, Connection, Transaction);
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

            return output;
        }

        public static List<RawModifiedResult> GetModified(string firstRunId, string secondRunId)
        {
            var output = new List<RawModifiedResult>();

            using var cmd = new SQLiteCommand(SQL_GET_COLLECT_MODIFIED, Connection, Transaction);
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

            return output;
        }

        public static void UpdateCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            using (var cmd = new SQLiteCommand(UPDATE_RUN_IN_RESULT_TABLE, Connection, Transaction))
            {
                cmd.Parameters.AddWithValue("@base_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@compare_run_id", secondRunId);
                cmd.Parameters.AddWithValue("@status", runStatus);
                cmd.ExecuteNonQuery();
            }
        }

        public static void DeleteRun(string runid)
        {
            using (var cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES_SINGLE, Connection, Transaction))
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
                        using (var inner_cmd = new SQLiteCommand(SQL_TRUNCATE_RUN, Connection, Transaction))
                        {
                            inner_cmd.Parameters.AddWithValue("@run_id", runid);
                            inner_cmd.ExecuteNonQuery();
                        }
                        if (reader["type"].ToString() == "monitor")
                        {
                            if ((int.Parse(reader["file_system"].ToString(), CultureInfo.InvariantCulture) != 0))
                            {
                                using (var inner_cmd = new SQLiteCommand(SQL_TRUNCATE_FILES_MONITORED, Connection, Transaction))
                                {
                                    inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                    inner_cmd.ExecuteNonQuery();
                                }
                            }
                        }
                        else
                        {
                            using (var inner_cmd = new SQLiteCommand(SQL_TRUNCATE_RESULTS, Connection, Transaction))
                            {
                                inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                inner_cmd.ExecuteNonQuery();
                            }
                            using (var inner_cmd = new SQLiteCommand(SQL_TRUNCATE_COLLECT, Connection, Transaction))
                            {
                                inner_cmd.Parameters.AddWithValue("@run_id", runid);
                                inner_cmd.ExecuteNonQuery();
                            }
                        }
                    }
                }
            }
            Commit();
        }

        public static bool GetOptOut()
        {
            using (var cmd = new SQLiteCommand(CHECK_TELEMETRY, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(UPDATE_TELEMETRY, Connection, Transaction))
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
            using var cmd = new SQLiteCommand(SQL_INSERT, Connection, Transaction);
            cmd.Parameters.AddWithValue("@run_id", RunId);
            cmd.Parameters.AddWithValue("@path", fmo.Path);
            cmd.Parameters.AddWithValue("@timestamp", fmo.Timestamp);
            cmd.Parameters.AddWithValue("@serialized", JsonSerializer.Serialize(fmo));

            cmd.ExecuteNonQuery();
        }

        public static Run GetRun(string RunId)
        {
            using (var cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES_SINGLE, Connection, Transaction))
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

            using var cmd = new SQLiteCommand(Select_Runs, Connection, Transaction);
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
            using (var cmd = new SQLiteCommand(GET_MONITOR_RESULTS, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(GET_RESULT_COUNT_MONITORED, Connection, Transaction))
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
            Transaction.Rollback();
        }

        public static List<CompareResult> GetComparisonResults(string comparisonId, int resultType, int offset, int numResults)
        {
            var results = new List<CompareResult>();
            using (var cmd = new SQLiteCommand(GET_COMPARISON_RESULTS_LIMIT, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(GET_RESULT_COUNT, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(SQL_GET_RESULT_TYPES, Connection, Transaction))
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
            using (var cmd = new SQLiteCommand(SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED, Connection, Transaction))
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
