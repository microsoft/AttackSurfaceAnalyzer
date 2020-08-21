using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class SystemSQLiteSqlConnectionHolder
    {
        public SystemSQLiteSqlConnectionHolder(string databaseFilename, DBSettings? dBSettings = default, int tableShards = 1)
        {
            _settings = dBSettings == null ? new DBSettings() : dBSettings;

            Source = databaseFilename;
            Connection = new SQLiteConnection($"Data source={Source}; Page Size={_settings.PageSize}; Journal Mode={_settings.JournalMode}; Synchronous={_settings.Synchronous};");
            Connection.Open();

            var command = string.Format(CultureInfo.InvariantCulture, PRAGMAS, _settings.LockingMode);
            using var cmd = new SQLiteCommand(command, Connection);
            cmd.ExecuteNonQuery();

            TableShards = tableShards;

            StartWriter();
            FlushCount = _settings.FlushCount;
        }

        public SQLiteConnection Connection { get; set; }
        public int FlushCount { get; set; } = -1;
        public bool KeepRunning { get; set; }
        public string Source { get; set; }
        public int TableShards { get; set; } = 1;
        public SQLiteTransaction? Transaction { get; set; }
        public ConcurrentQueue<WriteObject> WriteQueue { get; private set; } = new ConcurrentQueue<WriteObject>();

        public void BeginTransaction()
        {
            if (Transaction == null && Connection != null)
            {
                Transaction = Connection.BeginTransaction();
            }
        }

        public void Commit()
        {
            try
            {
                Transaction?.Commit();
            }
            catch (Exception e)
            {
                Log.Warning(e, $"Failed to commit data to {Source}, {e.StackTrace}");
            }
            finally
            {
                Transaction = null;
            }
        }

        public void Destroy()
        {
            ShutDown();
            try
            {
                File.Delete(Source);
            }
            catch (Exception e)
            {
                Log.Warning(e, $"Failed to delete database at {Source}");
            }
        }

        public void KeepFlushQueue()
        {
            KeepRunning = true;
            while (KeepRunning)
            {
                while (!WriteQueue.IsEmpty)
                {
                    if (FlushCount > 0)
                    {
                        if (RecordCount % FlushCount == FlushCount - 1)
                        {
                            Commit();
                            BeginTransaction();
                        }
                    }
                    WriteNext();
                }
                Thread.Sleep(1);
            }
        }

        public void WriteNext()
        {
            string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id, @result_type, @row_key, @identity, @serialized)";

            if (WriteQueue.TryDequeue(out WriteObject? objIn))
            {
                try
                {
                    using var cmd = new SQLiteCommand(SQL_INSERT_COLLECT_RESULT, Connection, Transaction);
                    cmd.Parameters.AddWithValue("@run_id", objIn.RunId);
                    cmd.Parameters.AddWithValue("@row_key", objIn.RowKey);
                    cmd.Parameters.AddWithValue("@identity", objIn.ColObj?.Identity);
                    cmd.Parameters.AddWithValue("@serialized", objIn.Serialized);
                    cmd.Parameters.AddWithValue("@result_type", objIn.ColObj?.ResultType);
                    cmd.ExecuteNonQuery();
                }
                catch (SQLiteException e)
                {
                    Log.Debug(exception: e, $"Error writing {objIn.ColObj?.Identity} to database.");
                }
                catch (NullReferenceException)
                {
                }
            }
        }

        internal void ShutDown()
        {
            KeepRunning = false;
            Connection.Close();
            Connection.Dispose();
            Transaction = null;
        }

        internal void StartWriter()
        {
            ((Action)(async () =>
            {
                await Task.Run(() => KeepFlushQueue()).ConfigureAwait(false);
            }))();
        }

        private const string PRAGMAS = "PRAGMA auto_vacuum = 0; PRAGMA locking_mode = {0};";
        private readonly DBSettings _settings;
        private int RecordCount { get; set; }
    }
}