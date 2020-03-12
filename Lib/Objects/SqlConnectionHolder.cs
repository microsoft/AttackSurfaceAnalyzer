using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Objects
{
    public class SqlConnectionHolder
    {
        public SqliteTransaction Transaction { get; set; }
        public SqliteConnection Connection { get; set; }
        public ConcurrentQueue<WriteObject> WriteQueue { get; private set; } = new ConcurrentQueue<WriteObject>();
        public bool KeepRunning { get; set; }
        public string Source { get; set; }
        private int RecordCount { get; set; }
        public int FlushCount { get; set; } = -1;

        private readonly DBSettings settings;

        private const string PRAGMAS = "PRAGMA auto_vacuum = 0; PRAGMA synchronous = {0}; PRAGMA journal_mode = {1}; PRAGMA page_size = {2}; PRAGMA locking_mode = {3};";

        public SqlConnectionHolder(string databaseFilename, DBSettings dBSettings = default)
        {
            settings = dBSettings;

            Source = databaseFilename;
            Connection = new SqliteConnection($"Data source={Source}");
            Connection.Open();

            if (settings != null)
            {
                var command = string.Format(CultureInfo.InvariantCulture, PRAGMAS, settings.Synchronous, settings.JournalMode, settings.PageSize, settings.LockingMode);
                using var cmd = new SqliteCommand(command, Connection);
                cmd.ExecuteNonQuery();
            }

            StartWriter();
            FlushCount = settings.FlushCount;
        }

        internal void StartWriter()
        {
            ((Action)(async () =>
            {
                await Task.Run(() => KeepFlushQueue()).ConfigureAwait(false);
            }))();
        }

        public void Destroy()
        {
            ShutDown();
            Connection = null;
            Transaction = null;
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
                Transaction.Commit();
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

        public void WriteNext()
        {
            string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id, @result_type, @row_key, @identity, @serialized)";

            WriteQueue.TryDequeue(out WriteObject objIn);

            try
            {
                using var cmd = new SqliteCommand(SQL_INSERT_COLLECT_RESULT, Connection, Transaction);
                cmd.Parameters.AddWithValue("@run_id", objIn.RunId);
                cmd.Parameters.AddWithValue("@row_key", objIn.GetRowKey());
                cmd.Parameters.AddWithValue("@identity", objIn.ColObj.Identity);
                cmd.Parameters.AddWithValue("@serialized", objIn.GetSerialized());
                cmd.Parameters.AddWithValue("@result_type", objIn.ColObj.ResultType);
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException e)
            {
                Log.Debug(exception: e, $"Error writing {objIn.ColObj.Identity} to database.");
            }
            catch (NullReferenceException)
            {
            }
        }

        internal void ShutDown()
        {
            KeepRunning = false;
            Connection.Close();
            Connection = null;
            Transaction = null;
        }
    }
}
