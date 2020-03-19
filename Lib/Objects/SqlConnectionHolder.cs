using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Objects
{
    public class SqlConnectionHolder
    {
        public SqliteTransaction? Transaction { get; set; }
        public SqliteConnection Connection { get; set; }
        public ConcurrentQueue<WriteObject> WriteQueue { get; private set; } = new ConcurrentQueue<WriteObject>();
        public bool KeepRunning { get; set; }
        public string Source { get; set; }
        private int RecordCount { get; set; }

        private readonly DBSettings settings;

        private const string PRAGMAS = "PRAGMA auto_vacuum = 0; PRAGMA synchronous = {0}; PRAGMA journal_mode = {1}; PRAGMA page_size = {2}; PRAGMA locking_mode = {3};";

        public SqlConnectionHolder(string databaseFilename, DBSettings? dBSettings = null)
        {
            settings = dBSettings ?? new DBSettings();

            Source = databaseFilename;
            Connection = new SqliteConnection($"Data source={Source}");
            Connection.Open();

            string command = string.Format(CultureInfo.InvariantCulture,
                                           PRAGMAS,
                                           settings.Synchronous,
                                           settings.JournalMode,
                                           settings.PageSize,
                                           settings.LockingMode);
            using var cmd = new SqliteCommand(command, Connection);
            cmd.ExecuteNonQuery();

            if (settings.BatchSize < 1)
            {
                settings.BatchSize = 1;
            }

            StartWriter();
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
                    if (settings.FlushCount > 0)
                    {
                        if (RecordCount % settings.FlushCount == settings.FlushCount - 1)
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

        public void WriteNext()
        {
            string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id_0, @result_type_0, @row_key_0, @identity_0, @serialized_0)";

            var innerQueue = new List<WriteObject>();
            
            while (innerQueue.Count < settings.BatchSize && WriteQueue.TryDequeue(out WriteObject objIn))
            {
                innerQueue.Add(objIn);
            }

            var stringBuilder = new StringBuilder();
            stringBuilder.Append(SQL_INSERT_COLLECT_RESULT);

            for (int i = 1; i < innerQueue.Count; i++)
            {
                stringBuilder.Append($",(@run_id_{i}, @result_type_{i}, @row_key_{i}, @identity_{i}, @serialized_{i})");
            }

            using var cmd = new SqliteCommand(SQL_INSERT_COLLECT_RESULT, Connection, Transaction);

            for (int i = 0; i < innerQueue.Count; i++)
            {
                cmd.Parameters.AddWithValue($"@run_id_{i}", innerQueue[i].RunId);
                cmd.Parameters.AddWithValue($"@row_key_{i}", innerQueue[i].GetRowKey());
                cmd.Parameters.AddWithValue($"@identity_{i}", innerQueue[i].ColObj?.Identity);
                cmd.Parameters.AddWithValue($"@serialized_{i}", innerQueue[i].GetSerialized());
                cmd.Parameters.AddWithValue($"@result_type_{i}", innerQueue[i].ColObj?.ResultType);
            }

            try
            {
                cmd.ExecuteNonQuery();
            }
            catch (SqliteException e)
            {
                Log.Debug(exception: e, $"Error writing to database.");
            }
            catch (NullReferenceException)
            {
            }
        }

        internal void ShutDown()
        {
            KeepRunning = false;
            Connection.Close();
            Connection.Dispose();
            Transaction = null;
        }
    }
}
