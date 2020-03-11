using System;
using System.IO;
using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;
using System.Threading;
using System.Threading.Tasks;
using Serilog;
using System.Globalization;

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

        private const string PRAGMAS = "PRAGMA auto_vacuum = 0; PRAGMA synchronous = OFF";
        private const string JOURNAL_MODE = "PRAGMA journal_mode = {0};";

        public SqlConnectionHolder(string databaseFilename, int flushCount = -1, string journalMode = "OFF")
        {
            Source = databaseFilename;
            Connection = new SqliteConnection($"Data source={Source}");
            Connection.Open();

            using var cmd = new SqliteCommand(PRAGMAS, Connection);
            cmd.ExecuteNonQuery();

            cmd.CommandText = string.Format(CultureInfo.InvariantCulture,JOURNAL_MODE, journalMode);
            cmd.ExecuteNonQuery();

            StartWriter();
            FlushCount = flushCount;
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
            if (Connection != null)
            {
                Connection.Close();
            }
            Connection = null;
            Transaction = null;
            try{
                File.Delete(Source);
            }
            catch(Exception e){
                Log.Warning(e,$"Failed to delete database at {Source}");
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
                        if (RecordCount % FlushCount == FlushCount-1)
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
                Log.Warning(e,$"Failed to commit data to {Source}, {e.StackTrace}");
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
    }
}
