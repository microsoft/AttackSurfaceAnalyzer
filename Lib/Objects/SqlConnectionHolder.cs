using System;
using System.Collections.Concurrent;
using System.Data.SQLite;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace AttackSurfaceAnalyzer.Objects
{
    public class SqlConnectionHolder
    {
        public SQLiteTransaction Transaction {get; set;}
        public SQLiteConnection Connection {get; set;}
        public ConcurrentQueue<WriteObject> WriteQueue { get; private set; }
        public bool KeepRunning { get; set; }

        public SqlConnectionHolder(SQLiteConnection connection, SQLiteTransaction transaction = null)
        {
            Connection = connection;
            Transaction = transaction;
            WriteQueue = new ConcurrentQueue<WriteObject>();
            StartWriter();
        }

        internal void StartWriter()
        {
            ((Action)(async () =>
            {
                await Task.Run(() => KeepFlushQueue()).ConfigureAwait(false);
            }))();
        }

        public void KeepFlushQueue()
        {
            KeepRunning = true;
            while (KeepRunning)
            {
                while (!WriteQueue.IsEmpty)
                {
                    WriteNext();
                }
                Thread.Sleep(1);
            }
        }

        public void WriteNext()
        {
            string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id, @result_type, @row_key, @identity, @serialized)";

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
    }
}
