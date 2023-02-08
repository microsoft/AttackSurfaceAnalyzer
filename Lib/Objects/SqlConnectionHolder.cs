 // Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Objects
{
    public class SqlConnectionHolder
    {
        private const string SQL_INSERT_COLLECT_RESULT = "insert or ignore into collect (run_id, result_type, row_key, identity, serialized) values ";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (first_run_id, second_run_id, analyses_hash, result_type, level, identity, first_id, second_id, meta_serialized) values";
        private const string SQL_GET_RESULTS_BY_ROW_ID = "select * from collect where _ROWID_ = @rowid";

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

            // Max number of variables determined by sqlite library at compile time
            if (settings.BatchSize > 199)
            {
                Log.Warning("Maximum batch size is 199. Setting Batch size to 199");
                settings.BatchSize = 199;
            }

            innerQueue = new WriteObject[settings.BatchSize];
            innerCompareResultQueue = new CompareResult[settings.BatchSize];

            _ = Task.Factory.StartNew(() => KeepFlushQueue());
        }

        public SqliteConnection Connection { get; set; }
        public bool IsWriting { get; private set; }
        public bool KeepRunning { get; set; }
        public string Source { get; set; }
        public SqliteTransaction? Transaction { get; set; }
        public ConcurrentStack<WriteObject> WriteQueue { get; private set; } = new ConcurrentStack<WriteObject>();
        public ConcurrentStack<CompareResult> CompareWriteQueue { get; private set; } = new ConcurrentStack<CompareResult>();

        private void WriteNextCompare()
        {
            IsWriting = true;

            var count = Math.Min(settings.BatchSize, WriteQueue.Count);
            var actual = CompareWriteQueue.TryPopRange(innerCompareResultQueue, 0, count);

            if (actual > 0)
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append(SQL_INSERT_FINDINGS_RESULT);
                using var cmd = new SqliteCommand(string.Empty, Connection, Transaction);
                for (int i = 0; i < actual; i++)
                {
                    CompareResult compareResult = innerCompareResultQueue[actual];
                    stringBuilder.Append($"(@first_run_id_{i}, @second_run_id_{i}, @analyses_hash_{i}, @result_type_{i}, @level_{i}, @identity_{i}, @first_serialized_{i}, @second_serialized_{i}, @meta_serialized_{i}),");
                    cmd.Parameters.AddWithValue($"@first_run_id_{i}", compareResult.BaseRunId ?? string.Empty);
                    cmd.Parameters.AddWithValue($"@second_run_id_{i}", compareResult.CompareRunId);
                    cmd.Parameters.AddWithValue($"@result_type_{i}", compareResult.ResultType);
                    cmd.Parameters.AddWithValue($"@level_{i}", compareResult.Analysis);
                    cmd.Parameters.AddWithValue($"@identity_{i}", compareResult.Identity);
                    cmd.Parameters.AddWithValue($"@first_id_{i}", compareResult.BaseRowId);
                    cmd.Parameters.AddWithValue($"@second_id_{i}", compareResult.CompareRowId);
                    cmd.Parameters.AddWithValue($"@analyses_hash_{i}", compareResult.AnalysesHash);
                    cmd.Parameters.AddWithValue($"@meta_serialized_{i}", SerializationUtils.DehydrateCompareResult(compareResult));
                }
                // remove trailing comma
                stringBuilder.Remove(stringBuilder.Length - 1, 1);
                cmd.CommandText = stringBuilder.ToString();

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Log.Warning(e, $"Error writing to database.");
                }
            }
            IsWriting = false;
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
                while (WriteQueue.Count > 0)
                {
                    WriteNext();
                }

                while (CompareWriteQueue.Count > 0)
                {
                    WriteNextCompare();
                }
                Thread.Sleep(1);
            }
        }

        internal void ShutDown()
        {
            KeepRunning = false;
            Connection.Close();
            Connection.Dispose();
            Transaction = null;
        }

        private const string PRAGMAS = "PRAGMA auto_vacuum = 0; PRAGMA synchronous = {0}; PRAGMA journal_mode = {1}; PRAGMA page_size = {2}; PRAGMA locking_mode = {3};";
        private readonly WriteObject[] innerQueue;
        private readonly CompareResult[] innerCompareResultQueue;
        private readonly DBSettings settings;

        private void WriteNext()
        {
            IsWriting = true;

            var count = Math.Min(settings.BatchSize, WriteQueue.Count);
            var actual = WriteQueue.TryPopRange(innerQueue, 0, count);

            if (actual > 0)
            {
                var stringBuilder = new StringBuilder();
                stringBuilder.Append(SQL_INSERT_COLLECT_RESULT);
                using var cmd = new SqliteCommand(string.Empty, Connection, Transaction);

                for (int i = 0; i < actual; i++)
                {
                    stringBuilder.Append($"(@run_id_{i}, @result_type_{i}, @row_key_{i}, @identity_{i}, @serialized_{i}),");
                    cmd.Parameters.AddWithValue($"@run_id_{i}", innerQueue[i].RunId);
                    cmd.Parameters.AddWithValue($"@result_type_{i}", innerQueue[i].ColObj.ResultType);
                    cmd.Parameters.AddWithValue($"@row_key_{i}", innerQueue[i].RowKey);
                    cmd.Parameters.AddWithValue($"@identity_{i}", innerQueue[i].ColObj.Identity);
                    cmd.Parameters.AddWithValue($"@serialized_{i}", innerQueue[i].Serialized);
                }
                // remove trailing comma
                stringBuilder.Remove(stringBuilder.Length - 1, 1);
                cmd.CommandText = stringBuilder.ToString();

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    Log.Warning(e, $"Error writing to database.");
                }
            }

            IsWriting = false;
        }

        public CollectObject? GetCollectObjectByRowId(int rowid, RESULT_TYPE resultType)
        {
            using var cmd = new SqliteCommand(SQL_GET_RESULTS_BY_ROW_ID, Connection, Transaction);
            cmd.Parameters.AddWithValue("@rowid", rowid);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                return SerializationUtils.Hydrate((byte[])reader["serialized"], resultType);
            }

            return null;
        }
    }
}