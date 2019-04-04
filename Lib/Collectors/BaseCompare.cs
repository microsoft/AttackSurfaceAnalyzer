// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public abstract class BaseCompare
    {
        private static readonly string INSERT_RESULT_SQL = "insert into compared (base_run_id, compare_run_id, change_type, base_row_key, compare_row_key, data_type) values (@base_run_id, @compare_run_id, @change_type, @base_row_key, @compare_row_key, @data_type);";

        public Dictionary<string, object> Results { get; protected set; }

        public BaseCompare()
        {
            Results = new Dictionary<string, object>();
        }

        private int numResults = 0;

        public abstract void Compare(string firstRunId, string secondRunId);

        public bool TryCompare(string firstRunId, string secondRunId)
        {
            Start();
            try
            {
                
                    Compare(firstRunId, secondRunId);
                

                Stop();
                return true;
            }
            catch(Exception ex)
            {
                Log.Warning(ex, "Exception from Compare(): {0}", ex.StackTrace);
                Log.Warning(ex.Message);
                Stop();
                return false;
            }
        }

        protected void InsertResult(CompareResult obj)
        {
            numResults++;
            var cmd = new SqliteCommand(INSERT_RESULT_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@base_run_id", obj.BaseRunId);
            cmd.Parameters.AddWithValue("@compare_run_id", obj.CompareRunId);
            cmd.Parameters.AddWithValue("@change_type", obj.ChangeType);
            cmd.Parameters.AddWithValue("@base_row_key", obj.BaseRowKey ?? "");
            cmd.Parameters.AddWithValue("@compare_row_key", obj.CompareRowKey ?? "");
            cmd.Parameters.AddWithValue("@data_type", obj.ResultType);
            cmd.ExecuteNonQuery();
        }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        protected RESULT_TYPE _type = RESULT_TYPE.UNKNOWN;

        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;

        }

        public void Stop()
        {
           _running = (numResults == 0) ? RUN_STATUS.NO_RESULTS : RUN_STATUS.COMPLETED;
        }

        public int GetNumResults()
        {
            return numResults;
        }
    }
}