// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class BaseCompare
    {
        private static readonly string INSERT_RESULT_SQL = "insert into compared (base_run_id, compare_run_id, change_type, base_row_key, compare_row_key, data_type) values (@base_run_id, @compare_run_id, @change_type, @base_row_key, @compare_row_key, @data_type);";

        public Dictionary<string, object> Results { get; protected set; }

        public BaseCompare()
        {
            Results = new Dictionary<string, object>();
        }

        private int numResults = 0;

        public CollectObject Hydrate(RawCollectResult res)
        {
            switch (res.ResultType)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(res.Serialized);
                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(res.Serialized);
                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(res.Serialized);
                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(res.Serialized);
                case RESULT_TYPE.SERVICES:
                    return JsonConvert.DeserializeObject<ServiceObject>(res.Serialized);
                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(res.Serialized);
                default:
                    return null;
            }
        }

        public void Compare(string firstRunId, string secondRunId)
        {
            if (firstRunId == null)
            {
                throw new ArgumentNullException("firstRunId");
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException("secondRunId");
            }
            List<RawCollectResult> addRows = DatabaseManager.GetMissingFromFirst(firstRunId, secondRunId);
            List<RawCollectResult> removeObjects = DatabaseManager.GetMissingFromFirst(secondRunId, firstRunId);
            List<RawModifiedResult> modifyObjects = DatabaseManager.GetModified(firstRunId, secondRunId);

            Dictionary<string, List<CompareResult>> results = new Dictionary<string, List<CompareResult>>();

            foreach (var added in addRows)
            {
                var obj = new CompareResult()
                {
                    Compare = Hydrate(added),
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    CompareRowKey = added.RowKey,
                    ChangeType = CHANGE_TYPE.CREATED,
                    ResultType = added.ResultType,
                    Identity = added.Identity
                };

                if (results.ContainsKey(String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString()))){
                    results[String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", added.ResultType.ToString(), CHANGE_TYPE.CREATED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (var removed in removeObjects)
            {
                var obj = new CompareResult()
                {
                    Base = Hydrate(removed),
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = removed.RowKey,
                    ChangeType = CHANGE_TYPE.DELETED,
                    ResultType = removed.ResultType,
                    Identity = removed.Identity
                };
                if (results.ContainsKey(String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString()))){
                    results[String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", removed.ResultType.ToString(), CHANGE_TYPE.DELETED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (var modified in modifyObjects)
            {
                var obj = new CompareResult()
                {
                    Base = Hydrate(modified.First),
                    Compare = Hydrate(modified.Second),
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = modified.First.RowKey,
                    CompareRowKey = modified.Second.RowKey,
                    ChangeType = CHANGE_TYPE.MODIFIED,
                    ResultType = modified.First.ResultType,
                    Identity = modified.First.Identity
                };
                if (results.ContainsKey(String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())))
                {
                    results[String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())].Add(obj);
                }
                else
                {
                    results[String.Format("{0}_{1}", modified.First.ResultType.ToString(), CHANGE_TYPE.MODIFIED.ToString())] = new List<CompareResult>() { obj };
                }
            }
            foreach (string key in results.Keys)
            {
                Results[key] = results[key];
            }
        }


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