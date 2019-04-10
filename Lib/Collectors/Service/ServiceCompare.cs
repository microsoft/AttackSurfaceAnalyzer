// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.Service
{
    public class ServiceCompare : BaseCompare
    {
        private static readonly string SELECT_MODIFIED_SQL = @"select a.serialized as 'a_serialized', b.serialized as 'b_serialized', a.row_key as 'a_row_key', b.row_key as 'b_row_key'
                                                               from win_system_service a
                                                               join win_system_service b
                                                               on a.service_name = b.service_name
                                                               where a.run_id = @first_run_id and b.run_id = @second_run_id
                                                               and (
                                                                a.row_key <> b.row_key
                                                               );";
        private static readonly string SELECT_INSERTED_SQL = "select * from win_system_service b where b.run_id = @second_run_id and service_name not in (select service_name from win_system_service a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select * from win_system_service a where a.run_id = @first_run_id and service_name not in (select service_name from win_system_service b where b.run_id = @second_run_id);";
        

        public ServiceCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["services_add"] = new List<ServiceResult>(),
                ["services_remove"] = new List<ServiceResult>(),
                ["services_modify"] = new List<ServiceResult>(),
            };
            _type = RESULT_TYPE.SERVICES;
        }

        public override void Compare(string firstRunId, string secondRunId)
        {
            if (firstRunId == null)
            {
                throw new ArgumentNullException("firstRunId");
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException("secondRunId");
            }

            var addObjects = new List<ServiceResult>();
            var cmd = new SqliteCommand(SELECT_INSERTED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    var obj = new ServiceResult()
                    {
                        Compare = JsonConvert.DeserializeObject<ServiceObject>(reader["serialized"].ToString()),
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        CompareRowKey = reader["row_key"].ToString(),
                        ChangeType = CHANGE_TYPE.CREATED,
                        ResultType = RESULT_TYPE.SERVICES
                    };
                    addObjects.Add(obj);
                    InsertResult(obj);
                }
            }
            Results["services_add"] = addObjects;

            Log.Information("{0} {1} {2}", Strings.Get("Found"), addObjects.Count, Strings.Get("Created")); ;

            var removeObjects = new List<ServiceResult>();
            cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    var obj = new ServiceResult()
                    {
                        Base = JsonConvert.DeserializeObject<ServiceObject>(reader["serialized"].ToString()),
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        BaseRowKey = reader["row_key"].ToString(),
                        ChangeType = CHANGE_TYPE.DELETED,
                        ResultType = RESULT_TYPE.SERVICES
                    };
                    removeObjects.Add(obj);
                    InsertResult(obj);
                }
            }
            Results["services_remove"] = removeObjects;

            Log.Information("{0} {1} {2}", Strings.Get("Found"), removeObjects.Count, Strings.Get("Deleted")); ;

            var modifyObjects = new List<ServiceResult>();
            cmd = new SqliteCommand(SELECT_MODIFIED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    var obj = new ServiceResult()
                    {
                        Base = JsonConvert.DeserializeObject<ServiceObject>(reader["a_serialized"].ToString()),
                        Compare = JsonConvert.DeserializeObject<ServiceObject>(reader["b_serialized"].ToString()),
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        BaseRowKey = reader["a_row_key"].ToString(),
                        CompareRowKey = reader["b_row_key"].ToString(),
                        ChangeType = CHANGE_TYPE.MODIFIED,
                        ResultType = RESULT_TYPE.SERVICES
                    };
                    modifyObjects.Add(obj);
                    InsertResult(obj);
                }
            }
            Results["services_modify"] = modifyObjects;

            Log.Information("{0} {1} {2}", Strings.Get("Found"), modifyObjects.Count, Strings.Get("Modified")); ;
        }
    }
}