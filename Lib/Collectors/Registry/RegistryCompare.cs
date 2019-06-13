// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.Registry
{
    public class RegistryCompare : BaseCompare
    {
        private static readonly string SELECT_MODIFIED_SQL = @"select a.key as 'a_key', a.serialized as 'a_serialized', a.row_key as 'a_row_key', b.serialized as 'b_serialized', b.row_key as 'b_row_key' from registry a, registry b where a.run_id=@first_run_id and b.run_id=@second_run_id and a.key = b.key and (a.row_key != b.row_key)";

        private static readonly string SELECT_INSERTED_SQL = "select * from registry b where b.run_id = @second_run_id and b.key not in (select key from registry a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select * from registry a where a.run_id = @first_run_id and a.key not in (select key from registry b where b.run_id = @second_run_id);";

        public RegistryCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["registry_add"] = new List<CompareResult>(),
                ["registry_remove"] = new List<CompareResult>(),
                ["registry_modify"] = new List<CompareResult>(),
            };
            _type = RESULT_TYPE.REGISTRY;
        }

        public override void Compare(string firstRunId, string secondRunId)
        {
            try
            {
                if (firstRunId == null)
                {
                    throw new ArgumentNullException("firstRunId");
                }
                if (secondRunId == null)
                {
                    throw new ArgumentNullException("secondRunId");
                }

                

                var addObjects = new List<CompareResult>();
                var cmd = new SqliteCommand(SELECT_INSERTED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new RegistryResult()
                        {
                            Compare = JsonConvert.DeserializeObject<RegistryObject>(reader["serialized"].ToString()),
                            CompareRowKey = reader["row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.REGISTRY,
                            ChangeType = CHANGE_TYPE.CREATED
                        };
                        addObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["registry_add"] = addObjects;

                Log.Information(Strings.Get("FoundCreated"), addObjects.Count);

                var removeObjects = new List<CompareResult>();
                cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new RegistryResult()
                        {
                            Base = JsonConvert.DeserializeObject<RegistryObject>(reader["serialized"].ToString()),
                            BaseRowKey = reader["row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.REGISTRY,
                            ChangeType = CHANGE_TYPE.DELETED
                        };
                        removeObjects.Add(obj);
                        InsertResult(obj);
                    }
                }

                Results["registry_remove"] = removeObjects;

                Log.Information(Strings.Get("FoundDeleted"), addObjects.Count);

                var modifyObjects = new List<CompareResult>();
                cmd = new SqliteCommand(SELECT_MODIFIED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new RegistryResult()
                        {
                            Base = JsonConvert.DeserializeObject<RegistryObject>(reader["a_serialized"].ToString()),
                            Compare = JsonConvert.DeserializeObject<RegistryObject>(reader["b_serialized"].ToString()),
                            BaseRowKey = reader["a_row_key"].ToString(),
                            CompareRowKey = reader["b_row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.REGISTRY,
                            ChangeType = CHANGE_TYPE.MODIFIED
                        };
                        modifyObjects.Add(obj);
                        InsertResult(obj);
                    }
                }

                Results["registry_modify"] = modifyObjects;

                Log.Information(Strings.Get("FoundModified"), addObjects.Count);
            }
            catch (Exception e)
            {
                Log.Information(e.Message);
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
        }
    }
}