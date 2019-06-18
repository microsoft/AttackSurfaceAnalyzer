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
    public class FileSystemCompare : BaseCompare
    {
        private static readonly string SELECT_MODIFIED_SQL = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', b.row_key as 'b_row_key', b.serialized as 'b_serialized' from file_system a, file_system b where a.run_id=@first_run_id and b.run_id=@second_run_id and a.path = b.path and a.row_key != b.row_key";

        private static readonly string SELECT_INSERTED_SQL = "select row_key, serialized from file_system b where b.run_id = @second_run_id and path not in (select path from file_system a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select row_key, serialized from file_system a where a.run_id = @first_run_id and path not in (select path from file_system b where b.run_id = @second_run_id);";


        public FileSystemCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["files_add"] = new List<CompareResult>(),
                ["files_remove"] = new List<CompareResult>(),
                ["files_modify"] = new List<CompareResult>(),
            };
            _type = RESULT_TYPE.FILE;
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
                        var obj = new FileSystemResult()
                        {
                            Compare = JsonConvert.DeserializeObject<FileSystemObject>(reader["serialized"].ToString()),
                            Base = null,
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            CompareRowKey = reader["row_key"].ToString(),
                            BaseRowKey = "",
                            ChangeType = CHANGE_TYPE.CREATED,
                            ResultType = RESULT_TYPE.FILE
                        };
                        addObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["files_add"] = addObjects;
                Log.Information("Found {0} Created", addObjects.Count);

                var removeObjects = new List<CompareResult>();
                cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new FileSystemResult()
                        {
                            Base = JsonConvert.DeserializeObject<FileSystemObject>(reader["serialized"].ToString()),
                            Compare = null,
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            BaseRowKey = reader["row_key"].ToString(),
                            ChangeType = CHANGE_TYPE.DELETED,
                            ResultType = RESULT_TYPE.FILE
                        };
                        removeObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["files_remove"] = removeObjects;

                Log.Information("Found {0} Deleted", removeObjects.Count);

                var modifyObjects = new List<CompareResult>();
                cmd = new SqliteCommand(SELECT_MODIFIED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new FileSystemResult()
                        {
                            Base = JsonConvert.DeserializeObject<FileSystemObject>(reader["a_serialized"].ToString()),
                            Compare = JsonConvert.DeserializeObject<FileSystemObject>(reader["b_serialized"].ToString()),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            CompareRowKey = reader["b_row_key"].ToString(),
                            BaseRowKey = reader["a_row_key"].ToString(),
                            ChangeType = CHANGE_TYPE.MODIFIED,
                            ResultType = RESULT_TYPE.FILE
                        };
                        modifyObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["files_modify"] = modifyObjects;

                Log.Information("Found {0} Modified", modifyObjects.Count);
            }
            catch (Exception e)
            {
                // Debugging
                Log.Information(e.Message);
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
            }
        }
    }
}