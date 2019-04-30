// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.OpenPorts
{
    public class OpenPortCompare : BaseCompare
    {
        //private static readonly string SELECT_MODIFIED_SQL = @"select a.*
        //                                                       from network_ports a
        //                                                       join network_ports b
        //                                                       on a.service_name = b.service_name
        //                                                       where a.run_id = @first_run_id and b.run_id = @second_run_id
        //                                                       and (
        //                                                        a.display_name <> b.display_name
        //                                                        or a.start_type <> b.start_type
        //                                                        or a.current_state <> b.current_state
        //                                                       );";
        private static readonly string SELECT_INSERTED_SQL = "select * from network_ports b where b.run_id = @second_run_id and row_key not in (select row_key from network_ports a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select * from network_ports a where a.run_id = @first_run_id and row_key not in (select row_key from network_ports b where b.run_id = @second_run_id);";
        
        public OpenPortCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["ports_add"] = new List<OpenPortResult>(),
                ["ports_remove"] = new List<OpenPortResult>(),
                ["ports_modify"] = new List<OpenPortResult>(),
            };
            _type = RESULT_TYPE.PORT;
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

            

            var addObjects = new List<OpenPortResult>();
            var cmd = new SqliteCommand(SELECT_INSERTED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    var obj = new OpenPortResult()
                    {
                        Compare = new OpenPortObject()
                        {
                            address = reader["address"].ToString(),
                            family = reader["family"].ToString(),
                            port = reader["port"].ToString(),
                            processName = reader["process_name"].ToString(),
                            type = reader["type"].ToString()
                        },
                        Base = null,
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        BaseRowKey = "",
                        CompareRowKey = reader["row_key"].ToString(),
                        ResultType = RESULT_TYPE.PORT,
                        ChangeType = CHANGE_TYPE.CREATED
                    };
                    addObjects.Add(obj);
                    InsertResult(obj);
                }
            }
            Results["ports_add"] = addObjects;

            Log.Information("{0} {1} {2}", Strings.Get("Found"), addObjects.Count, Strings.Get("Created")); ;

            var removeObjects = new List<OpenPortResult>();
            cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    var obj = new OpenPortResult()
                    {
                        Base = new OpenPortObject()
                        {
                            address = reader["address"].ToString(),
                            family = reader["family"].ToString(),
                            port = reader["port"].ToString(),
                            processName = reader["process_name"].ToString(),
                            type = reader["type"].ToString()
                        },
                        Compare = null,
                        BaseRunId = firstRunId,
                        CompareRunId = secondRunId,
                        CompareRowKey = "",
                        BaseRowKey = reader["row_key"].ToString(),
                        ResultType = RESULT_TYPE.PORT,
                        ChangeType = CHANGE_TYPE.DELETED
                    };
                    removeObjects.Add(obj);
                    InsertResult(obj);
                }
            }
            Results["ports_remove"] = removeObjects;

            Log.Information("{0} {1} {2}", Strings.Get("Found"), removeObjects.Count, Strings.Get("Deleted"));
        }
    }
}