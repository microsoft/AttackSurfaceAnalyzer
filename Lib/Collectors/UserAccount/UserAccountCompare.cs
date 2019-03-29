// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace AttackSurfaceAnalyzer.Collectors.UserAccount
{
    public class UserAccountCompare : BaseCompare
    {
        private static readonly string SELECT_MODIFIED_SQL = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', b.row_key as 'b_row_key', b.serialized as 'b_serialized' from user_account a, user_account b where (((a.name <> '' or b.name <> '') and a.name = b.name) or ((a.uid <> '' or b.uid <> '') and a.uid = b.uid)) and a.run_id = @first_run_id and b.run_id = @second_run_id and a.row_key <> b.row_key;";
        private static readonly string SELECT_INSERTED_SQL = "select b.serialized, b.row_key from user_account b where b.run_id = @second_run_id and row_key not in (select row_key from user_account a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select a.serialized, a.row_key from user_account a where a.run_id = @first_run_id and row_key not in (select row_key from user_account b where b.run_id = @second_run_id);";

        public UserAccountCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["users_add"] = new List<UserAccountResult>(), 
                ["users_remove"] = new List<UserAccountResult>(),
                ["users_modify"] = new List<UserAccountResult>(),
            };
            _type = RESULT_TYPE.USER;
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

            // Which new users were created?
            var addObjects = new List<UserAccountResult>();
            var cmd = new SqliteCommand(SELECT_INSERTED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
            cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
            try
            {
                using (SqliteDataReader reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new UserAccountResult()
                        {
                            Compare = JsonConvert.DeserializeObject<UserAccountObject>(reader["serialized"].ToString()),
                            CompareRowKey = reader["row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.USER,
                            ChangeType = CHANGE_TYPE.CREATED
                        };
                        addObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["users_add"] = addObjects;

                // Which users are gone?
                var removeObjects = new List<UserAccountResult>();
                cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new UserAccountResult()
                        {
                            Base = JsonConvert.DeserializeObject<UserAccountObject>(reader["serialized"].ToString()),
                            BaseRowKey = reader["row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.USER,
                            ChangeType = CHANGE_TYPE.DELETED
                        };
                        removeObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["users_remove"] = removeObjects;

                // Which users were modified?
                var modifyObjects = new List<UserAccountResult>();
                cmd = new SqliteCommand(SELECT_MODIFIED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Logger.Instance.Warn("Modified row: {0}", reader["row_key"]?.ToString());
                        var obj = new UserAccountResult()
                        {
                            Base = JsonConvert.DeserializeObject<UserAccountObject>(reader["a_serialized"].ToString()),
                            Compare = JsonConvert.DeserializeObject<UserAccountObject>(reader["b_serialized"].ToString()),
                            BaseRowKey = reader["a_row_key"].ToString(),
                            CompareRowKey = reader["b_row_key"].ToString(),
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            ResultType = RESULT_TYPE.USER,
                            ChangeType = CHANGE_TYPE.MODIFIED
                        };
                        modifyObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["users_modify"] = modifyObjects;
                DatabaseManager.Commit();
            }
            catch(Exception e)
            {
                Logger.Instance.Warn(e.StackTrace);
                Logger.Instance.Warn(e.GetType());
            }
        }
    }
}