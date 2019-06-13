// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using AttackSurfaceAnalyzer.ObjectTypes;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.Certificates
{
    public class CertificateCompare : BaseCompare
    {
        private static readonly string SELECT_INSERTED_SQL = "select * from certificates b where b.run_id = @second_run_id and hash_plus_store not in (select hash_plus_store from certificates a where a.run_id = @first_run_id);";
        private static readonly string SELECT_DELETED_SQL = "select * from certificates a where a.run_id = @first_run_id and hash_plus_store not in (select hash_plus_store from certificates b where b.run_id = @second_run_id);";

        public CertificateCompare()
        {
            Results = new Dictionary<string, object>
            {
                ["certs_add"] = new List<CompareResult>(),
                ["certs_remove"] = new List<CompareResult>(),
                ["certs_modify"] = new List<CompareResult>(),
            };
            _type = RESULT_TYPE.CERTIFICATE;
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
                        var obj = new CertificateResult()
                        {
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            CompareRowKey = reader["row_key"].ToString(),
                            Compare = new CertificateObject()
                            {
                                StoreLocation = reader["store_location"].ToString(),
                                StoreName = reader["store_name"].ToString(),
                                CertificateHashString = reader["hash"].ToString(),
                                Subject = reader["cn"].ToString()
                            },
                            ChangeType = CHANGE_TYPE.CREATED,
                            ResultType = RESULT_TYPE.CERTIFICATE
                        };
                        addObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["certs_add"] = addObjects;

                Log.Information(Strings.Get("FoundCreated"), addObjects.Count);

                var removeObjects = new List<CompareResult>();
                cmd = new SqliteCommand(SELECT_DELETED_SQL, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@first_run_id", firstRunId);
                cmd.Parameters.AddWithValue("@second_run_id", secondRunId);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var obj = new CertificateResult()
                        {
                            BaseRunId = firstRunId,
                            CompareRunId = secondRunId,
                            BaseRowKey = reader["row_key"].ToString(),
                            Base = new CertificateObject()
                            {
                                StoreLocation = reader["store_location"].ToString(),
                                StoreName = reader["store_name"].ToString(),
                                CertificateHashString = reader["hash"].ToString(),
                                Subject = reader["cn"].ToString()
                            },
                            ChangeType = CHANGE_TYPE.DELETED,
                            ResultType = RESULT_TYPE.CERTIFICATE
                        };
                        removeObjects.Add(obj);
                        InsertResult(obj);
                    }
                }
                Results["certs_remove"] = removeObjects;

                Log.Information(Strings.Get("FoundDeleted"), addObjects.Count);
            }
            catch (Exception e)
            {
                Log.Debug(e.StackTrace);
                Log.Debug(e.Message);
                Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error,e);
            }
        }
    }
}