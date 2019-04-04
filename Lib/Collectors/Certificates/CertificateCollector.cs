// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.Certificates
{
    /// <summary>
    /// Collects metadata from the local file system.
    /// </summary>
    public class CertificateCollector : BaseCollector
    {

        private static readonly string SQL_TRUNCATE = "delete from certificates where run_id=@run_id";
        private static readonly string SQL_INSERT = "insert into certificates (run_id, row_key, store_location, store_name, hash, hash_plus_store, cn, pkcs12) values (@run_id, @row_key, @store_location, @store_name, @hash, @hash_plus_store, @cn, @pkcs12)";

        private int recordCounter = 0;

        public CertificateCollector(string runId)
        {
            this.runId = runId;
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
            cmd.ExecuteNonQuery();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public void Write(StoreLocation storeLocation, StoreName storeName, X509Certificate2 obj)
        {
            try
            {
                recordCounter++;
                var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction);
                cmd.Parameters.AddWithValue("@run_id", runId);
                cmd.Parameters.AddWithValue("@store_location", storeLocation.ToString());
                cmd.Parameters.AddWithValue("@store_name", storeName.ToString());
                cmd.Parameters.AddWithValue("@hash", obj.GetCertHashString());
                cmd.Parameters.AddWithValue("@hash_plus_store", obj.GetCertHashString() + storeLocation.ToString() + storeName.ToString());
                cmd.Parameters.AddWithValue("@cn", obj.Subject);

                if (obj.HasPrivateKey)
                {
                    cmd.Parameters.AddWithValue("@pkcs12", "redacted");
                }
                else
                {
                    cmd.Parameters.AddWithValue("@pkcs12", obj.Export(X509ContentType.Pkcs12));
                }

                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(runId + recordCounter));

                cmd.ExecuteNonQuery();
            }
            catch (NullReferenceException e)
            {
                Log.Warning(e.StackTrace);
            }
            catch (Microsoft.Data.Sqlite.SqliteException e)
            {
                Log.Warning(e.Message);
                //This catches duplicate certificates
            }
        }

        public override void Execute()
        {
            if (!CanRunOnPlatform())
            {
                return;
            }

            Start();
            Truncate(runId);

            foreach (StoreLocation storeLocation in (StoreLocation[])Enum.GetValues(typeof(StoreLocation)))
            {
                foreach (StoreName storeName in (StoreName[])Enum.GetValues(typeof(StoreName)))
                {
                    try
                    {
                        X509Store store = new X509Store(storeName, storeLocation);
                        store.Open(OpenFlags.ReadOnly);

                        foreach (X509Certificate2 certificate in store.Certificates)
                        {
                            Write(storeLocation, storeName, certificate);
                        }
                        store.Close();
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e.StackTrace);
                        Log.Debug(e.GetType().ToString());
                        Log.Debug(e.Message);
                    }
                }
            }
            DatabaseManager.Commit();
            Stop();
        }
    }
}