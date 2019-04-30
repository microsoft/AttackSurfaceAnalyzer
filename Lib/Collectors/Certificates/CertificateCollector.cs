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
using AttackSurfaceAnalyzer.ObjectTypes;
using System.Text.RegularExpressions;
using System.Text;

namespace AttackSurfaceAnalyzer.Collectors.Certificates
{
    /// <summary>
    /// Collects metadata from the local file system.
    /// </summary>
    public class CertificateCollector : BaseCollector
    {

        private static readonly string SQL_TRUNCATE = "delete from certificates where run_id=@run_id";
        private static readonly string SQL_INSERT = "insert into certificates (run_id, row_key, store_location, store_name, hash, hash_plus_store, cn, pkcs12, serialized) values (@run_id, @row_key, @store_location, @store_name, @hash, @hash_plus_store, @cn, @pkcs12, @serialized)";

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
                    cmd.Parameters.AddWithValue("@pkcs12", obj.Export(X509ContentType.Pfx));
                }

                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(runId + recordCounter));

                var cert = new CertificateObject()
                {
                    StoreLocation = storeLocation.ToString(),
                    StoreName = storeName.ToString(),
                    CertificateHashString = obj.GetCertHashString(),
                    Subject = obj.Subject
                };
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(cert));
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
            catch (Exception e)
            {
                Log.Warning(e.GetType().ToString());
                Log.Warning(e.StackTrace);
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

            // On Windows we can use the .NET API to iterate through all the stores.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
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
                            Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                        }
                    }
                }
            }
            // On linux we check the central trusted root store (a folder), which has symlinks to actual cert locations scattered across the db
            // We list all the certificates and then create a new X509Certificate2 object for each by filename.
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var runner = new ExternalCommandRunner();

                var result = runner.RunExternalCommand("ls", new string[] { "/etc/ssl/certs", "-A" });
                Log.Debug("{0}", result);

                foreach (var _line in result.Split('\n'))
                {
                    Log.Debug("{0}",_line);
                    try
                    {
                        X509Certificate2 cert = new X509Certificate2("/etc/ssl/certs/" + _line);
                        Write(StoreLocation.LocalMachine, StoreName.Root, cert);
                    }
                    catch(Exception e)
                    {
                        Log.Debug("{0} {1} Issue creating certificate based on /etc/ssl/certs/{2}", e.GetType().ToString(), e.Message, _line);
                        Log.Debug("{0}", e.StackTrace);

                    }
                }
            }
            // On macos we use the keychain and export the certificates as .pem.
            // However, on macos Certificate2 doesn't support loading from a pem, 
            // so first we need pkcs12s instead, we convert using openssl, which requires we set a password
            // we import the pkcs12 with all our certs, delete the temp files and then iterate over it the certs
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var runner = new ExternalCommandRunner();

                var result = runner.RunExternalCommand("security", new string[] { "find-certificate", "-ap", "/System/Library/Keychains/SystemRootCertificates.keychain" });
                string tmpPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pem");
                string pkPath = Path.Combine(Directory.GetCurrentDirectory(), "tmpcert.pk12");

                File.WriteAllText(tmpPath, result);
                _ = runner.RunExternalCommand("openssl", new string[] { "pkcs12",  "-export",  "-nokeys" , "-out", pkPath, "-passout pass:pass", "-in", tmpPath });

                X509Certificate2Collection xcert = new X509Certificate2Collection();
                xcert.Import(pkPath,"pass",X509KeyStorageFlags.DefaultKeySet);

                File.Delete(tmpPath);
                File.Delete(pkPath);

                var X509Certificate2Enumerator = xcert.GetEnumerator();

                while (X509Certificate2Enumerator.MoveNext())
                {
                    Write(StoreLocation.LocalMachine, StoreName.Root, X509Certificate2Enumerator.Current);
                }
            }

            DatabaseManager.Commit();
            Stop();
        }
    }
}