// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors.Registry
{
    public class RegistryCollector : BaseCollector
    {
        private List<RegistryHive> Hives;
        private HashSet<string> roots;
        private HashSet<RegistryKey> _keys;
        private HashSet<RegistryObject> _values;

        private static readonly List<RegistryHive> DefaultHives = new List<RegistryHive>()
        {
            RegistryHive.ClassesRoot, RegistryHive.CurrentConfig, RegistryHive.CurrentUser, RegistryHive.LocalMachine, RegistryHive.Users
        };

        private Action<RegistryObject> customCrawlHandler = null;

        private static readonly string SQL_TRUNCATE = "delete from registry where run_id=@run_id";
        private static readonly string SQL_INSERT = "insert into registry (run_id, row_key, key, value, subkeys, permissions, serialized) values (@run_id, @row_key, @key, @value, @subkeys, @permissions, @serialized)";

        public RegistryCollector(string RunId) : this(RunId, DefaultHives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives) : this(RunId, Hives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives, Action<RegistryObject> customHandler)
        {
            Log.Debug("Initializing a new {0} object.", this.GetType().Name);
            this.runId = RunId;
            this.Hives = Hives;
            this.roots = new HashSet<string>();
            this._keys = new HashSet<RegistryKey>();
            this._values = new HashSet<RegistryObject>();
            this.customCrawlHandler = customHandler;
        }

        public void Truncate(string runid)
        {
            var cmd = new SqliteCommand(SQL_TRUNCATE, DatabaseManager.Connection, DatabaseManager.Transaction);
            cmd.Parameters.AddWithValue("@run_id", runId);
        }

        public void AddRoot(string root)
        {
            this.roots.Add(root);
        }

        public void ClearRoots()
        {
            this.roots.Clear();
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public void Write(RegistryObject obj)
        {
            try
            {
                string hashSeed = String.Format("{0}{1}", obj.Key, JsonConvert.SerializeObject(obj));

                using (var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction))
                {
                    cmd.Parameters.AddWithValue("@run_id", this.runId);
                    cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(hashSeed));
                    cmd.Parameters.AddWithValue("@key", obj.Key);
                   
                        cmd.Parameters.AddWithValue("@value", JsonConvert.SerializeObject(obj.Values));
                   

                    cmd.Parameters.AddWithValue("@subkeys", JsonConvert.SerializeObject(obj.Subkeys));
                    cmd.Parameters.AddWithValue("@permissions", obj.Permissions);
                    cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));

                    try
                    {
                        cmd.ExecuteNonQuery();
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e.GetType() + "thrown in registry collector");
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }

                    if (_numCollected++ % 100000 == 0)
                    {
                        Log.Information(_numCollected + (" of 6-800k"));
                    }
                }
            }
            catch(Exception)
            {
                Log.Debug("Had trouble writing {0}",obj.Key);
            }

            customCrawlHandler?.Invoke(obj);
        }

        

        public override void Execute()
        {
            Start();

            Log.Information(JsonConvert.SerializeObject(DefaultHives));

            if (!this.CanRunOnPlatform())
            {
                return;
            }
            Truncate(this.runId);

            Parallel.ForEach(Hives,
                (hive =>
                {
                    Log.Debug("Starting " + hive.ToString());
                    if (Filter.IsFiltered(Helpers.RuntimeString(), "Scan", "Registry", "Hive", "Include", hive.ToString()))
                    {
                    }
                    else if (Filter.IsFiltered(Helpers.RuntimeString(), "Scan", "Registry", "Hive", "Exclude", hive.ToString(), out Regex Capturer))
                    {
                        Log.Information("Excluding hive '{0}' due to filter '{1}'.", hive.ToString(), Capturer.ToString());

                        return;
                    }

                    var registryInfoEnumerable = RegistryWalker.WalkHive(hive);
                    try
                    {
                        Parallel.ForEach(registryInfoEnumerable,
                            (registryObject =>
                            {
                                try
                                {
                                    Write(registryObject);
                                }
                                // Some registry keys don't get along
                                catch (InvalidOperationException e)
                                {
                                    Log.Debug(registryObject.Key + " " + e.GetType());
                                }
                            }));
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e.GetType().ToString());
                        Log.Debug(e.Message);
                        Log.Debug(e.StackTrace);
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }

                }));
            
            DatabaseManager.Commit();
            Stop();
        }
    }
}