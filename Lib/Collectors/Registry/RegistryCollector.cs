// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.ObjectTypes;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Newtonsoft.Json;

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

        private static readonly string SQL_TRUNCATE = "delete from file_system where run_id=@run_id";
        private static readonly string SQL_INSERT = "insert into registry (run_id, row_key, key, value, subkeys, permissions, serialized) values (@run_id, @row_key, @key, @value, @subkeys, @permissions, @serialized)";

        public RegistryCollector(string RunId) : this(RunId, DefaultHives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives) : this(RunId, Hives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives, Action<RegistryObject> customHandler)
        {
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
            _numCollected++;
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
                catch(Exception e)
                {
                    Logger.Instance.Debug(e.GetType() + "thrown in registry collector");
                }

                if (_numCollected % 1000 == 0)
                {
                    DatabaseManager.Commit();
                }
            }

            customCrawlHandler?.Invoke(obj);
        }

        

        public override void Execute()
        {
            Start(); 

            if (!this.CanRunOnPlatform())
            {
                return;
            }
            Truncate(this.runId);

            Parallel.ForEach(Hives,
                (hive =>
                {
                    Logger.Instance.Debug("Starting " + hive.ToString());
                    if (Filter.IsFiltered(Filter.RuntimeString(), "Scan", "Registry", "Hive", "Exclude", hive.ToString()))
                    {
                        Logger.Instance.Debug("Hive {0} is filtered.", hive.ToString());
                    }
                    else
                    {
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
                                    catch (Exception e)
                                    {
                                        Logger.Instance.Debug("Walk of {0} fziled", hive.ToString());
                                        Logger.Instance.Debug(e.GetType());
                                    }
                                }));
                        }
                        catch (Exception e)
                        {
                            Logger.Instance.Debug(e.GetType());
                            Logger.Instance.Debug(e.Message);
                        }
                    }
                }));
            
            DatabaseManager.Commit();
            Stop();
        }
    }
}