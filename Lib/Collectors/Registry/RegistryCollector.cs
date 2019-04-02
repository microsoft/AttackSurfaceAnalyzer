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
        private static readonly string SQL_INSERT = "insert into registry (run_id, row_key, key, values, permissions, serialized) values (@run_id, @row_key, @key, @values, @permissions, @serialized)";

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
            string hashSeed = String.Format("{0}{1}", obj.Key.Name, JsonConvert.SerializeObject(obj.Values));

            using (var cmd = new SqliteCommand(SQL_INSERT, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@run_id", this.runId);
                cmd.Parameters.AddWithValue("@row_key", CryptoHelpers.CreateHash(hashSeed));
                cmd.Parameters.AddWithValue("@key", obj.Key.Name);
                cmd.Parameters.AddWithValue("@values", JsonConvert.SerializeObject(obj.Values));
                try
                {
                    cmd.Parameters.AddWithValue("@permissions", obj.Key.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
                }
                catch (ArgumentException)
                {
                    cmd.Parameters.AddWithValue("@permissions", "");
                    Logger.Instance.Debug("Couldn't get permissions for {0}", obj.Key.Name);
                }
                cmd.Parameters.AddWithValue("@serialized", JsonConvert.SerializeObject(obj));

                cmd.ExecuteNonQuery();

                if (_numCollected % 1000 == 0)
                {
                    DatabaseManager.Commit();
                }
            }

            customCrawlHandler?.Invoke(obj);
        }

        private Dictionary<string,string> GetValues(RegistryKey key)
        {
            Dictionary<string,string> values = new Dictionary<string,string>();
            // Write values under key and commit
            foreach (var value in key.GetValueNames())
            {
                var Value = key.GetValue(value);
                string str = "";

                // This is okay. It is a zero-length value
                if (Value == null)
                {
                    // We can leave this empty
                }
                    
                else if (Value.ToString() == "System.Byte[]")
                {
                    str = Convert.ToBase64String((System.Byte[])Value);
                }

                else if (Value.ToString() == "System.String[]")
                {
                    str = "";
                    foreach (String st in (System.String[])Value)
                    {
                        str += st;
                    }
                }

                else
                {
                    if (Value.ToString() == Value.GetType().ToString())
                    {
                        Logger.Instance.Warn("Uh oh, this type isn't handled. " + Value.ToString());
                    }
                    str = Value.ToString();
                }
                values.Add(value, str);
            }
            return values;
        }

        public override void Execute()
        {
            Start(); 

            if (!this.CanRunOnPlatform())
            {
                return;
            }
            Truncate(this.runId);

            foreach (RegistryHive Hive in Hives)
            {
                var registryInfoEnumerable = RegistryWalker.WalkHive(Hive);
                Parallel.ForEach(registryInfoEnumerable,
                                (registryKey =>
                                {
                                    var ValDict = GetValues(registryKey);
                                    var regObj = new RegistryObject(registryKey, ValDict);
                                    Write(regObj);
                                }));

                //                    Logger.Instance.Info("Starting on Hive: " + Hive);
                //var BaseKey = RegistryKey.OpenBaseKey(Hive, RegistryView.Default);
                //AddSubKeysAndValues(BaseKey, Hive + "\\");
            }
            DatabaseManager.Commit();
            Stop();
        }
    }
}