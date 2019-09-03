// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
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
                    Log.Debug("Starting " + hive.ToString());
                    if (Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "Registry", "Hive", "Include", hive.ToString()))
                    {
                    }
                    else if (Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "Registry", "Hive", "Exclude", hive.ToString(), out Regex Capturer))
                    {
                        Log.Information("{0} '{1}' {2} '{3}'.",Strings.Get("ExcludingHive"), hive.ToString(), Strings.Get("DueToFilter"),Capturer.ToString());

                        return;
                    }

                    Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "Registry", "Key", "Exclude", hive.ToString());
                    var registryInfoEnumerable = RegistryWalker.WalkHive(hive);
                    try
                    {
                        Parallel.ForEach(registryInfoEnumerable,
                            (registryObject =>
                            {
                                try
                                {
                                    DatabaseManager.Write(registryObject, this.runId);
                                }
                                catch (InvalidOperationException e)
                                {
                                    Logger.DebugException(e);
                                    Log.Debug(JsonConvert.SerializeObject(registryObject)+ " invalid op exept");
                                }
                            }));
                    }
                    catch (Exception e)
                    {
                        Logger.DebugException(e);
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }

                }));
            
            DatabaseManager.Commit();
            Stop();
        }
    }
}