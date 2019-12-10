// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects data from the local registry on Windows systems.
    /// </summary>
    public class RegistryCollector : BaseCollector
    {
        private List<RegistryHive> Hives;
        private HashSet<string> roots;
        private HashSet<RegistryKey> _keys;
        private HashSet<RegistryObject> _values;

        private static ConcurrentDictionary<string, string> SidMap = new ConcurrentDictionary<string, string>();

        private static readonly List<RegistryHive> DefaultHives = new List<RegistryHive>()
        {
            RegistryHive.ClassesRoot, RegistryHive.CurrentConfig, RegistryHive.CurrentUser, RegistryHive.LocalMachine, RegistryHive.Users
        };

        private Action<RegistryObject> customCrawlHandler = null;

        public RegistryCollector(string RunId) : this(RunId, DefaultHives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives) : this(RunId, Hives, null) { }

        public RegistryCollector(string RunId, List<RegistryHive> Hives, Action<RegistryObject> customHandler)
        {
            this.RunId = RunId;
            this.Hives = Hives;
            this.roots = new HashSet<string>();
            this._keys = new HashSet<RegistryKey>();
            this._values = new HashSet<RegistryObject>();
            this.customCrawlHandler = customHandler;
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

        public static string GetName(RegistryAccessRule rule)
        {
            if (rule == null)
            {
                return string.Empty;
            }
            if (!SidMap.ContainsKey(rule.IdentityReference.Value))
            {
                try
                {
                    var mappedValue = rule.IdentityReference.Translate(typeof(NTAccount)).Value;
                    SidMap.TryAdd(rule.IdentityReference.Value, mappedValue);
                }
                catch (IdentityNotMappedException)
                {
                    // This is fine. Some SIDs don't map to NT Accounts.
                    SidMap.TryAdd(rule.IdentityReference.Value, rule.IdentityReference.Value);
                }
            }
            
            return SidMap[rule.IdentityReference.Value];
        }

        public static RegistryObject RegistryKeyToRegistryObject(RegistryKey registryKey)
        {
            RegistryObject regObj = null;
            if (registryKey == null) { return regObj; }
            try
            {
                regObj = new RegistryObject()
                {
                    Key = registryKey.Name,
                };

                regObj.AddSubKeys(new List<string>(registryKey.GetSubKeyNames()));

                foreach (RegistryAccessRule rule in registryKey.GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
                {
                    string name = GetName(rule);

                    if (regObj.Permissions.ContainsKey(name))
                    {
                        regObj.Permissions[name].Add(rule.RegistryRights.ToString());
                    }
                    else
                    {
                        regObj.Permissions.Add(name, new List<string>() { rule.RegistryRights.ToString() });
                    }
                }

                foreach (string valueName in registryKey.GetValueNames())
                {
                    try
                    {
                        regObj.Values.Add(valueName, (registryKey.GetValue(valueName) == null) ? "" : (registryKey.GetValue(valueName).ToString()));
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "Found an exception processing registry values.");
                    }
                }
            }
            catch (System.ArgumentException e)
            {
                Log.Debug(e, "Exception parsing {0}", registryKey.Name);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Couldn't process reg key {0}", registryKey.Name);
            }

            return regObj;
        }

        public override void ExecuteInternal()
        {
            foreach (var hive in Hives)
            {
                Log.Debug("Starting " + hive.ToString());
                if (!Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "Registry", "Hive", "Include", hive.ToString()) && Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "Registry", "Hive", "Exclude", hive.ToString(), out Regex Capturer))
                {
                    Log.Debug("{0} '{1}' {2} '{3}'.", Strings.Get("ExcludingHive"), hive.ToString(), Strings.Get("DueToFilter"), Capturer.ToString());
                    return;
                }

                Filter.IsFiltered(AsaHelpers.GetPlatformString(), "Scan", "Registry", "Key", "Exclude", hive.ToString());
                var registryInfoEnumerable = RegistryWalker.WalkHive(hive);
                Parallel.ForEach(registryInfoEnumerable,
                    (registryKey =>
                    {
                        try
                        {
                            var regObj = RegistryKeyToRegistryObject(registryKey);

                            if (regObj != null)
                            {
                                DatabaseManager.Write(regObj, RunId);
                            }
                        }
                        catch (InvalidOperationException e)
                        {
                            Log.Debug(e, JsonConvert.SerializeObject(registryKey) + " invalid op exept");
                        }
                    }));
                Log.Debug("Finished " + hive.ToString());
            }
        }
    }
}