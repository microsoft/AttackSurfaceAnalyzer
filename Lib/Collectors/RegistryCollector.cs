// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects data from the local registry on Windows systems.
    /// </summary>
    public class RegistryCollector : BaseCollector
    {
        private readonly List<(RegistryHive, string)> Hives;
        private readonly bool Parallelize;

        private static readonly List<(RegistryHive,string)> DefaultHives = new List<(RegistryHive,string)>()
        {
            (RegistryHive.ClassesRoot,string.Empty), (RegistryHive.CurrentConfig,string.Empty), (RegistryHive.CurrentUser,string.Empty), (RegistryHive.LocalMachine,string.Empty), (RegistryHive.Users,string.Empty)
        };

        private readonly Action<RegistryObject>? customCrawlHandler;

        public RegistryCollector(bool Parallelize) : this(DefaultHives, Parallelize, null) { }

        public RegistryCollector(List<(RegistryHive, string)> Hives, bool Parallelize, Action<RegistryObject>? customHandler = null)
        {
            this.Hives = Hives;
            customCrawlHandler = customHandler;
            this.Parallelize = Parallelize;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public override void ExecuteInternal()
        {
            foreach (var hive in Hives)
            {
                Log.Debug("Starting " + hive.ToString());

                Action<RegistryHive, string, RegistryView> IterateOn = (registryHive, keyPath, registryView) =>
                {
                    Log.Verbose($"Beginning to parse {registryHive}\\{keyPath} in view {registryView}");
                    var regObj = RegistryWalker.RegistryKeyToRegistryObject(registryHive, keyPath, registryView);

                    if (regObj != null)
                    {
                        Results.Push(regObj);
                    }
                    Log.Verbose($"Finished parsing {keyPath} in view {registryView}");
                };

                var x86_Enumerable = RegistryWalker.WalkHive(hive.Item1, RegistryView.Registry32, hive.Item2);
                var x64_Enumerable = RegistryWalker.WalkHive(hive.Item1, RegistryView.Registry64, hive.Item2);

                if (Parallelize)
                {

                    x86_Enumerable.AsParallel().ForAll(
                    registryKey =>
                    {
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry32);
                    });
                    x64_Enumerable.AsParallel().ForAll(
                    registryKey =>
                    {
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry64);
                    });
                }
                else
                {
                    foreach (var registryKey in x86_Enumerable)
                    {
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry32);
                    }
                    foreach (var registryKey in x64_Enumerable)
                    {
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry64);
                    }
                }
                Log.Debug("Finished " + hive.ToString());
            }
        }
    }
}