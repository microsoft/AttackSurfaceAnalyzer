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
        private readonly List<RegistryHive> Hives;
        private readonly bool Parallelize;

        private static readonly List<RegistryHive> DefaultHives = new List<RegistryHive>()
        {
            RegistryHive.ClassesRoot, RegistryHive.CurrentConfig, RegistryHive.CurrentUser, RegistryHive.LocalMachine, RegistryHive.Users
        };

        private readonly Action<RegistryObject>? customCrawlHandler;

        public RegistryCollector(bool Parallelize) : this(DefaultHives, Parallelize, null) { }

        public RegistryCollector(List<RegistryHive> Hives, bool Parallelize, Action<RegistryObject>? customHandler = null)
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

                Action<RegistryKey, RegistryView> IterateOn = (registryKey, registryView) =>
                {
                    try
                    {
                        var regObj = RegistryWalker.RegistryKeyToRegistryObject(registryKey, registryView);

                        if (regObj != null)
                        {
                            Results.Add(regObj);
                        }
                    }
                    catch (InvalidOperationException e)
                    {
                        Log.Debug(e, JsonConvert.SerializeObject(registryKey) + " invalid op exept");
                    }
                };

                var x86_Enumerable = RegistryWalker.WalkHive(hive, RegistryView.Registry32);
                var x64_Enumerable = RegistryWalker.WalkHive(hive, RegistryView.Registry64);

                if (Parallelize)
                {

                    x86_Enumerable.AsParallel().ForAll(
                    registryKey =>
                    {
                        IterateOn(registryKey, RegistryView.Registry32);
                    });
                    x64_Enumerable.AsParallel().ForAll(
                    registryKey =>
                    {
                        IterateOn(registryKey, RegistryView.Registry64);
                    });
                }
                else
                {
                    foreach (var registryKey in x86_Enumerable)
                    {
                        IterateOn(registryKey, RegistryView.Registry32);
                    }
                    foreach (var registryKey in x64_Enumerable)
                    {
                        IterateOn(registryKey, RegistryView.Registry64);
                    }
                }
                Log.Debug("Finished " + hive.ToString());
            }
        }
    }
}