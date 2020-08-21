// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects data from the local registry on Windows systems.
    /// </summary>
    public class RegistryCollector : BaseCollector
    {
        public RegistryCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
            this.opts = opts ?? this.opts;
            Hives = DefaultHives;
            if (opts != null)
            {
                Parallelize = !opts.SingleThread;
                if (opts.SelectedHives.Any())
                {
                    Hives = new List<(RegistryHive, string)>();
                    foreach (var hive in opts.SelectedHives)
                    {
                        var innerSplit = hive.Split('\\');
                        if (Enum.TryParse(typeof(RegistryHive), innerSplit[0], out object? result))
                        {
                            if (result is RegistryHive selectedHive)
                            {
                                Hives.Add((selectedHive, innerSplit.Length > 1 ? string.Join('\\', innerSplit[1..]) : string.Empty));
                            }
                        }
                    }
                }
            }
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            foreach (var hive in Hives)
            {
                Log.Debug("Starting {0}\\{1}", hive.Item1, hive.Item2);
                using var BaseKey32 = RegistryKey.OpenBaseKey(hive.Item1, RegistryView.Registry32);
                using var BaseKey64 = RegistryKey.OpenBaseKey(hive.Item1, RegistryView.Registry64);

                Action<RegistryHive, string, RegistryView> IterateOn = (registryHive, keyPath, registryView) =>
                {
                    Log.Verbose("Beginning to parse {0}\\{1} in {2}", registryHive, keyPath, registryView);
                    RegistryObject? regObj = null;
                    try
                    {
                        var ourKey = registryView == RegistryView.Registry32 ? BaseKey32.OpenSubKey(keyPath) : BaseKey64.OpenSubKey(keyPath);
                        regObj = RegistryWalker.RegistryKeyToRegistryObject(ourKey, registryView);
                    }
                    catch (Exception e)
                    {
                        Log.Debug($"Failed to open Key {registryHive}\\{keyPath} for walking. {e.GetType()}");
                    }

                    if (regObj != null)
                    {
                        HandleChange(regObj);
                    }
                    Log.Verbose("Finished parsing {0}\\{1} in {1}", registryHive, keyPath, registryView);
                };

                var x86_Enumerable = RegistryWalker.WalkHive(hive.Item1, RegistryView.Registry32, hive.Item2);
                var x64_Enumerable = RegistryWalker.WalkHive(hive.Item1, RegistryView.Registry64, hive.Item2);

                if (Parallelize)
                {
                    ParallelOptions po = new ParallelOptions() { CancellationToken = cancellationToken };
                    Parallel.ForEach(x86_Enumerable, po, registryKey => IterateOn(hive.Item1, registryKey, RegistryView.Registry32));
                    Parallel.ForEach(x64_Enumerable, po, registryKey => IterateOn(hive.Item1, registryKey, RegistryView.Registry64));
                }
                else
                {
                    foreach (var registryKey in x86_Enumerable)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry32);
                    }
                    foreach (var registryKey in x64_Enumerable)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        IterateOn(hive.Item1, registryKey, RegistryView.Registry64);
                    }
                }
                Log.Debug("Finished {0}\\{1}", hive.Item1, hive.Item2);
            }
        }

        private static readonly List<(RegistryHive, string)> DefaultHives = new List<(RegistryHive, string)>()
        {
            (RegistryHive.ClassesRoot,string.Empty), (RegistryHive.CurrentConfig,string.Empty), (RegistryHive.CurrentUser,string.Empty), (RegistryHive.LocalMachine,string.Empty), (RegistryHive.Users,string.Empty)
        };

        private readonly List<(RegistryHive, string)> Hives;

        private readonly bool Parallelize;
    }
}