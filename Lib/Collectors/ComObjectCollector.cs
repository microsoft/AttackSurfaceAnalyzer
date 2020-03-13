// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects Com Objects referenced by the registry
    /// </summary>
    public class ComObjectCollector : BaseCollector
    {

        public ComObjectCollector(string RunId)
        {
            this.RunId = RunId;
        }

        /// <summary>
        /// Com Objects only exist on Windows.
        /// </summary>
        /// <returns></returns>
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        /// <summary>
        /// Execute the Com Collector.  We collect the list of Com Objects registered in the registry
        /// and then examine each binary on the disk they point to.
        /// </summary>
        public override void ExecuteInternal()
        {
            try
            {
                // Parse system Com Objects
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                var CLDIDs = SearchKey.OpenSubKey("SOFTWARE\\Classes\\CLSID");
                ParseComObjects(CLDIDs);
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is UnauthorizedAccessException
                || e is System.Security.SecurityException)
            {

            }


            try
            {
                // Parse user Com Objects
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                var subkeyNames = SearchKey.GetSubKeyNames();
                foreach (string subkeyName in subkeyNames)
                {
                    if (subkeyName.EndsWith("Classes"))
                    {
                        using var ComKey = SearchKey.OpenSubKey(subkeyName).OpenSubKey("CLSID");
                        ParseComObjects(ComKey);
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is UnauthorizedAccessException
                || e is System.Security.SecurityException)
            {

            }
        }

        public void ParseComObjects(RegistryKey SearchKey)
        {
            if (SearchKey == null) { return; }
            List<ComObject> comObjects = new List<ComObject>();
            try
            {
                Parallel.ForEach(SearchKey.GetSubKeyNames(), (SubKeyName) =>
                {
                    try
                    {
                        RegistryKey CurrentKey = SearchKey.OpenSubKey(SubKeyName);

                        var RegObj = RegistryWalker.RegistryKeyToRegistryObject(CurrentKey);

                        ComObject comObject = new ComObject()
                        {
                            Key = RegObj,
                        };

                        foreach (string ComDetails in CurrentKey.GetSubKeyNames())
                        {
                            var ComKey = CurrentKey.OpenSubKey(ComDetails);
                            comObject.Subkeys.Add(RegistryWalker.RegistryKeyToRegistryObject(ComKey));
                        }

                        //Get the information from the InProcServer32 Subkey (for 32 bit)
                        if (comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).Any() && comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).First().Values.ContainsKey(""))
                        {
                            comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).First().Values.TryGetValue("", out string? BinaryPath32);

                            if (BinaryPath32 != null)
                            {
                                // Clean up cases where some extra spaces are thrown into the start (breaks our permission checker)
                                BinaryPath32 = BinaryPath32.Trim();
                                // Clean up cases where the binary is quoted (also breaks permission checker)
                                if (BinaryPath32.StartsWith("\"") && BinaryPath32.EndsWith("\""))
                                {
                                    BinaryPath32 = BinaryPath32.AsSpan().Slice(1, BinaryPath32.Length - 2).ToString();
                                }
                                // Unqualified binary name probably comes from Windows\System32
                                if (!BinaryPath32.Contains("\\") && !BinaryPath32.Contains("%"))
                                {
                                    BinaryPath32 = Path.Combine(Environment.SystemDirectory, BinaryPath32.Trim());
                                }

                                comObject.x86_Binary = FileSystemCollector.FilePathToFileSystemObject(BinaryPath32.Trim(), true);
                                comObject.x86_BinaryName = BinaryPath32;
                            }
                        }
                        // And the InProcServer64 for 64 bit
                        if (comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).Any() && comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).First().Values.ContainsKey(""))
                        {
                            comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).First().Values.TryGetValue("", out string? BinaryPath64);

                            if (BinaryPath64 != null)
                            {
                                // Clean up cases where some extra spaces are thrown into the start (breaks our permission checker)
                                BinaryPath64 = BinaryPath64.Trim();
                                // Clean up cases where the binary is quoted (also breaks permission checker)
                                if (BinaryPath64.StartsWith("\"") && BinaryPath64.EndsWith("\""))
                                {
                                    BinaryPath64 = BinaryPath64.Substring(1, BinaryPath64.Length - 2);
                                }
                                // Unqualified binary name probably comes from Windows\System32
                                if (!BinaryPath64.Contains("\\") && !BinaryPath64.Contains("%"))
                                {
                                    BinaryPath64 = Path.Combine(Environment.SystemDirectory, BinaryPath64.Trim());
                                }
                                comObject.x64_Binary = FileSystemCollector.FilePathToFileSystemObject(BinaryPath64.Trim(), true);
                                comObject.x64_BinaryName = BinaryPath64;
                            }
                        }

                        comObjects.Add(comObject);
                    }
                    catch (Exception e) when (
                        e is System.Security.SecurityException
                        || e is ObjectDisposedException
                        || e is UnauthorizedAccessException
                        || e is IOException)
                    {
                        Log.Debug($"Couldn't parse {SubKeyName}");
                    }

                });
            }
            catch (Exception e) when (
                e is System.Security.SecurityException
                || e is ObjectDisposedException
                || e is UnauthorizedAccessException
                || e is IOException)
            {
                Log.Debug($"Failing parsing com objects {SearchKey.Name} {e.GetType().ToString()} {e.Message}");
            }

            foreach (var comObject in comObjects)
            {
                DatabaseManager.Write(comObject, RunId);
            }
        }
    }
}