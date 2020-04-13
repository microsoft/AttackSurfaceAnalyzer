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
            ParseView(RegistryView.Registry32);
            ParseView(RegistryView.Registry64);
        }

        public void ParseView(RegistryView view)
        {
            try
            {
                // Parse system Com Objects
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                var CLDIDs = SearchKey.OpenSubKey("SOFTWARE\\Classes\\CLSID");
                ParseComObjects(CLDIDs, view);
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
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.Users, view);
                var subkeyNames = SearchKey.GetSubKeyNames();
                foreach (string subkeyName in subkeyNames)
                {
                    if (subkeyName.EndsWith("Classes"))
                    {
                        using var ComKey = SearchKey.OpenSubKey(subkeyName).OpenSubKey("CLSID");
                        ParseComObjects(ComKey, view);
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

        /// <summary>
        /// Parse all the Subkeys of the given SearchKey into ComObjects and writes them to the database
        /// </summary>
        /// <param name="SearchKey">The Registry Key to search</param>
        /// <param name="View">The View of the registry to use</param>
        public void ParseComObjects(RegistryKey SearchKey, RegistryView View)
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

                        var RegObj = RegistryWalker.RegistryKeyToRegistryObject(CurrentKey, View);

                        if (RegObj != null)
                        {
                            ComObject comObject = new ComObject(RegObj);

                            foreach (string ComDetails in CurrentKey.GetSubKeyNames())
                            {
                                if (ComDetails.Contains("InprocServer32"))
                                {
                                    var ComKey = CurrentKey.OpenSubKey(ComDetails);
                                    var obj = RegistryWalker.RegistryKeyToRegistryObject(ComKey, View);
                                    string? BinaryPath32 = null;

                                    if (obj != null && obj.Values?.TryGetValue("", out BinaryPath32) is bool successful)
                                    {
                                        if (successful && BinaryPath32 != null)
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
                                        }
                                    }
                                }
                                if (ComDetails.Contains("InprocServer64"))
                                {
                                    var ComKey = CurrentKey.OpenSubKey(ComDetails);
                                    var obj = RegistryWalker.RegistryKeyToRegistryObject(ComKey, View);
                                    string? BinaryPath64 = null;

                                    if (obj != null && obj.Values?.TryGetValue("", out BinaryPath64) is bool successful)
                                    {
                                        if (successful && BinaryPath64 != null)
                                        {
                                            // Clean up cases where some extra spaces are thrown into the start (breaks our permission checker)
                                            BinaryPath64 = BinaryPath64.Trim();
                                            // Clean up cases where the binary is quoted (also breaks permission checker)
                                            if (BinaryPath64.StartsWith("\"") && BinaryPath64.EndsWith("\""))
                                            {
                                                BinaryPath64 = BinaryPath64.AsSpan().Slice(1, BinaryPath64.Length - 2).ToString();
                                            }
                                            // Unqualified binary name probably comes from Windows\System32
                                            if (!BinaryPath64.Contains("\\") && !BinaryPath64.Contains("%"))
                                            {
                                                BinaryPath64 = Path.Combine(Environment.SystemDirectory, BinaryPath64.Trim());
                                            }

                                            comObject.x64_Binary = FileSystemCollector.FilePathToFileSystemObject(BinaryPath64.Trim(), true);
                                        }
                                    }
                                }
                            }

                            comObjects.Add(comObject);
                        }
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