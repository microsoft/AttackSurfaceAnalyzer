// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     Collects Com Objects referenced by the registry
    /// </summary>
    public class ComObjectCollector : BaseCollector
    {
        public ComObjectCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler)
        {
        }

        /// <summary>
        ///     Parse all the Subkeys of the given SearchKey into ComObjects and returns a list of them
        /// </summary>
        /// <param name="SearchKey"> The Registry Key to search </param>
        /// <param name="View"> The View of the registry to use </param>
        public static IEnumerable<CollectObject> ParseComObjects(RegistryKey SearchKey, RegistryView View, bool SingleThreaded = false)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) { return new List<CollectObject>(); }
            if (SearchKey == null) { return new List<CollectObject>(); }
            List<ComObject> comObjects = new List<ComObject>();
            var fsc = new FileSystemCollector(new CollectorOptions() { SingleThread = SingleThreaded });
            Action<string> ParseComObjectsIn = SubKeyName =>
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
                                        // Clean up cases where some extra spaces are thrown into the start
                                        // (breaks our permission checker)
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

                                        comObject.x86_Binary = fsc.FilePathToFileSystemObject(BinaryPath32.Trim());
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
                                        // Clean up cases where some extra spaces are thrown into the start
                                        // (breaks our permission checker)
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

                                        comObject.x64_Binary = fsc.FilePathToFileSystemObject(BinaryPath64.Trim());
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
            };

            try
            {
                if (SingleThreaded)
                {
                    foreach (var subKey in SearchKey.GetSubKeyNames())
                    {
                        ParseComObjectsIn(subKey);
                    }
                }
                else
                {
                    SearchKey.GetSubKeyNames().AsParallel().ForAll(subKey => ParseComObjectsIn(subKey));
                }
            }
            catch (Exception e)
            {
                Log.Debug("Failing parsing com objects {0} {1}", SearchKey.Name, e.GetType());
            }

            return comObjects;
        }

        /// <summary>
        ///     Com Objects only exist on Windows.
        /// </summary>
        /// <returns> </returns>
        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        /// <summary>
        ///     Execute the Com Collector. We collect the list of Com Objects registered in the registry and
        ///     then examine each binary on the disk they point to.
        /// </summary>
        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                ParseView(RegistryView.Registry64, cancellationToken);
                ParseView(RegistryView.Registry32, cancellationToken);
            }
        }

        internal void ParseView(RegistryView view, CancellationToken cancellationToken)
        {
            try
            {
                // Parse system Com Objects
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                var CLDIDs = SearchKey.OpenSubKey("SOFTWARE\\Classes\\CLSID");
                foreach (var comObj in ParseComObjects(CLDIDs, view, opts.SingleThread))
                {
                    if (cancellationToken.IsCancellationRequested) { return; }
                    HandleChange(comObj);
                }
            }
            catch (Exception e) when (//lgtm [cs/empty-catch-block]
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
                    if (cancellationToken.IsCancellationRequested) { return; }

                    if (subkeyName.EndsWith("Classes"))
                    {
                        using var ComKey = SearchKey.OpenSubKey(subkeyName).OpenSubKey("CLSID");
                        foreach (var comObj in ParseComObjects(ComKey, view, opts.SingleThread))
                        {
                            HandleChange(comObj);
                        }
                    }
                }
            }
            catch (Exception e) when (//lgtm [cs/empty-catch-block]
                e is ArgumentException
                || e is UnauthorizedAccessException
                || e is System.Security.SecurityException)
            {
            }
        }
    }
}