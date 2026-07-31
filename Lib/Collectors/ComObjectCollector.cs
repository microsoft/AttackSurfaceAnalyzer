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
            List<ComObject> comObjects = new();
            var fsc = new FileSystemCollector(new CollectorOptions() { SingleThread = SingleThreaded });
            Action<string> ParseComObjectsIn = SubKeyName =>
            {
                try
                {
                    RegistryKey? CurrentKey = SearchKey.OpenSubKey(SubKeyName);

                    if (CurrentKey is not null)
                    {
                        var RegObj = RegistryWalker.RegistryKeyToRegistryObject(CurrentKey, View);

                        if (RegObj != null)
                        {
                            ComObject comObject = new(RegObj);
                            var binary = ResolveServerBinary(CurrentKey, View, fsc);

                            if (binary is not null)
                            {
                                // Which view the object came from is what determines the bitness of the
                                // server it registers; the key name does not. InprocServer32 holds the
                                // 64-bit server in the 64-bit view and the 32-bit server in the 32-bit view
                                // (where it is redirected to Wow6432Node).
                                if (View == RegistryView.Registry32)
                                {
                                    comObject.x86_Binary = binary;
                                }
                                else
                                {
                                    comObject.x64_Binary = binary;
                                }
                            }

                            comObjects.Add(comObject);
                        }
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
        ///     The subkeys of a CLSID that name the server implementing it, in the order they are preferred.
        ///     An in-process server is listed first because a DLL loaded into the calling process is the more
        ///     interesting load point.
        /// </summary>
        /// <remarks>
        ///     There is no InprocServer64 key; bitness is selected by the registry view.
        /// </remarks>
        private static readonly string[] ServerSubKeyNames = { "InprocServer32", "LocalServer32", "LocalServer" };

        /// <summary>
        ///     Reads the default value of the first server subkey present under a CLSID and resolves it to a
        ///     file on disk.
        /// </summary>
        private static FileSystemObject? ResolveServerBinary(RegistryKey clsidKey, RegistryView view, FileSystemCollector fsc)
        {
            string[] subKeyNames;

            try
            {
                subKeyNames = clsidKey.GetSubKeyNames();
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to enumerate subkeys of {0} ({1}:{2})", clsidKey.Name, e.GetType(), e.Message);
                return null;
            }

            foreach (var serverName in ServerSubKeyNames)
            {
                var match = Array.Find(subKeyNames, name => name.Equals(serverName, StringComparison.OrdinalIgnoreCase));
                if (match is null)
                {
                    continue;
                }

                using var serverKey = clsidKey.OpenSubKey(match);
                if (serverKey is null)
                {
                    continue;
                }

                var serverObj = RegistryWalker.RegistryKeyToRegistryObject(serverKey, view);
                if (serverObj?.Values is null
                    || !serverObj.Values.TryGetValue(string.Empty, out var raw)
                    || string.IsNullOrWhiteSpace(raw))
                {
                    continue;
                }

                // LocalServer values are command lines, not bare paths.
                var path = serverName.StartsWith("LocalServer", StringComparison.OrdinalIgnoreCase)
                    ? RegistryReferenceParser.ExtractExecutablePath(raw)
                    : RegistryReferenceParser.NormalizePath(raw);

                if (path is not null)
                {
                    return fsc.FilePathToFileSystemObject(path);
                }
            }

            return null;
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
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            try
            {
                // Parse system Com Objects
                using var SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                var CLSIDs = SearchKey.OpenSubKey("SOFTWARE\\Classes\\CLSID");
                if (CLSIDs is not null)
                {
                    foreach (var comObj in ParseComObjects(CLSIDs, view, opts.SingleThread))
                    {
                        if (cancellationToken.IsCancellationRequested) { return; }
                        HandleChange(comObj);
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is UnauthorizedAccessException
                || e is System.Security.SecurityException)
            {
                Log.Verbose("Exception when parsing COM objects: {0}:{1}", e.GetType(), e.Message);
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
                        using var ComKey = SearchKey.OpenSubKey(subkeyName)?.OpenSubKey("CLSID");
                        if (ComKey is not null)
                        {
                            foreach (var comObj in ParseComObjects(ComKey, view, opts.SingleThread))
                            {
                                HandleChange(comObj);
                            }
                        }
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is UnauthorizedAccessException
                || e is System.Security.SecurityException)
            {
                Log.Verbose("Exception when parsing COM objects: {0}:{1}", e.GetType(), e.Message);
            }
        }
    }
}