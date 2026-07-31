// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Threading;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    ///     How the data stored in a load point's registry value should be read.
    /// </summary>
    public enum LoadPointTargetKind
    {
        /// <summary>
        ///     The value holds one or more file paths.
        /// </summary>
        Path,

        /// <summary>
        ///     The value holds a command line; the executable is taken from the front of it.
        /// </summary>
        CommandLine,

        /// <summary>
        ///     The value references CLSIDs, which are resolved through Classes\CLSID to a binary.
        /// </summary>
        Clsid,

        /// <summary>
        ///     CLSIDs if the value contains any, otherwise file paths.
        /// </summary>
        Auto
    }

    /// <summary>
    ///     A value, or set of values, under a load point key that names code to load.
    /// </summary>
    public sealed class LoadPointValueSource
    {
        public LoadPointValueSource(string? subKey, string? valueName, LoadPointTargetKind kind)
        {
            SubKey = subKey;
            ValueName = valueName;
            Kind = kind;
        }

        /// <summary>
        ///     Subkey holding the value, relative to the unit being examined. Null means the unit key itself.
        /// </summary>
        public string? SubKey { get; }

        /// <summary>
        ///     The value to read. Empty string is the key's default value; null means every value.
        /// </summary>
        public string? ValueName { get; }

        public LoadPointTargetKind Kind { get; }
    }

    /// <summary>
    ///     A place in the registry the operating system reads to decide what code to load.
    /// </summary>
    public sealed class LoadPointDefinition
    {
        public LoadPointDefinition(string name, RegistryHive hive, string keyPath, bool enumerateSubKeys, params LoadPointValueSource[] sources)
        {
            Name = name;
            Hive = hive;
            KeyPath = keyPath;
            EnumerateSubKeys = enumerateSubKeys;
            Sources = new ReadOnlyCollection<LoadPointValueSource>(sources);
        }

        /// <summary>
        ///     Reported as <see cref="LoadPointObject.LoadPointType" />.
        /// </summary>
        public string Name { get; }

        public RegistryHive Hive { get; }

        public string KeyPath { get; }

        /// <summary>
        ///     When true each immediate subkey of <see cref="KeyPath" /> is a load point in its own right,
        ///     as with a CLSID or a service. When false the key itself is the load point.
        /// </summary>
        public bool EnumerateSubKeys { get; }

        public IReadOnlyList<LoadPointValueSource> Sources { get; }
    }

    /// <summary>
    ///     Collects registry load points joined to the binaries they resolve to, so that an unprivileged
    ///     user's ability to modify either end can be asserted by a single analysis rule.
    /// </summary>
    public class LoadPointCollector : BaseCollector
    {
        public LoadPointCollector(CollectorOptions? opts = null, Action<CollectObject>? changeHandler = null, IEnumerable<LoadPointDefinition>? definitions = null)
            : base(opts, changeHandler)
        {
            _definitions = definitions?.ToList() ?? DefaultDefinitions.ToList();
        }

        /// <summary>
        ///     The load points scanned unless the caller supplies its own set. Adding coverage is a matter of
        ///     adding an entry here rather than adding a branch to the collector.
        /// </summary>
        public static IReadOnlyList<LoadPointDefinition> DefaultDefinitions { get; } = new ReadOnlyCollection<LoadPointDefinition>(new[]
        {
            new LoadPointDefinition("ComServer", RegistryHive.LocalMachine, ClsidKeyPath, true,
                new LoadPointValueSource("InprocServer32", string.Empty, LoadPointTargetKind.Path),
                new LoadPointValueSource("LocalServer32", string.Empty, LoadPointTargetKind.CommandLine),
                new LoadPointValueSource("LocalServer", string.Empty, LoadPointTargetKind.CommandLine)),

            // The key that CVE-2026-50343 abuses: its DACL grants INTERACTIVE SetValue and CreateSubKey, and
            // the plugin IDs it maps are CoCreateInstance'd by a SYSTEM svchost.
            new LoadPointDefinition("StaticPluginMap", RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State", false,
                new LoadPointValueSource(null, null, LoadPointTargetKind.Auto)),

            new LoadPointDefinition("AppInit_DLLs", RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", false,
                new LoadPointValueSource(null, "AppInit_DLLs", LoadPointTargetKind.Path)),

            new LoadPointDefinition("Service", RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services", true,
                new LoadPointValueSource(null, "ImagePath", LoadPointTargetKind.CommandLine),
                new LoadPointValueSource("Parameters", "ServiceDll", LoadPointTargetKind.Path)),
        });

        /// <summary>
        ///     Registry load points only exist on Windows.
        /// </summary>
        public override bool CanRunOnPlatform() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return;
            }

            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                foreach (var definition in _definitions)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    foreach (var loadPoint in ParseDefinition(definition, view, cancellationToken))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            return;
                        }

                        HandleChange(loadPoint);
                    }
                }
            }
        }

        /// <summary>
        ///     Expands a single load point definition in one registry view.
        /// </summary>
        [SupportedOSPlatform("windows")]
        public IEnumerable<LoadPointObject> ParseDefinition(LoadPointDefinition definition, RegistryView view, CancellationToken cancellationToken = default)
        {
            if (definition is null)
            {
                throw new ArgumentNullException(nameof(definition));
            }

            RegistryKey? baseKey = null;
            RegistryKey? rootKey = null;

            try
            {
                baseKey = RegistryKey.OpenBaseKey(definition.Hive, view);
                rootKey = baseKey.OpenSubKey(definition.KeyPath);
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to open {0}\\{1} ({2}:{3})", definition.Hive, definition.KeyPath, e.GetType(), e.Message);
            }

            if (rootKey is null)
            {
                baseKey?.Dispose();
                return Array.Empty<LoadPointObject>();
            }

            List<LoadPointObject> results = new();
            var fsc = new FileSystemCollector(new CollectorOptions() { SingleThread = true });

            try
            {
                if (definition.EnumerateSubKeys)
                {
                    foreach (var subKeyName in SafeGetSubKeyNames(rootKey))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        using var unit = SafeOpenSubKey(rootKey, subKeyName);
                        if (unit is not null)
                        {
                            results.AddRange(ParseUnit(definition, unit, view, baseKey, fsc));
                        }
                    }
                }
                else
                {
                    results.AddRange(ParseUnit(definition, rootKey, view, baseKey, fsc));
                }
            }
            finally
            {
                rootKey.Dispose();
                baseKey?.Dispose();
            }

            return results;
        }

        [SupportedOSPlatform("windows")]
        private static IEnumerable<LoadPointObject> ParseUnit(LoadPointDefinition definition, RegistryKey unit, RegistryView view, RegistryKey? hiveRoot, FileSystemCollector fsc)
        {
            List<LoadPointObject> results = new();

            foreach (var source in definition.Sources)
            {
                RegistryKey? valueKey = unit;
                RegistryKey? opened = null;

                if (source.SubKey is not null)
                {
                    opened = SafeOpenSubKey(unit, source.SubKey);
                    valueKey = opened;
                }

                if (valueKey is null)
                {
                    continue;
                }

                try
                {
                    var sourceObj = RegistryWalker.RegistryKeyToRegistryObject(valueKey, view);
                    if (sourceObj?.Values is null || sourceObj.Values.Count == 0)
                    {
                        continue;
                    }

                    var sourceWritable = PermissionUtils.IsUserWritable(sourceObj.Permissions);

                    foreach (var entry in SelectValues(sourceObj.Values, source.ValueName))
                    {
                        foreach (var loadPoint in ResolveReferences(definition, source, sourceObj, sourceWritable, entry.Key, entry.Value, view, hiveRoot, fsc))
                        {
                            results.Add(loadPoint);
                        }
                    }
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to parse load point {0} under {1} ({2}:{3})", definition.Name, unit.Name, e.GetType(), e.Message);
                }
                finally
                {
                    opened?.Dispose();
                }
            }

            return results;
        }

        private static IEnumerable<KeyValuePair<string, string>> SelectValues(Dictionary<string, string> values, string? valueName)
        {
            if (valueName is null)
            {
                return values;
            }

            return values.TryGetValue(valueName, out var data)
                ? new[] { new KeyValuePair<string, string>(valueName, data) }
                : Array.Empty<KeyValuePair<string, string>>();
        }

        [SupportedOSPlatform("windows")]
        private static IEnumerable<LoadPointObject> ResolveReferences(
            LoadPointDefinition definition,
            LoadPointValueSource source,
            RegistryObject sourceObj,
            bool sourceWritable,
            string valueName,
            string valueData,
            RegistryView view,
            RegistryKey? hiveRoot,
            FileSystemCollector fsc)
        {
            if (string.IsNullOrWhiteSpace(valueData))
            {
                yield break;
            }

            var kind = source.Kind;
            IReadOnlyList<string> clsids = Array.Empty<string>();

            if (kind is LoadPointTargetKind.Clsid or LoadPointTargetKind.Auto)
            {
                clsids = RegistryReferenceParser.ExtractClsids(valueData).ToList();
                if (clsids.Count > 0)
                {
                    kind = LoadPointTargetKind.Clsid;
                }
                else if (kind == LoadPointTargetKind.Auto)
                {
                    kind = LoadPointTargetKind.Path;
                }
            }

            var origin = $"{sourceObj.Key}:{(string.IsNullOrEmpty(valueName) ? "(default)" : valueName)}";

            if (kind == LoadPointTargetKind.Clsid)
            {
                foreach (var clsid in clsids)
                {
                    var (path, chain) = ResolveClsid(clsid, hiveRoot, view);
                    var loadPoint = NewLoadPoint(definition, sourceObj, sourceWritable, valueName, valueData, view);
                    loadPoint.TargetClsid = clsid;
                    loadPoint.ResolutionChain.Add(origin);
                    loadPoint.ResolutionChain.AddRange(chain);
                    PopulateTarget(loadPoint, path, fsc);
                    yield return loadPoint;
                }

                yield break;
            }

            IEnumerable<string> paths = kind == LoadPointTargetKind.CommandLine
                ? new[] { RegistryReferenceParser.ExtractExecutablePath(valueData) }
                : RegistryReferenceParser.ExtractPaths(valueData);

            var any = false;

            foreach (var path in paths)
            {
                if (path is null)
                {
                    continue;
                }

                any = true;
                var loadPoint = NewLoadPoint(definition, sourceObj, sourceWritable, valueName, valueData, view);
                loadPoint.ResolutionChain.Add(origin);
                PopulateTarget(loadPoint, path, fsc);
                yield return loadPoint;
            }

            // A value that is a bare, unrooted binary name still names something the loader will find.
            if (!any && kind == LoadPointTargetKind.Path)
            {
                var fallback = RegistryReferenceParser.NormalizePath(valueData);
                if (fallback is not null)
                {
                    var loadPoint = NewLoadPoint(definition, sourceObj, sourceWritable, valueName, valueData, view);
                    loadPoint.ResolutionChain.Add(origin);
                    PopulateTarget(loadPoint, fallback, fsc);
                    yield return loadPoint;
                }
            }
        }

        /// <summary>
        ///     Follows a CLSID to the binary that implements it. This indirection is the point of the
        ///     collector: the key an attacker can write names a CLSID, and only the CLSID names the DLL.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private static (string? Path, List<string> Chain) ResolveClsid(string clsid, RegistryKey? hiveRoot, RegistryView view)
        {
            List<string> chain = new();

            if (hiveRoot is null)
            {
                return (null, chain);
            }

            foreach (var serverName in ClsidServerSubKeys)
            {
                var keyPath = $@"{ClsidKeyPath}\{clsid}\{serverName}";
                using var serverKey = SafeOpenSubKey(hiveRoot, keyPath);
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

                var path = serverName.StartsWith("LocalServer", StringComparison.OrdinalIgnoreCase)
                    ? RegistryReferenceParser.ExtractExecutablePath(raw)
                    : RegistryReferenceParser.NormalizePath(raw);

                chain.Add($@"{hiveRoot.Name}\{keyPath}:(default)");
                return (path, chain);
            }

            chain.Add($@"{hiveRoot.Name}\{ClsidKeyPath}\{clsid} (unresolved)");
            return (null, chain);
        }

        private static LoadPointObject NewLoadPoint(LoadPointDefinition definition, RegistryObject sourceObj, bool sourceWritable, string valueName, string valueData, RegistryView view)
            => new(definition.Name, sourceObj)
            {
                SourceValueName = valueName,
                SourceValueData = valueData.Length > MaxRetainedValueLength
                    ? valueData.Substring(0, MaxRetainedValueLength)
                    : valueData,
                SourceKeyUserWritable = sourceWritable,
                View = view,
            };

        /// <summary>
        ///     Records what the load point resolves to and who can write it. A target that does not exist is
        ///     reported as such and judged by the ACL of the directory that would receive it, which is the
        ///     exploitable shape this collector exists to find.
        /// </summary>
        [SupportedOSPlatform("windows")]
        private static void PopulateTarget(LoadPointObject loadPoint, string? path, FileSystemCollector fsc)
        {
            loadPoint.TargetPath = path;

            if (string.IsNullOrEmpty(path))
            {
                loadPoint.TargetAclSource = "None";
                return;
            }

            try
            {
                loadPoint.TargetExists = File.Exists(path) || Directory.Exists(path);
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to test existence of {0} ({1}:{2})", path, e.GetType(), e.Message);
            }

            if (loadPoint.TargetExists)
            {
                loadPoint.Target = fsc.FilePathToFileSystemObject(path!);
                loadPoint.TargetAclSource = "Target";
                loadPoint.TargetUserWritable = TryIsUserWritable(path!, out var unavailable);
                loadPoint.TargetAclUnavailable = unavailable;
                return;
            }

            var parent = PermissionUtils.NearestExistingParent(path);
            if (parent is null)
            {
                loadPoint.TargetAclSource = "None";
                loadPoint.TargetAclUnavailable = true;
                return;
            }

            loadPoint.NearestExistingParentPath = parent;
            loadPoint.NearestExistingParent = fsc.FilePathToFileSystemObject(parent);
            loadPoint.TargetAclSource = "NearestExistingParent";
            loadPoint.TargetUserWritable = TryIsUserWritable(parent, out var parentUnavailable);
            loadPoint.TargetAclUnavailable = parentUnavailable;
        }

        [SupportedOSPlatform("windows")]
        private static bool TryIsUserWritable(string path, out bool unavailable)
        {
            try
            {
                FileSystemSecurity security = Directory.Exists(path)
                    ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access)
                    : new FileInfo(path).GetAccessControl(AccessControlSections.Access);

                unavailable = false;
                return PermissionUtils.IsUserWritable(security);
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to read ACL of {0} ({1}:{2})", path, e.GetType(), e.Message);
                unavailable = true;
                return false;
            }
        }

        private static string[] SafeGetSubKeyNames(RegistryKey key)
        {
            try
            {
                return key.GetSubKeyNames();
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to enumerate subkeys of {0} ({1}:{2})", key.Name, e.GetType(), e.Message);
                return Array.Empty<string>();
            }
        }

        private static RegistryKey? SafeOpenSubKey(RegistryKey key, string name)
        {
            try
            {
                return key.OpenSubKey(name);
            }
            catch (Exception e)
            {
                Log.Verbose("Failed to open {0}\\{1} ({2}:{3})", key.Name, name, e.GetType(), e.Message);
                return null;
            }
        }

        private const string ClsidKeyPath = @"SOFTWARE\Classes\CLSID";

        private static readonly string[] ClsidServerSubKeys = { "InprocServer32", "LocalServer32", "LocalServer" };

        /// <summary>
        ///     Load point values such as StaticPluginMap can be large; only enough to identify what was
        ///     written is retained.
        /// </summary>
        private const int MaxRetainedValueLength = 512;

        private readonly List<LoadPointDefinition> _definitions;
    }
}
