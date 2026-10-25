// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class RegistryWalker
    {
        public static RegistryObject? RegistryKeyToRegistryObject(RegistryKey key, RegistryView registryView)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            if (key == null)
            {
                return null;
            }
            RegistryObject regObj = new(key.Name, registryView);
            try
            {
                regObj.AddSubKeys(key.GetSubKeyNames());
            }
            catch (System.ArgumentException)
            {
                Log.Debug("Invalid Handle (ArgumentException) {0}", key.Name);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Couldn't process reg key {0}", key.Name);
            }

            try
            {
                var security = key.GetAccessControl();

                try
                {
                    regObj.PermissionsString = security.GetSecurityDescriptorSddlForm(AccessControlSections.All);
                }
                catch (Exception e)
                {
                    Log.Verbose("Failed to get SDDL for {0} ({1}:{2})", regObj.Key, e.GetType(), e.Message);
                }

                foreach (RegistryAccessRule? rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule != null)
                    {
                        string name = AsaHelpers.SidToName(rule.IdentityReference);

                        if (!regObj.Permissions.TryGetValue(name, out List<string>? rights))
                        {
                            rights = new List<string>();
                            regObj.Permissions.Add(name, rights);
                        }

                        // RegistryRights.ToString() returns a comma joined combined mask. Split it so
                        // individual rights are matchable, and prefix each with the access control type so
                        // Allow and Deny are distinguishable.
                        foreach (var right in PermissionUtils.SplitRights(rule.RegistryRights.ToString()))
                        {
                            var entry = PermissionUtils.EncodeRight(rule.AccessControlType, right);
                            if (!rights.Contains(entry))
                            {
                                rights.Add(entry);
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.Debug(e, "Failed to get permissions for {0} ({1}:{2})", regObj.Key, e.GetType(), e.Message);
            }

            regObj.Values = RegistryObject.GetValues(key);
            PopulateReferences(regObj);

            return regObj;
        }

        /// <summary>
        ///     Cracks file paths and CLSIDs out of the key's values so that analysis rules, which cannot
        ///     follow a reference from one collected object to another, can interrogate them directly.
        /// </summary>
        private static void PopulateReferences(RegistryObject regObj)
        {
            if (regObj.Values is null || regObj.Values.Count == 0)
            {
                return;
            }

            HashSet<string> paths = new(StringComparer.OrdinalIgnoreCase);
            HashSet<string> clsids = new(StringComparer.OrdinalIgnoreCase);

            foreach (var value in regObj.Values.Values)
            {
                if (paths.Count >= MaxReferencesPerKey && clsids.Count >= MaxReferencesPerKey)
                {
                    break;
                }

                if (paths.Count < MaxReferencesPerKey)
                {
                    foreach (var path in RegistryReferenceParser.ExtractPaths(value))
                    {
                        if (paths.Add(path))
                        {
                            regObj.ReferencedPaths.Add(path);
                        }
                    }
                }

                if (clsids.Count < MaxReferencesPerKey)
                {
                    foreach (var clsid in RegistryReferenceParser.ExtractClsids(value))
                    {
                        if (clsids.Add(clsid))
                        {
                            regObj.ReferencedClsids.Add(clsid);
                        }
                    }
                }
            }
        }

        /// <summary>
        ///     Caps the references retained for a single key so that a pathological key cannot blow up the
        ///     collected object.
        /// </summary>
        private const int MaxReferencesPerKey = 128;

        public static IEnumerable<string> WalkHive(RegistryHive Hive, RegistryView View, string startingKey = "")
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw new PlatformNotSupportedException("ExecuteWindows is only supported on Windows platforms.");
            }
            Stack<string> keys = new();
            RegistryKey? BaseKey = null;
            try
            {
                BaseKey = RegistryKey.OpenBaseKey(Hive, View);
            }
            catch (Exception e) when (
                e is IOException ||
                e is ArgumentException ||
                e is UnauthorizedAccessException ||
                e is System.Security.SecurityException)
            {
                Log.Debug($"Failed to open Hive {Hive} for walking.");
            }

            if (BaseKey != null)
            {
                keys.Push(startingKey);

                while (keys.Count > 0)
                {
                    var key = keys.Pop();
                    try
                    {
                        RegistryKey? currentKey = BaseKey.OpenSubKey(key);

                        if (currentKey != null)
                        {
                            foreach (string subkey in currentKey.GetSubKeyNames())
                            {
                                keys.Push(!string.IsNullOrEmpty(key) ? $"{key}\\{subkey}" : subkey);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Log.Verbose("Failed to open SubKey {0} ({1})", key, e.GetType());
                    }

                    yield return key;
                }
            }

            BaseKey?.Dispose();
        }
    }
}