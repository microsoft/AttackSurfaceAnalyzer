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
                        foreach (var right in rule.RegistryRights.ToString().Split(','))
                        {
                            var entry = $"{rule.AccessControlType}:{right.Trim()}";
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

            return regObj;
        }

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