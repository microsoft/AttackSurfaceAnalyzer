// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public static class RegistryWalker
    {
        public static RegistryObject? RegistryKeyToRegistryObject(RegistryKey key, RegistryView registryView)
        {
            if (key == null)
            {
                return null;
            }
            RegistryObject regObj = new RegistryObject(key.Name, registryView);
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
                foreach (RegistryAccessRule? rule in key.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule != null)
                    {
                        string name = AsaHelpers.SidToName(rule.IdentityReference);

                        if (regObj.Permissions.ContainsKey(name))
                        {
                            regObj.Permissions[name].Add(rule.RegistryRights.ToString());
                        }
                        else
                        {
                            regObj.Permissions.Add(name, new List<string>() { rule.RegistryRights.ToString() });
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
            Stack<string> keys = new Stack<string>();

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
                        RegistryKey currentKey = BaseKey.OpenSubKey(key);

                        if (currentKey != null)
                        {
                            foreach (string subkey in currentKey.GetSubKeyNames())
                            {
                                keys.Push($"{key}\\{subkey}");
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