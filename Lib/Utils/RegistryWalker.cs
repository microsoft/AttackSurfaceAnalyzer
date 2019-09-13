// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Utils
{
    public class RegistryWalker
    {

        public static IEnumerable<RegistryObject> WalkHive(RegistryHive Hive, string startingKey = null)
        {
            Stack<RegistryKey> keys = new Stack<RegistryKey>();

            RegistryKey SearchKey = RegistryKey.OpenBaseKey(Hive, RegistryView.Default);
            if (startingKey != null)
            {
                SearchKey = SearchKey.OpenSubKey(startingKey);
            }

            keys.Push(SearchKey);

            while (keys.Count > 0)
            {
                RegistryKey currentKey = keys.Pop();

                if (currentKey == null)
                {
                    continue;
                }
                if (Filter.IsFiltered(Helpers.GetPlatformString(), "Scan", "Registry", "Key", currentKey.Name))
                {
                    continue;
                }

                // First push all the new subkeys onto our stack.
                foreach (string key in currentKey.GetSubKeyNames())
                {
                    try
                    {
                        var next = currentKey.OpenSubKey(name: key, writable: false);
                        keys.Push(next);
                    }
                    // These are expected as we are running as administrator, not System.
                    catch (System.Security.SecurityException e)
                    {
                        Log.Verbose(e, "Permission Denied: {0}", currentKey.Name);
                    }
                    // There seem to be some keys which are listed as existing by the APIs but don't actually exist.
                    // Unclear if these are just super transient keys or what the other cause might be.
                    // Since this isn't user actionable, also just supress these to the verbose stream.
                    catch (System.IO.IOException e)
                    {
                        Log.Verbose(e, "Error Reading: {0}", currentKey.Name);
                    }
                    catch (Exception e)
                    {
                        Log.Information(e, "Unexpected error when parsing {0}:", currentKey.Name);
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }
                }

                var regObj = RegistryKeyToRegistryObject(currentKey);

                if (regObj != null)
                {
                    yield return regObj;
                }
            }
        }

        public static RegistryObject RegistryKeyToRegistryObject(RegistryKey registryKey)
        {
            RegistryObject regObj = null;
            try
            {
                regObj = new RegistryObject()
                {
                    Subkeys = new List<string>(registryKey.GetSubKeyNames()),
                    Key = registryKey.Name,
                    Permissions = registryKey.GetAccessControl().GetSecurityDescriptorSddlForm(System.Security.AccessControl.AccessControlSections.All),
                    Values = new Dictionary<string, string>()
                };

                foreach (string valueName in registryKey.GetValueNames())
                {
                    try
                    {
                        if (registryKey.GetValue(valueName) == null)
                        {

                        }
                        regObj.Values.Add(valueName, (registryKey.GetValue(valueName) == null) ? "" : (registryKey.GetValue(valueName).ToString()));
                    }
                    catch (Exception ex)
                    {
                        Log.Debug(ex, "Found an exception processing registry values.");
                    }
                }
            }
            catch (System.ArgumentException e)
            {
                Logger.VerboseException(e);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Couldn't process reg key {0}", registryKey.Name);
            }

            return regObj;
        }
    }
}