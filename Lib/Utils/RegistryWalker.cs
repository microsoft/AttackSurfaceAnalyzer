// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using AttackSurfaceAnalyzer.Objects;
using Microsoft.Win32;
using Serilog;

namespace AttackSurfaceAnalyzer.Utils
{
    public class RegistryWalker
    {

        public static IEnumerable<RegistryObject> WalkHive(RegistryHive Hive)
        {
            // Data structure to hold names of subfolders to be
            // examined for files.
            Stack<RegistryKey> keys = new Stack<RegistryKey>();

            //if (!System.IO.Directory.Exists(root))
            //{
            //    throw new ArgumentException("Unable to find [" + root + "]");
            //}
            RegistryKey BaseKey = RegistryKey.OpenBaseKey(Hive, RegistryView.Default);

            keys.Push(BaseKey);

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
                        var next = currentKey.OpenSubKey(key, false);
                        keys.Push(next);
                    }
                    // These are expected as we are running as administrator, not System.
                    catch (System.Security.SecurityException e)
                    {
                        Log.Debug(e.GetType() + " " + e.Message + " " + currentKey.Name);

                    }
                    // There seem to be some keys which are listed as existing by the APIs but don't actually exist.
                    // Unclear if these are just super transient keys or what the other cause might be.
                    // Since this isn't use actionable, also just supress these to the debug stream.
                    catch (System.IO.IOException e)
                    {
                        Log.Debug(e.GetType() + " " + e.Message + " " + currentKey.Name);
                    }
                    catch (Exception e)
                    {
                        Log.Information(e.GetType() + " " + e.Message + " " + currentKey.Name);
                        Telemetry.TrackTrace(Microsoft.ApplicationInsights.DataContracts.SeverityLevel.Error, e);
                    }
                }
                RegistryObject regObj = null;
                try
                {
                    regObj = new RegistryObject();

                }
                catch (Exception) { Log.Debug("I'm blue"); }
                if (regObj != null)
                {
                    yield return regObj;
                }

            }
        }
    }
}