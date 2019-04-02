// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using AttackSurfaceAnalyzer.ObjectTypes;
using Microsoft.Win32;

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

                if (Filter.IsFiltered(Filter.RuntimeString(), "Scan", "Registry", "Key", "Exclude", currentKey.Name))
                {
                    continue;
                }

                string[] subKeys = currentKey.GetSubKeyNames();

                if (currentKey == null)
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
                        Logger.Instance.Debug(e.GetType() + " " + e.Message + " " + currentKey.Name);
                    }
                    // There seem to be some keys which are listed as existing by the APIs but don't actually exist.
                    // Unclear if these are just super transient keys or what the other cause might be.
                    // Since this isn't use actionable, also just supress these to the debug stream.
                    catch (System.IO.IOException e)
                    {
                        Logger.Instance.Debug(e.GetType() + " " + e.Message + " " + currentKey.Name);
                    }
                    catch (Exception e)
                    {
                        Logger.Instance.Info(e.GetType() + " " + e.Message + " " + currentKey.Name);
                    }
                }
                var regObj = new RegistryObject(currentKey);

                yield return regObj;
            }
        }
    }
}