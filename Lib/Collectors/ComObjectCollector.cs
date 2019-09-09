// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using Newtonsoft.Json;
using Serilog;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class ComObjectCollector : BaseCollector
    {

        public ComObjectCollector(string RunId)
        {
            this.runId = RunId;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public override void Execute()
        {

            if (!this.CanRunOnPlatform())
            {
                return;
            }
            Start();
            _ = DatabaseManager.Transaction;

            RegistryKey SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey("SOFTWARE\\Classes\\CLSID");
            
            foreach(string SubKeyName in SearchKey.GetSubKeyNames())
            {
                try
                {
                    RegistryKey CurrentKey = SearchKey.OpenSubKey(SubKeyName);

                    var RegObj = RegistryWalker.RegistryKeyToRegistryObject(CurrentKey);

                    ComObject comObject = new ComObject()
                    {
                        Key = RegObj,
                        Subkeys = new List<RegistryObject>()
                    };

                    foreach (string ComDetails in CurrentKey.GetSubKeyNames())
                    {
                        var ComKey = CurrentKey.OpenSubKey(ComDetails);
                        comObject.Subkeys.Add(RegistryWalker.RegistryKeyToRegistryObject(ComKey));
                    }

                    //Get the information from the InProcServer32 Subkey (for 32 bit)
                    if (comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).Count() > 0 && comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).First().Values.ContainsKey(""))
                    {
                        comObject.Subkeys.Where(x => x.Key.Contains("InprocServer32")).First().Values.TryGetValue("", out string BinaryPath32);
                        comObject.x86_Binary = FileSystemCollector.FileSystemInfoToFileSystemObject(new FileInfo(BinaryPath32), true);
                        comObject.x86_BinaryName = BinaryPath32;

                    }
                    // And the InProcServer64 for 64 bit
                    if (comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).Count() > 0 && comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).First().Values.ContainsKey(""))
                    {
                        comObject.Subkeys.Where(x => x.Key.Contains("InprocServer64")).First().Values.TryGetValue("", out string BinaryPath64);
                        comObject.x64_Binary = FileSystemCollector.FileSystemInfoToFileSystemObject(new FileInfo(BinaryPath64), true);
                        comObject.x64_BinaryName = BinaryPath64;
                    }

                    DatabaseManager.Write(comObject, runId);
                }
                catch(Exception e)
                {
                    Log.Debug(e, "Couldn't parse {0}", SubKeyName);
                }
                
            }

            DatabaseManager.Commit();
            Stop();
        }
    }
}