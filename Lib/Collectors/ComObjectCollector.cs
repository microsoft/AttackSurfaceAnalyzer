// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
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
    public class ComObjectcollector : BaseCollector
    {
        private List<RegistryHive> Hives;
        private HashSet<string> roots;
        private HashSet<RegistryKey> _keys;
        private HashSet<RegistryObject> _values;

        

        public ComObjectcollector(string RunId)
        {
            this.runId = RunId;
            this._keys = new HashSet<RegistryKey>();
            this._values = new HashSet<RegistryObject>();
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


            RegistryKey SearchKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default).OpenSubKey("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID");
            
            foreach(string SubKeyName in SearchKey.GetSubKeyNames())
            {
                RegistryKey CurrentKey = SearchKey.OpenSubKey(SubKeyName);

                var RegObj = RegistryWalker.RegistryKeyToRegistryObject(CurrentKey);

                ComObject comObject = new ComObject()
                {
                    Key = RegObj.Key,
                    CLSID = RegObj.Values[""],
                    Permissions = RegObj.Permissions,
                    Subkeys = new List<RegistryObject>()
                };

                foreach (string ComDetails in CurrentKey.GetSubKeyNames())
                {
                    var ComKey = CurrentKey.OpenSubKey(ComDetails);
                    comObject.Subkeys.Add(RegistryWalker.RegistryKeyToRegistryObject(ComKey));
                }

                //Get the information from the InProcServer32 Subkey (for 32 bit)
            }

            DatabaseManager.Commit();
            Stop();
        }
    }
}