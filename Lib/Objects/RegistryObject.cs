// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;
using Serilog;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class RegistryObject
    {

        public string Key = "";
        public Dictionary<string, string> Values = new Dictionary<string, string>();
        public List<string> Subkeys = new List<string>();
        public string Permissions = "";

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        private static List<string> GetSubkeys(RegistryKey key)
        {
            return new List<string>(key.GetSubKeyNames());
        }

                private static Dictionary<string, string> GetValues(RegistryKey key)
        {
            Dictionary<string, string> values = new Dictionary<string, string>();
            // Write values under key and commit
            foreach (var value in key.GetValueNames())
            {
                var Value = key.GetValue(value);
                string str = "";

                // This is okay. It is a zero-length value
                if (Value == null)
                {
                    // We can leave this empty
                }

                else if (Value.ToString() == "System.Byte[]")
                {
                    str = Convert.ToBase64String((System.Byte[])Value);
                }

                else if (Value.ToString() == "System.String[]")
                {
                    str = "";
                    foreach (String st in (System.String[])Value)
                    {
                        str += st;
                    }
                }

                else
                {
                    if (Value.ToString() == Value.GetType().ToString())
                    {
                        Log.Warning("Uh oh, this type isn't handled. " + Value.ToString());
                    }
                    str = Value.ToString();
                }
                values.Add(value, str);
            }
            return values;
        }

        public RegistryObject(RegistryKey Key)
        {
            this.Key = Key.Name;
            this.Values = GetValues(Key);
            this.Subkeys = GetSubkeys(Key);
            this.Permissions = "";
            try
            {
                Permissions = Key.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
            }
            catch(Exception e)
            {
                Log.Debug(e.GetType() + " failed to get security descriptor for " + Key.Name);
            }
        }

        public RegistryObject()
        { }
    }
}