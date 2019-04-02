// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;
using System.Security.AccessControl;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class RegistryObject
    {

        public RegistryKey Key;
        public Dictionary<string, string> Values;

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        public RegistryObject(RegistryKey Key, Dictionary<string,string> Values)
        {
            this.Key = Key;
            this.Values = Values;
        }

        public RegistryObject()
        { }
    }
}