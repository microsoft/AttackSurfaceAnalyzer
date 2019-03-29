// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Security.AccessControl;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.Win32;

namespace AttackSurfaceAnalyzer.ObjectTypes
{
    public class RegistryObject
    {

        public RegistryKey Key;

        public string Path;
        public bool IsKey;
        public string Value;
        public string Contents;

        public string RowKey
        {
            get
            {
                return CryptoHelpers.CreateHash(this.ToString());
            }
        }

        public override string ToString()
        {
            return string.Format("Key={0}, Value={1}, Contents={2}, IsKey={3}, Permissions={4}", Key.Name, Value, Contents, IsKey, Key.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        }

        public RegistryObject(RegistryKey Key, bool isKey) : this(Key, "", "", isKey) { }

        public RegistryObject(RegistryKey Key, string Value, string Contents, bool isKey)
        {
            this.Key = Key;
            this.Value = Value;
            this.Contents = Contents;
            this.IsKey = isKey;
        }

        public RegistryObject()
        { }
    }
}