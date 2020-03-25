// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using Microsoft.Win32;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class ComObject : CollectObject
    {
        // From Registry
        public RegistryObject Key { get; set; }
        public List<RegistryObject> Subkeys { get; set; }
        // From filesystem
        public FileSystemObject? x86_Binary { get; set; }
        public FileSystemObject? x64_Binary { get; set; }
        public string? x86_BinaryName { get; set; }
        public string? x64_BinaryName { get; set; }

        /// <summary>
        /// This is the correct constructor to use to create a ComObject.
        /// </summary>
        /// <param name="Key"></param>
        public ComObject(RegistryObject Key) : base()
        {
            this.Key = Key;
            Subkeys = new List<RegistryObject>();
            ResultType = RESULT_TYPE.COM;
        }

        public void AddSubKeys(List<RegistryObject> subkeysIn)
        {
            Subkeys.AddRange(subkeysIn);
        }

        public void AddSubKey(RegistryObject subkeysIn)
        {
            Subkeys.Add(subkeysIn);
        }

        public override string Identity
        {
            get
            {
                return Key.Identity;
            }
        }
    }
}