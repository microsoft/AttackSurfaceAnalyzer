// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using System.Collections.Generic;

namespace AttackSurfaceAnalyzer.Objects
{
    public class ComObject : CollectObject
    {
        // From Registry
        public RegistryObject Key { get; set; }
        public List<RegistryObject> Subkeys { get; set; }
        // From filesystem
        public FileSystemObject x86_Binary { get; set; }
        public FileSystemObject x64_Binary { get; set; }
        public string x86_BinaryName { get; set; }
        public string x64_BinaryName { get; set; }

        public ComObject()
        {
            ResultType = RESULT_TYPE.COM;
            Subkeys = new List<RegistryObject>();
        }

        public void AddSubKeys(List<RegistryObject> subkeysIn)
        {
            Subkeys.AddRange(subkeysIn);
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