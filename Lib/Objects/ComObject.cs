// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Collections.Generic;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class ComObject : CollectObject
    {
        // From Registry
        public string CLSID { get; set; }
        public string Name { get; set; }
        public List<RegistryObject> Subkeys;
        // From filesystem
        public FileSystemObject x86_Binary;
        public FileSystemObject x64_Binary;

        public ComObject()
        {
            ResultType = RESULT_TYPE.COM;
        }

        public override string Identity
        {
            get
            {
                return CLSID;
            }
        }
    }
}