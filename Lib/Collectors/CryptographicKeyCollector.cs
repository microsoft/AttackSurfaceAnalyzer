// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Objects;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class CryptographicKeyCollector : BaseCollector
    {
        public CryptographicKeyCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public override void ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Foreach (var ksp in ksps){
                //  enumeratekeys(ksp)
                // }
            }
        }
    }
}