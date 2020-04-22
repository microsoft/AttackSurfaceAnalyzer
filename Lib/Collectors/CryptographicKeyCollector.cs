// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class CryptographicKeyCollector : BaseCollector
    {
        public CryptographicKeyCollector()
        {
        }

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