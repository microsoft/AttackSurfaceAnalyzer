// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Objects;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class TpmCollector : BaseCollector
    {
        public TpmCollector(CollectCommandOptions? opts = null, Action<CollectObject>? changeHandler = null) : base(opts, changeHandler) { }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        public override void ExecuteInternal()
        {
            Tpm2Device? tpmDevice = null;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                tpmDevice = new TbsDevice();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                tpmDevice = new LinuxTpmDevice();
            }

            if (tpmDevice is Tpm2Device)
            {
                //
            }

            tpmDevice?.Dispose();
        }
    }
}