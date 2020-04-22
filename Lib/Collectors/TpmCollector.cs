// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Runtime.InteropServices;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class TpmCollector : BaseCollector
    {
        public TpmCollector()
        {
        }

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
                using var tpm = new Tpm2(tpmDevice);

                var obj = new TpmObject(tpm.GetFirmwareVersionEx());

                Tpm2.GetTpmInfo(tpm, out string manufacturer, out uint specYear, out uint specDay);
                obj.TpmSpecDate = new DateTime((int)specYear, 1, 1).AddDays(specDay - 1);
                obj.Manufacturer = manufacturer;
            }

            tpmDevice?.Dispose();
        }
    }
}