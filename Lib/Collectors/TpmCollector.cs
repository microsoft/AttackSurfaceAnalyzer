// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.Linq;
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

                // TODO: Put Device/ACPI location here
                var obj = new TpmObject(tpm.GetFirmwareVersionEx(), AsaHelpers.GetPlatformString());

                Tpm2.GetTpmInfo(tpm, out string manufacturer, out uint specYear, out uint specDay);
                obj.TpmSpecDate = new DateTime((int)specYear, 1, 1).AddDays(specDay - 1);
                obj.Manufacturer = manufacturer;

                obj.NV = DumpNV(tpm);

                obj.PCRs = DumpPCRs(tpm);
            }

            tpmDevice?.Dispose();
        }

        public static Dictionary<(TpmAlgId,int),byte[]> DumpPCRs(Tpm2 tpm)
        {
            var output = new Dictionary<(TpmAlgId, int), byte[]>();
            if (tpm == null)
            {
                return output;
            }

            // Spec defines 24 PCRs
            var allPcrs = new uint[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 };

            foreach(var pcrVal in DumpPCRs(tpm, TpmAlgId.Sha1, allPcrs))
            {
                output.Add(pcrVal.Key, pcrVal.Value);
            }
            foreach (var pcrVal in DumpPCRs(tpm, TpmAlgId.Sha256, allPcrs))
            {
                output.Add(pcrVal.Key, pcrVal.Value);
            }
            foreach (var pcrVal in DumpPCRs(tpm, TpmAlgId.Sha384, allPcrs))
            {
                output.Add(pcrVal.Key, pcrVal.Value);
            }
            foreach (var pcrVal in DumpPCRs(tpm, TpmAlgId.Sha512, allPcrs))
            {
                output.Add(pcrVal.Key, pcrVal.Value);
            }
            foreach (var pcrVal in DumpPCRs(tpm, TpmAlgId.Sm2, allPcrs))
            {
                output.Add(pcrVal.Key, pcrVal.Value);
            }

            return output;
        }

        public static Dictionary<(TpmAlgId, int), byte[]> DumpPCRs(Tpm2 tpm, TpmAlgId tpmAlgId, uint[] pcrs)
        {
            var output = new Dictionary<(TpmAlgId, int), byte[]>();
            if (tpm == null)
            {
                return output;
            }

            var valuesToRead = new PcrSelection[]
            {
                new PcrSelection(tpmAlgId, pcrs)
            };

            PcrSelection[] valsRead;
            Tpm2bDigest[] values;

            tpm.PcrRead(valuesToRead, out valsRead, out values);

            //
            // Check that what we read is what we asked for (the TPM does not 
            // guarantee this)
            // 
            if (valsRead[0] == valuesToRead[0])
            {
                for (int i = 0; i < 24; i++)
                {
                    var pcr1 = new TpmHash(TpmAlgId.Sha1, values[i].buffer);
                    output.Add((TpmAlgId.Sha1, i), pcr1);
                }
            }

            return output;
        }

        public static Dictionary<byte[],object> DumpNV(Tpm2 tpm)
        {
            var output = new Dictionary<byte[], object>();

            if (tpm == null)
            {
                return output;
            }

            byte moreData;
            do
            {
                ICapabilitiesUnion cap;
                uint maxHandles = UInt16.MaxValue;
                moreData = tpm.GetCapability(Cap.Handles, ((uint)Ht.NvIndex) << 24,
                                             maxHandles, out cap);
                HandleArray handles = (HandleArray)cap;
                foreach (TpmHandle hh in handles.handle)
                {
                    output.Add(hh.GetName(), hh.GetTpmRepresentation());
                }
            } while (moreData == 1);

            return output;
        }
    }
}