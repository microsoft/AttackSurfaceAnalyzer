// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class TpmCollector : BaseCollector
    {
        public bool TestMode { get; }

        private const string DefaultSimulatorName = "127.0.0.1";
        private const int DefaultSimulatorPort = 2321;

        public TpmCollector(bool TestMode)
        {
            this.TestMode = TestMode;
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        public override void ExecuteInternal()
        {
            Tpm2Device? tpmDevice = null;

            if (TestMode)
            {
                tpmDevice = new TcpTpmDevice(DefaultSimulatorName, DefaultSimulatorPort);
            }
            else
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    tpmDevice = new TbsDevice();
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    tpmDevice = new LinuxTpmDevice();
                }
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

        public static Dictionary<(TpmAlgId,uint),byte[]> DumpPCRs(Tpm2 tpm)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
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

        public static Dictionary<(TpmAlgId, uint), byte[]> DumpPCRs(Tpm2 tpm, TpmAlgId tpmAlgId, uint[] pcrs)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
            if (tpm == null || pcrs == null)
            {
                return output;
            }

            foreach(var pcr in pcrs)
            {
                var valuesToRead = new PcrSelection[]
                {
                    new PcrSelection(tpmAlgId, pcr)
                };

                PcrSelection[] valsRead;
                Tpm2bDigest[] values;

                tpm.PcrRead(valuesToRead, out valsRead, out values);

                var pcr1 = new TpmHash(TpmAlgId.Sha1, values[0].buffer);

                output.Add((TpmAlgId.Sha1, pcr), pcr1);
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
                    NvPublic nvPub = tpm.NvReadPublic(hh, out byte[] nvName);
                    byte[] value = tpm.NvRead(hh, hh, nvPub.dataSize, 0);
                    output.Add(nvName, value);
                }
            } while (moreData == 1);

            return output;
        }
    }
}