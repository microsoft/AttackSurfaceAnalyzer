// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Markdig.Parsers;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Tpm2Lib;

namespace AttackSurfaceAnalyzer.Collectors
{
    public class TpmCollector : BaseCollector
    {
        public bool TestMode { get; }

        private const string DefaultSimulatorName = "127.0.0.1";
        private const int DefaultSimulatorPort = 2321;

        public TpmCollector(bool TestMode = false)
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
                tpmDevice.Connect();

                using var tpm = new Tpm2(tpmDevice);

                if (tpmDevice is TcpTpmDevice)
                {
                    tpmDevice.PowerCycle();
                    tpm.Startup(Su.Clear);
                }

                // TODO: Put Device/ACPI location here instead of PlatformString
                var obj = new TpmObject(AsaHelpers.GetPlatformString());

                Tpm2.GetTpmInfo(tpm, out string manufacturer, out uint specYear, out uint specDay);

                obj.TpmSpecDate = new DateTime((int)specYear, 1, 1).AddDays(specDay - 1);

                obj.Manufacturer = manufacturer;

                obj.Version = GetVersionString(tpm,manufacturer);

                obj.NV = DumpNV(tpm);

                obj.PCRs = DumpPCRs(tpm);

                obj.PersistentKeys = DumpPersistentKeys(tpm);

                try
                {
                    GenerateRandomRsa(tpm, TpmAlgId.Sha256, 2048);
                }
                catch(Exception e)
                {
                    Log.Debug(e, "Failed to generate RSA Key");
                }
                // Turn that key into a CryptographicKeyObject
                // obj.RandomKeys.Add();

                // TODO: GenerateRandomEcc
            }

            tpmDevice?.Dispose();
        }

        public static string GetVersionString(Tpm2 tpm,string manufacturer)
        {
            var sb = new StringBuilder();

            if (tpm != null)
            {
                uint[] version = tpm.GetFirmwareVersionEx();
                if (version.Length > 0)
                {
                    sb.Append(version[0] >> 16);
                    sb.Append('.');
                    sb.Append(version[0] & 0x0000FFFF);
                    sb.Append('.');

                    if (version.Length > 1)
                    {
                        if (manufacturer is string && manufacturer.Equals("IFX"))
                        {
                            sb.Append((version[1] >> 8) & 0x0000FFFF);
                            sb.Append('.');
                            sb.Append(version[1] & 0x000000FF);
                        }
                        else
                        {
                            sb.Append(version[1] >> 16);
                            sb.Append('.');
                            sb.Append(version[1] & 0x0000FFFF);
                        }
                    }
                }
            }
            return sb.ToString();
        }

        private static TpmHandle[] GetLoadedEntities(Tpm2 tpm, Ht rangeToQuery)
        {
            uint maxHandles = uint.MaxValue;
            byte moreData = tpm.GetCapability(Cap.Handles, ((uint)rangeToQuery) << 24,
                                              maxHandles, out ICapabilitiesUnion h);

            // TODO: Handle these errors without throwing
            if (moreData != 0)
            {
                throw new NotImplementedException(
                                        "GetLoadedEntities: Too much data returned");
            }
            if (h.GetType() != typeof(HandleArray))
            {
                throw new Exception(
                            "GetLoadedEntities: Incorrect capability type requested");
            }
            return (h as HandleArray)?.handle ?? Array.Empty<TpmHandle>();
        }

        public static List<CryptographicKeyObject> DumpPersistentKeys(Tpm2 tpm)
        {
            var listOut = new List<CryptographicKeyObject>();
            if (tpm is null)
            {
                return listOut;
            }
            TpmHandle[] handles = GetLoadedEntities(tpm, Ht.Persistent);
            foreach (TpmHandle h in handles)
            {
               var tpmPublic = tpm.ReadPublic(h, out byte[] name, out byte[] qualifiedName);
               // TODO: Gather the details
            }
            return listOut;
        }

        public static Dictionary<(TpmAlgId,uint),byte[]> DumpPCRs(Tpm2 tpm)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
            if (tpm == null)
            {
                return output;
            }
            
            var algorithms = new TpmAlgId[] { TpmAlgId.Sha1, TpmAlgId.Sha256, TpmAlgId.Sha384, TpmAlgId.Sha512, TpmAlgId.Sm2 };

            foreach(var algorithm in algorithms)
            {
                // Spec defines 24 PCRs
                foreach(var pcrVal in DumpPCRs(tpm, algorithm, new PcrSelection[] { PcrSelection.FullPcrBank(algorithm, 24) }))
                {
                    output.Add(pcrVal.Key, pcrVal.Value);
                }
            }

            return output;
        }

        public static Dictionary<(TpmAlgId, uint), byte[]> DumpPCRs(Tpm2 tpm, TpmAlgId tpmAlgId, PcrSelection[] pcrs)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
            if (tpm == null || pcrs == null)
            {
                return output;
            }

            Log.Debug(JsonConvert.SerializeObject(pcrs));
            Log.Debug(tpmAlgId.ToString());

            try
            {
                // TODO: Check which PCRs are available first
                // This throws on unsupported algorithms.
                do
                {
                    tpm.PcrRead(pcrs, out PcrSelection[] valsRead, out Tpm2bDigest[] values);

                    var pcr = pcrs[0];
                    var valRead = valsRead[0];

                    if (values.Length == 0)
                    {
                        break;
                    }
                    var pcrsRead = valRead.GetSelectedPcrs();

                    var newPcrs = pcr.GetSelectedPcrs().Except(pcrsRead);

                    for (int i = 0; i < values.Length; i++)
                    {
                        output.Add((tpmAlgId, pcrsRead[i]), values[i].buffer);
                    }

                    pcrs[0] = new PcrSelection(tpmAlgId, 24);

                    foreach(var newPcr in newPcrs)
                    {
                        pcrs[0].SelectPcr(newPcr);
                    }

                    Log.Debug(JsonConvert.SerializeObject(valsRead));
                    Log.Debug(JsonConvert.SerializeObject(values));
                } while (pcrs[0].GetSelectedPcrs().Length > 0);
            }
            catch(Exception e)
            {
                Log.Debug(e,"Failed to read PCRs for algorithm {0}.",tpmAlgId);
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
                uint maxHandles = ushort.MaxValue;
                moreData = tpm.GetCapability(Cap.Handles, ((uint)Ht.NvIndex) << 24,
                                             maxHandles, out ICapabilitiesUnion cap);
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

        public static TpmHandle? GenerateRandomRsa(Tpm2 tpm, TpmAlgId hashAlg, ushort bits)
        {
            TpmHandle? keyHandle = null;
            if (tpm is null)
            {
                return keyHandle;
            }

            var ownerAuth = new AuthValue();

            // 
            // The TPM needs a template that describes the parameters of the key
            // or other object to be created.  The template below instructs the TPM 
            // to create a new 2048-bit migrateable signing key.
            // 
            var keyTemplate = new TpmPublic(hashAlg,      // Name algorithm
                                            ObjectAttr.Sign,     // Signing key
                                            null,               // No policy
                                            new RsaParms(new SymDefObject(),
                                                         new SchemeRsassa(hashAlg), bits, 0),
                                            new Tpm2bPublicKeyRsa());
            TpmPublic keyPublic;
            CreationData creationData;
            TkCreation creationTicket;
            byte[] creationHash;

            // 
            // Ask the TPM to create a new primary RSA signing key.
            // 
            try
            {
                keyHandle = tpm[ownerAuth].CreatePrimary(
                    TpmRh.Owner,                            // In the owner-hierarchy
                    null,     // With this auth-value
                    keyTemplate,                            // Describes key
                    null,                                   // Extra data for creation ticket
                    Array.Empty<PcrSelection>(),                    // Non-PCR-bound
                    out keyPublic,                          // PubKey and attributes
                    out creationData, out creationHash, out creationTicket);    // Not used here
            }
            catch(Exception e)
            {
                Log.Debug(e, "Failed to create RSA Key with algorithm {0} and size {1}", hashAlg, bits);
            }

            return keyHandle;
        }
    }
}