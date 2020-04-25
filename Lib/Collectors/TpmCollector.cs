// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Tpm2Lib;
using Tpm2Tester;

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

                if (tpmDevice is TcpTpmDevice tcpTpmDevice)
                {
                    tcpTpmDevice.PowerCycle();
                    tpm.Startup(Su.Clear);
                }

                // TODO: Put Device/ACPI location here instead of PlatformString
                var obj = new TpmObject(AsaHelpers.GetPlatformString());

                Tpm2.GetTpmInfo(tpm, out string manufacturer, out uint specYear, out uint specDay);

                obj.TpmSpecDate = new DateTime((int)specYear, 1, 1).AddDays(specDay - 1);

                obj.Manufacturer = manufacturer;

                obj.Version = GetVersionString(tpm, manufacturer);

                obj.NV = DumpNV(tpm);

                obj.PCRs = DumpPCRs(tpm);

                obj.PersistentKeys = DumpPersistentKeys(tpm);

                // TODO:
                // obj.Algorithms = GetSupportedAlgorithms(tpm);

                GenerateRandomRsa(tpm, TpmAlgId.Sha256, 2048);
                // Turn that key into a CryptographicKeyObject
                // obj.RandomKeys.Add();

                // TODO: GenerateRandomEcc

                Results.Enqueue(obj);

                tpmDevice.Close();
            }

            tpmDevice?.Dispose();
        }

        public static string GetVersionString(Tpm2 tpm, string manufacturer)
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

        public static Dictionary<(TpmAlgId, uint), byte[]> DumpPCRs(Tpm2 tpm)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
            if (tpm == null)
            {
                return output;
            }

            var algorithms = new TpmAlgId[] { TpmAlgId.Sha1, TpmAlgId.Sha256, TpmAlgId.Sha384, TpmAlgId.Sha512, TpmAlgId.Sm2 };

            foreach (var algorithm in algorithms)
            {
                // Spec defines 24 PCRs
                foreach (var pcrVal in DumpPCRs(tpm, algorithm, new PcrSelection[] { PcrSelection.FullPcrBank(algorithm, 24) }))
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

                    foreach (var newPcr in newPcrs)
                    {
                        pcrs[0].SelectPcr(newPcr);
                    }

                    Log.Debug(JsonConvert.SerializeObject(valsRead));
                    Log.Debug(JsonConvert.SerializeObject(values));
                } while (pcrs[0].GetSelectedPcrs().Length > 0);
            }
            catch (Exception e)
            {
                Log.Debug(e, "Failed to read PCRs for algorithm {0}.", tpmAlgId);
            }

            return output;
        }

        public static Dictionary<uint, object> DumpNV(Tpm2 tpm)
        {
            var output = new Dictionary<uint, object>();

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

                    // TODO: Skip if policy would prevent us from accessing it
                    try
                    {
                        byte[] value = tpm.NvRead(hh, hh, nvPub.dataSize, 0);

                        output.Add(nvPub.nvIndex.GetOffset(), new AsaNvIndex() { Index = hh.handle & 0x00FFFFFF, value = value });
                    }
                    catch (TpmException)
                    {
                        Log.Debug($"Dumping NV {hh.handle & 0x00FFFFFF} failed");
                    }
                }
            } while (moreData == 1);

            return output;
        }

        public static CryptographicKeyObject GenerateRandomRsa(Tpm2 tpm, TpmAlgId hashAlg, ushort bits)
        {
            TpmAlgId nameAlg = hashAlg;
            var policy = new PolicyTree(nameAlg);
            policy.SetPolicyRoot(new TpmPolicyCommand(TpmCc.Duplicate));

            var inPub = new TpmPublic(nameAlg,
                    ObjectAttr.Sign | ObjectAttr.AdminWithPolicy | ObjectAttr.SensitiveDataOrigin,
                    policy.GetPolicyDigest(),
                    new RsaParms(new SymDefObject(),
                                 new SchemeRsassa(hashAlg),
                                 bits, 0),
                    new Tpm2bPublicKeyRsa());

            var Substrate = TestSubstrate.Create(Array.Empty<string>(), new Tpm2Tests());

            TpmHandle hKey = Substrate.CreateAndLoad(tpm, inPub, out TpmPublic pub);

            // Duplicate
            TpmPrivate priv = TpmHelper.GetPlaintextPrivate(tpm, hKey, policy);

            // Third argument is public key portion.
            var cko = new CryptographicKeyObject("GenerateRandomRsa", TpmAlgId.Rsa, new RSAPublicInformation())
            {
                Private = new BigInteger(priv.buffer)
            };

            tpm?.FlushContext(hKey);

            return cko;
        }

        partial class Tpm2Tests
        {
            // A test case method must be marked with 
            [Test(Profile.TPM20, Privileges.StandardUser, Category.Misc, Special.None)]
            void TestCertifyX509_1(Tpm2 tpm, TestContext testCtx)
            {
            }
        }
}