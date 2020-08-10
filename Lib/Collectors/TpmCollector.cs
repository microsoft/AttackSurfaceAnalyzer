// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Tpm2Lib;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Collectors
{
    public class TpmCollector : BaseCollector
    {
        public TpmCollector(CollectorOptions? opts, Action<CollectObject>? changeHandler, bool TestMode = false) : base(opts, changeHandler)
        {
            this.TestMode = TestMode;
        }

        public bool TestMode { get; }

        public static List<AsaNvIndex> DumpNV(Tpm2 tpm)
        {
            var output = new List<AsaNvIndex>();

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

                    var index = new AsaNvIndex() { Index = hh.handle & 0x00FFFFFF, Attributes = nvPub.attributes };

                    // We can read with just the owner auth
                    if (nvPub.attributes.HasFlag(NvAttr.Ownerread))
                    {
                        try
                        {
                            index.value = tpm.NvRead(TpmRh.Owner, hh, nvPub.dataSize, 0).ToList();
                        }
                        catch (TpmException e)
                        {
                            Log.Verbose("Dumping NV {0} failed ({1}:{2})", hh.handle & 0x00FFFFFF, e.GetType(), e.Message);
                        }
                    }

                    // TODO: Attempt with auth values if DA is disabled

                    output.Add(index);
                }
            } while (moreData == 1);

            return output;
        }

        public static Dictionary<(TpmAlgId, uint), byte[]> DumpPCRs(Tpm2 tpm)
        {
            var output = new Dictionary<(TpmAlgId, uint), byte[]>();
            if (tpm == null)
            {
                return output;
            }

            // Get which PCRs are supported
            tpm.GetCapability(Cap.Pcrs, 0, 255, out ICapabilitiesUnion caps);
            PcrSelection[] pcrs = ((PcrSelectionArray)caps).pcrSelections;

            foreach (var selection in pcrs)
            {
                // Dump each PCR bank
                foreach (var pcrVal in DumpPCRs(tpm, selection.hash, new PcrSelection[] { new PcrSelection(selection.hash, selection.GetSelectedPcrs()) }))
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

            try
            {
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
                } while (pcrs[0].GetSelectedPcrs().Length > 0);
            }
            catch (Exception e)
            {
                Log.Verbose(e, "Failed to read PCRs for algorithm {0}.", tpmAlgId);
            }

            return output;
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

        public static List<AlgProperty> GetSupportedAlgorithms(Tpm2 tpm)
        {
            if (tpm != null)
            {
                try
                {
                    ICapabilitiesUnion caps;
                    tpm.GetCapability(Cap.Algs, 0, 1000, out caps);
                    var algsx = (AlgPropertyArray)caps;

                    return algsx.algProperties.ToList();
                }
                catch (Exception e)
                {
                    Log.Verbose("Error getting supported Algorithms. ({0}:{1})", e.GetType(), e.Message);
                }
            }
            return new List<AlgProperty>();
        }

        public static List<TpmCc> GetSupportedCommands(Tpm2 tpm)
        {
            if (tpm != null)
            {
                try
                {
                    tpm.GetCapability(Cap.TpmProperties, (uint)Pt.TotalCommands, 1, out ICapabilitiesUnion caps);
                    tpm.GetCapability(Cap.Commands, (uint)TpmCc.First, TpmCc.Last - TpmCc.First + 1, out caps);

                    return ((CcaArray)caps).commandAttributes.Select(attr => (TpmCc)((uint)attr & 0x0000FFFFU)).ToList();
                }
                catch (Exception e)
                {
                    Log.Verbose("Error getting supported commands. ({0}:{1})", e.GetType(), e.Message);
                }
            }
            return new List<TpmCc>();
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

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        internal override void ExecuteInternal(CancellationToken cancellationToken)
        {
            Tpm2Device? tpmDevice = null;

            if (TestMode)
            {
                tpmDevice = new TcpTpmDevice(DefaultSimulatorName, DefaultSimulatorPort, stopTpm: false);
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
                else
                {
                    throw new PlatformNotSupportedException();
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

                obj.Algorithms = GetSupportedAlgorithms(tpm).ToList();

                obj.Commands = GetSupportedCommands(tpm).ToList();

                // TODO: GenerateRandomRsa(tpm, TpmAlgId.Sha256, 2048);

                // TODO: GenerateRandomEcc

                HandleChange(obj);

                tpmDevice.Close();
            }

            tpmDevice?.Dispose();
        }

        private const string DefaultSimulatorName = "127.0.0.1";
        private const int DefaultSimulatorPort = 2321;

        private static TpmHandle[] GetLoadedEntities(Tpm2 tpm, Ht rangeToQuery)
        {
            uint maxHandles = uint.MaxValue;
            byte moreData = tpm.GetCapability(Cap.Handles, ((uint)rangeToQuery) << 24,
                                              maxHandles, out ICapabilitiesUnion h);

            // TODO: Handle these errors without throwing
            if (moreData != 0)
            {
                throw new NotImplementedException("GetLoadedEntities: Too much data returned");
            }
            if (h.GetType() != typeof(HandleArray))
            {
                throw new Exception("GetLoadedEntities: Incorrect capability type requested");
            }
            return (h as HandleArray)?.handle ?? Array.Empty<TpmHandle>();
        }
    }
}