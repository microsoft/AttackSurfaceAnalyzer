// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Tpm2Lib;
using WindowsFirewallHelper;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class CollectorTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
        }

        [TestMethod]
        public void TestFileCollector()
        {
            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var opts = new CollectCommandOptions()
            {
                EnableFileSystemCollector = true,
                GatherHashes = true,
                SelectedDirectories = testFolder,
                DownloadCloud = false,
            };

            using (var file = File.Open(Path.Combine(testFolder, "AsaLibTesterMZ"), FileMode.OpenOrCreate))
            {
                file.Write(FileSystemUtils.WindowsMagicNumber, 0, 2);
                file.Write(FileSystemUtils.WindowsMagicNumber, 0, 2);

                file.Close();
            }

            using (var file = File.Open(Path.Combine(testFolder, "AsaLibTesterJavaClass"), FileMode.OpenOrCreate))
            {
                file.Write(FileSystemUtils.JavaMagicNumber, 0, 4);
                file.Close();
            }

            var fsc = new FileSystemCollector(opts);
            fsc.Execute();

            Assert.IsTrue(fsc.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterJavaClass") && FSO.IsExecutable == true));
            Assert.IsTrue(fsc.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterMZ") && FSO.IsExecutable == true));
        }

        /// <summary>
        /// Requires Admin
        /// </summary>
        [TestMethod]
        public void TestEventCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());

                using EventLog eventLog = new EventLog("Application");
                eventLog.Source = "Attack Surface Analyzer Tests";
                eventLog.WriteEntry("This Log Entry was created for testing the Attack Surface Analyzer library.", EventLogEntryType.Warning, 101, 1);

                var fsc = new EventLogCollector();
                fsc.Execute();

                Assert.IsTrue(fsc.Results.Any(x => x is EventLogObject ELO && ELO.Source == "Attack Surface Analyzer Tests" && ELO.Timestamp is DateTime DT && DT.AddMinutes(1).CompareTo(DateTime.Now) > 0));
            }
        }

        /// <summary>
        /// Requires Admin
        /// </summary>
        [TestMethod]
        public void TestTpmCollector()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var process = TpmSim.GetTpmSimulator();
                process.Start();

                var nvData = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
                uint nvIndex = 3001;

                var tpmc = new TpmCollector(TestMode: true);
                // Prepare to write to NV 3001
                TpmHandle nvHandle = TpmHandle.NV(nvIndex);

                TcpTpmDevice tcpTpmDevice = new TcpTpmDevice("127.0.0.1", 2321);
                tcpTpmDevice.Connect();

                using var tpm = new Tpm2(tcpTpmDevice);
                tcpTpmDevice.PowerCycle();
                tpm.Startup(Su.Clear);

                try
                {
                    tpm._AllowErrors()
                        .NvUndefineSpace(TpmRh.Owner, nvHandle);

                    AuthValue nvAuth = new AuthValue();
                    tpm.NvDefineSpace(TpmRh.Owner, nvAuth,
                                      new NvPublic(nvHandle, TpmAlgId.Sha1,
                                                   NvAttr.NoDa | NvAttr.Ownerread | NvAttr.Ownerwrite,
                                                   null, 32));


                    // Write to NV 3001
                    tpm.NvWrite(nvHandle, nvHandle, nvData, 0);

                    var nvOut = tpm.NvRead(nvHandle, nvHandle, (ushort)nvData.Length, 0);
                    Assert.IsTrue(nvOut.SequenceEqual(nvData));
                }
                catch (TpmException e)
                {
                    Log.Debug(e, "Failed to Write to NV.");
                }

                // We haven't written anything to the PCRs yet so they should be the same.
                var pcrs = TpmCollector.DumpPCRs(tpm, TpmAlgId.Sha256, new PcrSelection[] { new PcrSelection(TpmAlgId.Sha256, new uint[] { 15, 16 }, 24) });
                Assert.IsTrue(pcrs[(TpmAlgId.Sha256, 15)].SequenceEqual(pcrs[(TpmAlgId.Sha256, 16)]));

                try
                {
                    // Measure to PCR 16
                    tpm.PcrEvent(TpmHandle.Pcr(16), nvData);
                }
                catch (TpmException e)
                {
                    Log.Debug(e, "Failed to Write PCR.");
                }

                tcpTpmDevice.Close();

                process.Kill();

                process = TpmSim.GetTpmSimulator();
                process.Start();

                // Execute the collector
                tpmc.Execute();

                process.Kill();
                // Clean up after simulator
                File.Delete("NVChip");

                if (tpmc.Results.TryPop(out CollectObject? collectObject))
                {
                    if (collectObject is TpmObject tpmObject)
                    {
                        // We should be able to confirm the NV Data we wrote
                        Assert.IsTrue(tpmObject.NV.ContainsKey(nvIndex));
                        Assert.IsTrue(tpmObject.NV[nvIndex] is byte[] bytes && bytes.SequenceEqual(nvData));

                        // We should also be able to confirm that the PCR bank we measured into has changed and that other's haven't
                        Assert.IsTrue(tpmObject.PCRs[(TpmAlgId.Sha1, 16)].SequenceEqual(pcrs[(TpmAlgId.Sha256, 16)]));
                        Assert.IsFalse(tpmObject.PCRs[(TpmAlgId.Sha1, 16)].SequenceEqual(pcrs[(TpmAlgId.Sha256, 16)]));
                        Assert.IsFalse(tpmObject.PCRs[(TpmAlgId.Sha1, 16)].SequenceEqual(tpmObject.PCRs[(TpmAlgId.Sha1, 15)]));
                    }
                    else
                    {
                        Assert.Fail();
                    }
                }
            }
        }

        /// <summary>
        /// Does not require admin.
        /// </summary>
        [TestMethod]
        public void TestCertificateCollectorWindows()
        {
            var fsc = new CertificateCollector();
            fsc.Execute();

            Assert.IsTrue(fsc.Results.Where(x => x.ResultType == RESULT_TYPE.CERTIFICATE).Count() > 0);
        }

        /// <summary>
        /// Does not require Admin.
        /// </summary>
        [TestMethod]
        public void TestPortCollectorWindows()
        {
            TcpListener? server = null;
            try
            {
                // Set the TcpListener on port 13000.
                int port = 13000;
                IPAddress localAddr = IPAddress.Parse("127.0.0.1");

                // TcpListener server = new TcpListener(port);
                server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();
            }
            catch (Exception)
            {
                Console.WriteLine("Failed to open port.");
            }
            var fsc = new OpenPortCollector();
            fsc.Execute();
            server?.Stop();

            Assert.IsTrue(fsc.Results.Any(x => x is OpenPortObject OPO && OPO.Port == 13000));
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCollectorOSX()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add /bin/bash");

                var fwc = new FirewallCollector();
                fwc.Execute();
                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove /bin/bash");
                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName == "/bin/bash"));
            }
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCollectorLinux()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var result = ExternalCommandRunner.RunExternalCommand("iptables", "-A INPUT -p tcp --dport 19999 -j DROP");

                var fwc = new FirewallCollector();
                fwc.Execute();

                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.LocalPorts != null && FWO.LocalPorts.Contains("19999")));

                result = ExternalCommandRunner.RunExternalCommand("iptables", "-D INPUT -p tcp --dport 19999 -j DROP");
            }
        }


        [TestMethod]
        public void TestFirewallCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());

                var rule = FirewallManager.Instance.CreatePortRule(
                    @"TestFirewallPortRule",
                    FirewallAction.Allow,
                    9999,
                    FirewallProtocol.TCP
                );
                FirewallManager.Instance.Rules.Add(rule);

                rule = FirewallManager.Instance.CreateApplicationRule(
                    @"TestFirewallAppRule",
                    FirewallAction.Allow,
                    @"C:\MyApp.exe"
                );
                rule.Direction = FirewallDirection.Outbound;
                FirewallManager.Instance.Rules.Add(rule);

                var fwc = new FirewallCollector();
                fwc.Execute();

                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.LocalPorts != null && FWO.LocalPorts.Contains("9999")));
                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName is string && FWO.ApplicationName.Equals(@"C:\MyApp.exe")));


                var rules = FirewallManager.Instance.Rules.Where(r => r.Name == "TestFirewallPortRule");
                foreach (var ruleIn in rules)
                {
                    FirewallManager.Instance.Rules.Remove(ruleIn);
                }

                rules = FirewallManager.Instance.Rules.Where(r => r.Name == "TestFirewallAppRule");
                foreach (var ruleIn in rules)
                {
                    FirewallManager.Instance.Rules.Remove(ruleIn);
                }
            }
        }

        /// <summary>
        /// Does not require administrator.
        /// </summary>
        [TestMethod]
        public void TestRegistryCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Create a registry key
                var name = Guid.NewGuid().ToString();
                var value = Guid.NewGuid().ToString();
                var value2 = Guid.NewGuid().ToString();

                RegistryKey key;
                key = Registry.CurrentUser.CreateSubKey(name);
                key.SetValue(value, value2);
                key.Close();

                var rc = new RegistryCollector(new List<(RegistryHive, string)>() { (RegistryHive.CurrentUser, name) }, new CollectCommandOptions() { SingleThread = true });
                rc.Execute();

                Registry.CurrentUser.DeleteSubKey(name);

                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name)));
                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name) && RO.Values != null && RO.Values.ContainsKey(value) && RO.Values[value] == value2));
            }
        }

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestServiceCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                // Create a service - This won't throw an exception, but it won't work if you are not an Admin.
                var serviceName = "AsaDemoService";
                var exeName = "AsaDemoService.exe";
                var cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                var sc = new ServiceCollector();
                sc.Execute();

                Assert.IsTrue(sc.Results.Any(x => x is ServiceObject RO && RO.Name.Equals(serviceName)));

                // Clean up
                cmd = string.Format("delete {0}", serviceName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);
            }
        }

        /// <summary>
        /// Requires admin.
        /// </summary>
        [TestMethod]
        public void TestComObjectCollector()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var coc = new ComObjectCollector(new CollectCommandOptions());
                coc.Execute();

                Assert.IsTrue(coc.Results.Any(x => x is ComObject y && y.x86_Binary != null));
            }
        }

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestUserCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var user = System.Guid.NewGuid().ToString().Substring(0, 10);
                var password = "$" + CryptoHelpers.GetRandomString(13);

                var cmd = string.Format("user /add {0} {1}", user, password);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                var uac = new UserAccountCollector();
                uac.Execute();

                Assert.IsTrue(uac.Results.Any(x => x is UserAccountObject y && y.Name.Equals(user)));

                cmd = string.Format("user /delete {0}", user);
                ExternalCommandRunner.RunExternalCommand("net", cmd);
            }
        }
    }
}
