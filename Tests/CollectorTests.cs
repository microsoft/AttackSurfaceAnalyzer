// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Microsoft.CST.AttackSurfaceAnalyzer.Collectors;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using Tpm2Lib;
using WindowsFirewallHelper;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class CollectorTests
    {
        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        /// <summary>
        ///     Does not require admin.
        /// </summary>
        [TestMethod]
        public void TestCertificateCollectorWindows()
        {
            var cc = new CertificateCollector();
            cc.TryExecute();

            Assert.IsTrue(cc.Results.Where(x => x.ResultType == RESULT_TYPE.CERTIFICATE).Count() > 0);

            ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
            cc = new CertificateCollector(changeHandler: x => results.Push(x));
            cc.TryExecute();

            Assert.IsTrue(results.Where(x => x.ResultType == RESULT_TYPE.CERTIFICATE).Count() > 0);
        }

        /// <summary>
        ///     Requires admin.
        /// </summary>
        [TestMethod]
        public void TestComObjectCollector()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var coc = new ComObjectCollector(new CollectorOptions());
                coc.TryExecute();

                Assert.IsTrue(coc.Results.Any(x => x is ComObject y && y.x86_Binary != null));

                ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
                coc = new ComObjectCollector(changeHandler: x => results.Push(x));
                coc.TryExecute();

                Assert.IsTrue(results.Any(x => x is ComObject y && y.x86_Binary != null));
            }
        }

        /// <summary>
        ///     Administrator not required
        /// </summary>
        [TestMethod]
        public void TestDriverCollector()
        {
            var dc = new DriverCollector(new CollectorOptions());
            dc.TryExecute();

            Assert.IsTrue(dc.Results.Any());
        }

        /// <summary>
        ///     Requires Admin
        /// </summary>
        [TestMethod]
        public void TestEventCollectorWindows()
        {
            var source = "AsaTests";
            var logname = "AsaTestLogs";

            if (EventLog.SourceExists(source))
            {
                // Delete the source and the log.
                EventLog.DeleteEventSource(source);
                EventLog.Delete(logname);
            }

            // Create the event source to make next try successful.
            EventLog.CreateEventSource(source, logname);

            using EventLog eventLog = new EventLog("Application");
            eventLog.Source = "Attack Surface Analyzer Tests";
            eventLog.WriteEntry("This Log Entry was created for testing the Attack Surface Analyzer library.", EventLogEntryType.Warning, 101, 1);

            var elc = new EventLogCollector(new CollectorOptions());
            elc.TryExecute();

            Assert.IsTrue(elc.Results.Any(x => x is EventLogObject ELO && ELO.Source == "Attack Surface Analyzer Tests" && ELO.Timestamp is DateTime DT && DT.AddMinutes(1).CompareTo(DateTime.Now) > 0));

            ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
            elc = new EventLogCollector(new CollectorOptions(), x => results.Push(x));
            elc.TryExecute();

            Assert.IsTrue(results.Any(x => x is EventLogObject ELO && ELO.Source == "Attack Surface Analyzer Tests" && ELO.Timestamp is DateTime DT && DT.AddMinutes(1).CompareTo(DateTime.Now) > 0));

            EventLog.DeleteEventSource(source);
            EventLog.Delete(logname);
        }

        [TestMethod]
        public void TestFileCollector()
        {
            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var opts = new CollectorOptions()
            {
                EnableFileSystemCollector = true,
                GatherHashes = true,
                SelectedDirectories = new List<string>(){ testFolder },
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
            fsc.TryExecute();

            Assert.IsTrue(fsc.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterJavaClass") && FSO.IsExecutable == true));
            Assert.IsTrue(fsc.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterMZ") && FSO.IsExecutable == true));

            ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
            fsc = new FileSystemCollector(opts, x => results.Push(x));
            fsc.TryExecute();

            Assert.IsTrue(results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterJavaClass") && FSO.IsExecutable == true));
            Assert.IsTrue(results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterMZ") && FSO.IsExecutable == true));
        }

        /// <summary>
        ///     Does not require admin
        /// </summary>
        [TestMethod]
        public void TestFileMonitor()
        {
            var stack = new ConcurrentStack<FileMonitorObject>();
            var monitor = new FileSystemMonitor(new MonitorCommandOptions() { MonitoredDirectories = new List<string> { Path.GetTempPath() } }, x => stack.Push(x));
            monitor.StartRun();

            var created = Path.GetTempFileName(); // Create a file
            var renamed = $"{created}-renamed";
            File.WriteAllText(created, "Test"); // Change the size
            Thread.Sleep(50);
            File.Move(created, renamed); // Rename it
            Thread.Sleep(50);
            File.Delete(renamed); //Delete it

            Thread.Sleep(100);

            monitor.StopRun();

            Assert.IsTrue(stack.Any(x => x.NotifyFilters == NotifyFilters.FileName && x.Path == created));
            Assert.IsTrue(stack.Any(x => x.NotifyFilters == NotifyFilters.Size && x.Path == created));
            Assert.IsTrue(stack.Any(x => x.ChangeType == CHANGE_TYPE.RENAMED && x.NotifyFilters == NotifyFilters.FileName && x.Path == renamed));
            Assert.IsTrue(stack.Any(x => x.ChangeType == CHANGE_TYPE.DELETED && x.Path == renamed));
        }

        /// <summary>
        ///     Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCollectorLinux()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var result = ExternalCommandRunner.RunExternalCommand("iptables", "-A INPUT -p tcp --dport 19999 -j DROP");

                var fwc = new FirewallCollector();
                fwc.TryExecute();

                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.LocalPorts.Contains("19999")));

                result = ExternalCommandRunner.RunExternalCommand("iptables", "-D INPUT -p tcp --dport 19999 -j DROP");
            }
        }

        /// <summary>
        ///     Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCollectorOSX()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add /bin/bash");

                var fwc = new FirewallCollector();
                fwc.TryExecute();
                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove /bin/bash");
                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName == "/bin/bash"));
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
                fwc.TryExecute();

                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.LocalPorts.Contains("9999")));
                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName is string && FWO.ApplicationName.Equals(@"C:\MyApp.exe")));

                ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
                fwc = new FirewallCollector(changeHandler: x => results.Push(x));
                fwc.TryExecute();

                Assert.IsTrue(results.Any(x => x is FirewallObject FWO && FWO.LocalPorts.Contains("9999")));
                Assert.IsTrue(results.Any(x => x is FirewallObject FWO && FWO.ApplicationName is string && FWO.ApplicationName.Equals(@"C:\MyApp.exe")));

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
        ///     Does not require Admin.
        /// </summary>
        [TestMethod]
        public void TestPortCollectorWindows()
        {
            TcpListener server = null;
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
            var pc = new OpenPortCollector();
            pc.TryExecute();
            var results1 = pc.Results;

            ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
            pc = new OpenPortCollector(changeHandler: x => results.Push(x));
            pc.TryExecute();

            server.Stop();

            Assert.IsTrue(results1.Any(x => x is OpenPortObject OPO && OPO.Port == 13000));
            Assert.IsTrue(results.Any(x => x is OpenPortObject OPO && OPO.Port == 13000));
        }

        /// <summary>
        ///     Administrator recommended
        /// </summary>
        [TestMethod]
        public void TestProcessCollector()
        {
            var pc = new ProcessCollector(new CollectorOptions());
            pc.TryExecute();

            var p = Process.GetCurrentProcess();

            Assert.IsTrue(pc.Results.Any(x => x is ProcessObject y && y.ProcessName == p.ProcessName));
        }

        /// <summary>
        ///     Does not require administrator.
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

                var rc = new RegistryCollector(new CollectorOptions() { SingleThread = true, SelectedHives = new List<string> { $"CurrentUser\\{name}" } });
                rc.TryExecute();

                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name)));
                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name) && RO.Values.ContainsKey(value) && RO.Values[value] == value2));

                ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
                rc = new RegistryCollector(new CollectorOptions() { SingleThread = true, SelectedHives = new List<string> { $"CurrentUser\\{name}" } }, x => results.Push(x));
                rc.TryExecute();

                Assert.IsTrue(results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name)));
                Assert.IsTrue(results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name) && RO.Values.ContainsKey(value) && RO.Values[value] == value2));

                Registry.CurrentUser.DeleteSubKey(name);
            }
        }

        /// <summary>
        ///     Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestServiceCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Create a service - This won't throw an exception, but it won't work if you are not an Admin.
                var serviceName = "AsaDemoService";
                var exeName = "AsaDemoService.exe";
                var cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                var sc = new ServiceCollector(new CollectorOptions());
                sc.TryExecute();

                Assert.IsTrue(sc.Results.Any(x => x is ServiceObject RO && RO.Name.Equals(serviceName)));

                ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
                sc = new ServiceCollector(changeHandler: x => results.Push(x));
                sc.TryExecute();

                Assert.IsTrue(results.Any(x => x is ServiceObject RO && RO.Name.Equals(serviceName)));

                // Clean up
                cmd = string.Format("delete {0}", serviceName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);
            }
        }

        /// <summary>
        ///     Requires Admin
        /// </summary>
        [TestMethod]
        public void TestTpmCollector()
        {
            var PcrAlgorithm = TpmAlgId.Sha256;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var process = TpmSim.GetTpmSimulator();
                process.Start();

                var nvData = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 };
                uint nvIndex = 3001;

                var tpmc = new TpmCollector(new CollectorOptions() { Verbose = true }, null, TestMode: true);
                // Prepare to write to NV 3001
                TpmHandle nvHandle = TpmHandle.NV(nvIndex);

                TcpTpmDevice tcpTpmDevice = new TcpTpmDevice("127.0.0.1", 2321, stopTpm: false);
                tcpTpmDevice.Connect();

                using var tpm = new Tpm2(tcpTpmDevice);
                tcpTpmDevice.PowerCycle();
                tpm.Startup(Su.Clear);

                try
                {
                    tpm._AllowErrors()
                        .NvUndefineSpace(TpmRh.Owner, nvHandle);

                    tpm.NvDefineSpace(TpmRh.Owner, null,
                                      new NvPublic(nvHandle, TpmAlgId.Sha1,
                                                   NvAttr.NoDa | NvAttr.Ownerread | NvAttr.Ownerwrite,
                                                   null, 32));

                    // Write to NV 3001
                    tpm.NvWrite(TpmRh.Owner, nvHandle, nvData, 0);

                    var nvOut = tpm.NvRead(TpmRh.Owner, nvHandle, (ushort)nvData.Length, 0);

                    Assert.IsTrue(nvOut.SequenceEqual(nvData));
                }
                catch (TpmException e)
                {
                    Log.Debug(e, "Failed to Write to NV.");
                    Assert.Fail();
                }

                // Verify that all the PCRs are blank to start with
                var pcrs = TpmCollector.DumpPCRs(tpm, PcrAlgorithm, new PcrSelection[] { new PcrSelection(PcrAlgorithm, new uint[] { 15, 16 }) });
                Assert.IsTrue(pcrs.All(x => x.Value.SequenceEqual(new byte[x.Value.Length])));

                // Measure to PCR 16
                try
                {
                    tpm.PcrExtend(TpmHandle.Pcr(16), tpm.PcrEvent(TpmHandle.Pcr(16), nvData));
                }
                catch (TpmException e)
                {
                    Log.Debug(e, "Failed to Write PCR.");
                }

                // Verify that we extended the PCR
                var pcrs2 = TpmCollector.DumpPCRs(tpm, PcrAlgorithm, new PcrSelection[] { new PcrSelection(PcrAlgorithm, new uint[] { 15, 16 }, 24) });
                Assert.IsTrue(pcrs2[(PcrAlgorithm, 15)].SequenceEqual(pcrs[(PcrAlgorithm, 15)]));
                Assert.IsFalse(pcrs2[(PcrAlgorithm, 16)].SequenceEqual(pcrs[(PcrAlgorithm, 16)]));

                // Close the test connection to the device
                tcpTpmDevice.Close();

                // Execute the collector
                tpmc.TryExecute();

                // Shut down the simulator
                process.Kill();

                // Clean up after simulator
                try
                {
                    File.Delete("NVChip");
                }
                catch (Exception)
                {
                    Log.Debug("Failed to delete NVChip file");
                }

                if (tpmc.Results.TryPop(out CollectObject collectObject))
                {
                    if (collectObject is TpmObject tpmObject)
                    {
                        Assert.IsTrue(tpmObject.PCRs.ContainsKey((TpmAlgId.Sha256, 1)));
                        // Verify that the NV Data we wrote was collected
                        Assert.IsTrue(tpmObject.NV.Any(x => x.Index == nvIndex));
                        Assert.IsTrue(tpmObject.NV.Where(x => x.Index == nvIndex).First() is AsaNvIndex nvi && nvi.value is List<byte> && nvi.value.GetRange(0, nvData.Length).SequenceEqual(nvData));
                    }
                    else
                    {
                        Assert.Fail();
                    }
                }
            }
        }

        /// <summary>
        ///     Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestUserCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var user = System.Guid.NewGuid().ToString().Substring(0, 10);
                var password = $"$A4%b^6a_";

                var cmd = string.Format("user /add {0} {1}", user, password);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                var uac = new UserAccountCollector();
                uac.TryExecute();

                Assert.IsTrue(uac.Results.Any(x => x is UserAccountObject y && y.Name.Equals(user)));

                ConcurrentStack<CollectObject> results = new ConcurrentStack<CollectObject>();
                uac = new UserAccountCollector(changeHandler: x => results.Push(x));
                uac.TryExecute();

                Assert.IsTrue(results.Any(x => x is UserAccountObject y && y.Name.Equals(user)));

                cmd = string.Format("user /delete {0}", user);
                ExternalCommandRunner.RunExternalCommand("net", cmd);
            }
        }

        /// <summary>
        ///     We can't actually guarantee there's any wifi networks on the test system. So we just check
        ///     that it doesn't crash.
        /// </summary>
        [TestMethod]
        public void TestWifiCollector()
        {
            var wc = new WifiCollector();
            wc.TryExecute();
        }
    }
}