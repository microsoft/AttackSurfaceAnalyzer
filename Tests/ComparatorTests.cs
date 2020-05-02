// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using WindowsFirewallHelper;

namespace AttackSurfaceAnalyzer.Tests
{
    [TestClass]
    public class ComparatorTests
    {
        [TestInitialize]
        public void Setup()
        {
            Logger.Setup(false, true);
            Strings.Setup();
            AsaTelemetry.Setup(test: true);
            DatabaseManager.Setup(Path.GetTempFileName());
        }

        [TestCleanup]
        public void TearDown()
        {
            DatabaseManager.Destroy();
        }

        [TestMethod]
        public void TestFileCompare()
        {
            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var opts = new CollectCommandOptions()
            {
                RunId = FirstRunId,
                EnableFileSystemCollector = true,
                GatherHashes = true,
                SelectedDirectories = testFolder,
                DownloadCloud = false,
                CertificatesFromFiles = false
            };

            var fsc = new FileSystemCollector(opts);
            fsc.Execute();

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

            opts.RunId = SecondRunId;

            var fsc2 = new FileSystemCollector(opts);
            fsc2.Execute();

            Assert.IsTrue(fsc2.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterMZ")));
            Assert.IsTrue(fsc2.Results.Any(x => x is FileSystemObject FSO && FSO.Path.EndsWith("AsaLibTesterJavaClass")));

            BaseCompare bc = new BaseCompare();
            bc.Compare(fsc.Results, fsc2.Results, FirstRunId, SecondRunId);
            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("AsaLibTesterMZ") && ((FileSystemObject)x.Compare).IsExecutable == true));
            Assert.IsTrue(results[(RESULT_TYPE.FILE, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("AsaLibTesterJavaClass") && ((FileSystemObject)x.Compare).IsExecutable == true));
        }

        /// <summary>
        /// Requires Admin
        /// </summary>
        [TestMethod]
        public void TestEventCompareWindows()
        {
            var FirstRunId = "TestEventCollector-1";
            var SecondRunId = "TestEventCollector-2";

            var fsc = new EventLogCollector();
            fsc.Execute();
            fsc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

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

            fsc = new EventLogCollector();
            fsc.Execute();

            EventLog.DeleteEventSource(source);
            EventLog.Delete(logname);

            Assert.IsTrue(fsc.Results.Any(x => x is EventLogObject ELO && ELO.Source == "Attack Surface Analyzer Tests" && ELO.Timestamp is DateTime DT && DT.AddMinutes(1).CompareTo(DateTime.Now) > 0));

            fsc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

            while (DatabaseManager.HasElements)
            {
                Thread.Sleep(1);
            }

            BaseCompare bc = new BaseCompare();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            var results = bc.Results;

            Assert.IsTrue(results[(RESULT_TYPE.LOG, CHANGE_TYPE.CREATED)].Any(x => x.Compare is EventLogObject ELO && ELO.Level == "Warning" && ELO.Source == "Attack Surface Analyzer Tests"));
        }

        /// <summary>
        /// Does not require Admin.
        /// </summary>
        [TestMethod]
        public void TestPortCompareWindows()
        {
            var FirstRunId = "TestPortCollector-1";
            var SecondRunId = "TestPortCollector-2";

            var fsc = new OpenPortCollector();
            fsc.Execute();

            fsc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

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

            fsc = new OpenPortCollector();
            fsc.Execute();

            server.Stop();

            Assert.IsTrue(fsc.Results.Any(x => x is OpenPortObject OPO && OPO.Port == 13000));

            fsc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

            while (DatabaseManager.HasElements)
            {
                Thread.Sleep(1);
            }

            BaseCompare bc = new BaseCompare();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey((RESULT_TYPE.PORT, CHANGE_TYPE.CREATED)));
            Assert.IsTrue(results[(RESULT_TYPE.PORT, CHANGE_TYPE.CREATED)].Any(x => x.Identity.Contains("13000")));
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCompareOSX()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add /bin/bash");

                fwc = new FirewallCollector();
                fwc.Execute();

                Assert.IsTrue(fwc.Results.Any(x => x is FirewallObject FWO && FWO.ApplicationName == "/bin/bash"));

                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove /bin/bash");

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("/bin/bash")).Count() > 0);
            }
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCompareLinux()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

                var result = ExternalCommandRunner.RunExternalCommand("iptables", "-A INPUT -p tcp --dport 19999 -j DROP");

                fwc = new FirewallCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

                result = ExternalCommandRunner.RunExternalCommand("iptables", "-D INPUT -p tcp --dport 19999 -j DROP");

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("9999")).Count() > 0);
            }
        }

        /// <summary>
        /// Does not require administrator.
        /// </summary>
        [TestMethod]
        public void TestRegistryCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var FirstRunId = "TestRegistryCollector-1";
                var SecondRunId = "TestRegistryCollector-2";

                var rc = new RegistryCollector(new List<RegistryHive>() { RegistryHive.CurrentUser }, true);
                rc.Execute();
                rc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

                // Create a registry key
                var name = Guid.NewGuid().ToString();
                var value = Guid.NewGuid().ToString();
                var value2 = Guid.NewGuid().ToString();

                RegistryKey key;
                key = Registry.CurrentUser.CreateSubKey(name);
                key.SetValue(value, value2);
                key.Close();

                rc = new RegistryCollector(new List<RegistryHive>() { RegistryHive.CurrentUser }, true);
                rc.Execute();

                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name)));
                Assert.IsTrue(rc.Results.Any(x => x is RegistryObject RO && RO.Key.EndsWith(name) && RO.Values.ContainsKey(value) && RO.Values[value] == value2));

                rc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

                // Clean up
                Registry.CurrentUser.DeleteSubKey(name);

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();

                bc.TryCompare(FirstRunId, SecondRunId);

                Assert.IsTrue(bc.Results.ContainsKey((RESULT_TYPE.REGISTRY, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(bc.Results[(RESULT_TYPE.REGISTRY, CHANGE_TYPE.CREATED)].Any(x => x.Compare is RegistryObject RO && RO.Key.EndsWith(name)));
            }
        }

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestServiceCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var FirstRunId = "TestServiceCollector-1";
                var SecondRunId = "TestServiceCollector-2";

                var fwc = new ServiceCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

                // Create a service - This won't throw an exception, but it won't work if you are not an Admin.
                var serviceName = "AsaDemoService";
                var exeName = "AsaDemoService.exe";
                var cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                fwc = new ServiceCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

                // Clean up
                cmd = string.Format("delete {0}", serviceName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.SERVICE, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.SERVICE, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("AsaDemoService")).Count() > 0);
            }
        }

        // @TODO ComObject Compare

        /// <summary>
        /// Requires Administrator Priviledges.
        /// </summary>
        [TestMethod]
        public void TestUserCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var FirstRunId = "TestUserCollector-1";
                var SecondRunId = "TestUserCollector-2";

                var fwc = new UserAccountCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

                var user = System.Guid.NewGuid().ToString().Substring(0, 10);
                var password = "$" + CryptoHelpers.GetRandomString(13);

                var cmd = string.Format("user /add {0} {1}", user, password);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                var serviceName = System.Guid.NewGuid();

                fwc = new UserAccountCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

                cmd = string.Format("user /delete {0}", user);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;
                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.USER, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.USER, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains(user)).Count() > 0);
            }
        }

        [TestMethod]
        public void TestFirewallCompareWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, FirstRunId));

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

                fwc = new FirewallCollector();
                fwc.Execute();
                fwc.Results.AsParallel().ForAll(x => DatabaseManager.Write(x, SecondRunId));

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

                while (DatabaseManager.HasElements)
                {
                    Thread.Sleep(1);
                }

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey((RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)));
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => ((FirewallObject)x.Compare).LocalPorts.Contains("9999")).Count() > 0);
                Assert.IsTrue(results[(RESULT_TYPE.FIREWALL, CHANGE_TYPE.CREATED)].Where(x => x.Identity.Contains("MyApp.exe")).Count() > 0);
            }
        }
    }
}
