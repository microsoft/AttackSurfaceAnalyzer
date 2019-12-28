using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using WindowsFirewallHelper;

namespace AsaTests
{
    [TestClass]
    public class AsaLibTests
    {
        public void Setup()
        {
            Logger.Setup();
            Strings.Setup();
            AsaTelemetry.TestMode();
            DatabaseManager.Setup(Path.GetTempFileName());
        }

        public void TearDown()
        {
            DatabaseManager.CloseDatabase();
            try
            {
                File.Delete(DatabaseManager.SqliteFilename);
            }
            catch (Exception)
            {
            }
        }

        [TestMethod]
        public void TestFileCollector()
        {
            Setup();

            var FirstRunId = "TestFileCollector-1";
            var SecondRunId = "TestFileCollector-2";

            var testFolder = AsaHelpers.GetTempFolder();
            Directory.CreateDirectory(testFolder);

            var fsc = new FileSystemCollector(FirstRunId, enableHashing: true, directories: testFolder, downloadCloud: false, examineCertificates: true);
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

            fsc = new FileSystemCollector(SecondRunId, enableHashing: true, directories: testFolder, downloadCloud: false, examineCertificates: true);
            fsc.Execute();

            BaseCompare bc = new BaseCompare();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey("FILE_CREATED"));
            Assert.IsTrue(results["FILE_CREATED"].Where(x => x.Identity.Contains("AsaLibTesterMZ") && ((FileSystemObject)x.Compare).IsExecutable == true).Any());
            Assert.IsTrue(results["FILE_CREATED"].Where(x => x.Identity.Contains("AsaLibTesterJavaClass") && ((FileSystemObject)x.Compare).IsExecutable == true).Any());

            TearDown();
        }

        /// <summary>
        /// Requires Admin
        /// </summary>
        [TestMethod]
        public void TestEventCollectorWindows()
        {
            Setup();

            var FirstRunId = "TestEventCollector-1";
            var SecondRunId = "TestEventCollector-2";

            var fsc = new EventLogCollector(FirstRunId);
            fsc.Execute();

            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "Attack Surface Analyzer Tests";
                eventLog.WriteEntry("This Log Entry was created for testing the Attack Surface Analyzer library.", EventLogEntryType.Warning, 101, 1);
            }

            fsc = new EventLogCollector(SecondRunId);
            fsc.Execute();

            BaseCompare bc = new BaseCompare();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            var results = bc.Results;

            Assert.IsTrue(results["LOG_CREATED"].Where(x => ((EventLogObject)x.Compare).Level == "Warning" && ((EventLogObject)x.Compare).Source == "Attack Surface Analyzer Tests").Count() == 1);

            TearDown();
        }

        /// <summary>
        /// Does not require admin.
        /// </summary>
        [TestMethod]
        public void TestCertificateCollectorWindows()
        {
            Setup();

            var FirstRunId = "TestCertificateCollector-1";

            var fsc = new CertificateCollector(FirstRunId);
            fsc.Execute();

            var results = DatabaseManager.GetResultsByRunid(FirstRunId);

            Assert.IsTrue(results.Where(x => x.ResultType == RESULT_TYPE.CERTIFICATE).Count() > 0);

            TearDown();
        }

        /// <summary>
        /// Does not require Admin.
        /// </summary>
        [TestMethod]
        public void TestPortCollectorWindows()
        {
            Setup();

            var FirstRunId = "TestPortCollector-1";
            var SecondRunId = "TestPortCollector-2";

            var fsc = new OpenPortCollector(FirstRunId);
            fsc.Execute();

            TcpListener server = null;
            try
            {
                // Set the TcpListener on port 13000.
                Int32 port = 13000;
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

            fsc = new OpenPortCollector(SecondRunId);
            fsc.Execute();

            server.Stop();

            BaseCompare bc = new BaseCompare();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            var results = bc.Results;

            Assert.IsTrue(results.ContainsKey("PORT_CREATED"));
            Assert.IsTrue(results["PORT_CREATED"].Where(x => x.Identity.Contains("13000")).Count() > 0);

            TearDown();
        }

        /// <summary>
        /// Requires root.
        /// </summary>
        [TestMethod]
        public void TestFirewallCollectorOSX()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                Setup();
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector(FirstRunId);
                fwc.Execute();

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add", "/bin/bash");

                fwc = new FirewallCollector(SecondRunId);
                fwc.Execute();

                _ = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove", "/bin/bash");

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey("FIREWALL_CREATED"));
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => x.Identity.Contains("/bin/bash")).Count() > 0);

                TearDown();
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
                Setup();
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector(FirstRunId);
                fwc.Execute();

                var result = ExternalCommandRunner.RunExternalCommand("iptables", "-A INPUT -p tcp --dport 19999 -j DROP");

                fwc = new FirewallCollector(SecondRunId);
                fwc.Execute();

                result = ExternalCommandRunner.RunExternalCommand("iptables", "-D INPUT -p tcp --dport 19999 -j DROP");

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey("FIREWALL_CREATED"));
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => x.Identity.Contains("9999")).Count() > 0);

                TearDown();
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
                Setup();

                var FirstRunId = "TestRegistryCollector-1";
                var SecondRunId = "TestRegistryCollector-2";

                var rc = new RegistryCollector(FirstRunId, new List<RegistryHive>() { RegistryHive.CurrentUser }, true);
                rc.Execute();

                // Create a registry key
                var name = System.Guid.NewGuid().ToString().Substring(0, 10);
                var value = System.Guid.NewGuid().ToString().Substring(0, 10);
                var value2 = System.Guid.NewGuid().ToString().Substring(0, 10);

                RegistryKey key;
                key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(name);
                key.SetValue(value, value2);
                key.Close();

                rc = new RegistryCollector(SecondRunId, new List<RegistryHive>() { RegistryHive.CurrentUser }, true);
                rc.Execute();

                // Clean up
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKey(name);

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey("REGISTRY_CREATED"));
                Assert.IsTrue(results["REGISTRY_CREATED"].Where(x => x.Identity.Contains(name)).Count() > 0);

                TearDown();
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
                Setup();

                var FirstRunId = "TestServiceCollector-1";
                var SecondRunId = "TestServiceCollector-2";

                var fwc = new ServiceCollector(FirstRunId);
                fwc.Execute();

                // Create a service - This won't throw an exception, but it won't work if you are not an Admin.
                var serviceName = "AsaDemoService";
                var exeName = "AsaDemoService.exe";
                var cmd = string.Format("create {0} binPath=\"{1}\"", serviceName, exeName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                fwc = new ServiceCollector(SecondRunId);
                fwc.Execute();

                // Clean up
                cmd = string.Format("delete {0}", serviceName);
                ExternalCommandRunner.RunExternalCommand("sc.exe", cmd);

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey("SERVICE_CREATED"));
                Assert.IsTrue(results["SERVICE_CREATED"].Where(x => x.Identity.Contains("AsaDemoService")).Count() > 0);

                TearDown();
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
                Setup();

                var FirstRunId = "TestComObjectCollector-1";

                var coc = new ComObjectCollector(FirstRunId);
                coc.Execute();

                List<RawCollectResult> collectResults = DatabaseManager.GetResultsByRunid(FirstRunId);

                List<ComObject> comObjects = new List<ComObject>();

                foreach (var collectResult in collectResults)
                {
                    comObjects.Add((ComObject)BaseCompare.Hydrate(collectResult));
                }

                Assert.IsTrue(comObjects.Where(x => x.x86_Binary != null).Count() > 0);

                TearDown();
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
                Setup();

                var FirstRunId = "TestUserCollector-1";
                var SecondRunId = "TestUserCollector-2";

                var fwc = new UserAccountCollector(FirstRunId);
                fwc.Execute();

                var user = System.Guid.NewGuid().ToString().Substring(0, 10);
                var password = System.Guid.NewGuid().ToString().Substring(0, 10);
                var cmd = string.Format("user /add {0} {1}", user, password);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                var serviceName = System.Guid.NewGuid();

                fwc = new UserAccountCollector(SecondRunId);
                fwc.Execute();

                cmd = string.Format("user /delete {0}", user);
                ExternalCommandRunner.RunExternalCommand("net", cmd);

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;
                Assert.IsTrue(results.ContainsKey("USER_CREATED"));
                Assert.IsTrue(results["USER_CREATED"].Where(x => x.Identity.Contains(user)).Count() > 0);

                TearDown();
            }
        }

        [TestMethod]
        public void TestFirewallCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.IsTrue(AsaHelpers.IsAdmin());
                Setup();
                var FirstRunId = "TestFirewallCollector-1";
                var SecondRunId = "TestFirewallCollector-2";

                var fwc = new FirewallCollector(FirstRunId);
                fwc.Execute();

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

                fwc = new FirewallCollector(SecondRunId);
                fwc.Execute();

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

                BaseCompare bc = new BaseCompare();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                var results = bc.Results;

                Assert.IsTrue(results.ContainsKey("FIREWALL_CREATED"));
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => ((FirewallObject)x.Compare).LocalPorts.Contains("9999")).Count() > 0);
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => x.Identity.Contains("MyApp.exe")).Count() > 0);

                TearDown();
            }
        }
    }
}
