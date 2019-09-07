using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WindowsFirewallHelper;

namespace AsaTests
{
    [TestClass]
    public class AsaLibTests
    {
        public void Setup()
        {
            Strings.Setup();
            Telemetry.TestMode();
            DatabaseManager.SqliteFilename = Path.GetTempFileName();
            DatabaseManager.Setup();
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
            var fsc = new FileSystemCollector(FirstRunId, enableHashing: true, directories: Path.GetTempPath(), downloadCloud: false, examineCertificates: true);
            fsc.Execute();

            var testFile = Path.GetTempFileName();

            fsc = new FileSystemCollector(SecondRunId, enableHashing: true, directories: Path.GetTempPath(), downloadCloud: false, examineCertificates: true);
            fsc.Execute();

            BaseCompare bc = new BaseCompare();
            var watch = System.Diagnostics.Stopwatch.StartNew();
            if (!bc.TryCompare(FirstRunId, SecondRunId))
            {
                Assert.Fail();
            }

            Dictionary<string, List<CompareResult>> results = bc.Results;
            Assert.IsTrue(results["FILE_CREATED"].Where(x => x.Identity.Contains(testFile)).Count() > 0);

            TearDown();
        }

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

                var result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--add", "/bin/bash");

                fwc = new FirewallCollector(SecondRunId);
                fwc.Execute();

                result = ExternalCommandRunner.RunExternalCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--remove", "/bin/bash");

                BaseCompare bc = new BaseCompare();
                var watch = System.Diagnostics.Stopwatch.StartNew();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                Dictionary<string, List<CompareResult>> results = bc.Results;
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => x.Identity.Contains("/bin/bash")).Count() > 0);

                TearDown();
            }
        }


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

                // Create a service
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
                var watch = System.Diagnostics.Stopwatch.StartNew();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                Dictionary<string, List<CompareResult>> results = bc.Results;
                Assert.IsTrue(results["SERVICE_CREATED"].Where(x => x.Identity.Contains("AsaDemoService")).Count() > 0);

                TearDown();
            }
        }

        [TestMethod]
        public void UserCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
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
                var watch = System.Diagnostics.Stopwatch.StartNew();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                Dictionary<string, List<CompareResult>> results = bc.Results;
                Assert.IsTrue(results["USER_CREATED"].Where(x => x.Identity.Contains(user)).Count() > 0);

                TearDown();
            }
        }

        [TestMethod]
        public void TestFirewallCollectorWindows()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
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

                rule = FirewallManager.Instance.Rules.SingleOrDefault(r => r.Name == "TestFirewallPortRule");
                if (rule != null)
                {
                    FirewallManager.Instance.Rules.Remove(rule);
                }

                rule = FirewallManager.Instance.Rules.SingleOrDefault(r => r.Name == "TestFirewallAppRule");
                if (rule != null)
                {
                    FirewallManager.Instance.Rules.Remove(rule);
                }

                BaseCompare bc = new BaseCompare();
                var watch = System.Diagnostics.Stopwatch.StartNew();
                if (!bc.TryCompare(FirstRunId, SecondRunId))
                {
                    Assert.Fail();
                }

                Dictionary<string, List<CompareResult>> results = bc.Results;
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => ((FirewallObject)x.Compare).LocalPorts.Contains("9999")).Count() > 0);
                Assert.IsTrue(results["FIREWALL_CREATED"].Where(x => x.Identity.Contains("MyApp.exe")).Count() > 0);

                TearDown();
            }
        }
    }
}
