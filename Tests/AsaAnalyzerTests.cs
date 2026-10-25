using Microsoft.CST.AttackSurfaceAnalyzer.Cli;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.CST.OAT;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass, TestCategory("PipelineSafeTests")]
    public class AsaAnalyzerTests
    {
        public AsaAnalyzerTests()
        {
        }

        [ClassInitialize]
        public static void ClassSetup(TestContext _)
        {
            Logger.Setup(false, true);
            Strings.Setup();
        }

        [TestMethod]
        public void VerifyEmbeddedRulesAreValid()
        {
            var analyzer = new AsaAnalyzer();
            var ruleFile = RuleFile.LoadEmbeddedFilters();
            Assert.IsTrue(!analyzer.EnumerateRuleIssues(ruleFile.Rules).Any());
        }

        [TestMethod]
        public void VerifyFileMonitorAsFile()
        {
            var RuleName = "AndRule";
            var andRule = new AsaRule(RuleName)
            {
                Expression = "0 AND 1",
                ResultType = RESULT_TYPE.FILE,
                Flag = ANALYSIS_RESULT_TYPE.FATAL,
                Clauses = new List<Clause>()
                {
                    new Clause(Operation.Equals,"Path")
                    {
                        Label = "0",
                        Data = new List<string>()
                        {
                            "TestPath1"
                        }
                    },
                    new Clause(Operation.IsTrue,"IsExecutable")
                    {
                        Label = "1"
                    }
                }
            };

            var analyzer = new AsaAnalyzer();

            var opts = new CompareCommandOptions(null, "SecondRun") { ApplySubObjectRulesToMonitor = true };

            var ruleFile = new RuleFile(new AsaRule[] { andRule });
            var results = AttackSurfaceAnalyzerClient.AnalyzeMonitored(opts, analyzer, new MonitorObject[] { testPathOneObject }, ruleFile);

            Assert.IsTrue(results.Any(x => x.Value.Any(y => y.Identity == testPathOneObject.Identity && y.Rules.Contains(andRule))));

            opts = new CompareCommandOptions(null, "SecondRun") { ApplySubObjectRulesToMonitor = false };

            results = AttackSurfaceAnalyzerClient.AnalyzeMonitored(opts, analyzer, new MonitorObject[] { testPathOneObject }, ruleFile);

            Assert.IsFalse(results.Any(x => x.Value.Any(y => y.Identity == testPathOneObject.Identity && y.Rules.Contains(andRule))));
        }

        private const string TestPathOne = "TestPath1";

        private readonly FileMonitorObject testPathOneObject = new(TestPathOne) { FileSystemObject = new FileSystemObject(TestPathOne) { IsExecutable = true } };

        /// <summary>
        ///     The CVE-2026-50343 shape: a load point key an unprivileged user can write, pointing through a
        ///     CLSID at a DLL that does not exist in a directory they can also write.
        /// </summary>
        [TestMethod]
        public void VerifyLoadPointRulesFlagLayAndWaitConfiguration()
        {
            var sourceKey = new RegistryObject(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State",
                RegistryView.Registry64);
            sourceKey.Permissions.Add("NT AUTHORITY\\INTERACTIVE", new List<string> { "Allow:SetValue", "Allow:CreateSubKey" });

            var loadPoint = new LoadPointObject("StaticPluginMap", sourceKey)
            {
                SourceValueName = "StaticPluginMap",
                SourceKeyUserWritable = true,
                TargetClsid = "{E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}",
                TargetPath = @"C:\ProgramData\CrossDevice\CrossDevice.Streaming.Source.dll",
                TargetExists = false,
                TargetUserWritable = true,
                TargetAclSource = "NearestExistingParent",
                NearestExistingParentPath = @"C:\ProgramData",
            };

            var matched = AnalyzeLoadPoint(loadPoint);

            Assert.IsTrue(matched.Contains("Load Point Writable by Unprivileged Users"));
            Assert.IsTrue(matched.Contains("Load Point Target Missing from Unprivileged Writable Directory"));
            Assert.IsTrue(matched.Contains("Privilege Escalation via Unprivileged Load Point"));

            // The DLL does not exist, so the rule about replacing an existing binary must not claim it.
            Assert.IsFalse(matched.Contains("Load Point Target Writable by Unprivileged Users"));
        }

        /// <summary>
        ///     A correctly ACLed COM registration must not flag. A rule that fires on every COM object is
        ///     worthless.
        /// </summary>
        [TestMethod]
        public void VerifyLoadPointRulesDoNotFlagBenignComRegistration()
        {
            var sourceKey = new RegistryObject(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\InprocServer32",
                RegistryView.Registry64);
            sourceKey.Permissions.Add("NT AUTHORITY\\SYSTEM", new List<string> { "Allow:FullControl" });
            sourceKey.Permissions.Add("BUILTIN\\Administrators", new List<string> { "Allow:FullControl" });
            sourceKey.Permissions.Add("BUILTIN\\Users", new List<string> { "Allow:ReadKey", "Allow:QueryValues" });

            var loadPoint = new LoadPointObject("ComServer", sourceKey)
            {
                SourceValueName = string.Empty,
                SourceKeyUserWritable = false,
                TargetPath = @"C:\Windows\System32\shell32.dll",
                TargetExists = true,
                TargetUserWritable = false,
                TargetAclSource = "Target",
            };

            Assert.AreEqual(0, AnalyzeLoadPoint(loadPoint).Count);
        }

        /// <summary>
        ///     A target whose ACL could not be read is not evidence of anything and must not flag.
        /// </summary>
        [TestMethod]
        public void VerifyLoadPointRulesDoNotFlagUnreadableTargetAcl()
        {
            var sourceKey = new RegistryObject(@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{1}\InprocServer32", RegistryView.Registry64);
            sourceKey.Permissions.Add("NT AUTHORITY\\SYSTEM", new List<string> { "Allow:FullControl" });

            var loadPoint = new LoadPointObject("ComServer", sourceKey)
            {
                SourceKeyUserWritable = false,
                TargetPath = @"C:\Windows\System32\protected.dll",
                TargetExists = true,
                TargetUserWritable = false,
                TargetAclUnavailable = true,
                TargetAclSource = "Target",
            };

            Assert.AreEqual(0, AnalyzeLoadPoint(loadPoint).Count);
        }

        /// <summary>
        ///     An existing binary an unprivileged user can replace is flagged, but not by the
        ///     missing-target rule.
        /// </summary>
        [TestMethod]
        public void VerifyLoadPointRulesFlagWritableExistingTarget()
        {
            var sourceKey = new RegistryObject(@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2}\InprocServer32", RegistryView.Registry64);
            sourceKey.Permissions.Add("NT AUTHORITY\\SYSTEM", new List<string> { "Allow:FullControl" });

            var loadPoint = new LoadPointObject("ComServer", sourceKey)
            {
                SourceKeyUserWritable = false,
                TargetPath = @"C:\ProgramData\Contoso\plugin.dll",
                TargetExists = true,
                TargetUserWritable = true,
                TargetAclSource = "Target",
            };

            var matched = AnalyzeLoadPoint(loadPoint);

            Assert.IsTrue(matched.Contains("Load Point Target Writable by Unprivileged Users"));
            Assert.IsFalse(matched.Contains("Load Point Target Missing from Unprivileged Writable Directory"));
            Assert.IsFalse(matched.Contains("Load Point Writable by Unprivileged Users"));
        }

        private static HashSet<string> AnalyzeLoadPoint(LoadPointObject loadPoint)
        {
            var analyzer = new AsaAnalyzer();
            var rules = RuleFile.LoadEmbeddedFilters().Rules
                .Where(rule => rule.ResultType == RESULT_TYPE.LOADPOINT)
                .ToList();

            Assert.IsTrue(rules.Count > 0, "No load point rules are present in the embedded rule file.");

            return analyzer.Analyze(rules, new CompareResult() { Compare = loadPoint })
                .Select(rule => rule.Name)
                .ToHashSet();
        }
    }
}