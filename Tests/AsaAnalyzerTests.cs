using Microsoft.CST.AttackSurfaceAnalyzer.Cli;
using Microsoft.CST.AttackSurfaceAnalyzer.Objects;
using Microsoft.CST.AttackSurfaceAnalyzer.Types;
using Microsoft.CST.AttackSurfaceAnalyzer.Utils;
using Microsoft.CST.OAT;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Tests
{
    [TestClass]
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

        private readonly FileMonitorObject testPathOneObject = new FileMonitorObject(TestPathOne) { FileSystemObject = new FileSystemObject(TestPathOne) { IsExecutable = true } };
    }
}